package fetch

import (
	"crypto/tls"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func mustGuard(t *testing.T, c *http.Client) (*guardTransport, *http.Transport) {
	t.Helper()
	guard, ok := c.Transport.(*guardTransport)
	if !ok {
		t.Fatalf("client transport is %T, want *guardTransport", c.Transport)
	}
	base, ok := guard.base.(*http.Transport)
	if !ok {
		t.Fatalf("base transport is %T, want *http.Transport", guard.base)
	}
	return guard, base
}

func TestNewClientAppliesDefaults(t *testing.T) {
	c, err := NewClient(Policy{})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	guard, base := mustGuard(t, c)

	if c.Timeout != 15*time.Second || DefaultTimeout != 15*time.Second {
		t.Errorf("Timeout = %v, want 15s", c.Timeout)
	}
	if DefaultDialTimeout != 5*time.Second || base.TLSHandshakeTimeout != DefaultDialTimeout {
		t.Errorf("dial/handshake timeout = %v, want 5s", base.TLSHandshakeTimeout)
	}
	if guard.maxBytes != 8<<20 || DefaultMaxResponseBytes != 8<<20 {
		t.Errorf("maxBytes = %d, want 8 MiB", guard.maxBytes)
	}
	if guard.maxRedirects != 0 {
		t.Errorf("maxRedirects = %d, want 0", guard.maxRedirects)
	}
	if base.MaxResponseHeaderBytes != 64<<10 {
		t.Errorf("MaxResponseHeaderBytes = %d, want 64 KiB", base.MaxResponseHeaderBytes)
	}
	if c.CheckRedirect == nil || c.Jar != nil {
		t.Error("the client must police redirects and must not keep cookies")
	}
}

func TestNewClientTransportHardening(t *testing.T) {
	c, err := NewClient(Policy{})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, base := mustGuard(t, c)
	if base.Proxy != nil {
		t.Error("Proxy must be nil: through a proxy the dial check only sees the proxy")
	}
	if !base.DisableKeepAlives {
		t.Error("keep-alive must be off so the standard library cannot retry on a stale connection")
	}
	if base.DialContext == nil {
		t.Error("DialContext must be the guarded dialer")
	}
	if base.ForceAttemptHTTP2 || base.TLSNextProto == nil {
		t.Error("HTTP/2 must stay off")
	}
	if base.TLSClientConfig == nil || base.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Error("TLS 1.2 must be the minimum")
	}
}

func TestNewClientHonoursExplicitLimits(t *testing.T) {
	c, err := NewClient(Policy{
		Timeout:          3 * time.Second,
		DialTimeout:      time.Second,
		MaxResponseBytes: 1234,
		MaxRedirects:     4,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	guard, base := mustGuard(t, c)
	if c.Timeout != 3*time.Second || base.TLSHandshakeTimeout != time.Second ||
		guard.maxBytes != 1234 || guard.maxRedirects != 4 {
		t.Fatalf("limits not applied: timeout=%v handshake=%v bytes=%d redirects=%d",
			c.Timeout, base.TLSHandshakeTimeout, guard.maxBytes, guard.maxRedirects)
	}
}

func TestNewClientRejectsInvalidPolicy(t *testing.T) {
	cases := []struct {
		name string
		p    Policy
	}{
		{"negative timeout", Policy{Timeout: -1}},
		{"negative dial timeout", Policy{DialTimeout: -time.Second}},
		{"negative max bytes", Policy{MaxResponseBytes: -1}},
		{"negative redirects", Policy{MaxRedirects: -1}},
		{"too many redirects", Policy{MaxRedirects: maxRedirectsCeiling + 1}},
		{"empty allow entry", Policy{AllowHosts: []string{"ok.test", "  "}}},
		{"url as allow entry", Policy{AllowHosts: []string{"https://ok.test"}}},
		{"path in allow entry", Policy{AllowHosts: []string{"ok.test/path"}}},
		{"user info in allow entry", Policy{AllowHosts: []string{"user@ok.test"}}},
		{"port in allow entry", Policy{AllowHosts: []string{"ok.test:8080"}}},
		{"ipv4 port in allow entry", Policy{AllowHosts: []string{"10.0.0.1:80"}}},
		{"zoned allow entry", Policy{AllowHosts: []string{"fe80::1%eth0"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewClient(tc.p)
			if err == nil || c != nil {
				t.Fatalf("NewClient = (%v, %v), want an error", c, err)
			}
			if !strings.HasPrefix(err.Error(), "fetch: policy") {
				t.Errorf("error %q should say it is a policy error", err)
			}
		})
	}
}

func TestAllowHostsAreNormalisedAndCopied(t *testing.T) {
	entries := []string{"Example.COM", "[::1]", "0:0:0:0:0:0:0:1", "127.0.0.1", "  padded.test  "}
	c, err := NewClient(Policy{AllowHosts: entries})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	guard, _ := mustGuard(t, c)
	for _, want := range []string{"example.com", "::1", "127.0.0.1", "padded.test"} {
		if _, ok := guard.allowHosts[want]; !ok {
			t.Errorf("allow set is missing %q: %v", want, guard.allowHosts)
		}
	}
	if len(guard.allowHosts) != 4 {
		t.Errorf("allow set has %d entries, want 4 (the two spellings of ::1 collapse)", len(guard.allowHosts))
	}

	entries[0] = "evil.test" // mutating the caller's slice must not reach the client
	if _, ok := guard.allowHosts["evil.test"]; ok {
		t.Error("the client aliases the caller's AllowHosts slice")
	}
}

func TestAllowHostsRestrictRequests(t *testing.T) {
	hits := &hitCounter{}
	srv := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.inc()
		_, _ = w.Write([]byte("ok"))
	}))
	port := portOf(t, srv)
	resolver := newFakeResolver(t, map[string][]string{
		"allowed.test": {"127.0.0.1"},
		"other.test":   {"127.0.0.1"},
	})
	client := newTestClient(t, Policy{
		AllowPrivate: true,
		AllowHosts:   []string{"allowed.test", "127.0.0.1"},
		Resolver:     resolver,
	})

	for _, allowed := range []string{
		"http://allowed.test:" + port + "/",
		"http://ALLOWED.test:" + port + "/", // host comparison is case-insensitive
		"http://127.0.0.1:" + port + "/",
	} {
		if body, err := getBody(client, allowed); err != nil || string(body) != "ok" {
			t.Errorf("%s: body %q, err %v", allowed, body, err)
		}
	}
	before := hits.count()
	for _, denied := range []string{
		"http://other.test:" + port + "/",
		"http://allowed.test.evil.test:" + port + "/",
		"http://[::1]:" + port + "/",
		"http://localhost:" + port + "/",
	} {
		if _, err := get(client, denied); !errors.Is(err, ErrBlockedHost) {
			t.Errorf("%s: got %v, want ErrBlockedHost", denied, err)
		}
	}
	if hits.count() != before {
		t.Error("a request to a host outside the allow-list reached the server")
	}
	if resolver.callCount() != 2 {
		t.Errorf("resolver called %d times; only the two allowed names should be resolved", resolver.callCount())
	}
}

func TestAllowHostsNeverWidenTheAddressPolicy(t *testing.T) {
	client := newTestClient(t, Policy{AllowHosts: []string{"127.0.0.1", "169.254.169.254"}, AllowPrivate: true})
	if _, err := get(client, "http://169.254.169.254/"); !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("got %v, want ErrBlockedAddress: an allow-list entry must not open metadata", err)
	}
	strict := newTestClient(t, Policy{AllowHosts: []string{"127.0.0.1"}})
	if _, err := get(strict, "http://127.0.0.1/"); !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("got %v, want ErrBlockedAddress: an allow-list entry must not open loopback", err)
	}
}

// TestProxyEnvironmentIgnored points the standard proxy variables at a server
// and checks the request still goes straight to the target.
func TestProxyEnvironmentIgnored(t *testing.T) {
	proxyHits := &hitCounter{}
	proxy := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyHits.inc()
		_, _ = w.Write([]byte("proxy"))
	}))
	target := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("target"))
	}))
	for _, name := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY"} {
		t.Setenv(name, proxy.URL)
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")

	resolver := newFakeResolver(t, map[string][]string{"svc.example.test": {"127.0.0.1"}})
	client := newTestClient(t, Policy{AllowPrivate: true, Resolver: resolver})
	body, err := getBody(client, "http://svc.example.test:"+portOf(t, target)+"/")
	if err != nil || string(body) != "target" {
		t.Fatalf("body %q, err %v", body, err)
	}
	if proxyHits.count() != 0 {
		t.Fatal("the request went through the proxy from the environment")
	}
}
