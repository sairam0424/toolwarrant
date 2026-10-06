package fetch

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// literalCase is one way of naming a forbidden destination. Each case is
// exercised twice: written into the URL, and returned by a resolver for a
// public-looking host name.
type literalCase struct {
	name string
	// urlHost is the authority as written in the URL.
	urlHost string
	// ips is the address(es) the literal denotes, i.e. what a resolver that
	// understands the spelling would return.
	ips []string
	// alwaysBlocked marks spellings and ranges that AllowPrivate must not open.
	alwaysBlocked bool
}

var literalCases = []literalCase{
	{"loopback", "127.0.0.1", []string{"127.0.0.1"}, false},
	{"loopback short form", "127.1", []string{"127.0.0.1"}, true},
	{"loopback decimal", "2130706433", []string{"127.0.0.1"}, true},
	{"loopback hex", "0x7f.0.0.1", []string{"127.0.0.1"}, true},
	{"loopback octal", "0177.0.0.1", []string{"127.0.0.1"}, true},
	{"loopback trailing dot", "127.0.0.1.", []string{"127.0.0.1"}, true},
	{"localhost", "localhost", []string{"127.0.0.1", "::1"}, false},
	{"ipv6 loopback", "[::1]", []string{"::1"}, false},
	{"ipv4-mapped loopback dotted", "[::ffff:127.0.0.1]", []string{"::ffff:127.0.0.1"}, false},
	{"ipv4-mapped loopback hex", "[::ffff:7f00:1]", []string{"::ffff:7f00:1"}, false},
	{"ipv4-compatible loopback", "[::7f00:1]", []string{"::7f00:1"}, true},
	{"unspecified v4", "0.0.0.0", []string{"0.0.0.0"}, true},
	{"unspecified v6", "[::]", []string{"::"}, true},
	{"cloud metadata", "169.254.169.254", []string{"169.254.169.254"}, true},
	{"cloud metadata ipv4-mapped", "[::ffff:a9fe:a9fe]", []string{"::ffff:a9fe:a9fe"}, true},
	{"cloud metadata aws ipv6", "[fd00:ec2::254]", []string{"fd00:ec2::254"}, true},
	{"cloud metadata via nat64", "[64:ff9b::a9fe:a9fe]", []string{"64:ff9b::a9fe:a9fe"}, true},
	{"cloud metadata via 6to4", "[2002:a9fe:a9fe::]", []string{"2002:a9fe:a9fe::"}, true},
	{"azure wireserver", "168.63.129.16", []string{"168.63.129.16"}, true},
	{"link-local v6", "[fe80::1]", []string{"fe80::1"}, true},
	{"link-local v6 with zone", "[fe80::1%25eth0]", []string{"fe80::1"}, true},
	{"rfc1918 10/8", "10.0.0.1", []string{"10.0.0.1"}, false},
	{"rfc1918 172.16/12", "172.16.0.1", []string{"172.16.0.1"}, false},
	{"rfc1918 192.168/16", "192.168.1.1", []string{"192.168.1.1"}, false},
	{"unique local", "[fc00::1]", []string{"fc00::1"}, false},
	{"cgnat", "100.64.0.1", []string{"100.64.0.1"}, true},
	{"ietf protocol assignments", "192.0.0.1", []string{"192.0.0.1"}, true},
	{"test-net-1", "192.0.2.1", []string{"192.0.2.1"}, true},
	{"benchmarking", "198.18.0.1", []string{"198.18.0.1"}, true},
	{"multicast", "224.0.0.1", []string{"224.0.0.1"}, true},
	{"broadcast", "255.255.255.255", []string{"255.255.255.255"}, true},
	{"reserved", "240.0.0.1", []string{"240.0.0.1"}, true},
	{"nat64 loopback", "[64:ff9b::7f00:1]", []string{"64:ff9b::7f00:1"}, true},
	{"6to4 loopback", "[2002:7f00:1::]", []string{"2002:7f00:1::"}, true},
	{"teredo", "[2001::1]", []string{"2001::1"}, true},
}

// resolverFor returns a resolver that knows only what the case needs:
// nothing for a literal (so any lookup fails the test), and the loopback
// answers for the name "localhost".
func resolverFor(t *testing.T, tc literalCase) *fakeResolver {
	answers := map[string][]string{}
	if tc.urlHost == "localhost" {
		answers["localhost"] = tc.ips
	}
	return newFakeResolver(t, answers)
}

func TestLiteralBlockedAsURL(t *testing.T) {
	for _, tc := range literalCases {
		t.Run(tc.name, func(t *testing.T) {
			resolver := resolverFor(t, tc)
			client := newTestClient(t, Policy{Resolver: resolver})
			_, err := get(client, "http://"+tc.urlHost+"/")
			if !errors.Is(err, ErrBlockedAddress) {
				t.Fatalf("http://%s/: got %v, want ErrBlockedAddress", tc.urlHost, err)
			}
			if tc.urlHost != "localhost" && resolver.callCount() != 0 {
				t.Fatalf("resolver was consulted for the literal %q", tc.urlHost)
			}
		})
	}
}

func TestLiteralBlockedAsResolvedAddress(t *testing.T) {
	for _, tc := range literalCases {
		if tc.urlHost == "localhost" {
			continue // already a name; covered by the URL test
		}
		t.Run(tc.name, func(t *testing.T) {
			resolver := newFakeResolver(t, map[string][]string{"public.example.test": tc.ips})
			client := newTestClient(t, Policy{Resolver: resolver})
			_, err := get(client, "http://public.example.test/")
			if !errors.Is(err, ErrBlockedAddress) {
				t.Fatalf("resolving to %v: got %v, want ErrBlockedAddress", tc.ips, err)
			}
			if resolver.callCount() != 1 {
				t.Fatalf("resolver called %d times, want 1", resolver.callCount())
			}
		})
	}
}

// TestAllowPrivateDoesNotOpenNeverRanges repeats the URL and resolved forms
// with AllowPrivate=true for everything that must stay closed.
func TestAllowPrivateDoesNotOpenNeverRanges(t *testing.T) {
	for _, tc := range literalCases {
		if !tc.alwaysBlocked {
			continue
		}
		t.Run(tc.name+"/url", func(t *testing.T) {
			client := newTestClient(t, Policy{AllowPrivate: true, Resolver: resolverFor(t, tc)})
			if _, err := get(client, "http://"+tc.urlHost+"/"); !errors.Is(err, ErrBlockedAddress) {
				t.Fatalf("got %v, want ErrBlockedAddress", err)
			}
		})
		if !allForbiddenWithAllowPrivate(t, tc.ips) {
			// Only the spelling is refused; the address it denotes is loopback
			// or private, which a resolver may legitimately return in this mode.
			continue
		}
		t.Run(tc.name+"/resolved", func(t *testing.T) {
			resolver := newFakeResolver(t, map[string][]string{"public.example.test": tc.ips})
			client := newTestClient(t, Policy{AllowPrivate: true, Resolver: resolver})
			if _, err := get(client, "http://public.example.test/"); !errors.Is(err, ErrBlockedAddress) {
				t.Fatalf("got %v, want ErrBlockedAddress", err)
			}
		})
	}
}

// allForbiddenWithAllowPrivate reports whether every address stays forbidden
// under AllowPrivate=true, i.e. whether a resolver returning them must still
// be refused in that mode.
func allForbiddenWithAllowPrivate(t *testing.T, texts []string) bool {
	t.Helper()
	for _, addr := range mustIPAddrs(t, texts) {
		if !IsForbiddenIP(addr.IP, true) {
			return false
		}
	}
	return true
}

func TestAllowPrivateLetsLoopbackServerThrough(t *testing.T) {
	hits := &hitCounter{}
	srv := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.inc()
		_, _ = w.Write([]byte("hello"))
	}))
	port := portOf(t, srv)

	t.Run("blocked by default", func(t *testing.T) {
		client := newTestClient(t, Policy{})
		if _, err := get(client, srv.URL); !errors.Is(err, ErrBlockedAddress) {
			t.Fatalf("got %v, want ErrBlockedAddress", err)
		}
		if hits.count() != 0 {
			t.Fatal("the server was reached although loopback is forbidden")
		}
	})
	t.Run("literal allowed", func(t *testing.T) {
		client := newTestClient(t, Policy{AllowPrivate: true})
		body, err := getBody(client, srv.URL)
		if err != nil || string(body) != "hello" {
			t.Fatalf("body %q, err %v", body, err)
		}
	})
	t.Run("resolved name allowed", func(t *testing.T) {
		resolver := newFakeResolver(t, map[string][]string{"svc.example.test": {"127.0.0.1"}})
		client := newTestClient(t, Policy{AllowPrivate: true, Resolver: resolver})
		body, err := getBody(client, "http://svc.example.test:"+port+"/")
		if err != nil || string(body) != "hello" {
			t.Fatalf("body %q, err %v", body, err)
		}
	})
	t.Run("metadata still blocked", func(t *testing.T) {
		client := newTestClient(t, Policy{AllowPrivate: true})
		if _, err := get(client, "http://169.254.169.254/latest/meta-data/"); !errors.Is(err, ErrBlockedAddress) {
			t.Fatalf("got %v, want ErrBlockedAddress", err)
		}
	})
}

func TestUserInfoRejected(t *testing.T) {
	urls := []string{
		"http://example.com@127.0.0.1/",
		"http://user:hunter2@public.example.test/",
		"https://:hunter2@public.example.test/",
	}
	for _, raw := range urls {
		client := newTestClient(t, Policy{AllowPrivate: true, Resolver: newFakeResolver(t, nil)})
		_, err := get(client, raw)
		if !errors.Is(err, ErrBlockedHost) {
			t.Errorf("%s: got %v, want ErrBlockedHost", raw, err)
			continue
		}
		if strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%s: error leaks the password: %v", raw, err)
		}
	}
}

func TestSchemesOtherThanHTTPRefused(t *testing.T) {
	urls := []string{
		"file:///etc/passwd",
		"gopher://127.0.0.1:70/",
		"ftp://example.test/file",
		"ws://example.test/",
		"javascript:alert(1)",
		"data:text/plain,hi",
	}
	client := newTestClient(t, Policy{Resolver: newFakeResolver(t, nil)})
	for _, raw := range urls {
		if _, err := get(client, raw); !errors.Is(err, ErrBlockedScheme) {
			t.Errorf("%s: got %v, want ErrBlockedScheme", raw, err)
		}
	}
}

func TestMalformedRequestsRefused(t *testing.T) {
	long := strings.Repeat("a", 64) + ".test"
	tooLong := strings.Repeat("abcdefgh.", 32) + "test"
	cases := []struct {
		name string
		u    *url.URL
		want error
	}{
		{"empty host", &url.URL{Scheme: "http", Host: ""}, ErrBlockedHost},
		{"space in host", &url.URL{Scheme: "http", Host: "exa mple.test"}, ErrBlockedHost},
		{"non-ascii host", &url.URL{Scheme: "http", Host: "éxample.test"}, ErrBlockedHost},
		{"empty label", &url.URL{Scheme: "http", Host: "a..test"}, ErrBlockedHost},
		{"over-long label", &url.URL{Scheme: "http", Host: long}, ErrBlockedHost},
		{"over-long name", &url.URL{Scheme: "http", Host: tooLong}, ErrBlockedHost},
		{"bare dot", &url.URL{Scheme: "http", Host: "."}, ErrBlockedHost},
		{"unparsable v6", &url.URL{Scheme: "http", Host: "[1:2:3]"}, ErrBlockedHost},
		{"path-ish host", &url.URL{Scheme: "http", Host: "a/b.test"}, ErrBlockedHost},
	}
	client := newTestClient(t, Policy{Resolver: newFakeResolver(t, nil)})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &http.Request{Method: http.MethodGet, URL: tc.u, Header: http.Header{}}
			if _, err := client.Transport.RoundTrip(req); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
	t.Run("nil request url", func(t *testing.T) {
		if _, err := client.Transport.RoundTrip(&http.Request{}); !errors.Is(err, ErrBlockedHost) {
			t.Fatalf("got %v, want ErrBlockedHost", err)
		}
	})
	t.Run("nil request", func(t *testing.T) {
		if _, err := client.Transport.RoundTrip(nil); !errors.Is(err, ErrBlockedHost) {
			t.Fatalf("got %v, want ErrBlockedHost", err)
		}
	})
}

func TestRequestBodyClosedOnRefusal(t *testing.T) {
	body := &closeTracker{}
	req, err := http.NewRequest(http.MethodPost, "file:///etc/passwd", body)
	if err != nil {
		t.Fatal(err)
	}
	client := newTestClient(t, Policy{})
	if _, err := client.Transport.RoundTrip(req); !errors.Is(err, ErrBlockedScheme) {
		t.Fatalf("got %v, want ErrBlockedScheme", err)
	}
	if !body.closed {
		t.Fatal("the request body was not closed on a refused request")
	}
}

type closeTracker struct{ closed bool }

func (c *closeTracker) Read([]byte) (int, error) { return 0, errors.New("unused") }
func (c *closeTracker) Close() error             { c.closed = true; return nil }

func TestParseTarget(t *testing.T) {
	cases := []struct {
		host    string
		want    error // nil means accepted
		literal bool
	}{
		{"example.com", nil, false},
		{"Example.COM", nil, false},
		{"a-b_c.example.test.", nil, false},
		{"localhost", nil, false},
		{"8.8.8.8", nil, true},
		{"::1", nil, true},
		{"2606:4700:4700::1111", nil, true},
		{"1234.example.com", nil, false},
		{"", ErrBlockedHost, false},
		{"127.1", ErrBlockedAddress, false},
		{"2130706433", ErrBlockedAddress, false},
		{"0x7f.0.0.1", ErrBlockedAddress, false},
		{"0X7F000001", ErrBlockedAddress, false},
		{"0177.0.0.1", ErrBlockedAddress, false},
		{"1.2.3.4.5", ErrBlockedAddress, false},
		{"127.0.0.1.", ErrBlockedAddress, false},
		{"example.123", ErrBlockedAddress, false},
		{"fe80::1%eth0", ErrBlockedAddress, false},
		{"1:2:3", ErrBlockedHost, false},
		{"exa_mple$.test", ErrBlockedHost, false},
	}
	for _, tc := range cases {
		got, err := parseTarget(tc.host)
		if tc.want == nil {
			if err != nil {
				t.Errorf("parseTarget(%q): unexpected error %v", tc.host, err)
			} else if got.isLiteral() != tc.literal {
				t.Errorf("parseTarget(%q): literal = %v, want %v", tc.host, got.isLiteral(), tc.literal)
			}
			continue
		}
		if !errors.Is(err, tc.want) {
			t.Errorf("parseTarget(%q): got %v, want %v", tc.host, err, tc.want)
		}
	}
}

func TestQuoteShortTruncates(t *testing.T) {
	long := strings.Repeat("x", 500)
	if got := quoteShort(long); len(got) > 100 {
		t.Fatalf("quoteShort kept %d bytes of a hostile value", len(got))
	}
	if got := quoteShort("ok"); got != `"ok"` {
		t.Fatalf("quoteShort(ok) = %s", got)
	}
}
