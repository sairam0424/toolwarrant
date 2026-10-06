package fetch

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

var errNoSuchHost = errors.New("fake resolver: no such host")

// mustIPAddrs converts text addresses to net.IPAddr, keeping any zone.
func mustIPAddrs(t *testing.T, texts []string) []net.IPAddr {
	t.Helper()
	out := make([]net.IPAddr, 0, len(texts))
	for _, text := range texts {
		addr, err := netip.ParseAddr(text)
		if err != nil {
			t.Fatalf("bad test address %q: %v", text, err)
		}
		out = append(out, net.IPAddr{IP: addr.AsSlice(), Zone: addr.Zone()})
	}
	return out
}

// fakeResolver answers from a fixed table and fails the test on a lookup of a
// name it was not told about, which proves the resolver was not consulted.
type fakeResolver struct {
	t       *testing.T
	mu      sync.Mutex
	answers map[string][]string
	calls   []string
}

func newFakeResolver(t *testing.T, answers map[string][]string) *fakeResolver {
	return &fakeResolver{t: t, answers: answers}
}

func (f *fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	f.mu.Lock()
	f.calls = append(f.calls, host)
	texts, ok := f.answers[strings.ToLower(host)]
	f.mu.Unlock()
	if !ok {
		f.t.Errorf("unexpected lookup of %q", host)
		return nil, errNoSuchHost
	}
	return mustIPAddrs(f.t, texts), nil
}

func (f *fakeResolver) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// seqResolver returns a different answer on each call; the last one repeats.
type seqResolver struct {
	t     *testing.T
	mu    sync.Mutex
	seq   [][]string
	calls int
}

func (s *seqResolver) LookupIPAddr(_ context.Context, _ string) ([]net.IPAddr, error) {
	s.mu.Lock()
	idx := min(s.calls, len(s.seq)-1)
	s.calls++
	s.mu.Unlock()
	return mustIPAddrs(s.t, s.seq[idx]), nil
}

func (s *seqResolver) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// resolverFunc adapts a function to Resolver.
type resolverFunc func(ctx context.Context, host string) ([]net.IPAddr, error)

func (f resolverFunc) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return f(ctx, host)
}

// startServer runs h on 127.0.0.1 and tears it down, dropping any connection
// a handler is still holding open.
func startServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(func() {
		srv.CloseClientConnections()
		srv.Close()
	})
	return srv
}

// newTestClient builds a client with short timeouts so a regression that
// tries to connect somewhere it should not fails fast instead of hanging.
func newTestClient(t *testing.T, p Policy) *http.Client {
	t.Helper()
	if p.DialTimeout == 0 {
		p.DialTimeout = 500 * time.Millisecond
	}
	if p.Timeout == 0 {
		p.Timeout = 5 * time.Second
	}
	c, err := NewClient(p)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func get(c *http.Client, rawURL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// getBody fetches rawURL and reads the whole body, returning the first error
// from either step.
func getBody(c *http.Client, rawURL string) ([]byte, error) {
	resp, err := get(c, rawURL)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	return io.ReadAll(resp.Body)
}

// portOf returns the port of a server URL.
func portOf(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse %q: %v", srv.URL, err)
	}
	return u.Port()
}

// hitCounter counts requests that reach a handler.
type hitCounter struct {
	mu   sync.Mutex
	hits int
}

func (h *hitCounter) inc() {
	h.mu.Lock()
	h.hits++
	h.mu.Unlock()
}

func (h *hitCounter) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.hits
}
