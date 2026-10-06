package fetch

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"testing"
)

// redirectServer serves the redirect scenarios used below and records what it
// saw. Everything is on loopback, so clients use AllowPrivate.
type redirectServer struct {
	mu   sync.Mutex
	seen map[string]http.Header // path -> headers of the latest request
	hits map[string]int
}

func newRedirectServer(t *testing.T, target string) (*redirectServer, string) {
	rs := &redirectServer{seen: map[string]http.Header{}, hits: map[string]int{}}
	mux := http.NewServeMux()
	record := func(r *http.Request) {
		rs.mu.Lock()
		defer rs.mu.Unlock()
		rs.hits[r.URL.Path]++
		rs.seen[r.URL.Path] = r.Header.Clone()
	}
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		http.Redirect(w, r, "/next", http.StatusFound)
	})
	mux.HandleFunc("/next", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		_, _ = w.Write([]byte("arrived"))
	})
	mux.HandleFunc("/chain", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		left, _ := strconv.Atoi(r.URL.Query().Get("left"))
		if left > 0 {
			http.Redirect(w, r, fmt.Sprintf("/chain?left=%d", left-1), http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("done"))
	})
	mux.HandleFunc("/cross", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		http.Redirect(w, r, target+"/secret", http.StatusFound)
	})
	mux.HandleFunc("/secret", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		_, _ = w.Write([]byte("secret"))
	})
	for path, location := range map[string]string{
		"/metadata": "http://169.254.169.254/latest/meta-data/",
		"/loopback": "http://127.0.0.1:1/",
		"/file":     "file:///etc/passwd",
		"/gopher":   "gopher://127.0.0.1:70/_x",
		"/ftp":      "ftp://example.test/x",
	} {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			record(r)
			http.Redirect(w, r, location, http.StatusFound)
		})
	}
	for path, code := range map[string]int{"/multiple": 300, "/notmodified": 304, "/nolocation": 302, "/usepxy": 305} {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			record(r)
			if path == "/multiple" || path == "/notmodified" {
				w.Header().Set("Location", "/next")
			}
			w.WriteHeader(code)
		})
	}
	srv := startServer(t, mux)
	return rs, srv.URL
}

func (rs *redirectServer) hitCount(path string) int {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.hits[path]
}

func (rs *redirectServer) header(path, name string) string {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.seen[path].Get(name)
}

func TestRedirectsRefusedByDefault(t *testing.T) {
	otherHits := &hitCounter{}
	other := startServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { otherHits.inc() }))
	rs, base := newRedirectServer(t, other.URL)
	client := newTestClient(t, Policy{AllowPrivate: true})

	for _, path := range []string{
		"/start", "/cross", "/metadata", "/loopback", "/multiple", "/notmodified", "/nolocation", "/usepxy",
	} {
		if _, err := get(client, base+path); !errors.Is(err, ErrRedirect) {
			t.Errorf("%s: got %v, want ErrRedirect", path, err)
		}
	}
	if rs.hitCount("/next") != 0 || rs.hitCount("/secret") != 0 || otherHits.count() != 0 {
		t.Error("a refused redirect was followed anyway")
	}
}

func TestRedirectToOtherSchemesIsBlockedScheme(t *testing.T) {
	for _, maxRedirects := range []int{0, 3} {
		_, base := newRedirectServer(t, "")
		client := newTestClient(t, Policy{AllowPrivate: true, MaxRedirects: maxRedirects})
		for _, path := range []string{"/file", "/gopher", "/ftp"} {
			_, err := get(client, base+path)
			if !errors.Is(err, ErrBlockedScheme) || !errors.Is(err, ErrRedirect) {
				t.Errorf("MaxRedirects=%d %s: got %v, want both ErrBlockedScheme and ErrRedirect", maxRedirects, path, err)
			}
		}
	}
}

func TestSameOriginRedirectsFollowedWithinLimit(t *testing.T) {
	rs, base := newRedirectServer(t, "")
	client := newTestClient(t, Policy{AllowPrivate: true, MaxRedirects: 3})

	body, err := getBody(client, base+"/chain?left=3")
	if err != nil || string(body) != "done" {
		t.Fatalf("three redirects within a limit of three: body %q, err %v", body, err)
	}
	if rs.hitCount("/chain") != 4 {
		t.Errorf("chain was hit %d times, want 4", rs.hitCount("/chain"))
	}
}

func TestRedirectChainLongerThanLimitRefused(t *testing.T) {
	rs, base := newRedirectServer(t, "")
	client := newTestClient(t, Policy{AllowPrivate: true, MaxRedirects: 2})

	if _, err := get(client, base+"/chain?left=5"); !errors.Is(err, ErrRedirect) {
		t.Fatalf("got %v, want ErrRedirect", err)
	}
	// The initial request plus two followed hops; the third hop is refused
	// before any request is sent for it.
	if got := rs.hitCount("/chain"); got != 3 {
		t.Errorf("server saw %d requests, want 3", got)
	}
}

func TestCrossOriginRedirectRefused(t *testing.T) {
	otherHits := &hitCounter{}
	other := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		otherHits.inc()
		_, _ = w.Write([]byte("other"))
	}))
	_, base := newRedirectServer(t, other.URL) // same host, different port
	client := newTestClient(t, Policy{AllowPrivate: true, MaxRedirects: 5})

	if _, err := get(client, base+"/cross"); !errors.Is(err, ErrRedirect) {
		t.Fatalf("different port: got %v, want ErrRedirect", err)
	}
	for _, path := range []string{"/metadata", "/loopback"} {
		if _, err := get(client, base+path); !errors.Is(err, ErrRedirect) {
			t.Errorf("%s: got %v, want ErrRedirect", path, err)
		}
	}
	if otherHits.count() != 0 {
		t.Fatal("the cross-origin target was contacted")
	}

	// localhost and 127.0.0.1 are different hosts even though they resolve alike.
	u, _ := url.Parse(base)
	mux := http.NewServeMux()
	mux.HandleFunc("/to-localhost", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://localhost:"+u.Port()+"/next", http.StatusFound)
	})
	sibling := startServer(t, mux)
	if _, err := get(client, sibling.URL+"/to-localhost"); !errors.Is(err, ErrRedirect) {
		t.Fatalf("different host name, same machine: got %v, want ErrRedirect", err)
	}
}

func TestNonFollowable3xxIsRefusedEvenWithRedirectsEnabled(t *testing.T) {
	_, base := newRedirectServer(t, "")
	client := newTestClient(t, Policy{AllowPrivate: true, MaxRedirects: 3})
	for _, path := range []string{"/multiple", "/notmodified", "/nolocation", "/usepxy"} {
		if _, err := get(client, base+path); !errors.Is(err, ErrRedirect) {
			t.Errorf("%s: got %v, want ErrRedirect", path, err)
		}
	}
}

func TestCredentialsNotForwardedAcrossRedirects(t *testing.T) {
	rs, base := newRedirectServer(t, "")
	client := newTestClient(t, Policy{AllowPrivate: true, MaxRedirects: 3})

	req, err := http.NewRequest(http.MethodGet, base+"/start", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer sekrit")
	req.Header.Set("Cookie", "session=sekrit")
	req.Header.Set("Proxy-Authorization", "Basic sekrit")
	req.Header.Set("X-Trace", "kept")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = resp.Body.Close()

	for _, name := range []string{"Authorization", "Cookie", "Proxy-Authorization"} {
		if rs.header("/start", name) == "" {
			t.Fatalf("%s never reached the first hop; the test proves nothing", name)
		}
		if got := rs.header("/next", name); got != "" {
			t.Errorf("%s was forwarded to the redirect target: %q", name, got)
		}
	}
	if rs.header("/next", "X-Trace") != "kept" {
		t.Error("harmless headers should still follow a same-origin redirect")
	}
	if got := req.Header.Get("Authorization"); got != "Bearer sekrit" {
		t.Errorf("the caller's request was modified: Authorization = %q", got)
	}
}

func TestSameOrigin(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"http://a.test/x", "http://A.TEST:80/y", true},
		{"https://a.test/x", "https://a.test:443/y", true},
		{"http://a.test", "https://a.test", false},
		{"http://a.test", "http://a.test:8080", false},
		{"http://a.test", "http://b.test", false},
		{"https://a.test:443", "http://a.test:80", false},
		{"http://[::1]:80/", "http://[0:0:0:0:0:0:0:1]/", true},
		{"http://127.0.0.1/", "http://localhost/", false},
	}
	for _, tc := range cases {
		a, _ := url.Parse(tc.a)
		b, _ := url.Parse(tc.b)
		if got := sameOrigin(a, b); got != tc.want {
			t.Errorf("sameOrigin(%s, %s) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestCheckRedirectFailsClosedOnUnexpectedCalls(t *testing.T) {
	disabled := &guardTransport{maxRedirects: 0}
	req := &http.Request{URL: &url.URL{Scheme: "http", Host: "a.test"}}
	if err := disabled.checkRedirect(req, []*http.Request{req}); !errors.Is(err, ErrRedirect) {
		t.Fatalf("redirects disabled: got %v, want ErrRedirect", err)
	}
	enabled := &guardTransport{maxRedirects: 2}
	if err := enabled.checkRedirect(req, nil); !errors.Is(err, ErrRedirect) {
		t.Fatalf("no originating request: got %v, want ErrRedirect", err)
	}
}

func TestOutgoingLeavesPlainRequestsAlone(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://a.test/", nil)
	if got := outgoing(req); got != req {
		t.Fatal("a request that needs no change must not be copied")
	}
	req.Header.Set("Accept-Encoding", "gzip, br")
	got := outgoing(req)
	if got == req || got.Header.Get("Accept-Encoding") != "" {
		t.Fatal("Accept-Encoding must be dropped from a copy")
	}
	if req.Header.Get("Accept-Encoding") != "gzip, br" {
		t.Fatal("the caller's request was modified")
	}
}
