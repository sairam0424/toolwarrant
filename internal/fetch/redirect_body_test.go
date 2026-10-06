package fetch

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// nonRewindable is a request body http.NewRequest cannot derive GetBody for, so
// net/http cannot send it a second time after a 307 or 308.
type nonRewindable struct{ r io.Reader }

func (n *nonRewindable) Read(p []byte) (int, error) { return n.r.Read(p) }

// bodyServer serves the redirect shapes whose outcome depends on the request
// body and records what reached /next.
type bodyServer struct {
	mu      sync.Mutex
	arrived []string // "METHOD body" for every request that reached /next
}

func newBodyServer(t *testing.T) (*bodyServer, string) {
	t.Helper()
	bs := &bodyServer{}
	redirect := func(to string, code int) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, to, code) }
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/307", redirect("/next", http.StatusTemporaryRedirect))
	mux.HandleFunc("/308", redirect("/next", http.StatusPermanentRedirect))
	mux.HandleFunc("/302", redirect("/next", http.StatusFound))
	mux.HandleFunc("/302-then-307", redirect("/307", http.StatusFound))
	mux.HandleFunc("/307-then-307", redirect("/307", http.StatusTemporaryRedirect))
	mux.HandleFunc("/next", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bs.mu.Lock()
		bs.arrived = append(bs.arrived, r.Method+" "+string(body))
		bs.mu.Unlock()
		_, _ = w.Write([]byte("arrived"))
	})
	srv := startServer(t, mux)
	return bs, srv.URL
}

func (bs *bodyServer) seen() []string {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	return append([]string(nil), bs.arrived...)
}

func post(c *http.Client, rawURL string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, rawURL, body)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// postBody posts and reads the whole answer, returning the first error.
func postBody(c *http.Client, rawURL string, body io.Reader) ([]byte, error) {
	resp, err := post(c, rawURL, body)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	return io.ReadAll(resp.Body)
}

// A 307 or 308 after a request whose body cannot be sent again: net/http does
// not follow it and does not fail either, it returns the 3xx to the caller as
// if it were the answer (redirectBehavior in net/http/client.go). The guard
// must turn that into ErrRedirect, and the target must never be contacted. The
// third path proves the decision looks at the caller's request, not at the hop
// request net/http built: after the 302 the hop is a bodiless GET, yet net/http
// still judges the 307 by the original POST.
func TestRedirect307And308WithNonRewindableBodyAreRefused(t *testing.T) {
	bs, base := newBodyServer(t)
	client := newTestClient(t, Policy{AllowPrivate: true, MaxRedirects: 3})
	for _, path := range []string{"/307", "/308", "/302-then-307"} {
		resp, err := post(client, base+path, &nonRewindable{strings.NewReader("payload")})
		if err == nil {
			_ = resp.Body.Close()
			t.Errorf("%s: a %d reached the caller as a normal response", path, resp.StatusCode)
			continue
		}
		if !errors.Is(err, ErrRedirect) {
			t.Errorf("%s: got %v, want ErrRedirect", path, err)
		}
	}
	if got := bs.seen(); len(got) != 0 {
		t.Errorf("/next was reached although every redirect was refused: %v", got)
	}
}

// The control: the plain client really does hand the 3xx back, so the test
// above exercises a real gap and not a hypothetical one.
func TestPlainClientReturns307WithNonRewindableBody(t *testing.T) {
	_, base := newBodyServer(t)
	plain := &http.Client{Timeout: 5 * time.Second}
	resp, err := post(plain, base+"/302-then-307", &nonRewindable{strings.NewReader("payload")})
	if err != nil {
		t.Skipf("net/http no longer returns the 3xx here (%v); the refusal test proves less than it used to", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Skipf("net/http answered %d, not 307; the refusal test proves less than it used to", resp.StatusCode)
	}
}

// With a body net/http can replay, 307 and 308 are followed and the body is
// sent again, through one hop and through two.
func TestRedirect307WithRewindableBodyIsFollowedWithTheBody(t *testing.T) {
	bs, base := newBodyServer(t)
	client := newTestClient(t, Policy{AllowPrivate: true, MaxRedirects: 3})
	for _, path := range []string{"/307", "/308", "/307-then-307", "/302-then-307"} {
		body, err := postBody(client, base+path, bytes.NewReader([]byte("payload")))
		if err != nil || string(body) != "arrived" {
			t.Fatalf("%s: body %q, err %v", path, body, err)
		}
	}
	// After a 302 the method is GET, and net/http (go1.27.1) then follows the
	// later 307 as a bodiless GET: once a hop has dropped the body it is not
	// replayed. That is net/http's choice, not the guard's; the guard only
	// decides that the hop may be followed.
	want := "POST payload|POST payload|POST payload|GET "
	if got := strings.Join(bs.seen(), "|"); got != want {
		t.Errorf("/next saw %q, want %q", got, want)
	}
}

// 301, 302 and 303 retry as GET without a body, so a body that cannot be
// replayed does not matter there; the guard must not over-refuse.
func TestRedirect302WithNonRewindableBodyIsFollowedAsGet(t *testing.T) {
	bs, base := newBodyServer(t)
	client := newTestClient(t, Policy{AllowPrivate: true, MaxRedirects: 3})
	body, err := postBody(client, base+"/302", &nonRewindable{strings.NewReader("payload")})
	if err != nil || string(body) != "arrived" {
		t.Fatalf("body %q, err %v", body, err)
	}
	if got := bs.seen(); len(got) != 1 || got[0] != "GET " {
		t.Errorf("/next saw %v, want one bodiless GET", got)
	}
}

func TestFollowableFailsClosedWithoutACallerRequest(t *testing.T) {
	header := http.Header{"Location": {"/next"}}
	t.Run("no request at all", func(t *testing.T) {
		resp := &http.Response{StatusCode: http.StatusTemporaryRedirect, Header: header}
		if followable(resp) {
			t.Fatal("a 307 with no originating request was declared followable")
		}
	})
	t.Run("chain longer than net/http can build", func(t *testing.T) {
		req := &http.Request{GetBody: func() (io.ReadCloser, error) { return http.NoBody, nil }}
		for i := 0; i <= maxRedirectChain; i++ {
			req = &http.Request{Response: &http.Response{Request: req}}
		}
		resp := &http.Response{StatusCode: http.StatusPermanentRedirect, Header: header, Request: req}
		if followable(resp) {
			t.Fatal("an overlong request chain was walked instead of refused")
		}
	})
	t.Run("302 needs no replayable body", func(t *testing.T) {
		resp := &http.Response{StatusCode: http.StatusFound, Header: header}
		if !followable(resp) {
			t.Fatal("a 302 with a Location must stay followable")
		}
	})
}

func TestBodyReplayable(t *testing.T) {
	getBody := func() (io.ReadCloser, error) { return http.NoBody, nil }
	cases := map[string]struct {
		req  *http.Request
		want bool
	}{
		"no body":                    {&http.Request{}, true},
		"NoBody":                     {&http.Request{Body: http.NoBody}, true},
		"body with GetBody":          {&http.Request{Body: io.NopCloser(strings.NewReader("x")), GetBody: getBody}, true},
		"body without GetBody":       {&http.Request{Body: io.NopCloser(strings.NewReader("x"))}, false},
		"sized body without GetBody": {&http.Request{Body: io.NopCloser(strings.NewReader("x")), ContentLength: 1}, false},
	}
	for name, tc := range cases {
		if got := bodyReplayable(tc.req); got != tc.want {
			t.Errorf("%s: bodyReplayable = %v, want %v", name, got, tc.want)
		}
	}
}
