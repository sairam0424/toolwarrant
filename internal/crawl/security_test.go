package crawl

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// canary builds a value that stands in for a credential. No error may contain
// the "CANARY" marker it carries.
func canary(kind string) string { return "CANARY-" + kind + "-7f3a" }

func canaryOptions() Options {
	opt := testOptions()
	opt.Headers = http.Header{
		"Authorization": {"Bearer " + canary("auth")},
		"X-Api-Key":     {canary("apikey")},
	}
	return opt
}

// canaryURL puts a canary in the endpoint's query string, where credentials
// sometimes live.
func canaryURL(base string) string { return base + "?q=" + canary("query") }

func assertNoCanaries(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		t.Errorf("%s: expected an error", what)
		return
	}
	for _, text := range []string{err.Error(), fmt.Sprintf("%v|%+v|%#v", err, err, err)} {
		for _, leak := range []string{"CANARY"} {
			if strings.Contains(text, leak) {
				t.Errorf("%s: error leaks %q: %s", what, leak, text)
			}
		}
	}
}

func TestCredentialsNeverAppearInErrors(t *testing.T) {
	status := func(method string, code int) func(*fake) {
		return func(f *fake) {
			f.override = func(w http.ResponseWriter, _ *http.Request, in rpcIn) bool {
				if in.Method != method {
					return false
				}
				http.Error(w, "nope", code)
				return true
			}
		}
	}
	cases := map[string]func(*fake){
		"401 at initialize": status(methodInitialize, http.StatusUnauthorized),
		"500 at tools/list": status(methodToolsList, http.StatusInternalServerError),
		"500 at notify":     status(methodInitialized, http.StatusInternalServerError),
		"malformed page": func(f *fake) {
			f.page = func(int, string) string { return `{"tools":[{"name":5}]}` }
		},
		"duplicate tool": func(f *fake) {
			f.page = func(int, string) string { return `{"tools":[{"name":"a"},{"name":"a"}]}` }
		},
		"cursor loop": func(f *fake) {
			f.page = func(int, string) string { return `{"tools":[],"nextCursor":"x"}` }
		},
	}
	for name, tweak := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFake(t, modeJSON, pagesOf(5, nTools(1)))
			tweak(f)
			_, err := ListTools(context.Background(), canaryURL(f.url()), canaryOptions())
			assertNoCanaries(t, name, err)
		})
	}
	t.Run("connection refused", func(t *testing.T) {
		f := newFake(t, modeJSON, pagesOf(5, nTools(1)))
		url := canaryURL(f.url())
		f.srv.Close()
		_, err := ListTools(context.Background(), url, canaryOptions())
		assertNoCanaries(t, "refused", err)
	})
	t.Run("cancelled context", func(t *testing.T) {
		f := newFake(t, modeJSON, pagesOf(5, nTools(1)))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := ListTools(ctx, canaryURL(f.url()), canaryOptions())
		assertNoCanaries(t, "cancelled", err)
	})
	t.Run("invalid header value", func(t *testing.T) {
		f := newFake(t, modeJSON, pagesOf(5, nTools(1)))
		opt := testOptions()
		opt.Headers = http.Header{"Authorization": {"Bearer " + canary("bad") + "\nINJECT"}}
		_, err := ListTools(context.Background(), canaryURL(f.url()), opt)
		assertNoCanaries(t, "bad header", err)
	})
}

func TestHeadersAreSentOnEveryRequestAndNotMutated(t *testing.T) {
	f := newFake(t, modeSSE, pagesOf(2, nTools(5)))
	opt := canaryOptions()
	before := opt.Headers.Clone()
	if _, err := ListTools(context.Background(), f.url(), opt); err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	reqs := f.requests()
	if len(reqs) < 5 {
		t.Fatalf("only %d requests", len(reqs))
	}
	for i, r := range reqs {
		if r.Header.Get("Authorization") != "Bearer "+canary("auth") || r.Header.Get("X-Api-Key") != canary("apikey") {
			t.Errorf("request %d (%s %s) lacks the caller headers", i, r.HTTPMethod, r.RPCMethod)
		}
	}
	if last := reqs[len(reqs)-1]; last.HTTPMethod != http.MethodDelete {
		t.Errorf("last request %s, want the DELETE to carry headers too", last.HTTPMethod)
	}
	for k, v := range before {
		if strings.Join(opt.Headers[k], ",") != strings.Join(v, ",") {
			t.Errorf("Options.Headers[%q] was mutated", k)
		}
	}
	if len(opt.Headers) != len(before) {
		t.Error("Options.Headers gained keys")
	}
}

func TestCallerCannotOverrideProtocolHeaders(t *testing.T) {
	f := newFake(t, modeJSON, pagesOf(5, nTools(1)))
	opt := testOptions()
	opt.Headers = http.Header{
		"Mcp-Session-Id":       {"forged"},
		"Mcp-Protocol-Version": {"1999-01-01"},
		"Content-Type":         {"text/plain"},
		"Accept":               {"text/html"},
		"X-Keep":               {"yes"},
	}
	if _, err := ListTools(context.Background(), f.url(), opt); err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	for i, r := range f.requests() {
		if got := r.Header.Get("Mcp-Session-Id"); got == "forged" {
			t.Errorf("request %d carries the forged session id", i)
		}
		if got := r.Header.Get("Mcp-Protocol-Version"); got == "1999-01-01" {
			t.Errorf("request %d carries the forged protocol version", i)
		}
		if r.HTTPMethod == http.MethodPost && (r.Header.Get("Content-Type") != "application/json" || !strings.Contains(r.Header.Get("Accept"), "text/event-stream")) {
			t.Errorf("request %d framing headers overridden: %v", i, r.Header)
		}
		if r.Header.Get("X-Keep") != "yes" {
			t.Errorf("request %d lost an ordinary caller header", i)
		}
	}
}

func TestContextCancellation(t *testing.T) {
	t.Run("already cancelled", func(t *testing.T) {
		f := newFake(t, modeJSON, pagesOf(5, nTools(1)))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := ListTools(ctx, f.url(), testOptions())
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
		if n := len(f.requests()); n != 0 {
			t.Errorf("a cancelled crawl still sent %d requests", n)
		}
	})
	t.Run("cancelled while the server stalls", func(t *testing.T) {
		assertStallEndsWith(t, func(ctx context.Context) (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(ctx)
			time.AfterFunc(100*time.Millisecond, cancel)
			return ctx, cancel
		}, context.Canceled)
	})
	t.Run("deadline while the server stalls", func(t *testing.T) {
		assertStallEndsWith(t, func(ctx context.Context) (context.Context, context.CancelFunc) {
			return context.WithTimeout(ctx, 100*time.Millisecond)
		}, context.DeadlineExceeded)
	})
}

// assertStallEndsWith crawls a server that never answers tools/list and
// expects ListTools to give up promptly with want, and not to send a DELETE
// for a crawl its caller abandoned.
func assertStallEndsWith(t *testing.T, mkCtx func(context.Context) (context.Context, context.CancelFunc), want error) {
	t.Helper()
	f := newFake(t, modeJSON, pagesOf(5, nTools(1)))
	f.override = func(_ http.ResponseWriter, r *http.Request, in rpcIn) bool {
		if in.Method != methodToolsList {
			return false
		}
		<-r.Context().Done()
		return true
	}
	ctx, cancel := mkCtx(context.Background())
	defer cancel()
	start := time.Now()
	_, err := ListTools(ctx, f.url(), testOptions())
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("took %v to notice cancellation", elapsed)
	}
	time.Sleep(50 * time.Millisecond)
	for _, r := range f.requests() {
		if r.HTTPMethod == http.MethodDelete {
			t.Error("sent DELETE for an abandoned crawl")
		}
	}
}

func TestCancellationWhileReadingAStreamingBody(t *testing.T) {
	f := newFake(t, modeSSE, pagesOf(5, nTools(1)))
	f.override = func(w http.ResponseWriter, r *http.Request, in rpcIn) bool {
		if in.Method != methodToolsList {
			return false
		}
		w.Header().Set("Content-Type", mediaSSE)
		_, _ = fmt.Fprint(w, ": started\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := ListTools(ctx, f.url(), testOptions())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
}
