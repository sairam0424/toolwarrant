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

// countLists counts the tools/list requests the fake served.
func countLists(f *fake) int {
	n := 0
	for _, r := range f.requests() {
		if r.RPCMethod == methodToolsList {
			n++
		}
	}
	return n
}

// TestTotalByteBudgetAcrossPages reproduces the review finding: every page was
// under the message cap, but nothing bounded their sum, so a server could make
// one crawl retain MaxPages x MaxMessageBytes. Now the sum is capped and the
// crawl stops at the page that crosses it.
func TestTotalByteBudgetAcrossPages(t *testing.T) {
	const pages, perTool = 20, 100 << 10
	big := strings.Repeat("x", perTool)
	server := func(call int, _ string) string {
		tool := fmt.Sprintf(`{"name":"t%d","description":%q}`, call, big)
		if call < pages {
			return fmt.Sprintf(`{"tools":[%s],"nextCursor":"c%d"}`, tool, call)
		}
		return fmt.Sprintf(`{"tools":[%s]}`, tool)
	}
	t.Run("over the budget", func(t *testing.T) {
		f := newFake(t, modeJSON, server)
		opt := testOptions()
		opt.MaxMessageBytes = 512 << 10
		opt.MaxTotalBytes = 1 << 20
		res, err := ListTools(context.Background(), f.url(), opt)
		if !errors.Is(err, ErrTooLarge) {
			t.Fatalf("err = %v, want ErrTooLarge", err)
		}
		if len(res.Tools) != 0 || len(res.Unusable) != 0 {
			t.Errorf("a failed crawl returned tools: %+v", res)
		}
		// Ten tools fit under one MiB, the eleventh crosses it.
		if n := countLists(f); n != 11 {
			t.Errorf("made %d tools/list requests, want 11: the crawl must stop at the page that crosses the budget", n)
		}
	})
	t.Run("under the default budget", func(t *testing.T) {
		f := newFake(t, modeJSON, server)
		opt := testOptions()
		opt.MaxMessageBytes = 512 << 10
		res, err := ListTools(context.Background(), f.url(), opt)
		if err != nil || len(res.Tools) != pages {
			t.Fatalf("tools=%d err=%v, want %d tools", len(res.Tools), err, pages)
		}
	})
}

func TestTotalByteBudgetBoundary(t *testing.T) {
	a, b := toolJSON(0), toolJSON(1)
	sum := len(a) + len(b)
	for budget, wantErr := range map[int]bool{sum: false, sum - 1: true} {
		f := newFake(t, modeJSON, func(int, string) string { return `{"tools":[` + a + `,` + b + `]}` })
		opt := testOptions()
		opt.MaxTotalBytes = budget
		_, err := ListTools(context.Background(), f.url(), opt)
		if wantErr != errors.Is(err, ErrTooLarge) {
			t.Errorf("MaxTotalBytes=%d: err = %v", budget, err)
		}
	}
	t.Run("unusable tools count too", func(t *testing.T) {
		f := newFake(t, modeJSON, func(int, string) string { return `{"tools":["str",` + a + `]}` })
		opt := testOptions()
		opt.MaxTotalBytes = len(a)
		if _, err := ListTools(context.Background(), f.url(), opt); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("err = %v, want ErrTooLarge", err)
		}
	})
}

func TestUnusableToolsCountTowardMaxTools(t *testing.T) {
	page := func(int, string) string {
		return fmt.Sprintf(`{"tools":["str",%s,%s]}`, toolJSON(0), toolJSON(1))
	}
	for maxTools, wantErr := range map[int]bool{3: false, 2: true} {
		f := newFake(t, modeJSON, page)
		opt := testOptions()
		opt.MaxTools = maxTools
		res, err := ListTools(context.Background(), f.url(), opt)
		if wantErr != errors.Is(err, ErrTooManyTools) {
			t.Errorf("MaxTools=%d: err = %v", maxTools, err)
		}
		if !wantErr && (len(res.Tools) != 2 || len(res.Unusable) != 1) {
			t.Errorf("MaxTools=%d: tools=%d unusable=%d", maxTools, len(res.Tools), len(res.Unusable))
		}
	}
}

// TestPerToolSizeCap: a definition over Options.MaxToolBytes is reported as
// unusable under its name and is not hashed, so a cheap oversized blob cannot
// buy an expensive canonicalisation (the spoiled copy would otherwise be
// reported as not canonical).
func TestPerToolSizeCap(t *testing.T) {
	const sizeCap = 300
	fits := toolOfSize(t, "fits", sizeCap, "")
	over := toolOfSize(t, "over", sizeCap+1, "")
	spoiled := toolOfSize(t, "spoiled", sizeCap+1, `"n":1e400,`)
	f := newFake(t, modeJSON, func(int, string) string { return `{"tools":[` + fits + `,` + over + `,` + spoiled + `]}` })
	opt := testOptions()
	opt.MaxToolBytes = sizeCap
	res, err := ListTools(context.Background(), f.url(), opt)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(res.Tools) != 1 || res.Tools[0].Name != "fits" {
		t.Errorf("usable = %+v, want only the tool at the cap", res.Tools)
	}
	if len(res.Unusable) != 2 {
		t.Fatalf("unusable = %+v, want the two over the cap", res.Unusable)
	}
	for i, want := range []string{"over", "spoiled"} {
		if u := res.Unusable[i]; u.Name != want || u.Reason != ReasonTooLarge {
			t.Errorf("unusable[%d] = (%q, %q), want (%q, too-large)", i, u.Name, u.Reason, want)
		}
	}
}

func TestResponseLargerThanMessageCap(t *testing.T) {
	big := fmt.Sprintf(`{"name":"big","description":%q}`, strings.Repeat("x", 5000))
	for name, mode := range map[string]replyMode{"json": modeJSON, "sse": modeSSE} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t, mode, func(int, string) string { return `{"tools":[` + big + `]}` })
			opt := testOptions()
			opt.MaxMessageBytes = 1024
			_, err := ListTools(context.Background(), f.url(), opt)
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
			opt.MaxMessageBytes = 64 << 10
			if _, err := ListTools(context.Background(), f.url(), opt); err != nil {
				t.Fatalf("under the cap: %v", err)
			}
		})
	}
}

// TestCrawlTimeoutEndsAStalledCrawl: Options.Timeout bounds the whole crawl,
// not one request, so a server that stalls at any step ends the crawl with
// context.DeadlineExceeded, promptly, and the abandoned session gets no DELETE.
func TestCrawlTimeoutEndsAStalledCrawl(t *testing.T) {
	for _, stallAt := range []string{methodInitialize, methodToolsList} {
		t.Run("stall at "+stallAt, func(t *testing.T) {
			f := newFake(t, modeJSON, pagesOf(5, nTools(1)))
			f.override = func(_ http.ResponseWriter, r *http.Request, in rpcIn) bool {
				if in.Method != stallAt {
					return false
				}
				<-r.Context().Done()
				return true
			}
			opt := testOptions()
			opt.Timeout = 100 * time.Millisecond
			start := time.Now()
			_, err := ListTools(context.Background(), f.url(), opt)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("err = %v, want context.DeadlineExceeded", err)
			}
			if elapsed := time.Since(start); elapsed > 5*time.Second {
				t.Errorf("took %v to give up", elapsed)
			}
			time.Sleep(50 * time.Millisecond)
			for _, r := range f.requests() {
				if r.HTTPMethod == http.MethodDelete {
					t.Error("sent DELETE for a crawl that ran out of time")
				}
			}
		})
	}
	t.Run("a crawl within the timeout is unaffected", func(t *testing.T) {
		f := newFake(t, modeJSON, pagesOf(2, nTools(5)))
		opt := testOptions()
		opt.Timeout = 5 * time.Second
		res, err := ListTools(context.Background(), f.url(), opt)
		if err != nil || len(res.Tools) != 5 {
			t.Fatalf("tools=%d err=%v", len(res.Tools), err)
		}
	})
}
