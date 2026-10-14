package main

import (
	"strings"
	"testing"
)

// --max-crawl-age (D21, owner decision O-7) is a duration like
// --max-evidence-age: a negative value is a usage error decided before the
// catalog is opened or a socket is bound, zero is the default and keeps the
// rule of every version before, and a positive value reaches the processor,
// whose stats line then carries the stale counter. The processor's own rule
// is TestJudgeCall_StaleCrawlDeniesUnlessFreshlyListed; end-to-end scenario R
// drives the flag against the real gateway. On the code before this round the
// first run fails with "flag provided but not defined: -max-crawl-age".
func TestServeRejectsANegativeMaxCrawlAge(t *testing.T) {
	c, _ := fixture(t)
	r := c.fail(exitUsage, "serve", "--server", "s1", "--listen", "127.0.0.1:0", "--max-crawl-age", "-1s")
	wantContains(t, "stderr", r.stderr, "--max-crawl-age must not be negative", "usage: "+programName)
	wantNotContains(t, "stdout", r.stdout, "listening on")

	for _, age := range []string{"0", "1h"} {
		out, _, stop := c.start("serve", "--server", "s1", "--listen", "127.0.0.1:0", "--max-crawl-age", age)
		if addr := waitListening(t, out); !strings.HasPrefix(addr, "127.0.0.1:") {
			t.Fatalf("--max-crawl-age %s: listening on %q, want a loopback address", age, addr)
		}
		if code := stop(); code != exitOK {
			t.Fatalf("--max-crawl-age %s: serve exit %d:\n%s", age, code, out.String())
		}
		wantContains(t, "stdout with --max-crawl-age "+age, out.String(), "calls allowed=0 denied=0 (stale=0)")
	}
}
