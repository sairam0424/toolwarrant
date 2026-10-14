//go:build e2e

package e2e

import (
	"strings"
	"testing"
	"time"
)

const (
	// freshnessAge is the value scenario R gives both serve ages: long enough
	// for a listing and the call that follows it to land inside, short enough
	// for the scenario to wait it out twice.
	freshnessAge = 2 * time.Second
	// freshnessWait is how long the scenario sleeps for both ages to pass; the
	// latest listing and the latest crawl are then both older than
	// freshnessAge.
	freshnessWait = 3 * time.Second
	// staleCause is the cause class the processor's denial carries (D21).
	staleCause = "crawl evidence too old"
)

// scenarioR: --max-crawl-age bounds limit L1 when crawls stop (D21, owner
// decision O-7). mock's processor is restarted with --max-crawl-age 2s and
// --max-evidence-age 2s while the catalog's latest crawl is minutes old: a
// session that lists is allowed to call on its fresh listing alone; three
// seconds later, with the listing aged and no crawl within the age, the same
// session is denied "crawl evidence too old"; a new session that lists is
// allowed again; after the ages pass once more a crawl, and no listing, allows
// the call; the stats line counts the two stale denials apart from the other
// denials; the processor is restored without the flags. The scenario restarts
// a processor mid-run as H does; the hostile server's processor is untouched.
func scenarioR(t *testing.T, s *stack) {
	stats := lastLineWith(s.stopProcessor(t, "mock"), statsPrefix)
	s.note(t, "R: the processor without the ages printed on SIGTERM: %s", stats)
	s.startProcessor(t, "mock", nil, "--max-crawl-age", freshnessAge.String(), "--max-evidence-age", freshnessAge.String())

	cs := s.eventuallyServes(t, "mock", "add", "echo")
	t0 := time.Now()
	o := s.expectAllowed(t, cs, "echo", "hello")
	s.note(t, "R: %s after the session listed, with the latest crawl older than %s, tools/call echo -> %s", since(t0), freshnessAge, o)

	time.Sleep(freshnessWait)
	o = s.expectDenied(t, cs, "echo")
	mustContain(t, "denial with the listing and the crawl both older than the age", o.detail(), staleCause)
	s.note(t, "R: %s after the listing, tools/call echo on the same session -> %s", since(t0), o)

	cs2 := s.eventuallyServes(t, "mock", "add", "echo")
	o = s.expectAllowed(t, cs2, "echo", "hello")
	s.note(t, "R: a new session listed, tools/call echo -> %s", o)

	time.Sleep(freshnessWait)
	o = s.expectDenied(t, cs2, "echo")
	mustContain(t, "denial after the second wait", o.detail(), staleCause)
	t1 := time.Now()
	mustContain(t, "crawl with the ages set", s.twOK(t, "crawl", "mock"), "complete", "unchanged=3")
	o = s.expectAllowed(t, cs2, "echo", "hello")
	s.note(t, "R: %s after a crawl and with no listing since the denial, tools/call echo -> %s", since(t1), o)

	stats = lastLineWith(s.stopProcessor(t, "mock"), statsPrefix)
	s.note(t, "R: the processor with the ages printed on SIGTERM: %s", stats)
	if allowed, denied, stale := callCounters(t, stats); allowed != 3 || denied != 2 || stale != 2 {
		t.Errorf("stats line counts calls allowed=%d denied=%d stale=%d, want 3, 2 and 2 (the two stale denials and no other): %s", allowed, denied, stale, stats)
	}
	s.startProcessor(t, "mock", nil)
	s.expectServing(t)
}

// callCounters reads the three call counters of one stats line. The denied
// key appears twice on the line (lists, then calls), so the calls part is cut
// out and handed to statValue behind the prefix it keys on.
func callCounters(t *testing.T, stats string) (allowed, denied, stale int) {
	t.Helper()
	_, calls, ok := strings.Cut(stats, "calls allowed=")
	if !ok {
		t.Fatalf("no calls allowed= in the stats line %q", stats)
	}
	calls = statsPrefix + " calls allowed=" + calls
	return statValue(t, calls, "calls allowed"), statValue(t, calls, "denied"), statValue(t, calls, "stale")
}
