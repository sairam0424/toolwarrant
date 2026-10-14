package processor

import (
	"strings"
	"testing"
	"time"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// crawlAged configures both ages of the processor for the freshness tests:
// the crawl's word carries a call for an hour, a listing for half of that.
func crawlAged(c *Config) {
	c.MaxCrawlAge = time.Hour
	c.MaxEvidenceAge = 30 * time.Minute
}

// D21, owner decision O-7, bounding limit L1 when crawls stop. With
// MaxCrawlAge set, a call whose only allowing evidence is the latest crawl's
// word (LastSeen equal to the approval) is denied as "crawl evidence too old"
// once that crawl is older than the age; a fresh listing of the approved bytes
// carries the call while it is itself fresh (MaxEvidenceAge), a new complete
// crawl carries it without any listing, and a snapshot with no complete crawl
// is never fresh. A contradiction wins over the crawl's age: a stale crawl
// next to a changed listing is denied as changed, not as stale, and a stale
// crawl next to no evidence of a tool the crawl never saw stays not yet
// verified.
func TestJudgeCall_StaleCrawlDeniesUnlessFreshlyListed(t *testing.T) {
	d1 := mustDigest(t, echoV1)

	t.Run("the crawl's word carries the call only while fresh", func(t *testing.T) {
		src := newFakeSource(map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)})
		s, _ := newTestServer(src, crawlAged)
		clk := withClock(s)
		src.crawled(clk.now)
		requireAllowed(t, call(t, s, callReq("echo")))
		clk.advance(time.Hour) // exactly the age is still fresh
		requireAllowed(t, call(t, s, callReq("echo")))
		clk.advance(time.Second)
		requireCallDenied(t, call(t, s, callReq("echo")), "echo", causeStale)

		servedNames(t, list(t, s, listBody("", echoV1))) // a fresh listing of the approved bytes
		requireAllowed(t, call(t, s, callReq("echo")))
		clk.advance(30*time.Minute + time.Second) // the listing ages too
		requireCallDenied(t, call(t, s, callReq("echo")), "echo", causeStale)

		src.crawled(clk.now) // a new complete crawl, no listing
		requireAllowed(t, call(t, s, callReq("echo")))
		if st := s.Stats(); st.CallsAllowed != 4 || st.CallsDenied != 2 || st.CallsStale != 2 {
			t.Errorf("stats = %+v", st)
		}
	})

	t.Run("a snapshot with no complete crawl is never fresh", func(t *testing.T) {
		s, _ := newTestServer(newFakeSource(map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)}), crawlAged)
		withClock(s)
		requireCallDenied(t, call(t, s, callReq("echo")), "echo", causeStale)
		servedNames(t, list(t, s, listBody("", echoV1)))
		requireAllowed(t, call(t, s, callReq("echo")))
	})

	t.Run("a contradiction wins over the crawl's age", func(t *testing.T) {
		src := newFakeSource(map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)})
		s, _ := newTestServer(src, crawlAged)
		clk := withClock(s)
		src.crawled(clk.now.Add(-2 * time.Hour))
		if got := servedNames(t, list(t, s, listBody("", echoV2))); len(got) != 0 {
			t.Fatalf("served %v", got)
		}
		requireCallDenied(t, call(t, s, callReq("echo")), "echo", causeChanged)
		clk.advance(1000 * time.Hour)
		requireCallDenied(t, call(t, s, callReq("echo")), "echo", causeChanged)
		if st := s.Stats(); st.CallsStale != 0 {
			t.Errorf("stats = %+v: a changed denial is not a stale one", st)
		}
	})

	t.Run("a stale crawl that never saw the tool is not yet verified", func(t *testing.T) {
		src := newFakeSource(map[string]catalog.ToolPolicy{"echo": policy(lifecycle.Enabled, d1, "")})
		s, _ := newTestServer(src, crawlAged)
		clk := withClock(s)
		src.crawled(clk.now.Add(-2 * time.Hour))
		requireCallDenied(t, call(t, s, callReq("echo")), "echo", causeUnverified)
	})
}

// MaxCrawlAge zero, the default, keeps the rule of every version before: the
// crawl's word carries a call however old the crawl is, and a snapshot with no
// complete crawl at all (zero CrawledAt) carries it too, so an operator who
// sets nothing sees no new denial and the stale counter stays at zero.
func TestCheckRequest_MaxCrawlAgeZeroKeepsTheOldRule(t *testing.T) {
	d1 := mustDigest(t, echoV1)
	for name, crawledAt := range map[string]time.Time{"an old crawl": time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), "no complete crawl": {}} {
		t.Run(name, func(t *testing.T) {
			src := newFakeSource(map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)})
			s, _ := newTestServer(src, func(c *Config) { c.MaxEvidenceAge = time.Hour })
			clk := withClock(s)
			src.crawled(crawledAt)
			requireAllowed(t, call(t, s, callReq("echo")))
			clk.advance(10000 * time.Hour)
			requireAllowed(t, call(t, s, callReq("echo")))
			if st := s.Stats(); st.CallsAllowed != 2 || st.CallsDenied != 0 || st.CallsStale != 0 {
				t.Errorf("stats = %+v", st)
			}
		})
	}
}

// Stats.CallsStale counts the denials for a crawl older than MaxCrawlAge and
// nothing else: it moves with CallsDenied for a stale denial, stays while a
// denial has another cause, and the log line names the cause, so the stats
// line and the log tell a stopped crawler from drift.
func TestCheckRequest_StaleCrawlCountsInStats(t *testing.T) {
	d1 := mustDigest(t, echoV1)
	src := newFakeSource(map[string]catalog.ToolPolicy{"echo": servedPolicy(d1), "gone": policy(lifecycle.Enabled, d1, mustDigest(t, echoV2))})
	s, logs := newTestServer(src, crawlAged)
	clk := withClock(s)
	src.crawled(clk.now.Add(-2 * time.Hour))
	requireCallDenied(t, call(t, s, callReq("echo")), "echo", causeStale)
	requireCallDenied(t, call(t, s, callReq("echo")), "echo", causeStale)
	requireCallDenied(t, call(t, s, callReq("gone")), "gone", causeChanged)
	requireCallDenied(t, call(t, s, callReq("never")), "never", causeNotApproved)
	if st := s.Stats(); st.CallsDenied != 4 || st.CallsStale != 2 || st.CallsAllowed != 0 {
		t.Errorf("stats = %+v, want 4 denied of which 2 stale", st)
	}
	if got := strings.Count(logs.String(), `cause="crawl evidence too old"`); got != 2 {
		t.Errorf("the log names the stale cause %d times, want 2:\n%s", got, logs.String())
	}
	src.crawled(clk.now)
	requireAllowed(t, call(t, s, callReq("echo")))
	if st := s.Stats(); st.CallsStale != 2 {
		t.Errorf("stats = %+v: an allowed call moved the stale counter", st)
	}
}
