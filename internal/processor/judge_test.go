package processor

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// judgeCase is one row of the call rule's table: the listing evidence, the
// crawl evidence, whether the latest crawl is older than MaxCrawlAge, and the
// cause the call must be denied with ("" allows).
type judgeCase struct {
	observed, lastSeen string
	staleCrawl         bool
	want               cause
}

// nothingListed stands for "no listing evidence" in the table.
const nothingListed = "<nothing listed>"

// D9 as one table, with the D21 rows. The evidence for a tools/call is what
// the gateway last listed for the tool (observed) and what the latest crawl
// saw (LastSeen). Nothing is listed, or the approval, another digest, or the
// conflict marker a bad page leaves; the crawl saw the approval, nothing
// (absent), another digest, or a definition it could not use. The stale rows
// run with MaxCrawlAge set and the crawl older than that: only the row whose
// sole allowing evidence is the crawl's word changes, to "crawl evidence too
// old"; a fresh agreeing listing still allows, and every denial keeps its
// cause.
func TestJudgeCall_RuleTable(t *testing.T) {
	d1, d2 := mustDigest(t, echoV1), mustDigest(t, echoV2)
	cases := []judgeCase{
		{nothingListed, d1, false, ""},
		{nothingListed, "", false, causeUnverified},
		{nothingListed, d2, false, causeChanged},
		{nothingListed, lifecycle.UnusableDigest, false, causeUnverified},

		{d1, d1, false, ""},
		{d1, "", false, ""}, // absent at the last crawl is no contradiction once the gateway listed the approval
		{d1, d2, false, causeChanged},
		{d1, lifecycle.UnusableDigest, false, causeUnverified},

		{d2, d1, false, causeChanged},
		{d2, "", false, causeChanged},
		{d2, d2, false, causeChanged},
		{d2, lifecycle.UnusableDigest, false, causeChanged},

		{observedConflict, d1, false, causeChanged},
		{observedConflict, "", false, causeChanged},
		{observedConflict, d2, false, causeChanged},
		{observedConflict, lifecycle.UnusableDigest, false, causeChanged},

		{nothingListed, d1, true, causeStale}, // the one row MaxCrawlAge changes
		{nothingListed, "", true, causeUnverified},
		{nothingListed, d2, true, causeChanged},
		{nothingListed, lifecycle.UnusableDigest, true, causeUnverified},
		{d1, d1, true, ""}, // a fresh agreeing listing carries the call
		{d1, "", true, ""},
		{d2, d1, true, causeChanged},
		{observedConflict, d1, true, causeChanged},
	}
	for _, tc := range cases {
		t.Run(tc.name(), func(t *testing.T) { runJudgeCase(t, tc, d1) })
	}
}

// name labels a row by the first bytes of each piece of evidence.
func (tc judgeCase) name() string {
	short := func(v string) string {
		if len(v) > 12 {
			return v[:12]
		}
		return v
	}
	label := "listed " + short(tc.observed) + " crawl " + short(tc.lastSeen)
	if tc.staleCrawl {
		label += " stale"
	}
	return label
}

// runJudgeCase judges one call against the row. A stale row configures
// MaxCrawlAge and a crawl one second older than it; a fresh row leaves
// MaxCrawlAge at zero, so a never-crawled snapshot (zero CrawledAt) is fresh
// as every version before. The listing, when there is one, is recorded now,
// so it is fresh.
func runJudgeCase(t *testing.T, tc judgeCase, approved string) {
	t.Helper()
	const maxCrawlAge = time.Hour
	src := newFakeSource(map[string]catalog.ToolPolicy{"echo": policy(lifecycle.Enabled, approved, tc.lastSeen)})
	var mutate []func(*Config)
	if tc.staleCrawl {
		mutate = append(mutate, func(c *Config) { c.MaxCrawlAge = maxCrawlAge })
	}
	s, _ := newTestServer(src, mutate...)
	clk := withClock(s)
	if tc.staleCrawl {
		src.crawled(clk.now.Add(-maxCrawlAge - time.Second))
	}
	if _, err := s.current(context.Background()); err != nil { // load the snapshot the evidence is recorded against
		t.Fatal(err)
	}
	if tc.observed != nothingListed {
		s.observe("echo", tc.observed)
	}
	res := call(t, s, callReq("echo"))
	if tc.want == "" {
		requireAllowed(t, res)
		return
	}
	requireCallDenied(t, res, "echo", tc.want)
}

// The catalog marks a tool whose live definition it could not use with a
// LastSeen that is not a digest (the "unusable" marker: an invalid or
// duplicated definition, or an exhausted proposal budget). Such a tool is
// hidden even while the gateway shows the approved bytes, and no call goes
// through: the crawl could not verify what the upstream binds the name to, so
// a tool hidden for a marker is also uncallable, as README and the threat
// model promise ("marked UNUSABLE and never served"). The rule is one-way
// (D9): a listed tool may still be denied, after a revert the crawl has not
// recorded or after its listing evidence was dropped, until the crawl or a
// listing records the digest the gateway shows. Any marker shape is treated
// the same way, in both servable states. Before this round the list hook
// judged bytes alone and listed a tool whose every call it then denied.
func TestJudgeCall_NonDigestLastSeenMarkersHideTheToolAndDenyCalls(t *testing.T) {
	d1 := mustDigest(t, echoV1)
	markers := []string{lifecycle.UnusableDigest, "UNUSABLE", "x", d1[:63], strings.ToUpper(d1), d1 + "0", observedConflict}
	for _, marker := range markers {
		for _, state := range []lifecycle.State{lifecycle.Enabled, lifecycle.ChangedPendingReapproval} {
			s, logs := newTestServer(newFakeSource(map[string]catalog.ToolPolicy{"echo": policy(state, d1, marker)}))
			if got := servedNames(t, list(t, s, listBody("", echoV1))); len(got) != 0 {
				t.Fatalf("marker %q in state %s: listed %v although every call to it is denied", marker, state, got)
			}
			if st := s.Stats(); st.ToolsHidden != 1 || st.ToolsUnverified != 1 || st.ToolsMismatched != 0 || st.ToolsUnapproved != 0 {
				t.Errorf("marker %q in state %s: stats = %+v", marker, state, st)
			}
			if !strings.Contains(logs.String(), "unverified=1") {
				t.Errorf("marker %q: the page summary should count the hide:\n%s", marker, logs.String())
			}
			requireCallDenied(t, call(t, s, callReq("echo")), "echo", causeUnverified)
		}
	}
}

// Listed and callable move together: a clean crawl that records the approved
// digest lifts the hide and the denial at once, and "" (absent at the latest
// crawl) is not a marker, so the gateway's own listing carries the tool in
// both hooks (D9).
func TestCheckResponse_ListedAndCallableCoincideAcrossCrawlEvidence(t *testing.T) {
	d1 := mustDigest(t, echoV1)
	src := newFakeSource(map[string]catalog.ToolPolicy{"echo": policy(lifecycle.Enabled, d1, lifecycle.UnusableDigest)})
	s, _ := newTestServer(src)
	if got := servedNames(t, list(t, s, listBody("", echoV1))); len(got) != 0 {
		t.Fatalf("served %v while the crawl says unusable", got)
	}
	requireCallDenied(t, call(t, s, callReq("echo")), "echo", causeUnverified)
	src.publish(map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)})
	if got := servedNames(t, list(t, s, listBody("", echoV1))); !reflect.DeepEqual(got, []string{"echo"}) {
		t.Fatalf("served %v after a clean crawl, want [echo]", got)
	}
	requireAllowed(t, call(t, s, callReq("echo")))

	absent, _ := newTestServer(newFakeSource(map[string]catalog.ToolPolicy{"echo": policy(lifecycle.Enabled, d1, "")}))
	if got := servedNames(t, list(t, absent, listBody("", echoV1))); !reflect.DeepEqual(got, []string{"echo"}) {
		t.Fatalf("served %v with LastSeen \"\", want [echo]", got)
	}
	requireAllowed(t, call(t, absent, callReq("echo")))
	if st := absent.Stats(); st.ToolsUnverified != 0 || st.ToolsHidden != 0 {
		t.Errorf("stats = %+v", st)
	}
}

// clock replaces the processor's time source so a test can age evidence.
type clock struct{ now time.Time }

func (c *clock) advance(d time.Duration) { c.now = c.now.Add(d) }

func withClock(s *Server) *clock {
	c := &clock{now: time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)}
	s.now = func() time.Time { return c.now }
	return c
}

// A digest the gateway listed long ago says nothing about what the upstream
// serves now. With MaxEvidenceAge set, an observation that agrees with the
// approval is no evidence once it is older than that, so it no longer carries
// a call on its own; crawl evidence is aged by MaxCrawlAge, not here. A
// contradiction is not aged at all (TestEvidence_ContradictionsNeverExpire;
// before D21 the third case of this test required the opposite, limit L15).
func TestEvidence_ObservedDigestsExpire(t *testing.T) {
	d1 := mustDigest(t, echoV1)
	const maxAge = time.Hour
	aged := func(c *Config) { c.MaxEvidenceAge = maxAge }

	t.Run("crawl absent: the listing carries the call only while fresh", func(t *testing.T) {
		s, _ := newTestServer(newFakeSource(map[string]catalog.ToolPolicy{"echo": policy(lifecycle.Enabled, d1, "")}), aged)
		clk := withClock(s)
		servedNames(t, list(t, s, listBody("", echoV1)))
		requireAllowed(t, call(t, s, callReq("echo")))
		clk.advance(maxAge) // exactly the age is still fresh
		requireAllowed(t, call(t, s, callReq("echo")))
		clk.advance(time.Second)
		requireCallDenied(t, call(t, s, callReq("echo")), "echo", causeUnverified)
		if seen, _, ok := s.observedDigest("echo"); !ok || seen != d1 {
			t.Fatalf("the aged entry was removed from the table: %q, %v; it is kept and judged stale", seen, ok)
		}
		servedNames(t, list(t, s, listBody("", echoV1))) // a new listing is fresh evidence
		requireAllowed(t, call(t, s, callReq("echo")))
	})

	t.Run("crawl evidence is not aged by MaxEvidenceAge", func(t *testing.T) {
		s, _ := newTestServer(newFakeSource(map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)}), aged)
		clk := withClock(s)
		requireAllowed(t, call(t, s, callReq("echo")))
		clk.advance(1000 * time.Hour)
		requireAllowed(t, call(t, s, callReq("echo")))
	})

	t.Run("an aged agreeing listing leaves the call to the crawl", func(t *testing.T) {
		s, _ := newTestServer(newFakeSource(map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)}), aged)
		clk := withClock(s)
		servedNames(t, list(t, s, listBody("", echoV1)))
		clk.advance(maxAge + time.Second)
		requireAllowed(t, call(t, s, callReq("echo"))) // on the crawl's word alone, until the next listing
	})

	t.Run("zero means evidence never expires", func(t *testing.T) {
		s, _ := newTestServer(newFakeSource(map[string]catalog.ToolPolicy{"echo": policy(lifecycle.Enabled, d1, "")}))
		clk := withClock(s)
		servedNames(t, list(t, s, listBody("", echoV1)))
		clk.advance(10000 * time.Hour)
		requireAllowed(t, call(t, s, callReq("echo")))
	})
}

// D21, owner decision O-7, closing limit L15: before this round observedDigest
// aged every entry, so a contradiction older than MaxEvidenceAge stopped
// denying and the call passed on the crawl's word although the most recent
// page the processor saw showed another definition. Only evidence that agrees
// with the approval ages now: another digest and the conflict marker deny for
// as long as they stand, whatever MaxEvidenceAge says, and only a clean page
// that shows the approved bytes releases the call. Ageing only ever removes
// evidence that would allow. The test uses no package internals beyond the
// hooks, so it compiles against the code before this round, where it fails
// at the call after the age has passed.
func TestEvidence_ContradictionsNeverExpire(t *testing.T) {
	d1 := mustDigest(t, echoV1)
	const maxAge = time.Hour
	aged := func(c *Config) { c.MaxEvidenceAge = maxAge }
	duplicate := listBody("", echoV1, echoV1) // the same name twice: a page denied as a whole, leaving the conflict marker

	contradictions := map[string][]byte{"another digest": listBody("", echoV2), "the conflict marker": duplicate}
	for name, page := range contradictions {
		for _, lastSeen := range []string{d1, ""} {
			t.Run(name+" with LastSeen "+lastSeen[:min(len(lastSeen), 12)], func(t *testing.T) {
				s, _ := newTestServer(newFakeSource(map[string]catalog.ToolPolicy{"echo": policy(lifecycle.Enabled, d1, lastSeen)}), aged)
				clk := withClock(s)
				if got := servedNames(t, list(t, s, listBody("", echoV1))); len(got) != 1 {
					t.Fatalf("served %v before the contradiction", got)
				}
				requireAllowed(t, call(t, s, callReq("echo")))
				if res := list(t, s, page); res.GetError() == nil && len(servedNames(t, res)) != 0 {
					t.Fatalf("the contradicting page served something: %v", res)
				}
				requireCallDenied(t, call(t, s, callReq("echo")), "echo", causeChanged)
				for _, step := range []time.Duration{maxAge, time.Second, 1000 * time.Hour} {
					clk.advance(step)
					requireCallDenied(t, call(t, s, callReq("echo")), "echo", causeChanged)
				}
				servedNames(t, list(t, s, listBody("", echoV1))) // only a clean page releases the call
				requireAllowed(t, call(t, s, callReq("echo")))
				if st := s.Stats(); st.CallsAllowed != 2 || st.CallsDenied != 4 {
					t.Errorf("stats = %+v", st)
				}
			})
		}
	}
}
