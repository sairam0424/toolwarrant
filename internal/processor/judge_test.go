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

// D9 as one table. The evidence for a tools/call is what the gateway last
// listed for the tool (observed) and what the latest crawl saw (LastSeen).
// Nothing is listed, or the approval, another digest, or the conflict marker a
// bad page leaves; the crawl saw the approval, nothing (absent), another
// digest, or a definition it could not use.
func TestJudgeCall_RuleTable(t *testing.T) {
	d1, d2 := mustDigest(t, echoV1), mustDigest(t, echoV2)
	const nothing = "<nothing listed>"
	cases := []struct {
		observed, lastSeen string
		want               cause // "" allows
	}{
		{nothing, d1, ""},
		{nothing, "", causeUnverified},
		{nothing, d2, causeChanged},
		{nothing, lifecycle.UnusableDigest, causeUnverified},

		{d1, d1, ""},
		{d1, "", ""}, // absent at the last crawl is no contradiction once the gateway listed the approval
		{d1, d2, causeChanged},
		{d1, lifecycle.UnusableDigest, causeUnverified},

		{d2, d1, causeChanged},
		{d2, "", causeChanged},
		{d2, d2, causeChanged},
		{d2, lifecycle.UnusableDigest, causeChanged},

		{observedConflict, d1, causeChanged},
		{observedConflict, "", causeChanged},
		{observedConflict, d2, causeChanged},
		{observedConflict, lifecycle.UnusableDigest, causeChanged},
	}
	short := func(v string) string {
		if len(v) > 12 {
			return v[:12]
		}
		return v
	}
	for _, tc := range cases {
		t.Run("listed "+short(tc.observed)+" crawl "+short(tc.lastSeen), func(t *testing.T) {
			s, _ := newTestServer(newFakeSource(map[string]catalog.ToolPolicy{"echo": policy(lifecycle.Enabled, d1, tc.lastSeen)}))
			if _, err := s.current(context.Background()); err != nil { // load the snapshot the evidence is recorded against
				t.Fatal(err)
			}
			if tc.observed != nothing {
				s.observe("echo", tc.observed)
			}
			res := call(t, s, callReq("echo"))
			if tc.want == "" {
				requireAllowed(t, res)
				return
			}
			requireCallDenied(t, res, "echo", tc.want)
		})
	}
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
// serves now. With MaxEvidenceAge set, an observation older than that is no
// evidence at all, in either direction; crawl evidence (LastSeen) carries no
// timestamp yet and is not aged here.
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
		servedNames(t, list(t, s, listBody("", echoV1))) // a new listing is fresh evidence
		requireAllowed(t, call(t, s, callReq("echo")))
	})

	t.Run("crawl evidence is not aged", func(t *testing.T) {
		s, _ := newTestServer(newFakeSource(map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)}), aged)
		clk := withClock(s)
		requireAllowed(t, call(t, s, callReq("echo")))
		clk.advance(1000 * time.Hour)
		requireAllowed(t, call(t, s, callReq("echo")))
	})

	t.Run("a stale contradiction no longer counts either", func(t *testing.T) {
		s, _ := newTestServer(newFakeSource(map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)}), aged)
		clk := withClock(s)
		if got := servedNames(t, list(t, s, listBody("", echoV2))); len(got) != 0 {
			t.Fatalf("served %v", got)
		}
		requireCallDenied(t, call(t, s, callReq("echo")), "echo", causeChanged)
		clk.advance(maxAge + time.Second)
		requireAllowed(t, call(t, s, callReq("echo"))) // on the crawl's word alone, until the next listing
		if got := servedNames(t, list(t, s, listBody("", echoV2))); len(got) != 0 {
			t.Fatalf("served %v", got)
		}
		requireCallDenied(t, call(t, s, callReq("echo")), "echo", causeChanged)
	})

	t.Run("zero means evidence never expires", func(t *testing.T) {
		s, _ := newTestServer(newFakeSource(map[string]catalog.ToolPolicy{"echo": policy(lifecycle.Enabled, d1, "")}))
		clk := withClock(s)
		servedNames(t, list(t, s, listBody("", echoV1)))
		clk.advance(10000 * time.Hour)
		requireAllowed(t, call(t, s, callReq("echo")))
	})
}
