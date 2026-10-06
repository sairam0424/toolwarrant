package processor

import (
	"context"
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
			cur, err := s.current(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if tc.observed != nothing {
				s.observe("echo", tc.observed, cur.generation)
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
// LastSeen that is not a digest. Such a tool is listed when the gateway shows
// the approved bytes (the list hook judges bytes, not crawl history) but no
// call goes through: the crawl could not verify what the upstream binds the
// name to, and any marker shape is treated the same way.
func TestJudgeCall_NonDigestLastSeenMarkersDenyAsUnverified(t *testing.T) {
	d1 := mustDigest(t, echoV1)
	markers := []string{lifecycle.UnusableDigest, "UNUSABLE", "x", d1[:63], strings.ToUpper(d1), d1 + "0", observedConflict}
	for _, marker := range markers {
		s, _ := newTestServer(newFakeSource(map[string]catalog.ToolPolicy{"echo": policy(lifecycle.Enabled, d1, marker)}))
		if got := servedNames(t, list(t, s, listBody("", echoV1))); len(got) != 1 {
			t.Fatalf("marker %q: the approved bytes were not listed: %v", marker, got)
		}
		requireCallDenied(t, call(t, s, callReq("echo")), "echo", causeUnverified)
	}
}

func TestIsDigest(t *testing.T) {
	d1 := mustDigest(t, echoV1)
	for _, good := range []string{d1, strings.Repeat("0", 64), strings.Repeat("f", 64)} {
		if !isDigest(good) {
			t.Errorf("isDigest(%q) = false", good)
		}
	}
	bad := []string{
		"", lifecycle.UnusableDigest, observedConflict, d1[:63], d1 + "0", strings.ToUpper(d1),
		strings.Repeat("g", 64), strings.Repeat("0", 63) + "G", strings.Repeat("0", 62) + "é",
		strings.Repeat(" ", 64), d1[:63] + "\x00",
	}
	for _, b := range bad {
		if isDigest(b) {
			t.Errorf("isDigest(%q) = true", b)
		}
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
