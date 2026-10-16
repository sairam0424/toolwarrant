package lifecycle_test

import (
	"fmt"
	"slices"
	"testing"

	lc "github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// crawlTable is the transition table a crawl may make, as the invariants pin
// it: a sighting proposes to a discovered or deprecated tool, flags an enabled
// tool changed or brings a changed one back, a miss at the threshold
// deprecates every state but discovered, deprecated and disabled, nothing
// leaves disabled, and an observation that changes nothing stays. It is spelled
// out here, by hand, so that a widening of the exported function fails this
// test while a narrowing fails the property tests, whose steps the state
// machine made (invariants_test.go, crawlViolations).
func crawlTable() map[lc.State][]lc.State {
	return map[lc.State][]lc.State{
		lc.Discovered:               {lc.Discovered, lc.PendingReview},
		lc.PendingReview:            {lc.PendingReview, lc.Deprecated},
		lc.Enabled:                  {lc.Enabled, lc.ChangedPendingReapproval, lc.Deprecated},
		lc.ChangedPendingReapproval: {lc.ChangedPendingReapproval, lc.Enabled, lc.Deprecated},
		lc.Disabled:                 {lc.Disabled},
		lc.Deprecated:               {lc.Deprecated, lc.PendingReview},
	}
}

// crawlFixtures is one tool in every state, with an approval where the state
// admits one and a sighting to miss, so that every observation below has
// something to move.
func crawlFixtures() map[lc.State]lc.Tool {
	return map[lc.State]lc.Tool{
		lc.Discovered:               newTool(),
		lc.PendingReview:            pendingReviewTool(dA, alice),
		lc.Enabled:                  enabledTool(dA),
		lc.ChangedPendingReapproval: changedTool(dA, dB, bob),
		lc.Disabled:                 toolOf(lc.Disabled, dA, dA, 0, ver(dA, lc.VersionApproved, alice, true)),
		lc.Deprecated:               toolOf(lc.Deprecated, dA, "", deprecateAfterThree, ver(dA, lc.VersionApproved, alice, true)),
	}
}

// crawlObservations are the sightings that between them realise every
// transition of the table: the approved digest, another digest, an unusable
// definition and a miss.
func crawlObservations() []lc.ObserveCrawl {
	return []lc.ObserveCrawl{crawl(dA, carol), crawl(dB, carol), crawl(dC, carol), unusable(), miss()}
}

// CrawlMayMove equals the table the invariants pin, pair for pair, and every
// pair it admits is reached by some crawl observation on some tool, so the
// exported table is neither wider nor narrower than the state machine. The
// three sentences the catalog's walk relies on (the v0.4 plan, rule 6) are
// pinned by name: disabled reaches only disabled, deprecated reappears to
// pending_review, enabled and changed_pending_reapproval move between
// themselves. A state this package does not define moves nowhere.
func TestCrawlMayMove_EqualsTheInvariantsTable(t *testing.T) {
	table := crawlTable()
	for _, from := range allStates() {
		for _, to := range allStates() {
			if got, want := lc.CrawlMayMove(from, to), slices.Contains(table[from], to); got != want {
				t.Errorf("CrawlMayMove(%s, %s) = %v, the invariants table says %v", from, to, got, want)
			}
		}
	}
	reached := map[string]bool{}
	for _, from := range allStates() {
		for _, c := range crawlObservations() {
			for _, p := range []lc.Policy{plainPolicy(), {DeprecateAfter: 1}} {
				res, err := lc.Apply(crawlFixtures()[from], c, p)
				if err != nil {
					continue
				}
				if !lc.CrawlMayMove(from, res.Tool.State) {
					t.Errorf("a crawl moved %s -> %s (%+v), which CrawlMayMove forbids", from, res.Tool.State, c)
				}
				reached[fmt.Sprintf("%s->%s", from, res.Tool.State)] = true
			}
		}
	}
	for from, tos := range table {
		for _, to := range tos {
			if !reached[fmt.Sprintf("%s->%s", from, to)] {
				t.Errorf("CrawlMayMove admits %s -> %s but no observation of the fixtures reaches it; the table is wider than the machine", from, to)
			}
		}
	}
	if lc.CrawlMayMove(lc.Disabled, lc.Enabled) || lc.CrawlMayMove(lc.Disabled, lc.PendingReview) || lc.CrawlMayMove(lc.Disabled, lc.Deprecated) {
		t.Error("a crawl may leave disabled; only Enable does")
	}
	if !lc.CrawlMayMove(lc.Deprecated, lc.PendingReview) || lc.CrawlMayMove(lc.Deprecated, lc.Enabled) {
		t.Error("a deprecated tool reappears to pending_review and nowhere else")
	}
	if !lc.CrawlMayMove(lc.Enabled, lc.ChangedPendingReapproval) || !lc.CrawlMayMove(lc.ChangedPendingReapproval, lc.Enabled) {
		t.Error("enabled and changed_pending_reapproval move between themselves")
	}
	for _, s := range allStates() {
		if lc.CrawlMayMove(s, lc.State("bogus")) || lc.CrawlMayMove(lc.State("bogus"), s) {
			t.Errorf("an unknown state is reachable from or reaches %s", s)
		}
	}
	if lc.CrawlMayMove(lc.State("bogus"), lc.State("bogus")) {
		t.Error("an unknown state stays in place; it must be refused")
	}
}
