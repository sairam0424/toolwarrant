package catalog

import (
	"testing"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
	"github.com/sairam0424/toolwarrant/internal/signing"
)

// The continuity memory across the walk's page boundary (D22 (d), orchestrator
// decision 26 of the v0.4 round). The walk reads the log in pages of auditPage
// entries and carries what the newest entry about every tool left it
// (chainMemory.states) from one page to the next; the adversarial reviews of
// PR 7.5 covered the boundary with scratch tests only. Here the signed
// disable's lifecycle entry is the last entry of the first page and the lying
// crawl-shaped entry the first of the second, so a fresh open must refuse the
// lie against a state it recorded one page earlier.

// pageBoundaryPadRounds bounds the idle crawls padTo may need after the big
// crawl: one or two, since the big crawl lands within one entry of the target.
const pageBoundaryPadRounds = 4

// TestWalk_ContinuityMemoryCrossesThePageBoundary: after the bootstrap and a
// log padded to exactly auditPage-2 entries, a signed disable of echo writes
// its decision.signed entry at auditPage-1 and tool.disabled at auditPage, the
// last entry of the first page; a sealed tool.reverted by the crawler saying
// changed_pending_reapproval->enabled, with the column edited to match, lands
// at auditPage+1, the first entry of the second page, and is refused by the
// long-lived Store, by every fresh open and by Integrity with the continuity
// sentence naming the disable's entry at auditPage. It writes about 5000
// audit entries, so -short skips it (named in CLAUDE.md; the test-full job
// runs it).
func TestWalk_ContinuityMemoryCrossesThePageBoundary(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("writes about 5000 audit entries")
	}
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	d := approvedEcho(t, s)
	alice := newOperator(t, "alice")
	mustSetTrust(t, s, 1, alice, alice)
	padTo(t, s, auditPage-2)
	r := mustDecide(t, s, alice, signing.KindDisable, "alpha", "echo", "")
	disabled := r.Seq + 1
	if disabled != auditPage || auditCount(t, s) != auditPage {
		t.Fatalf("the disable's lifecycle entry sits at seq %d and the log holds %d entries; the test needs both at the page size %d", disabled, auditCount(t, s), auditPage)
	}
	lie := lyingRevert(t, rawDB(t, path), d)
	if lie != auditPage+1 {
		t.Fatalf("the lie sits at seq %d, want %d, the first entry of the second page", lie, auditPage+1)
	}
	rep := walkRefuses(t, s, path, lie, continuitySentence(lie, "alpha/echo", lifecycle.ChangedPendingReapproval, disabled, lifecycle.Disabled))
	if rep.CrawlTransitionsForged != 1 || rep.UnsignedDecisionsAfterBootstrap != 0 {
		t.Errorf("Integrity = %+v, want exactly one forged crawl transition", rep)
	}
}

// padTo appends entries until the log holds exactly n: a second server with
// as many fresh small tools as fit in one crawl (two entries per tool, one for
// the server and one for the crawl), then idle crawls of alpha, which append
// their crawl.completed entry and nothing else.
func padTo(t *testing.T, s *Store, n int64) {
	t.Helper()
	have := int64(auditCount(t, s))
	mustAddServer(t, s, "beta")
	have++
	if k := (n - have - 1) / 2; k > 0 {
		mustCrawl(t, s, "beta", bigCrawl(int(k), "v1")...)
		have += 2*k + 1
	}
	for i := 0; have < n && i < pageBoundaryPadRounds; i++ {
		mustCrawl(t, s, "alpha", tool("echo", "v1"))
		have = int64(auditCount(t, s))
	}
	if have != n {
		t.Fatalf("padded the log to %d entries, want %d", have, n)
	}
}
