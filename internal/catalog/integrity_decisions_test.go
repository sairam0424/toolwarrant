package catalog

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
	"github.com/sairam0424/toolwarrant/internal/signing"
)

// Integrity over the decisions after the bootstrap (D22 (b) and (d)): every
// refusal of the walk reported in one run with the walk's sentence, and the
// approvals in force that predate the bootstrap listed as information.

// Integrity reports every decision problem the walk would refuse, one line
// each, and goes on: an unlisted key's record and the approval naming it, a
// key under another operator's name, a record whose digest token disagrees, an
// unsigned approval, a sealed crawl-shaped entry that leaves disabled, and an
// approval naming a decision of another transaction, under the counters of
// their rules, while a well-formed signed decision between them is not
// reported and the chain verifies.
func TestIntegrity_ReportsEveryDecisionRecordProblemTheWalkRefuses(t *testing.T) {
	t.Parallel()
	s, path, alice, bob := trustedCatalog(t)
	carol := newOperator(t, "carol")
	d, e1 := pendingSum(t), digestOf(t, "echo", "v1")
	good := mustDecide(t, s, alice, signing.KindApprove, "alpha", "sum", d)
	mustCrawl(t, s, "alpha", tool("echo", "v1"), tool("sum", "v1"), tool("new", "v1"))
	db := rawDB(t, path)
	id := s.identity

	unlisted, _ := forgeDecision(t, db, id, carol, carol.actor(), signing.KindApprove, "alpha", "new", digestOf(t, "new", "v1"))
	f := forgedApproval(carol.actor(), "new", digestOf(t, "new", "v1"), signedNote(unlisted))
	f.ts = rawEntryAt(t, db, unlisted).TS
	naming := appendEntry(t, db, f.entry())
	another, _ := forgeDecision(t, db, id, operator{name: bob.name, key: alice.key}, bob.actor(), signing.KindDisable, "alpha", "echo", "")
	rec := signDecisionPayload(t, decisionOf(id, rawHead(t, db), alice, signing.KindApprove, "alpha", "new", digestOf(t, "new", "v1")), alice)
	token := appendSigned(t, db, forgedEntry{by: alice.actor(), event: evDecisionSigned, subject: "alpha/new", detail: decisionDetail(signing.KindApprove, d)}, *rec)
	unsigned := appendEntry(t, db, forgedApproval(alice.actor(), "new", digestOf(t, "new", "v1"), "").entry())
	reverted := appendEntry(t, db, toolEntry{by: crawler, event: string(lifecycle.EvReverted), subject: "alpha/echo", digest: e1, before: e1, after: e1,
		from: lifecycle.Disabled, to: lifecycle.Enabled, lastSeen: e1}.entry())
	replay := forgedApproval(alice.actor(), "sum", d, signedNote(good.Seq))
	replay.ts = rawEntryAt(t, db, good.Seq).TS
	replayed := appendEntry(t, db, replay.entry())

	_, err := s.Snapshot(bg, "alpha")
	wantCorruptNaming(t, "the long-lived Store", err, fmt.Sprintf("signed record of entry %d: signer %s is not in trust list v2", unlisted, carol.fp()))
	fo := forensicOpen(t, path, "")
	if _, err := fo.VerifyAudit(bg); err != nil {
		t.Errorf("VerifyAudit = %v; every forged entry is correctly sealed", err)
	}
	rep := mustIntegrity(t, fo)
	if rep.SignedRecordsInvalid != 3 || rep.UnsignedDecisionsAfterBootstrap != 3 || rep.CrawlTransitionsForged != 1 || rep.TrustListsInvalid != 0 || rep.ChainBreaks != 0 {
		t.Errorf("Integrity = %+v; want 3 invalid records, 3 unsigned decisions, 1 forged crawl transition", rep)
	}
	problemMentioning(t, rep,
		fmt.Sprintf("signed record of entry %d: signer %s is not in trust list v2 in force at that entry", unlisted, carol.fp()),
		fmt.Sprintf("audit entry %d names signed=%d, which is not a verified decision.signed entry", naming, unlisted),
		fmt.Sprintf(`signed record of entry %d: signer %s belongs to "alice" but the entry and payload name "bob"`, another, alice.fp()),
		fmt.Sprintf("audit entry %d says digest=%s but its signed decision names digest %s", token, quote(d), digestOf(t, "new", "v1")),
		unsignedSentence(unsigned, string(lifecycle.EvApproved), mustTrustListSeq(t, path)),
		crawlSentence(reverted, "alpha/echo", lifecycle.Disabled, lifecycle.Enabled, string(lifecycle.EvReverted)),
		fmt.Sprintf("audit entry %d names signed=%d, whose transaction ended before it", replayed, good.Seq))
	for _, p := range rep.Problems {
		for _, seq := range []int64{good.Seq, good.Seq + 1} {
			if containsEntry(p, seq) {
				t.Errorf("the well-formed signed approval (entries %d, %d) was reported: %q", good.Seq, good.Seq+1, p)
			}
		}
	}
	if !slices.Equal(rep.LegacyApprovalsInService, []string{"alpha/echo"}) {
		t.Errorf("LegacyApprovalsInService = %v, want echo alone: sum was approved after the bootstrap", rep.LegacyApprovalsInService)
	}
}

// containsEntry reports whether a problem line names entry seq, followed by
// a space, a colon or a comma, so that entry 12 does not match entry 123.
func containsEntry(p string, seq int64) bool {
	for _, suffix := range []string{" ", ":", ","} {
		if strings.Contains(p, fmt.Sprintf("entry %d%s", seq, suffix)) {
			return true
		}
	}
	return false
}

// Integrity lists the approvals in force that predate the bootstrap (O-12),
// sorted, as information and not as a problem; a tool re-approved with a
// signed decision leaves the list, and a catalog without a bootstrap has no
// list at all.
func TestIntegrity_CountsLegacyApprovalsInService(t *testing.T) {
	t.Parallel()
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("echo", "v1"), tool("sum", "v1"), tool("new", "v1"))
	for _, name := range []string{"echo", "sum"} {
		mustApprove(t, s, "alpha", name, digestOf(t, name, "v1"))
	}
	if rep := mustIntegrity(t, s); rep.LegacyApprovalsInService != nil || len(rep.Problems) != 0 {
		t.Errorf("before any bootstrap: %+v", rep)
	}
	alice := newOperator(t, "alice")
	mustSetTrust(t, s, 1, alice, alice)
	rep := mustIntegrity(t, s)
	if !slices.Equal(rep.LegacyApprovalsInService, []string{"alpha/echo", "alpha/sum"}) || len(rep.Problems) != 0 {
		t.Errorf("after the bootstrap: %+v, want echo and sum listed and no problem", rep)
	}
	mustCrawl(t, s, "alpha", tool("echo", "v2"), tool("sum", "v1"), tool("new", "v1"))
	mustDecide(t, s, alice, signing.KindApprove, "alpha", "echo", digestOf(t, "echo", "v2"))
	mustDecide(t, s, alice, signing.KindApprove, "alpha", "new", digestOf(t, "new", "v1"))
	rep = mustIntegrity(t, s)
	if !slices.Equal(rep.LegacyApprovalsInService, []string{"alpha/sum"}) || len(rep.Problems) != 0 {
		t.Errorf("after re-approving echo and approving new: %+v, want sum alone", rep)
	}
	fo := forensicOpen(t, path, "")
	if got := mustIntegrity(t, fo); !slices.Equal(got.LegacyApprovalsInService, rep.LegacyApprovalsInService) {
		t.Errorf("forensic Integrity = %v, want %v", got.LegacyApprovalsInService, rep.LegacyApprovalsInService)
	}
	mustBeClean(t, s, "with a legacy approval in service")
}
