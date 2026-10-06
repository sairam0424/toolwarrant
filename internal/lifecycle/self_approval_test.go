package lifecycle_test

// D4, ported from the reviewers' reproductions (catalog review
// "Self-approval check compares against the LAST proposer" and system review
// "ProposedBy is rewritten on re-proposal and by Enable"). Before D4 every
// step marked "laundered" succeeded: a re-proposal or an Enable renamed the
// proposer, so the person who introduced the bytes could approve them.

import (
	"testing"

	lc "github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// TestRV_SelfApproval_LaunderedByReproposal: alice crawls D and cannot approve
// it; the upstream (which alice may control) flips to E and back to D while the
// system crawler runs; alice still cannot approve D.
func TestSelfApproval_ReproposalByAnotherCrawlerDoesNotLaunder(t *testing.T) {
	p := lc.DefaultPolicy()
	tool := step(t, newTool(), crawl(dD, alice), p)
	mustFail(t, tool, lc.Approve{Digest: dD, Actor: alice}, p, lc.ErrSelfApproval)

	tool = step(t, tool, crawl("digest-e", crawler), p)
	tool = step(t, tool, crawl(dD, crawler), p)
	requireProposers(t, tool, dD, alice, crawler)
	mustFail(t, tool, lc.Approve{Digest: dD, Actor: alice}, p, lc.ErrSelfApproval)   // laundered before D4
	mustFail(t, tool, lc.Approve{Digest: dD, Actor: crawler}, p, lc.ErrSelfApproval) // the second proposer neither
	tool = step(t, tool, lc.Approve{Digest: dD, Actor: bob}, p)
	requireServes(t, tool, dD, true)
}

// TestRV_Lifecycle_EnableOverwritesProposer: alice crawls B while the tool is
// disabled, bob enables under the default policy. B must stay alice's
// proposal: alice is refused, bob (who introduced nothing) is not.
func TestSelfApproval_EnableDoesNotRenameTheProposer(t *testing.T) {
	p := lc.DefaultPolicy()
	tool := approvedAt(t, dA, p)
	tool = step(t, tool, lc.Disable{Actor: alice}, p)
	tool = step(t, tool, crawl(dB, alice), p)
	res := applyOK(t, tool, lc.Enable{Actor: bob}, p)
	tool = res.Tool
	requireState(t, tool, lc.PendingReview)
	requireKinds(t, res, lc.EvSuperseded, lc.EvEnabled) // no second version.proposed for B
	requireProposers(t, tool, dB, alice)

	mustFail(t, tool, lc.Approve{Digest: dB, Actor: alice}, p, lc.ErrSelfApproval) // laundered before D4
	tool = step(t, tool, lc.Approve{Digest: dB, Actor: bob}, p)
	requireServes(t, tool, dB, true)
}

// TestProposedByOverwritten: A (alice) -> B (bob) -> A (bob). A's row keeps
// alice as its first proposer and gains bob; alice is refused, bob is refused,
// carol may approve.
func TestSelfApproval_FirstProposerIsRememberedAcrossReproposals(t *testing.T) {
	p := lc.DefaultPolicy()
	tool := step(t, newTool(), crawl(dA, alice), p)
	tool = step(t, tool, crawl(dB, bob), p)
	tool = step(t, tool, crawl(dA, bob), p)
	requireProposers(t, tool, dA, alice, bob)
	requireProposers(t, tool, dB, bob)
	if v, _ := findVersion(tool, dA); v.ProposedBy != alice {
		t.Errorf("ProposedBy of dA = %q, want %q (set once, never changes)", v.ProposedBy, alice)
	}
	mustFail(t, tool, lc.Approve{Digest: dA, Actor: alice}, p, lc.ErrSelfApproval) // laundered before D4
	mustFail(t, tool, lc.Approve{Digest: dA, Actor: bob}, p, lc.ErrSelfApproval)
	tool = step(t, tool, lc.Approve{Digest: dA, Actor: carol}, p)
	requireServes(t, tool, dA, true)
}

// A reappearance after deprecation and a rollback-then-resighting both reuse
// a version; each adds the crawler and keeps everyone who came before.
func TestSelfApproval_HistoryGrowsThroughReappearanceAndRollback(t *testing.T) {
	p := plainPolicy()
	tool := approvedAt(t, dA, p)
	for i := 0; i < deprecateAfterThree; i++ {
		tool = step(t, tool, miss(), p)
	}
	tool = step(t, tool, crawl(dA, carol), p) // reappearance re-proposes dA
	requireProposers(t, tool, dA, alice, carol)
	mustFail(t, tool, lc.Approve{Digest: dA, Actor: carol}, p, lc.ErrSelfApproval)
	tool = step(t, tool, lc.Approve{Digest: dA, Actor: bob}, p)

	tool = step(t, tool, crawl(dB, crawler), p)
	tool = step(t, tool, lc.Approve{Digest: dB, Actor: bob}, p)
	tool = step(t, tool, lc.Rollback{To: dA, Actor: bob}, p)
	tool = step(t, tool, crawl(dB, alice), p) // the superseded dB is proposed again
	requireProposers(t, tool, dB, crawler, alice)
	mustFail(t, tool, lc.Approve{Digest: dB, Actor: alice}, p, lc.ErrSelfApproval)
	mustFail(t, tool, lc.Approve{Digest: dB, Actor: crawler}, p, lc.ErrSelfApproval)
	applyOK(t, tool, lc.Approve{Digest: dB, Actor: carol}, p)
}

// A proposer may always reject, and the policy switch restores self-approval
// for every proposer, not only the first.
func TestSelfApproval_RejectIsOpenAndThePolicySwitchCoversEveryProposer(t *testing.T) {
	tool := step(t, newTool(), crawl(dA, alice), plainPolicy())
	tool = step(t, tool, crawl(dB, bob), plainPolicy())
	tool = step(t, tool, crawl(dA, carol), plainPolicy())
	requireProposers(t, tool, dA, alice, carol)
	for _, actor := range []string{alice, carol} {
		applyOK(t, tool, lc.Reject{Digest: dA, Actor: actor}, plainPolicy())
		applyOK(t, tool, lc.Approve{Digest: dA, Actor: actor}, selfApprovePolicy())
	}
}
