package lifecycle_test

// Walks through the state diagram using only public commands, asserting the
// state, the approved digest and whether each digest would be served after
// every step. These are the user-visible stories of the product: nothing is
// served until approved, drift hides a tool, and only a person's approval of
// one exact digest brings it back.

import (
	"testing"

	lc "github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// approvedAt discovers digest d (proposed by alice) and has bob approve it.
func approvedAt(t *testing.T, d string, p lc.Policy) lc.Tool {
	t.Helper()
	tool := step(t, newTool(), crawl(d, alice), p)
	return step(t, tool, lc.Approve{Digest: d, Actor: bob}, p)
}

func TestPath_DiscoverThenApprove(t *testing.T) {
	p := plainPolicy()
	tool := newTool()
	requireState(t, tool, lc.Discovered)
	requireServes(t, tool, dA, false)

	tool = step(t, tool, crawl(dA, alice), p)
	requireState(t, tool, lc.PendingReview)
	requireServes(t, tool, dA, false) // nothing is served until approved
	if tool.Pending() != dA || tool.Approved != "" {
		t.Fatalf("pending=%q approved=%q", tool.Pending(), tool.Approved)
	}

	tool = step(t, tool, crawl(dA, alice), p) // a second identical crawl changes nothing
	requireState(t, tool, lc.PendingReview)
	requireServes(t, tool, dA, false)

	tool = step(t, tool, lc.Approve{Digest: dA, Actor: bob}, p)
	requireState(t, tool, lc.Enabled)
	requireServes(t, tool, dA, true)
	requireServes(t, tool, dB, false)
	if tool.Drifted() || tool.Pending() != "" {
		t.Errorf("drifted=%v pending=%q", tool.Drifted(), tool.Pending())
	}
}

func TestPath_DriftHidesTheToolAndRevertRestoresIt(t *testing.T) {
	p := plainPolicy()
	tool := approvedAt(t, dA, p)

	tool = step(t, tool, crawl(dB, carol), p) // the upstream changed the definition
	requireState(t, tool, lc.ChangedPendingReapproval)
	if tool.Approved != dA || tool.Pending() != dB || !tool.Drifted() {
		t.Fatalf("approved=%q pending=%q drifted=%v", tool.Approved, tool.Pending(), tool.Drifted())
	}
	requireServes(t, tool, dB, false) // strict mode: the new definition is not served
	// The processor compares the live digest with the approved one; a tool whose
	// upstream serves dB must not be shown, while dA would be, if it came back.
	requireServes(t, tool, dA, true)

	tool = step(t, tool, crawl(dA, carol), p) // the upstream reverted
	requireState(t, tool, lc.Enabled)
	requireServes(t, tool, dA, true)
	if tool.Drifted() || tool.Pending() != "" {
		t.Errorf("after revert: drifted=%v pending=%q", tool.Drifted(), tool.Pending())
	}
	if v, _ := findVersion(tool, dB); v.Status != lc.VersionSuperseded {
		t.Errorf("reverted-away proposal status = %s, want superseded", v.Status)
	}
}

func TestPath_DriftThenReject(t *testing.T) {
	p := plainPolicy()
	tool := approvedAt(t, dA, p)
	tool = step(t, tool, crawl(dB, carol), p)
	tool = step(t, tool, lc.Reject{Digest: dB, Actor: bob}, p)

	requireState(t, tool, lc.Enabled)
	if tool.Approved != dA {
		t.Errorf("the old approval must stay after a rejection, got %q", tool.Approved)
	}
	requireServes(t, tool, dB, false)
	if !tool.Drifted() {
		t.Error("the upstream still serves the rejected digest, so the tool is still drifted")
	}

	// The upstream keeps serving the rejected digest: no new proposal appears.
	tool = step(t, tool, crawl(dB, carol), p)
	requireState(t, tool, lc.Enabled)
	if tool.Pending() != "" {
		t.Errorf("rejected digest re-proposed: %q", tool.Pending())
	}

	// A third definition is a fresh proposal.
	tool = step(t, tool, crawl(dC, carol), p)
	requireState(t, tool, lc.ChangedPendingReapproval)
	if tool.Pending() != dC {
		t.Errorf("pending = %q, want %q", tool.Pending(), dC)
	}
}

func TestPath_DriftThenApprove(t *testing.T) {
	p := plainPolicy()
	tool := approvedAt(t, dA, p)
	tool = step(t, tool, crawl(dB, carol), p)
	tool = step(t, tool, lc.Approve{Digest: dB, Actor: bob}, p)

	requireState(t, tool, lc.Enabled)
	if tool.Approved != dB || tool.Drifted() {
		t.Fatalf("approved=%q drifted=%v", tool.Approved, tool.Drifted())
	}
	requireServes(t, tool, dB, true)
	requireServes(t, tool, dA, false)
	old, _ := findVersion(tool, dA)
	if old.Status != lc.VersionSuperseded || !old.EverApproved {
		t.Errorf("old approval: status=%s everApproved=%v", old.Status, old.EverApproved)
	}
}

func TestPath_Rollback(t *testing.T) {
	p := plainPolicy()
	tool := approvedAt(t, dA, p)
	tool = step(t, tool, crawl(dB, carol), p)
	tool = step(t, tool, lc.Approve{Digest: dB, Actor: bob}, p)

	tool = step(t, tool, lc.Rollback{To: dA, Actor: carol}, p)
	requireState(t, tool, lc.Enabled)
	if tool.Approved != dA {
		t.Fatalf("approved = %q, want %q", tool.Approved, dA)
	}
	// The upstream still serves dB, so the tool reads as drifted and dB is not served.
	if !tool.Drifted() {
		t.Error("after a rollback the upstream still serves dB: want drifted")
	}
	requireServes(t, tool, dB, false)

	// The next crawl sees dB again: it is a known, once-approved, superseded
	// version, so it comes back as a fresh proposal rather than silently served.
	tool = step(t, tool, crawl(dB, carol), p)
	requireState(t, tool, lc.ChangedPendingReapproval)
	if v, _ := findVersion(tool, dB); v.Status != lc.VersionPending || !v.EverApproved {
		t.Errorf("dB after re-proposal: status=%s everApproved=%v", v.Status, v.EverApproved)
	}

	// A person can approve it again (the proposer, carol, cannot).
	mustFail(t, tool, lc.Approve{Digest: dB, Actor: carol}, p, lc.ErrSelfApproval)
	tool = step(t, tool, lc.Approve{Digest: dB, Actor: bob}, p)
	requireServes(t, tool, dB, true)
}

func TestPath_DisableThenEnableWithoutReview(t *testing.T) {
	p := plainPolicy()
	tool := approvedAt(t, dA, p)

	tool = step(t, tool, lc.Disable{Actor: carol}, p)
	requireState(t, tool, lc.Disabled)
	requireServes(t, tool, dA, false)

	tool = step(t, tool, lc.Enable{Actor: carol}, p)
	requireState(t, tool, lc.Enabled)
	requireServes(t, tool, dA, true)
	if tool.Approved != dA {
		t.Errorf("the retained approval must come back, got %q", tool.Approved)
	}
}

func TestPath_DisableCrawlWhileOffThenEnableWithoutReview(t *testing.T) {
	p := plainPolicy()
	tool := approvedAt(t, dA, p)
	tool = step(t, tool, lc.Disable{Actor: carol}, p)
	tool = step(t, tool, crawl(dB, carol), p) // upstream changed while the tool was off
	requireState(t, tool, lc.Disabled)
	requireServes(t, tool, dB, false)

	tool = step(t, tool, lc.Enable{Actor: carol}, p)
	requireState(t, tool, lc.ChangedPendingReapproval)
	requireServes(t, tool, dB, false)
	if tool.Approved != dA || tool.Pending() != dB {
		t.Errorf("approved=%q pending=%q", tool.Approved, tool.Pending())
	}
}

func TestPath_DisableThenEnableWithReview(t *testing.T) {
	p := reviewPolicy()
	tool := approvedAt(t, dA, p)

	tool = step(t, tool, lc.Disable{Actor: carol}, p)
	requireState(t, tool, lc.Disabled)

	tool = step(t, tool, lc.Enable{Actor: carol}, p)
	requireState(t, tool, lc.PendingReview)
	if tool.Approved != "" {
		t.Fatalf("the old approval must be gone, got %q", tool.Approved)
	}
	requireServes(t, tool, dA, false) // nothing is served until a person approves again

	mustFail(t, tool, lc.Approve{Digest: dA, Actor: carol}, p, lc.ErrSelfApproval)
	tool = step(t, tool, lc.Approve{Digest: dA, Actor: bob}, p)
	requireState(t, tool, lc.Enabled)
	requireServes(t, tool, dA, true)
}

func TestPath_DeprecateThenReappear(t *testing.T) {
	p := plainPolicy()
	tool := approvedAt(t, dA, p)

	for i := 0; i < deprecateAfterThree; i++ {
		requireState(t, tool, lc.Enabled)
		tool = step(t, tool, miss(), p)
	}
	requireState(t, tool, lc.Deprecated)
	requireServes(t, tool, dA, false)
	tool = step(t, tool, miss(), p) // further misses change nothing
	requireState(t, tool, lc.Deprecated)

	tool = step(t, tool, crawl(dA, carol), p)
	requireState(t, tool, lc.PendingReview)
	if tool.Approved != "" || tool.Pending() != dA {
		t.Fatalf("approved=%q pending=%q", tool.Approved, tool.Pending())
	}
	requireServes(t, tool, dA, false) // the old approval is not revived
	mustFail(t, tool, lc.Approve{Digest: dA, Actor: carol}, p, lc.ErrSelfApproval)
	tool = step(t, tool, lc.Approve{Digest: dA, Actor: bob}, p)
	requireState(t, tool, lc.Enabled)
	requireServes(t, tool, dA, true)
}

func TestPath_RejectInPendingReviewThenNewDefinition(t *testing.T) {
	p := plainPolicy()
	tool := step(t, newTool(), crawl(dA, alice), p)
	tool = step(t, tool, lc.Reject{Digest: dA, Actor: bob}, p)
	requireState(t, tool, lc.PendingReview)
	if tool.Approved != "" || tool.Pending() != "" {
		t.Fatalf("approved=%q pending=%q", tool.Approved, tool.Pending())
	}

	tool = step(t, tool, crawl(dA, alice), p) // still the rejected digest
	if tool.Pending() != "" {
		t.Errorf("rejected digest re-proposed: %q", tool.Pending())
	}
	tool = step(t, tool, crawl(dB, alice), p)
	if tool.Pending() != dB {
		t.Errorf("pending = %q, want %q", tool.Pending(), dB)
	}
	mustFail(t, tool, lc.Approve{Digest: dA, Actor: bob}, p, lc.ErrStaleVersion)
	tool = step(t, tool, lc.Approve{Digest: dB, Actor: bob}, p)
	requireServes(t, tool, dB, true)
}

func TestPath_ApprovalNamesTheExactDigestLookedAt(t *testing.T) {
	p := plainPolicy()
	tool := step(t, newTool(), crawl(dA, alice), p)
	tool = step(t, tool, crawl(dB, alice), p) // the proposal moved while the approver was reading dA
	mustFail(t, tool, lc.Approve{Digest: dA, Actor: bob}, p, lc.ErrStaleVersion)
	requireState(t, tool, lc.PendingReview)
	requireServes(t, tool, dA, false)
}

func TestPath_SelfApprovalPolicyLetsTheProposerApprove(t *testing.T) {
	p := selfApprovePolicy()
	tool := step(t, newTool(), crawl(dA, alice), p)
	tool = step(t, tool, lc.Approve{Digest: dA, Actor: alice}, p)
	requireState(t, tool, lc.Enabled)
	requireServes(t, tool, dA, true)
}

func TestPath_CrawlsAloneNeverServeAnything(t *testing.T) {
	p := plainPolicy()
	tool := newTool()
	for i, d := range []string{dA, dB, dA, dC, dC, dB, dD, dA} {
		tool = step(t, tool, crawl(d, carol), p)
		if tool.Approved != "" {
			t.Fatalf("crawl %d approved %q", i, tool.Approved)
		}
		for _, live := range []string{dA, dB, dC, dD, ""} {
			requireServes(t, tool, live, false)
		}
	}
}

func TestPath_LongLifeKeepsExactlyOneApproval(t *testing.T) {
	p := reviewPolicy()
	tool := approvedAt(t, dA, p)
	seq := []lc.Command{
		crawl(dB, carol), lc.Approve{Digest: dB, Actor: bob},
		crawl(dC, carol), lc.Reject{Digest: dC, Actor: bob},
		lc.Rollback{To: dA, Actor: bob},
		lc.Disable{Actor: bob}, lc.Enable{Actor: bob},
		crawl(dA, carol), lc.Approve{Digest: dA, Actor: alice},
		miss(), miss(), miss(),
		crawl(dA, carol), lc.Approve{Digest: dA, Actor: bob},
	}
	for i, cmd := range seq {
		tool = step(t, tool, cmd, p)
		approved := 0
		for _, v := range tool.Versions {
			if v.Status == lc.VersionApproved {
				approved++
			}
		}
		if approved > 1 {
			t.Fatalf("step %d (%T): %d approved versions in %+v", i, cmd, approved, tool)
		}
	}
	requireState(t, tool, lc.Enabled)
	requireServes(t, tool, dA, true)
}
