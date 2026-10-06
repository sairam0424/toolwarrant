package lifecycle_test

// Approve and Reject tables, derived from the specification:
//
//	Approve{Digest:d, Actor:a}: allowed only in pending_review or
//	changed_pending_reapproval (else ErrInvalidTransition); d must name a known
//	version (else ErrUnknownVersion) whose status is pending (else
//	ErrStaleVersion); unless policy.AllowSelfApproval, a must differ from that
//	version's ProposedBy (else ErrSelfApproval). Effect: the previously
//	approved version (if any) becomes superseded, d becomes approved with
//	EverApproved true, Approved=d, state enabled.
//
//	Reject{Digest:d, Actor:a}: same preconditions as Approve but no proposer
//	rule. d becomes rejected; a tool in changed_pending_reapproval becomes
//	enabled (its old approval stays); a tool in pending_review stays in
//	pending_review.

import (
	"testing"

	lc "github.com/sairam0424/toolwarrant/internal/lifecycle"
)

func TestApprove_Success(t *testing.T) {
	p := plainPolicy()
	runApplyCases(t, []applyCase{
		{
			name:  "pending_review first approval",
			start: pendingReviewTool(dA, alice),
			cmd:   lc.Approve{Digest: dA, Actor: bob},
			pol:   p,
			want:  toolOf(lc.Enabled, dA, dA, 0, ver(dA, lc.VersionApproved, alice, true)),
		},
		{
			name:  "changed_pending_reapproval supersedes the old approval",
			start: changedTool(dA, dB, alice),
			cmd:   lc.Approve{Digest: dB, Actor: bob},
			pol:   p,
			want: toolOf(lc.Enabled, dB, dB, 0,
				ver(dA, lc.VersionSuperseded, alice, true),
				ver(dB, lc.VersionApproved, alice, true)),
		},
		{
			name: "pending_review re-approving a reused superseded digest keeps EverApproved",
			start: toolOf(lc.PendingReview, "", dA, 0,
				ver(dA, lc.VersionPending, bob, true)),
			cmd:  lc.Approve{Digest: dA, Actor: carol},
			pol:  p,
			want: toolOf(lc.Enabled, dA, dA, 0, ver(dA, lc.VersionApproved, bob, true)),
		},
		{
			name: "approval leaves unrelated versions alone",
			start: toolOf(lc.PendingReview, "", dC, 0,
				ver(dA, lc.VersionRejected, alice, false),
				ver(dB, lc.VersionSuperseded, alice, true),
				ver(dC, lc.VersionPending, alice, false)),
			cmd: lc.Approve{Digest: dC, Actor: bob},
			pol: p,
			want: toolOf(lc.Enabled, dC, dC, 0,
				ver(dA, lc.VersionRejected, alice, false),
				ver(dB, lc.VersionSuperseded, alice, true),
				ver(dC, lc.VersionApproved, alice, true)),
		},
		{
			name:  "approval does not touch LastSeen or MissingCrawls",
			start: toolOf(lc.PendingReview, "", "", 2, ver(dA, lc.VersionPending, alice, false)),
			cmd:   lc.Approve{Digest: dA, Actor: bob},
			pol:   p,
			want:  toolOf(lc.Enabled, dA, "", 2, ver(dA, lc.VersionApproved, alice, true)),
		},
	})
}

func TestApprove_SelfApprovalPolicy(t *testing.T) {
	start := pendingReviewTool(dA, alice)
	mustFail(t, start, lc.Approve{Digest: dA, Actor: alice}, plainPolicy(), lc.ErrSelfApproval)
	mustFail(t, start, lc.Approve{Digest: dA, Actor: alice}, lc.DefaultPolicy(), lc.ErrSelfApproval)

	got := applyOK(t, start, lc.Approve{Digest: dA, Actor: alice}, selfApprovePolicy()).Tool
	want := toolOf(lc.Enabled, dA, dA, 0, ver(dA, lc.VersionApproved, alice, true))
	if !sameTool(got, want) {
		t.Errorf("self-approval allowed: got %+v, want %+v", got, want)
	}
}

func TestApprove_SelfApprovalChecksTheProposerOfThatVersionOnly(t *testing.T) {
	// bob proposed the pending version; alice proposed the old approved one.
	start := toolOf(lc.ChangedPendingReapproval, dA, dB, 0,
		ver(dA, lc.VersionApproved, alice, true),
		ver(dB, lc.VersionPending, bob, false))
	applyOK(t, start, lc.Approve{Digest: dB, Actor: alice}, plainPolicy())
	mustFail(t, start, lc.Approve{Digest: dB, Actor: bob}, plainPolicy(), lc.ErrSelfApproval)
}

func TestApprove_Errors(t *testing.T) {
	p := plainPolicy()
	pendingWithA := pendingReviewTool(dA, alice)
	runErrCases(t, []errCase{
		{"invalid from discovered", newTool(), lc.Approve{Digest: dA, Actor: bob}, p, lc.ErrInvalidTransition},
		{"invalid from enabled", enabledTool(dA), lc.Approve{Digest: dA, Actor: bob}, p, lc.ErrInvalidTransition},
		{
			"invalid from disabled even with a pending version",
			toolOf(lc.Disabled, "", dA, 0, ver(dA, lc.VersionPending, alice, false)),
			lc.Approve{Digest: dA, Actor: bob}, p, lc.ErrInvalidTransition,
		},
		{
			"invalid from deprecated even with a pending version",
			toolOf(lc.Deprecated, "", "", 3, ver(dA, lc.VersionPending, alice, false)),
			lc.Approve{Digest: dA, Actor: bob}, p, lc.ErrInvalidTransition,
		},
		{"unknown digest", pendingWithA, lc.Approve{Digest: dB, Actor: bob}, p, lc.ErrUnknownVersion},
		{"unknown digest on a tool with no versions", toolOf(lc.PendingReview, "", "", 0), lc.Approve{Digest: dB, Actor: bob}, p, lc.ErrUnknownVersion},
		{
			"rejected version is stale",
			toolOf(lc.PendingReview, "", dA, 0, ver(dA, lc.VersionRejected, alice, false)),
			lc.Approve{Digest: dA, Actor: bob}, p, lc.ErrStaleVersion,
		},
		{
			"superseded version is stale",
			toolOf(lc.PendingReview, "", dB, 0,
				ver(dA, lc.VersionSuperseded, alice, false), ver(dB, lc.VersionPending, alice, false)),
			lc.Approve{Digest: dA, Actor: bob}, p, lc.ErrStaleVersion,
		},
		{
			"already approved version is stale",
			changedTool(dA, dB, alice),
			lc.Approve{Digest: dA, Actor: bob}, p, lc.ErrStaleVersion,
		},
		{"self approval", pendingWithA, lc.Approve{Digest: dA, Actor: alice}, p, lc.ErrSelfApproval},
		{"empty actor", pendingWithA, lc.Approve{Digest: dA}, p, lc.ErrNoActor},
		{"empty digest", pendingWithA, lc.Approve{Actor: bob}, p, lc.ErrNoDigest},
		{"empty actor on an invalid state", enabledTool(dA), lc.Approve{Digest: dA}, p, lc.ErrNoActor},
	})
}

// Spec: "Approval names the exact digest the approver looked at and fails if
// the pending proposal has since changed."
func TestApprove_FailsWhenTheProposalMovedOn(t *testing.T) {
	tool := step(t, newTool(), crawl(dA, alice), plainPolicy())
	tool = step(t, tool, crawl(dB, alice), plainPolicy()) // the proposal changed under the approver
	mustFail(t, tool, lc.Approve{Digest: dA, Actor: bob}, plainPolicy(), lc.ErrStaleVersion)
	applyOK(t, tool, lc.Approve{Digest: dB, Actor: bob}, plainPolicy())
}

func TestReject_Success(t *testing.T) {
	p := plainPolicy()
	runApplyCases(t, []applyCase{
		{
			name:  "pending_review stays pending_review and nothing is approved",
			start: pendingReviewTool(dA, alice),
			cmd:   lc.Reject{Digest: dA, Actor: bob},
			pol:   p,
			want:  toolOf(lc.PendingReview, "", dA, 0, ver(dA, lc.VersionRejected, alice, false)),
		},
		{
			name:  "the proposer may reject their own proposal",
			start: pendingReviewTool(dA, alice),
			cmd:   lc.Reject{Digest: dA, Actor: alice},
			pol:   p,
			want:  toolOf(lc.PendingReview, "", dA, 0, ver(dA, lc.VersionRejected, alice, false)),
		},
		{
			name:  "changed_pending_reapproval returns to enabled and keeps the approval",
			start: changedTool(dA, dB, bob),
			cmd:   lc.Reject{Digest: dB, Actor: carol},
			pol:   p,
			want: toolOf(lc.Enabled, dA, dB, 0,
				ver(dA, lc.VersionApproved, alice, true),
				ver(dB, lc.VersionRejected, bob, false)),
		},
		{
			name: "rejecting a re-proposed, once-approved version keeps EverApproved",
			start: toolOf(lc.ChangedPendingReapproval, dB, dA, 0,
				ver(dA, lc.VersionPending, carol, true),
				ver(dB, lc.VersionApproved, bob, true)),
			cmd: lc.Reject{Digest: dA, Actor: alice},
			pol: p,
			want: toolOf(lc.Enabled, dB, dA, 0,
				ver(dA, lc.VersionRejected, carol, true),
				ver(dB, lc.VersionApproved, bob, true)),
		},
		{
			name:  "rejection is allowed under a self-approval policy too",
			start: pendingReviewTool(dA, alice),
			cmd:   lc.Reject{Digest: dA, Actor: bob},
			pol:   selfApprovePolicy(),
			want:  toolOf(lc.PendingReview, "", dA, 0, ver(dA, lc.VersionRejected, alice, false)),
		},
	})
}

func TestReject_Errors(t *testing.T) {
	p := plainPolicy()
	pendingWithA := pendingReviewTool(dA, alice)
	runErrCases(t, []errCase{
		{"invalid from discovered", newTool(), lc.Reject{Digest: dA, Actor: bob}, p, lc.ErrInvalidTransition},
		{"invalid from enabled", enabledTool(dA), lc.Reject{Digest: dA, Actor: bob}, p, lc.ErrInvalidTransition},
		{
			"invalid from disabled",
			toolOf(lc.Disabled, "", dA, 0, ver(dA, lc.VersionPending, alice, false)),
			lc.Reject{Digest: dA, Actor: bob}, p, lc.ErrInvalidTransition,
		},
		{
			"invalid from deprecated",
			toolOf(lc.Deprecated, "", "", 3, ver(dA, lc.VersionPending, alice, false)),
			lc.Reject{Digest: dA, Actor: bob}, p, lc.ErrInvalidTransition,
		},
		{"unknown digest", pendingWithA, lc.Reject{Digest: dB, Actor: bob}, p, lc.ErrUnknownVersion},
		{
			"already rejected is stale",
			toolOf(lc.PendingReview, "", dA, 0, ver(dA, lc.VersionRejected, alice, false)),
			lc.Reject{Digest: dA, Actor: bob}, p, lc.ErrStaleVersion,
		},
		{
			"approved version cannot be rejected",
			changedTool(dA, dB, bob),
			lc.Reject{Digest: dA, Actor: carol}, p, lc.ErrStaleVersion,
		},
		{
			"superseded version is stale",
			toolOf(lc.PendingReview, "", dB, 0,
				ver(dA, lc.VersionSuperseded, alice, false), ver(dB, lc.VersionPending, alice, false)),
			lc.Reject{Digest: dA, Actor: bob}, p, lc.ErrStaleVersion,
		},
		{"empty actor", pendingWithA, lc.Reject{Digest: dA}, p, lc.ErrNoActor},
		{"empty digest", pendingWithA, lc.Reject{Actor: bob}, p, lc.ErrNoDigest},
	})
}

// A rejected digest that the upstream keeps serving must not come back as a
// proposal, and must never be served.
func TestReject_RejectedDigestStaysOutUntilTheUpstreamChanges(t *testing.T) {
	p := plainPolicy()
	tool := step(t, enabledTool(dA), crawl(dB, alice), p)
	tool = step(t, tool, lc.Reject{Digest: dB, Actor: bob}, p)
	requireState(t, tool, lc.Enabled)
	tool = step(t, tool, crawl(dB, alice), p)
	requireState(t, tool, lc.Enabled)
	if tool.Pending() != "" {
		t.Errorf("rejected digest came back as pending: %q", tool.Pending())
	}
	requireServes(t, tool, dB, false)
	if !tool.Drifted() {
		t.Error("upstream still serves the rejected digest, Drifted() must be true")
	}
	tool = step(t, tool, crawl(dA, alice), p)
	requireServes(t, tool, dA, true)
	if tool.Drifted() {
		t.Error("upstream is back on the approved digest, Drifted() must be false")
	}
}
