package lifecycle_test

// Disable and Enable tables, derived from the specification:
//
//	Disable{Actor}: allowed from every state except disabled
//	(ErrInvalidTransition); only the state changes.
//
//	Enable{Actor}: only from disabled. With policy.ReEnableRequiresReview the
//	retained approval is retired and the digest in LastSeen, if it is a real
//	digest that was not rejected, becomes the proposal again without gaining a
//	proposer (D4: Enable adds nobody; before D4 the rows below expected the
//	enabler to become ProposedBy). Without it the retained approval is restored,
//	except when LastSeen is "" or UnusableDigest: with no live definition to
//	compare, the approval is retired and the tool waits in pending_review.

import (
	"testing"

	lc "github.com/sairam0424/toolwarrant/internal/lifecycle"
)

func TestDisable_FromEveryStateButDisabled(t *testing.T) {
	starts := map[string]lc.Tool{
		"discovered": newTool(),
		"pending":    pendingReviewTool(dA, alice),
		"enabled":    enabledTool(dA),
		"changed":    changedTool(dA, dB, bob),
		"deprecated": toolOf(lc.Deprecated, dA, "", 3, ver(dA, lc.VersionApproved, alice, true)),
		"unusable":   toolOf(lc.Enabled, dA, lc.UnusableDigest, 0, ver(dA, lc.VersionApproved, alice, true)),
	}
	for name, start := range starts {
		t.Run(name, func(t *testing.T) {
			res := applyOK(t, start, lc.Disable{Actor: bob}, plainPolicy())
			want := cloneTool(start)
			want.State = lc.Disabled
			if !sameTool(res.Tool, want) {
				t.Errorf("Disable must change only the state\n got: %+v\nwant: %+v", res.Tool, want)
			}
			requireKinds(t, res, lc.EvDisabled)
			if res.Tool.Serves(start.Approved) {
				t.Error("a disabled tool must not be served")
			}
		})
	}
}

func TestDisable_Errors(t *testing.T) {
	disabled := toolOf(lc.Disabled, dA, dA, 0, ver(dA, lc.VersionApproved, alice, true))
	runErrCases(t, []errCase{
		{"already disabled", disabled, lc.Disable{Actor: bob}, plainPolicy(), lc.ErrInvalidTransition},
		{"empty actor", enabledTool(dA), lc.Disable{}, plainPolicy(), lc.ErrNoActor},
		{"empty actor when already disabled", disabled, lc.Disable{}, plainPolicy(), lc.ErrNoActor},
	})
}

func TestEnable_Errors(t *testing.T) {
	starts := map[string]lc.Tool{
		"discovered": newTool(),
		"pending":    pendingReviewTool(dA, alice),
		"enabled":    enabledTool(dA),
		"changed":    changedTool(dA, dB, bob),
		"deprecated": toolOf(lc.Deprecated, dA, "", 3, ver(dA, lc.VersionApproved, alice, true)),
	}
	for name, start := range starts {
		for _, p := range []lc.Policy{plainPolicy(), reviewPolicy()} {
			t.Run(name, func(t *testing.T) {
				mustFail(t, start, lc.Enable{Actor: bob}, p, lc.ErrInvalidTransition)
			})
		}
	}
	disabled := toolOf(lc.Disabled, dA, dA, 0, ver(dA, lc.VersionApproved, alice, true))
	mustFail(t, disabled, lc.Enable{}, plainPolicy(), lc.ErrNoActor)
	mustFail(t, disabled, lc.Enable{}, reviewPolicy(), lc.ErrNoActor)
}

// The three branches of Enable without review, each with a live digest.
func TestEnable_WithoutReview(t *testing.T) {
	p := plainPolicy()
	runApplyCases(t, []applyCase{
		{
			name:  "no approval and a pending proposal: pending_review",
			start: toolOf(lc.Disabled, "", dA, 0, ver(dA, lc.VersionPending, alice, false)),
			cmd:   lc.Enable{Actor: bob},
			pol:   p,
			want:  toolOf(lc.PendingReview, "", dA, 0, ver(dA, lc.VersionPending, alice, false)),
		},
		{
			name:  "no approval and only a rejected digest: pending_review",
			start: toolOf(lc.Disabled, "", dA, 0, ver(dA, lc.VersionRejected, alice, false)),
			cmd:   lc.Enable{Actor: bob},
			pol:   p,
			want:  toolOf(lc.PendingReview, "", dA, 0, ver(dA, lc.VersionRejected, alice, false)),
		},
		{
			name:  "approval retained and nothing pending: enabled",
			start: toolOf(lc.Disabled, dA, dA, 0, ver(dA, lc.VersionApproved, alice, true)),
			cmd:   lc.Enable{Actor: bob},
			pol:   p,
			want:  toolOf(lc.Enabled, dA, dA, 0, ver(dA, lc.VersionApproved, alice, true)),
		},
		{
			name: "approval retained and a pending proposal: changed_pending_reapproval",
			start: toolOf(lc.Disabled, dA, dB, 0,
				ver(dA, lc.VersionApproved, alice, true),
				ver(dB, lc.VersionPending, carol, false)),
			cmd: lc.Enable{Actor: bob},
			pol: p,
			want: toolOf(lc.ChangedPendingReapproval, dA, dB, 0,
				ver(dA, lc.VersionApproved, alice, true),
				ver(dB, lc.VersionPending, carol, false)),
		},
		{
			name: "approval retained and only a rejected newer digest: enabled",
			start: toolOf(lc.Disabled, dA, dB, 0,
				ver(dA, lc.VersionApproved, alice, true),
				ver(dB, lc.VersionRejected, carol, false)),
			cmd: lc.Enable{Actor: bob},
			pol: p,
			want: toolOf(lc.Enabled, dA, dB, 0,
				ver(dA, lc.VersionApproved, alice, true),
				ver(dB, lc.VersionRejected, carol, false)),
		},
	})
	res := applyOK(t, toolOf(lc.Disabled, dA, dA, 0, ver(dA, lc.VersionApproved, alice, true)), lc.Enable{Actor: bob}, p)
	requireKinds(t, res, lc.EvEnabled)
}

// Spec: "except when LastSeen is "" or UnusableDigest: with no live definition
// to compare, the approval is retired and the tool waits in pending_review".
// This closes the reviewer's finding that Disable then Enable (no review)
// brought a deprecated tool straight back to enabled.
func TestEnable_WithoutReviewNeedsALiveDefinition(t *testing.T) {
	p := plainPolicy()
	runApplyCases(t, []applyCase{
		{
			name:  "nothing was ever observed: pending_review",
			start: toolOf(lc.Disabled, "", "", 0),
			cmd:   lc.Enable{Actor: bob},
			pol:   p,
			want:  toolOf(lc.PendingReview, "", "", 0),
		},
		{
			name:  "approval retained but absent at the last crawl: the approval is retired",
			start: toolOf(lc.Disabled, dA, "", 2, ver(dA, lc.VersionApproved, alice, true)),
			cmd:   lc.Enable{Actor: bob},
			pol:   p,
			want:  toolOf(lc.PendingReview, "", "", 2, ver(dA, lc.VersionSuperseded, alice, true)),
		},
		{
			name:  "approval retained but the live definition is unusable: the approval is retired",
			start: toolOf(lc.Disabled, dA, lc.UnusableDigest, 0, ver(dA, lc.VersionApproved, alice, true)),
			cmd:   lc.Enable{Actor: bob},
			pol:   p,
			want:  toolOf(lc.PendingReview, "", lc.UnusableDigest, 0, ver(dA, lc.VersionSuperseded, alice, true)),
		},
		{
			name: "absent with an approval and a pending proposal: the proposal stays, the approval goes",
			start: toolOf(lc.Disabled, dA, "", 1,
				ver(dA, lc.VersionApproved, alice, true),
				ver(dB, lc.VersionPending, carol, false)),
			cmd: lc.Enable{Actor: bob},
			pol: p,
			want: toolOf(lc.PendingReview, "", "", 1,
				ver(dA, lc.VersionSuperseded, alice, true),
				ver(dB, lc.VersionPending, carol, false)),
		},
	})
	res := applyOK(t, toolOf(lc.Disabled, dA, "", 2, ver(dA, lc.VersionApproved, alice, true)), lc.Enable{Actor: bob}, p)
	requireKinds(t, res, lc.EvSuperseded, lc.EvEnabled)
	requireServes(t, res.Tool, dA, false)
}

func TestEnable_WithReview(t *testing.T) {
	p := reviewPolicy()
	runApplyCases(t, []applyCase{
		{
			name:  "approved digest is retired and becomes the proposal again, with its original proposer only",
			start: toolOf(lc.Disabled, dA, dA, 0, ver(dA, lc.VersionApproved, alice, true)),
			cmd:   lc.Enable{Actor: bob},
			pol:   p,
			want:  toolOf(lc.PendingReview, "", dA, 0, ver(dA, lc.VersionPending, alice, true)),
		},
		{
			name: "a different LastSeen digest stays the proposal, unchanged, and the old approval is superseded",
			start: toolOf(lc.Disabled, dA, dB, 0,
				ver(dA, lc.VersionApproved, alice, true),
				ver(dB, lc.VersionPending, carol, false)),
			cmd: lc.Enable{Actor: bob},
			pol: p,
			want: toolOf(lc.PendingReview, "", dB, 0,
				ver(dA, lc.VersionSuperseded, alice, true),
				ver(dB, lc.VersionPending, carol, false)),
		},
		{
			name:  "an absent LastSeen proposes nothing",
			start: toolOf(lc.Disabled, dA, "", 0, ver(dA, lc.VersionApproved, alice, true)),
			cmd:   lc.Enable{Actor: bob},
			pol:   p,
			want:  toolOf(lc.PendingReview, "", "", 0, ver(dA, lc.VersionSuperseded, alice, true)),
		},
		{
			name:  "an unusable LastSeen proposes nothing",
			start: toolOf(lc.Disabled, dA, lc.UnusableDigest, 0, ver(dA, lc.VersionApproved, alice, true)),
			cmd:   lc.Enable{Actor: bob},
			pol:   p,
			want:  toolOf(lc.PendingReview, "", lc.UnusableDigest, 0, ver(dA, lc.VersionSuperseded, alice, true)),
		},
		{
			name: "a rejected LastSeen digest is not proposed",
			start: toolOf(lc.Disabled, dA, dB, 0,
				ver(dA, lc.VersionApproved, alice, true),
				ver(dB, lc.VersionRejected, carol, false)),
			cmd: lc.Enable{Actor: bob},
			pol: p,
			want: toolOf(lc.PendingReview, "", dB, 0,
				ver(dA, lc.VersionSuperseded, alice, true),
				ver(dB, lc.VersionRejected, carol, false)),
		},
		{
			name: "a superseded LastSeen digest is reused as the proposal with its history intact",
			start: toolOf(lc.Disabled, dB, dA, 0,
				verP(dA, lc.VersionSuperseded, alice, true, alice, carol),
				ver(dB, lc.VersionApproved, bob, true)),
			cmd: lc.Enable{Actor: carol},
			pol: p,
			want: toolOf(lc.PendingReview, "", dA, 0,
				verP(dA, lc.VersionPending, alice, true, alice, carol),
				ver(dB, lc.VersionSuperseded, bob, true)),
		},
		{
			name:  "no approval to retire: the LastSeen pending digest stays as it is",
			start: toolOf(lc.Disabled, "", dA, 0, ver(dA, lc.VersionPending, alice, false)),
			cmd:   lc.Enable{Actor: bob},
			pol:   p,
			want:  toolOf(lc.PendingReview, "", dA, 0, ver(dA, lc.VersionPending, alice, false)),
		},
		{
			name:  "nothing ever observed: pending_review with no versions",
			start: toolOf(lc.Disabled, "", "", 0),
			cmd:   lc.Enable{Actor: bob},
			pol:   p,
			want:  toolOf(lc.PendingReview, "", "", 0),
		},
	})
}

// Spec: a digest that is already pending "stays as it is and no event is
// emitted for it"; a retired approval that becomes the proposal again is
// announced once.
func TestEnable_WithReviewEvents(t *testing.T) {
	p := reviewPolicy()
	res := applyOK(t, toolOf(lc.Disabled, "", dA, 0, ver(dA, lc.VersionPending, alice, false)), lc.Enable{Actor: bob}, p)
	requireKinds(t, res, lc.EvEnabled)
	res = applyOK(t, toolOf(lc.Disabled, dA, dA, 0, ver(dA, lc.VersionApproved, alice, true)), lc.Enable{Actor: bob}, p)
	requireKinds(t, res, lc.EvSuperseded, lc.EvProposed, lc.EvEnabled)
	res = applyOK(t, toolOf(lc.Disabled, dA, "", 1, ver(dA, lc.VersionApproved, alice, true)), lc.Enable{Actor: bob}, p)
	requireKinds(t, res, lc.EvSuperseded, lc.EvEnabled)
}

// D4: "Enable adds none." The person who runs Enable introduced no
// definition, so the two-person rule does not bind them; it still binds the
// original proposer. Before D4 this test expected the opposite (the enabler
// refused, anyone else allowed).
func TestEnable_ReReviewKeepsTheOriginalProposer(t *testing.T) {
	disabled := toolOf(lc.Disabled, dA, dA, 0, ver(dA, lc.VersionApproved, alice, true))
	enabled := applyOK(t, disabled, lc.Enable{Actor: bob}, lc.DefaultPolicy()).Tool
	requireState(t, enabled, lc.PendingReview)
	requireProposers(t, enabled, dA, alice)
	mustFail(t, enabled, lc.Approve{Digest: dA, Actor: alice}, lc.DefaultPolicy(), lc.ErrSelfApproval)
	approved := applyOK(t, enabled, lc.Approve{Digest: dA, Actor: bob}, lc.DefaultPolicy()).Tool
	requireState(t, approved, lc.Enabled)
	requireServes(t, approved, dA, true)
}

// Spec: "Disabled: an operator switched the tool off. Never served." and
// Enable without review restores the retained approval.
func TestEnable_DisabledToolIsNotServedAndRestoredApprovalServes(t *testing.T) {
	tool := enabledTool(dA)
	requireServes(t, tool, dA, true)
	tool = step(t, tool, lc.Disable{Actor: bob}, plainPolicy())
	requireServes(t, tool, dA, false)
	tool = step(t, tool, lc.Enable{Actor: bob}, plainPolicy())
	requireServes(t, tool, dA, true)
}
