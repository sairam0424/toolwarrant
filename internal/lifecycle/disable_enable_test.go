package lifecycle_test

// Disable and Enable tables, derived from the specification:
//
//	Disable{Actor}: allowed from every state except disabled
//	(ErrInvalidTransition); only the state changes.
//
//	Enable{Actor}: only from disabled. With policy.ReEnableRequiresReview: the
//	approved version (if any) becomes superseded and Approved becomes "", the
//	state becomes pending_review, and the digest in LastSeen (if non-empty and
//	not a rejected version) is proposed with ProposedBy equal to the Enable
//	actor. Without it: Approved=="" gives pending_review, otherwise a pending
//	version gives changed_pending_reapproval, otherwise enabled.

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
	}
	for name, start := range starts {
		t.Run(name, func(t *testing.T) {
			got := applyOK(t, start, lc.Disable{Actor: bob}, plainPolicy()).Tool
			want := cloneTool(start)
			want.State = lc.Disabled
			if !sameTool(got, want) {
				t.Errorf("Disable must change only the state\n got: %+v\nwant: %+v", got, want)
			}
			if got.Serves(start.Approved) {
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

func TestEnable_WithoutReview(t *testing.T) {
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
			name:  "no approval and a pending proposal: pending_review",
			start: toolOf(lc.Disabled, "", dA, 0, ver(dA, lc.VersionPending, alice, false)),
			cmd:   lc.Enable{Actor: bob},
			pol:   p,
			want:  toolOf(lc.PendingReview, "", dA, 0, ver(dA, lc.VersionPending, alice, false)),
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
}

func TestEnable_WithReview(t *testing.T) {
	p := reviewPolicy()
	runApplyCases(t, []applyCase{
		{
			name:  "approved digest is retired and re-proposed by the enabler",
			start: toolOf(lc.Disabled, dA, dA, 0, ver(dA, lc.VersionApproved, alice, true)),
			cmd:   lc.Enable{Actor: bob},
			pol:   p,
			want:  toolOf(lc.PendingReview, "", dA, 0, ver(dA, lc.VersionPending, bob, true)),
		},
		{
			name: "a different LastSeen digest is proposed and the old approval is superseded",
			start: toolOf(lc.Disabled, dA, dB, 0,
				ver(dA, lc.VersionApproved, alice, true),
				ver(dB, lc.VersionPending, carol, false)),
			cmd: lc.Enable{Actor: bob},
			pol: p,
			want: toolOf(lc.PendingReview, "", dB, 0,
				ver(dA, lc.VersionSuperseded, alice, true),
				ver(dB, lc.VersionPending, bob, false)),
		},
		{
			name:  "an unknown LastSeen digest cannot occur, but an absent one proposes nothing",
			start: toolOf(lc.Disabled, dA, "", 0, ver(dA, lc.VersionApproved, alice, true)),
			cmd:   lc.Enable{Actor: bob},
			pol:   p,
			want:  toolOf(lc.PendingReview, "", "", 0, ver(dA, lc.VersionSuperseded, alice, true)),
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
			name: "a superseded LastSeen digest is reused as the proposal",
			start: toolOf(lc.Disabled, dB, dA, 0,
				ver(dA, lc.VersionSuperseded, alice, true),
				ver(dB, lc.VersionApproved, bob, true)),
			cmd: lc.Enable{Actor: carol},
			pol: p,
			want: toolOf(lc.PendingReview, "", dA, 0,
				ver(dA, lc.VersionPending, carol, true),
				ver(dB, lc.VersionSuperseded, bob, true)),
		},
		{
			name:  "no approval to retire: the LastSeen pending digest is proposed by the enabler",
			start: toolOf(lc.Disabled, "", dA, 0, ver(dA, lc.VersionPending, alice, false)),
			cmd:   lc.Enable{Actor: bob},
			pol:   p,
			want:  toolOf(lc.PendingReview, "", dA, 0, ver(dA, lc.VersionPending, bob, false)),
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

// Spec: "ProposedBy equal to the Enable actor": the enabler cannot approve the
// digest they just re-proposed, under the default policy.
func TestEnable_EnablerCannotSelfApproveTheReReview(t *testing.T) {
	disabled := toolOf(lc.Disabled, dA, dA, 0, ver(dA, lc.VersionApproved, alice, true))
	enabled := applyOK(t, disabled, lc.Enable{Actor: bob}, lc.DefaultPolicy()).Tool
	requireState(t, enabled, lc.PendingReview)
	mustFail(t, enabled, lc.Approve{Digest: dA, Actor: bob}, lc.DefaultPolicy(), lc.ErrSelfApproval)
	approved := applyOK(t, enabled, lc.Approve{Digest: dA, Actor: carol}, lc.DefaultPolicy()).Tool
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
