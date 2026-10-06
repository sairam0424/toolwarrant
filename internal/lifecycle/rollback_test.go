package lifecycle_test

// Rollback tables, derived from the specification:
//
//	Rollback{To:d, Actor:a}: only from enabled or changed_pending_reapproval; d
//	must be a known version (ErrUnknownVersion) with EverApproved true whose
//	status is not approved and not rejected (else ErrNotRollbackTarget).
//	Effect: the current approved version becomes superseded, d becomes
//	approved, Approved=d, the state becomes changed_pending_reapproval if a
//	pending version exists else enabled. The self-approval rule does not apply
//	to rollback.

import (
	"testing"

	lc "github.com/sairam0424/toolwarrant/internal/lifecycle"
)

func TestRollback_Success(t *testing.T) {
	p := plainPolicy()
	runApplyCases(t, []applyCase{
		{
			name: "enabled: previous approval returns, current one is superseded",
			start: toolOf(lc.Enabled, dB, dB, 0,
				ver(dA, lc.VersionSuperseded, alice, true),
				ver(dB, lc.VersionApproved, bob, true)),
			cmd: lc.Rollback{To: dA, Actor: carol},
			pol: p,
			want: toolOf(lc.Enabled, dA, dB, 0,
				ver(dA, lc.VersionApproved, alice, true),
				ver(dB, lc.VersionSuperseded, bob, true)),
		},
		{
			name: "changed_pending_reapproval: the pending proposal survives and the state stays changed",
			start: toolOf(lc.ChangedPendingReapproval, dB, dC, 0,
				ver(dA, lc.VersionSuperseded, alice, true),
				ver(dB, lc.VersionApproved, bob, true),
				ver(dC, lc.VersionPending, carol, false)),
			cmd: lc.Rollback{To: dA, Actor: alice},
			pol: p,
			want: toolOf(lc.ChangedPendingReapproval, dA, dC, 0,
				ver(dA, lc.VersionApproved, alice, true),
				ver(dB, lc.VersionSuperseded, bob, true),
				ver(dC, lc.VersionPending, carol, false)),
		},
		{
			name: "rolling back to the pending, once-approved version consumes the proposal",
			start: toolOf(lc.ChangedPendingReapproval, dB, dA, 0,
				ver(dA, lc.VersionPending, carol, true),
				ver(dB, lc.VersionApproved, bob, true)),
			cmd: lc.Rollback{To: dA, Actor: alice},
			pol: p,
			want: toolOf(lc.Enabled, dA, dA, 0,
				ver(dA, lc.VersionApproved, carol, true),
				ver(dB, lc.VersionSuperseded, bob, true)),
		},
		{
			name: "the self-approval rule does not apply: the proposer of the target may roll back to it",
			start: toolOf(lc.Enabled, dB, dB, 0,
				ver(dA, lc.VersionSuperseded, alice, true),
				ver(dB, lc.VersionApproved, bob, true)),
			cmd: lc.Rollback{To: dA, Actor: alice},
			pol: lc.DefaultPolicy(),
			want: toolOf(lc.Enabled, dA, dB, 0,
				ver(dA, lc.VersionApproved, alice, true),
				ver(dB, lc.VersionSuperseded, bob, true)),
		},
		{
			name: "rejected and never-approved versions are left alone",
			start: toolOf(lc.Enabled, dC, dC, 1,
				ver(dA, lc.VersionRejected, alice, false),
				ver(dB, lc.VersionSuperseded, alice, true),
				ver(dC, lc.VersionApproved, bob, true),
				ver(dD, lc.VersionSuperseded, alice, false)),
			cmd: lc.Rollback{To: dB, Actor: carol},
			pol: p,
			want: toolOf(lc.Enabled, dB, dC, 1,
				ver(dA, lc.VersionRejected, alice, false),
				ver(dB, lc.VersionApproved, alice, true),
				ver(dC, lc.VersionSuperseded, bob, true),
				ver(dD, lc.VersionSuperseded, alice, false)),
		},
	})
}

func TestRollback_Errors(t *testing.T) {
	p := plainPolicy()
	history := toolOf(lc.Enabled, dB, dB, 0,
		ver(dA, lc.VersionSuperseded, alice, true),
		ver(dB, lc.VersionApproved, bob, true),
		ver(dC, lc.VersionSuperseded, alice, false),
		ver(dD, lc.VersionRejected, alice, true))
	runErrCases(t, []errCase{
		{"invalid from discovered", newTool(), lc.Rollback{To: dA, Actor: bob}, p, lc.ErrInvalidTransition},
		{
			"invalid from pending_review",
			toolOf(lc.PendingReview, "", dB, 0, ver(dA, lc.VersionSuperseded, alice, true), ver(dB, lc.VersionPending, bob, false)),
			lc.Rollback{To: dA, Actor: carol}, p, lc.ErrInvalidTransition,
		},
		{
			"invalid from disabled",
			toolOf(lc.Disabled, dB, dB, 0, ver(dA, lc.VersionSuperseded, alice, true), ver(dB, lc.VersionApproved, bob, true)),
			lc.Rollback{To: dA, Actor: carol}, p, lc.ErrInvalidTransition,
		},
		{
			"invalid from deprecated",
			toolOf(lc.Deprecated, dB, "", 3, ver(dA, lc.VersionSuperseded, alice, true), ver(dB, lc.VersionApproved, bob, true)),
			lc.Rollback{To: dA, Actor: carol}, p, lc.ErrInvalidTransition,
		},
		{"unknown digest", history, lc.Rollback{To: "digest-zzz", Actor: carol}, p, lc.ErrUnknownVersion},
		{"never approved", history, lc.Rollback{To: dC, Actor: carol}, p, lc.ErrNotRollbackTarget},
		{"already approved", history, lc.Rollback{To: dB, Actor: carol}, p, lc.ErrNotRollbackTarget},
		{"rejected even if once approved", history, lc.Rollback{To: dD, Actor: carol}, p, lc.ErrNotRollbackTarget},
		{
			"pending but never approved",
			changedTool(dA, dB, bob),
			lc.Rollback{To: dB, Actor: carol}, p, lc.ErrNotRollbackTarget,
		},
		{"empty actor", history, lc.Rollback{To: dA}, p, lc.ErrNoActor},
		{"empty digest", history, lc.Rollback{Actor: carol}, p, lc.ErrNoDigest},
	})
}
