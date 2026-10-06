package lifecycle_test

// Tests of the tests: each planted violation must be caught by the invariant
// checker or the oracle, otherwise a green property run proves nothing.

import (
	"errors"
	"testing"

	lc "github.com/sairam0424/toolwarrant/internal/lifecycle"
)

func plantedRecord(before lc.Tool, cmd lc.Command, pol lc.Policy, after lc.Tool) stepRecord {
	return stepRecord{before: before, cmd: cmd, pol: pol, res: lc.Result{Tool: after}}
}

func TestMeta_InvariantCheckerAcceptsACorrectStep(t *testing.T) {
	good := plantedRecord(enabledTool(dA), crawl(dA, bob), plainPolicy(), enabledTool(dA))
	if v := stepViolations(good); len(v) != 0 {
		t.Errorf("a correct step was flagged: %v", v)
	}
	if m := oracleMismatches(good); len(m) != 0 {
		t.Errorf("a correct step disagrees with the oracle: %v", m)
	}
}

func TestMeta_InvariantCheckerCatchesPlantedViolations(t *testing.T) {
	plain := plainPolicy()
	cases := []struct {
		name string
		rec  stepRecord
	}{
		{"self approval (invariant 8)", plantedRecord(
			pendingReviewTool(dA, alice), lc.Approve{Digest: dA, Actor: alice}, plain, enabledTool(dA))},
		{"crawl approves a new digest (invariant 5)", plantedRecord(
			enabledTool(dA), crawl(dB, bob), plain,
			toolOf(lc.Enabled, dB, dB, 0, ver(dA, lc.VersionSuperseded, alice, true), ver(dB, lc.VersionApproved, bob, true)))},
		{"enabled with a pending version (invariant 3)", plantedRecord(
			enabledTool(dA), crawl(dB, bob), plain,
			toolOf(lc.Enabled, dA, dB, 0, ver(dA, lc.VersionApproved, alice, true), ver(dB, lc.VersionPending, bob, false)))},
		{"pending_review with an approval (invariant 3)", plantedRecord(
			pendingReviewTool(dA, alice), crawl(dA, bob), plain,
			toolOf(lc.PendingReview, dA, dA, 0, ver(dA, lc.VersionApproved, alice, true)))},
		{"rejected becomes pending (invariant 4)", plantedRecord(
			toolOf(lc.PendingReview, "", dA, 0, ver(dA, lc.VersionRejected, alice, false)),
			crawl(dB, bob), plain,
			toolOf(lc.PendingReview, "", dB, 0, ver(dA, lc.VersionPending, alice, false), ver(dB, lc.VersionPending, bob, false)))},
		{"duplicate digests (invariant 1)", plantedRecord(
			newTool(), crawl(dA, alice), plain,
			toolOf(lc.PendingReview, "", dA, 0, ver(dA, lc.VersionPending, alice, false), ver(dA, lc.VersionSuperseded, alice, false)))},
		{"two approved versions (invariant 2)", plantedRecord(
			enabledTool(dA), crawl(dA, bob), plain,
			toolOf(lc.Enabled, dA, dA, 0, ver(dA, lc.VersionApproved, alice, true), ver(dB, lc.VersionApproved, alice, true)))},
		{"Approved names a non-approved version (invariant 2)", plantedRecord(
			enabledTool(dA), crawl(dA, bob), plain,
			toolOf(lc.Enabled, dB, dA, 0, ver(dA, lc.VersionApproved, alice, true)))},
		{"EverApproved cleared (invariant 4)", plantedRecord(
			enabledTool(dA), crawl(dA, bob), plain,
			toolOf(lc.Enabled, dA, dA, 0, ver(dA, lc.VersionApproved, alice, false)))},
		{"version removed", plantedRecord(
			enabledTool(dA), crawl(dA, bob), plain, toolOf(lc.Enabled, "", dA, 0))},
		{"a miss leaves LastSeen set", plantedRecord(
			enabledTool(dA), miss(), plain, toolOf(lc.Enabled, dA, dA, 1, ver(dA, lc.VersionApproved, alice, true)))},
		{"deprecated below the threshold", plantedRecord(
			enabledTool(dA), miss(), plain, toolOf(lc.Deprecated, dA, "", 1, ver(dA, lc.VersionApproved, alice, true)))},
		{"disabled tool deprecated", plantedRecord(
			toolOf(lc.Disabled, dA, "", 2, ver(dA, lc.VersionApproved, alice, true)), miss(), plain,
			toolOf(lc.Deprecated, dA, "", 3, ver(dA, lc.VersionApproved, alice, true)))},
		{"disable touches more than the state", plantedRecord(
			enabledTool(dA), lc.Disable{Actor: bob}, plain,
			toolOf(lc.Disabled, "", dA, 0, ver(dA, lc.VersionSuperseded, alice, true)))},
		{"Disable deprecates", plantedRecord(
			enabledTool(dA), lc.Disable{Actor: bob}, plain,
			toolOf(lc.Deprecated, dA, dA, 0, ver(dA, lc.VersionApproved, alice, true)))},
		{"success with an empty actor", plantedRecord(
			enabledTool(dA), lc.Disable{}, plain, toolOf(lc.Disabled, dA, dA, 0, ver(dA, lc.VersionApproved, alice, true)))},
		{"enable with review keeps the approval", plantedRecord(
			toolOf(lc.Disabled, dA, dA, 0, ver(dA, lc.VersionApproved, alice, true)), lc.Enable{Actor: bob}, reviewPolicy(),
			enabledTool(dA))},
		{"rollback without superseding", plantedRecord(
			toolOf(lc.Enabled, dB, dB, 0, ver(dA, lc.VersionSuperseded, alice, true), ver(dB, lc.VersionApproved, bob, true)),
			lc.Rollback{To: dA, Actor: carol}, plain,
			toolOf(lc.Enabled, dA, dB, 0, ver(dA, lc.VersionApproved, alice, true), ver(dB, lc.VersionApproved, bob, true)))},
		{"error is not a documented sentinel", stepRecord{
			before: enabledTool(dA), cmd: crawl(dA, bob), pol: plain, err: errors.New("boom")}},
		{"empty actor reported as another error", stepRecord{
			before: enabledTool(dA), cmd: lc.Disable{}, pol: plain, err: lc.ErrInvalidTransition}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if len(stepViolations(tc.rec)) == 0 {
				t.Errorf("planted violation was not caught: %+v", tc.rec.res.Tool)
			}
		})
	}
}

func TestMeta_OracleRejectsAWrongResult(t *testing.T) {
	rec := plantedRecord(pendingReviewTool(dA, alice), lc.Approve{Digest: dA, Actor: bob}, plainPolicy(),
		enabledTool(dB)) // wrong digest approved
	if len(oracleMismatches(rec)) == 0 {
		t.Error("the oracle accepted a wrong approval")
	}
	ok := plantedRecord(pendingReviewTool(dA, alice), lc.Approve{Digest: dA, Actor: bob}, plainPolicy(),
		toolOf(lc.Enabled, dA, dA, 0, ver(dA, lc.VersionApproved, alice, true)))
	if m := oracleMismatches(ok); len(m) != 0 {
		t.Errorf("the oracle rejected the right approval: %v", m)
	}
	// An implementation that succeeds where the spec fails must be flagged, and
	// vice versa.
	succeeded := plantedRecord(pendingReviewTool(dA, alice), lc.Approve{Digest: dA, Actor: alice}, plainPolicy(), enabledTool(dA))
	if len(oracleMismatches(succeeded)) == 0 {
		t.Error("the oracle accepted a self-approval")
	}
	failed := stepRecord{before: pendingReviewTool(dA, alice), cmd: lc.Approve{Digest: dA, Actor: bob}, pol: plainPolicy(), err: lc.ErrStaleVersion}
	if len(oracleMismatches(failed)) == 0 {
		t.Error("the oracle accepted a spurious failure")
	}
}
