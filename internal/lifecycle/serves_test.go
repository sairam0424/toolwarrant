package lifecycle_test

// Serves, Tool.Serves, Tool.Drifted, Tool.Pending and DefaultPolicy.
//
// Spec: "Serves(state, approved, live): true exactly when approved != \"\" and
// live == approved and the state is enabled or changed_pending_reapproval.
// Tool.Serves(live) and Tool.Drifted() (Approved and LastSeen both non-empty
// and different) and Tool.Pending() (digest of the pending version or \"\")
// follow from the fields."

import (
	"testing"

	lc "github.com/sairam0424/toolwarrant/internal/lifecycle"
)

func wantServes(state lc.State, approved, live string) bool {
	servable := state == lc.Enabled || state == lc.ChangedPendingReapproval
	return approved != "" && live == approved && servable
}

func TestServes_ExhaustiveTruthTable(t *testing.T) {
	states := append(allStates(), lc.State("bogus"), lc.State(""))
	for _, state := range states {
		for _, approved := range []string{"", dA, dB} {
			for _, live := range []string{"", dA, dB, dC} {
				got := lc.Serves(state, approved, live)
				if want := wantServes(state, approved, live); got != want {
					t.Errorf("Serves(%q, %q, %q) = %v, want %v", state, approved, live, got, want)
				}
			}
		}
	}
}

func TestServes_NothingIsServedWithoutAnApproval(t *testing.T) {
	// The dangerous corner: both the approved and the live digest are empty.
	for _, state := range allStates() {
		if lc.Serves(state, "", "") {
			t.Errorf("Serves(%s, \"\", \"\") = true: empty must never match empty", state)
		}
	}
}

func TestToolServes_MatchesTheFunctionForEveryStateAndFieldCombination(t *testing.T) {
	for _, state := range allStates() {
		for _, approved := range []string{"", dA} {
			for _, live := range []string{"", dA, dB} {
				tool := lc.Tool{State: state, Approved: approved, LastSeen: dB}
				if got, want := tool.Serves(live), lc.Serves(state, approved, live); got != want {
					t.Errorf("Tool{%s,%q}.Serves(%q) = %v, Serves() = %v", state, approved, live, got, want)
				}
			}
		}
	}
}

func TestToolDrifted(t *testing.T) {
	tests := []struct {
		name               string
		approved, lastSeen string
		want               bool
	}{
		{"same digest", dA, dA, false},
		{"different digests", dA, dB, true},
		{"nothing approved", "", dA, false},
		{"not seen", dA, "", false},
		{"nothing approved and not seen", "", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tool := lc.Tool{State: lc.Enabled, Approved: tc.approved, LastSeen: tc.lastSeen}
			if got := tool.Drifted(); got != tc.want {
				t.Errorf("Drifted() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestToolPending(t *testing.T) {
	tests := []struct {
		name string
		tool lc.Tool
		want string
	}{
		{"no versions", newTool(), ""},
		{"only approved", enabledTool(dA), ""},
		{"pending among others", toolOf(lc.ChangedPendingReapproval, dA, dC, 0,
			ver(dA, lc.VersionApproved, alice, true),
			ver(dB, lc.VersionRejected, alice, false),
			ver(dC, lc.VersionPending, bob, false)), dC},
		{"only rejected and superseded", toolOf(lc.PendingReview, "", "", 0,
			ver(dA, lc.VersionRejected, alice, false),
			ver(dB, lc.VersionSuperseded, alice, false)), ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.tool.Pending(); got != tc.want {
				t.Errorf("Pending() = %q, want %q", got, tc.want)
			}
		})
	}
}

// Spec (doc): "safe default: no self-approval, re-review after a disable,
// deprecate after three missed crawls."
func TestDefaultPolicy(t *testing.T) {
	p := lc.DefaultPolicy()
	if p.AllowSelfApproval {
		t.Error("DefaultPolicy must not allow self-approval")
	}
	if !p.ReEnableRequiresReview {
		t.Error("DefaultPolicy must require re-review after a disable")
	}
	if p.DeprecateAfter != deprecateAfterThree {
		t.Errorf("DefaultPolicy.DeprecateAfter = %d, want %d", p.DeprecateAfter, deprecateAfterThree)
	}
}
