package lifecycle_test

import (
	"fmt"
	"slices"
	"testing"

	lc "github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// decisionTable is the transition table of the five decisions, as the
// invariants pin it: approve makes a pending or changed tool enabled, reject
// leaves a pending tool pending and returns a changed one to its approval,
// rollback keeps an enabled tool enabled and a changed tool changed, or makes
// it enabled when the target is the pending version itself, disable reaches
// disabled from every other state, and enable leaves disabled for a fresh
// review, the retained approval with a proposal pending, or the retained
// approval alone. It is spelled out here, by hand, so that a widening of the
// exported function fails this test while a narrowing fails the property
// tests, whose steps the state machine made (invariants_test.go,
// decisionViolations).
func decisionTable() map[string]map[lc.State][]lc.State {
	return map[string]map[lc.State][]lc.State{
		"Approve": {
			lc.PendingReview:            {lc.Enabled},
			lc.ChangedPendingReapproval: {lc.Enabled},
		},
		"Reject": {
			lc.PendingReview:            {lc.PendingReview},
			lc.ChangedPendingReapproval: {lc.Enabled},
		},
		"Rollback": {
			lc.Enabled:                  {lc.Enabled},
			lc.ChangedPendingReapproval: {lc.ChangedPendingReapproval, lc.Enabled},
		},
		"Disable": {
			lc.Discovered:               {lc.Disabled},
			lc.PendingReview:            {lc.Disabled},
			lc.Enabled:                  {lc.Disabled},
			lc.ChangedPendingReapproval: {lc.Disabled},
			lc.Deprecated:               {lc.Disabled},
		},
		"Enable": {
			lc.Disabled: {lc.PendingReview, lc.ChangedPendingReapproval, lc.Enabled},
		},
	}
}

// decisionCommands is one zero-valued command per row of the table, so the
// exported function can be asked about each.
func decisionCommands() map[string]lc.Command {
	return map[string]lc.Command{
		"Approve": lc.Approve{}, "Reject": lc.Reject{}, "Rollback": lc.Rollback{}, "Disable": lc.Disable{}, "Enable": lc.Enable{},
	}
}

// decisionStep is one command applied to one fixture under one policy.
type decisionStep struct {
	row  string
	tool lc.Tool
	cmd  lc.Command
	pol  lc.Policy
}

// decisionSteps are the applications that between them realise every pair of
// the table: the approver and the rejecter never proposed the digest they
// decide on, the rollback targets are versions approved before, and the
// enables run under both policies and from every shape of a disabled tool.
func decisionSteps() []decisionStep {
	plain := plainPolicy()
	rolledBack := toolOf(lc.Enabled, dB, dB, 0, ver(dA, lc.VersionSuperseded, alice, true), ver(dB, lc.VersionApproved, alice, true))
	changedWithHistory := toolOf(lc.ChangedPendingReapproval, dB, dC, 0, ver(dA, lc.VersionSuperseded, alice, true), ver(dB, lc.VersionApproved, alice, true), ver(dC, lc.VersionPending, bob, false))
	changedToTarget := toolOf(lc.ChangedPendingReapproval, dA, dB, 0, ver(dA, lc.VersionApproved, alice, true), ver(dB, lc.VersionPending, bob, true))
	disabledApproved := toolOf(lc.Disabled, dA, dA, 0, ver(dA, lc.VersionApproved, alice, true))
	disabledChanged := toolOf(lc.Disabled, dA, dB, 0, ver(dA, lc.VersionApproved, alice, true), ver(dB, lc.VersionPending, bob, false))
	steps := []decisionStep{
		{"Approve", pendingReviewTool(dA, alice), lc.Approve{Digest: dA, Actor: bob}, plain},
		{"Approve", changedTool(dA, dB, bob), lc.Approve{Digest: dB, Actor: carol}, plain},
		{"Reject", pendingReviewTool(dA, alice), lc.Reject{Digest: dA, Actor: bob}, plain},
		{"Reject", changedTool(dA, dB, bob), lc.Reject{Digest: dB, Actor: alice}, plain},
		{"Rollback", rolledBack, lc.Rollback{To: dA, Actor: bob}, plain},
		{"Rollback", changedWithHistory, lc.Rollback{To: dA, Actor: bob}, plain},
		{"Rollback", changedToTarget, lc.Rollback{To: dB, Actor: bob}, plain},
		{"Enable", disabledApproved, lc.Enable{Actor: bob}, plain},
		{"Enable", disabledApproved, lc.Enable{Actor: bob}, reviewPolicy()},
		{"Enable", disabledChanged, lc.Enable{Actor: bob}, plain},
	}
	for state, tool := range crawlFixtures() {
		if state != lc.Disabled {
			steps = append(steps, decisionStep{"Disable", tool, lc.Disable{Actor: bob}, plain})
		}
	}
	return steps
}

// DecisionMayMove equals the table the invariants pin, pair for pair and row
// for row, and every pair it admits is reached by some command on some
// fixture, so the exported table is neither wider nor narrower than the state
// machine. The sentences the catalog's walk relies on are pinned by name:
// nothing but Enable leaves disabled, Disable reaches disabled only, Approve
// and Rollback are the only decisions that make a tool enabled from another
// state, a crawl and an unknown command move nothing, and so does a state
// this package does not define.
func TestDecisionMayMove_EqualsTheInvariantsTable(t *testing.T) {
	table := decisionTable()
	for row, cmd := range decisionCommands() {
		for _, from := range allStates() {
			for _, to := range allStates() {
				if got, want := lc.DecisionMayMove(cmd, from, to), slices.Contains(table[row][from], to); got != want {
					t.Errorf("DecisionMayMove(%s, %s, %s) = %v, the invariants table says %v", row, from, to, got, want)
				}
			}
		}
	}
	reached := map[string]bool{}
	for _, st := range decisionSteps() {
		res, err := lc.Apply(st.tool, st.cmd, st.pol)
		if err != nil {
			t.Fatalf("%s on a %s tool: %v; every step of the table must apply", st.row, st.tool.State, err)
		}
		if !lc.DecisionMayMove(st.cmd, st.tool.State, res.Tool.State) {
			t.Errorf("%s moved %s -> %s, which DecisionMayMove forbids", st.row, st.tool.State, res.Tool.State)
		}
		reached[fmt.Sprintf("%s %s->%s", st.row, st.tool.State, res.Tool.State)] = true
	}
	for row, tos := range table {
		for from, states := range tos {
			for _, to := range states {
				if !reached[fmt.Sprintf("%s %s->%s", row, from, to)] {
					t.Errorf("DecisionMayMove admits %s %s -> %s but no step of the fixtures reaches it; the table is wider than the machine", row, from, to)
				}
			}
		}
	}
	checkDecisionSentences(t)
}

// checkDecisionSentences pins the rows the catalog's binding relies on.
func checkDecisionSentences(t *testing.T) {
	t.Helper()
	for row, cmd := range decisionCommands() {
		for _, to := range allStates() {
			if row != "Enable" && to != lc.Disabled && lc.DecisionMayMove(cmd, lc.Disabled, to) {
				t.Errorf("%s leaves disabled for %s; only Enable leaves disabled", row, to)
			}
		}
		for _, from := range allStates() {
			if from == lc.Enabled || !lc.DecisionMayMove(cmd, from, lc.Enabled) {
				continue
			}
			switch {
			case row == "Approve", row == "Rollback":
			case row == "Reject" && from == lc.ChangedPendingReapproval:
			case row == "Enable" && from == lc.Disabled:
			default:
				t.Errorf("%s makes a %s tool enabled; only Approve, Rollback, Reject of a changed tool and Enable of a disabled one do", row, from)
			}
		}
	}
	if lc.DecisionMayMove(lc.Disable{}, lc.Enabled, lc.Enabled) || lc.DecisionMayMove(lc.Disable{}, lc.Disabled, lc.Disabled) {
		t.Error("Disable reaches disabled from another state only")
	}
	for _, from := range allStates() {
		for _, to := range allStates() {
			if lc.DecisionMayMove(lc.ObserveCrawl{}, from, to) || lc.DecisionMayMove(nil, from, to) {
				t.Errorf("a crawl or an unknown command moves %s -> %s", from, to)
			}
		}
		if lc.DecisionMayMove(lc.Disable{}, from, lc.State("bogus")) || lc.DecisionMayMove(lc.Enable{}, lc.State("bogus"), from) {
			t.Errorf("an unknown state is reachable from or reaches %s", from)
		}
	}
}
