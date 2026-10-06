package lifecycle_test

// Property tests over random command sequences (pgregory.net/rapid).
//
// Invariants 1-9 live in invariants_test.go and effects_test.go; invariant 10
// (replay determinism) and the differential comparison with the specification
// oracle are here.

import (
	"errors"
	"strings"
	"testing"

	lc "github.com/sairam0424/toolwarrant/internal/lifecycle"
	"pgregory.net/rapid"
)

// propertyRounds is how many times each property is checked (rapid runs 100
// sequences per round by default). Sequences are cheap, so several rounds cost
// well under a second and make rare paths reliable.
const propertyRounds = 8

// checkRounds runs prop through propertyRounds independent rapid.Check calls.
func checkRounds(t *testing.T, prop func(*rapid.T)) {
	t.Helper()
	for i := 0; i < propertyRounds; i++ {
		rapid.Check(t, prop)
	}
}

// checkAll fails the property on the first step that breaks an invariant or
// disagrees with the oracle (when withOracle is set).
func checkAll(rt *rapid.T, perStepPolicy, withOracle bool) {
	for i, rec := range walk(rt, perStepPolicy) {
		problems := stepViolations(rec)
		if withOracle {
			problems = append(problems, oracleMismatches(rec)...)
		}
		if len(problems) > 0 {
			rt.Fatalf("step %d: %T %+v under policy %+v\n  %s\nbefore: %+v\nresult: %+v (err %v)",
				i, rec.cmd, rec.cmd, rec.pol, strings.Join(problems, "\n  "), rec.before, rec.res.Tool, rec.err)
		}
	}
}

func TestProperty_InvariantsHoldOnRandomSequences(t *testing.T) {
	checkRounds(t, func(rt *rapid.T) { checkAll(rt, false, false) })
}

func TestProperty_InvariantsHoldWhenThePolicyChangesBetweenSteps(t *testing.T) {
	checkRounds(t, func(rt *rapid.T) { checkAll(rt, true, false) })
}

// Differential test: the implementation must agree with the naive model of
// the specification on every step of every random sequence.
func TestProperty_ImplementationAgreesWithTheSpecificationOracle(t *testing.T) {
	t.Run("fixed policy", func(t *testing.T) {
		checkRounds(t, func(rt *rapid.T) { checkAll(rt, false, true) })
	})
	t.Run("policy changes between steps", func(t *testing.T) {
		checkRounds(t, func(rt *rapid.T) { checkAll(rt, true, true) })
	})
}

// Invariant (10): replaying the same commands from the same start yields the
// same results, including events and error text.
func TestProperty_ReplayYieldsIdenticalResults(t *testing.T) {
	checkRounds(t, func(rt *rapid.T) {
		records := walk(rt, true)
		if diff := replayDiffers(rt, records); diff != "" {
			rt.Fatalf("%s", diff)
		}
	})
}

// Guard against vacuous properties: the generators must actually reach every
// state, every documented error and every successful command kind.
func TestProperty_GeneratorsExerciseEveryStateErrorAndCommand(t *testing.T) {
	states := map[lc.State]bool{}
	errs := map[error]bool{}
	succeeded := map[string]bool{}
	checkRounds(t, func(rt *rapid.T) {
		for _, rec := range walk(rt, false) {
			if rec.err != nil {
				for _, s := range sentinelErrors() {
					if errors.Is(rec.err, s) {
						errs[s] = true
					}
				}
				continue
			}
			states[rec.res.Tool.State] = true
			succeeded[commandKind(rec.cmd)] = true
		}
	})
	for _, s := range allStates() {
		if !states[s] {
			t.Errorf("no random sequence reached state %s", s)
		}
	}
	for _, e := range sentinelErrors() {
		if !errs[e] {
			t.Errorf("no random sequence produced %v", e)
		}
	}
	for _, kind := range []string{"crawl", "miss", "approve", "reject", "disable", "enable", "rollback"} {
		if !succeeded[kind] {
			t.Errorf("no random %s command ever succeeded", kind)
		}
	}
}

func commandKind(cmd lc.Command) string {
	switch c := cmd.(type) {
	case lc.ObserveCrawl:
		if c.Present {
			return "crawl"
		}
		return "miss"
	case lc.Approve:
		return "approve"
	case lc.Reject:
		return "reject"
	case lc.Disable:
		return "disable"
	case lc.Enable:
		return "enable"
	case lc.Rollback:
		return "rollback"
	}
	return "unknown"
}
