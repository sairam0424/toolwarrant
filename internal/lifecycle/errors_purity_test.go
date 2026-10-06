package lifecycle_test

// Input validation, purity and determinism of Apply across every fixture,
// command and policy.
//
// Spec: "Apply(tool, command, policy) is pure: it never mutates the tool it is
// given (including the Versions slice; mutating the returned Versions must not
// change the input), is deterministic, and on error returns a zero Result and
// the caller keeps the old tool. Commands with an empty Actor fail with
// ErrNoActor; commands that need a digest fail with ErrNoDigest when it is
// empty; an unknown command type is an error."

import (
	"errors"
	"reflect"
	"testing"

	lc "github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// fixtureTools covers every state with realistic and awkward version layouts.
// It is a function so no mutable package state exists.
func fixtureTools() map[string]lc.Tool {
	return map[string]lc.Tool{
		"discovered":          newTool(),
		"discovered-unusable": toolOf(lc.Discovered, "", lc.UnusableDigest, 0),
		"pending":             pendingReviewTool(dA, alice),
		"pending-with-rejected": toolOf(lc.PendingReview, "", dB, 0,
			ver(dA, lc.VersionRejected, alice, false), ver(dB, lc.VersionPending, bob, false)),
		"pending-missed": toolOf(lc.PendingReview, "", "", 1,
			ver(dA, lc.VersionRejected, alice, false), ver(dB, lc.VersionPending, bob, false)),
		"enabled": enabledTool(dA),
		"enabled-with-history": toolOf(lc.Enabled, dB, dB, 0,
			ver(dA, lc.VersionSuperseded, alice, true),
			ver(dB, lc.VersionApproved, bob, true),
			ver(dC, lc.VersionSuperseded, alice, false),
			ver(dD, lc.VersionRejected, alice, true)),
		"enabled-unusable": toolOf(lc.Enabled, dA, lc.UnusableDigest, 0, ver(dA, lc.VersionApproved, alice, true)),
		"enabled-two-proposers": toolOf(lc.Enabled, dB, dB, 0,
			verP(dA, lc.VersionSuperseded, alice, false, alice, carol),
			ver(dB, lc.VersionApproved, bob, true)),
		"changed": changedTool(dA, dB, bob),
		"changed-reproposed": toolOf(lc.ChangedPendingReapproval, dB, dA, 0,
			ver(dA, lc.VersionPending, carol, true), ver(dB, lc.VersionApproved, bob, true)),
		"disabled-approved":    toolOf(lc.Disabled, dA, dA, 0, ver(dA, lc.VersionApproved, alice, true)),
		"disabled-unapproved":  toolOf(lc.Disabled, "", dA, 0, ver(dA, lc.VersionPending, alice, false)),
		"disabled-absent":      toolOf(lc.Disabled, dA, "", 2, ver(dA, lc.VersionApproved, alice, true)),
		"disabled-empty":       toolOf(lc.Disabled, "", "", 0),
		"deprecated":           toolOf(lc.Deprecated, dA, "", 3, ver(dA, lc.VersionApproved, alice, true)),
		"deprecated-with-prop": toolOf(lc.Deprecated, dA, "", 3, ver(dA, lc.VersionApproved, alice, true), ver(dB, lc.VersionPending, bob, false)),
	}
}

// commandMatrix lists commands over a small digest and actor alphabet.
func commandMatrix() []lc.Command {
	var cmds []lc.Command
	for _, actor := range []string{alice, bob} {
		cmds = append(cmds,
			lc.ObserveCrawl{Present: false, Actor: actor},
			lc.ObserveCrawl{Present: true, Unusable: true, Actor: actor},
			lc.Disable{Actor: actor}, lc.Enable{Actor: actor})
		for _, d := range []string{dA, dB, dC, dD} {
			cmds = append(cmds,
				lc.ObserveCrawl{Present: true, Digest: d, Actor: actor},
				lc.Approve{Digest: d, Actor: actor},
				lc.Reject{Digest: d, Actor: actor},
				lc.Rollback{To: d, Actor: actor})
		}
	}
	return cmds
}

func policyMatrix() []lc.Policy {
	return []lc.Policy{{}, plainPolicy(), reviewPolicy(), selfApprovePolicy(), lc.DefaultPolicy()}
}

func TestApply_PureAndDeterministicForEveryFixtureCommandAndPolicy(t *testing.T) {
	for name, tool := range fixtureTools() {
		for _, cmd := range commandMatrix() {
			for _, p := range policyMatrix() {
				first, err1 := checkPure(t, tool, cmd, p)
				second, err2 := checkPure(t, tool, cmd, p)
				if (err1 == nil) != (err2 == nil) || (err1 != nil && err1.Error() != err2.Error()) {
					t.Fatalf("%s %T %+v policy %+v: errors differ between runs: %v vs %v", name, cmd, cmd, p, err1, err2)
				}
				if !reflect.DeepEqual(first.Events, second.Events) || !sameTool(first.Tool, second.Tool) {
					t.Fatalf("%s %T %+v policy %+v: results differ between runs\n%+v\n%+v", name, cmd, cmd, p, first, second)
				}
			}
		}
	}
}

// Every successful step over the fixture matrix must also satisfy the
// invariants the property tests check on random sequences, so hand-made
// awkward layouts (legacy versions, markers, histories) get the same scrutiny.
func TestApply_FixtureMatrixSatisfiesTheInvariants(t *testing.T) {
	for name, tool := range fixtureTools() {
		for _, cmd := range commandMatrix() {
			for _, p := range policyMatrix() {
				res, err := checkPure(t, tool, cmd, p)
				rec := stepRecord{before: cloneTool(tool), cmd: cmd, pol: p, res: res, err: err}
				if v := stepViolations(rec); len(v) != 0 {
					t.Errorf("%s %T %+v policy %+v: %v\nresult %+v events %+v", name, cmd, cmd, p, v, res.Tool, res.Events)
				}
			}
		}
	}
}

func TestApply_EmptyActorIsRejectedForEveryCommandInEveryState(t *testing.T) {
	cmds := []lc.Command{
		lc.ObserveCrawl{Present: true, Digest: dA},
		lc.ObserveCrawl{Present: true, Unusable: true},
		lc.ObserveCrawl{Present: false},
		lc.Approve{Digest: dA},
		lc.Reject{Digest: dA},
		lc.Disable{},
		lc.Enable{},
		lc.Rollback{To: dA},
	}
	for name, tool := range fixtureTools() {
		for _, cmd := range cmds {
			for _, p := range policyMatrix() {
				res, err := checkPure(t, tool, cmd, p)
				if !errors.Is(err, lc.ErrNoActor) {
					t.Errorf("%s %T without actor: err = %v (result %+v), want ErrNoActor", name, cmd, err, res)
				}
			}
		}
	}
}

func TestApply_EmptyDigestIsRejectedWhereADigestIsNeeded(t *testing.T) {
	// ObserveCrawl needs a digest in every state when Present and usable.
	for name, tool := range fixtureTools() {
		_, err := checkPure(t, tool, lc.ObserveCrawl{Present: true, Actor: crawler}, plainPolicy())
		if !errors.Is(err, lc.ErrNoDigest) {
			t.Errorf("%s: crawl without digest: err = %v, want ErrNoDigest", name, err)
		}
	}
	// Approve, Reject and Rollback are tested from a state where they are
	// otherwise allowed, so the digest check is the only thing that can fail.
	pending := pendingReviewTool(dA, alice)
	mustFail(t, pending, lc.Approve{Actor: bob}, plainPolicy(), lc.ErrNoDigest)
	mustFail(t, pending, lc.Reject{Actor: bob}, plainPolicy(), lc.ErrNoDigest)
	history := fixtureTools()["enabled-with-history"]
	mustFail(t, history, lc.Rollback{Actor: bob}, plainPolicy(), lc.ErrNoDigest)
}

func TestApply_MissingObservationNeedsNoDigest(t *testing.T) {
	for name, tool := range fixtureTools() {
		if _, err := checkPure(t, tool, lc.ObserveCrawl{Present: false, Actor: crawler}, plainPolicy()); err != nil {
			t.Errorf("%s: a missing-tool observation without digest failed: %v", name, err)
		}
	}
}

func TestApply_EmptyActorAndDigestReportsOneOfTheTwo(t *testing.T) {
	_, err := checkPure(t, pendingReviewTool(dA, alice), lc.Approve{}, plainPolicy())
	if !errors.Is(err, lc.ErrNoActor) && !errors.Is(err, lc.ErrNoDigest) {
		t.Errorf("err = %v, want ErrNoActor or ErrNoDigest", err)
	}
}

// bogusCommand satisfies lifecycle.Command only by embedding the interface, so
// it exercises the "unknown command type" path. Its embedded value is nil:
// Apply must not call methods on a command it does not recognise.
type bogusCommand struct{ lc.Command }

func TestApply_UnknownCommandIsAnError(t *testing.T) {
	for name, cmd := range map[string]lc.Command{"nil": nil, "embedded-nil": bogusCommand{}} {
		t.Run(name, func(t *testing.T) {
			for toolName, tool := range fixtureTools() {
				res, err := checkPure(t, tool, cmd, plainPolicy())
				if err == nil {
					t.Errorf("%s: unknown command accepted: %+v", toolName, res)
				}
			}
		})
	}
}

func TestApply_ErrorResultIsTheZeroResult(t *testing.T) {
	res, err := lc.Apply(enabledTool(dA), lc.Approve{Digest: dA, Actor: bob}, plainPolicy())
	if err == nil {
		t.Fatal("expected an error")
	}
	if !reflect.DeepEqual(res, lc.Result{}) {
		t.Errorf("Result on error = %+v, want the zero Result", res)
	}
	if res.Tool.State != "" || res.Tool.Versions != nil || res.Events != nil {
		t.Errorf("zero Result expected, got %+v", res)
	}
}

func TestErrors_AreDistinctSentinels(t *testing.T) {
	all := []error{
		lc.ErrInvalidTransition, lc.ErrUnknownVersion, lc.ErrStaleVersion, lc.ErrSelfApproval,
		lc.ErrNotRollbackTarget, lc.ErrNoActor, lc.ErrNoDigest, lc.ErrInvalidObservation,
	}
	for i, a := range all {
		if a == nil || a.Error() == "" {
			t.Fatalf("sentinel %d is nil or has an empty message", i)
		}
		for j, b := range all {
			if i != j && errors.Is(a, b) {
				t.Errorf("sentinels %d (%v) and %d (%v) are not distinct", i, a, j, b)
			}
		}
	}
}

func TestApply_ReturnedToolDoesNotAliasTheInputVersions(t *testing.T) {
	in := changedTool(dA, dB, bob)
	res := applyOK(t, in, lc.Reject{Digest: dB, Actor: carol}, plainPolicy())
	before := cloneTool(res.Tool)
	scramble(in.Versions) // mutate the caller's copy after the fact
	if !sameTool(res.Tool, before) {
		t.Errorf("result shares memory with the input: got %+v, want %+v", res.Tool, before)
	}
}
