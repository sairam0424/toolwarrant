package lifecycle_test

// A second, deliberately naive implementation of the written specification,
// used as an oracle for differential testing against lifecycle.Apply. It is
// written from the specification text only. Where the text is silent or
// ambiguous the oracle says so (altStates, skipMissing, skipAll) instead of
// guessing, so a mismatch is always a real disagreement with the text.

import (
	"errors"
	"slices"

	lc "github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// oracleOutcome is what the specification demands for one Apply call.
type oracleOutcome struct {
	tool lc.Tool
	// wantErrs non-empty means the call must fail with one of these errors.
	// Every independently failing precondition contributes an error because
	// the text does not fix which is reported first.
	wantErrs []error
	// altStates lists further states the text allows (ambiguous thresholds).
	altStates []lc.State
	// skipMissing: the text does not say what happens to MissingCrawls.
	skipMissing bool
	// skipAll: the text is silent about the outcome; only invariants apply.
	skipAll bool
}

func oracleFail(errs ...error) oracleOutcome { return oracleOutcome{wantErrs: errs} }

func indexOf(t lc.Tool, digest string) int {
	for i, v := range t.Versions {
		if v.Digest == digest {
			return i
		}
	}
	return -1
}

func pendingIndex(t lc.Tool) int {
	for i, v := range t.Versions {
		if v.Status == lc.VersionPending {
			return i
		}
	}
	return -1
}

// supersedePending turns every pending version except keep into superseded.
func supersedePending(t *lc.Tool, keep int) {
	for i := range t.Versions {
		if i != keep && t.Versions[i].Status == lc.VersionPending {
			t.Versions[i].Status = lc.VersionSuperseded
		}
	}
}

// retireApproval makes the approved version superseded and clears Approved.
func retireApproval(t *lc.Tool) {
	if i := indexOf(*t, t.Approved); i >= 0 && t.Approved != "" {
		t.Versions[i].Status = lc.VersionSuperseded
	}
	t.Approved = ""
}

// propose makes digest the single pending version proposed by actor.
func propose(t *lc.Tool, digest, actor string) {
	i := indexOf(*t, digest)
	if i < 0 {
		t.Versions = append(t.Versions, lc.Version{Digest: digest})
		i = len(t.Versions) - 1
	}
	t.Versions[i].Status = lc.VersionPending
	t.Versions[i].ProposedBy = actor
	supersedePending(t, i)
}

func oracle(tool lc.Tool, cmd lc.Command, p lc.Policy) oracleOutcome {
	t := cloneTool(tool)
	switch c := cmd.(type) {
	case lc.ObserveCrawl:
		return oracleObserve(t, c, p)
	case lc.Approve:
		return oracleDecide(t, c.Digest, c.Actor, true, p)
	case lc.Reject:
		return oracleDecide(t, c.Digest, c.Actor, false, p)
	case lc.Disable:
		if c.Actor == "" {
			return oracleFail(lc.ErrNoActor)
		}
		if t.State == lc.Disabled {
			return oracleFail(lc.ErrInvalidTransition)
		}
		t.State = lc.Disabled
		return oracleOutcome{tool: t}
	case lc.Enable:
		return oracleEnable(t, c, p)
	case lc.Rollback:
		return oracleRollback(t, c)
	}
	return oracleFail()
}

func oracleObserve(t lc.Tool, c lc.ObserveCrawl, p lc.Policy) oracleOutcome {
	var errs []error
	if c.Actor == "" {
		errs = append(errs, lc.ErrNoActor)
	}
	if c.Present && c.Digest == "" {
		errs = append(errs, lc.ErrNoDigest)
	}
	if len(errs) > 0 {
		return oracleFail(errs...)
	}
	if !c.Present {
		return oracleMissing(t, p)
	}
	t.LastSeen, t.MissingCrawls = c.Digest, 0
	if t.State == lc.Deprecated {
		return oracleReappear(t, c)
	}
	i := indexOf(t, c.Digest)
	switch {
	case c.Digest == t.Approved:
		if t.State == lc.ChangedPendingReapproval {
			supersedePending(&t, -1)
			t.State = lc.Enabled
		}
	case i >= 0 && (t.Versions[i].Status == lc.VersionRejected || t.Versions[i].Status == lc.VersionPending):
	default:
		propose(&t, c.Digest, c.Actor)
		switch t.State {
		case lc.Discovered:
			t.State = lc.PendingReview
		case lc.Enabled:
			t.State = lc.ChangedPendingReapproval
		}
	}
	return oracleOutcome{tool: t}
}

// oracleReappear is rule (e). When the digest is rejected and another version
// is pending the text does not say what happens to that version.
func oracleReappear(t lc.Tool, c lc.ObserveCrawl) oracleOutcome {
	retireApproval(&t)
	t.State = lc.PendingReview
	if i := indexOf(t, c.Digest); i >= 0 && t.Versions[i].Status == lc.VersionRejected {
		return oracleOutcome{tool: t, skipAll: pendingIndex(t) >= 0}
	}
	propose(&t, c.Digest, c.Actor)
	return oracleOutcome{tool: t}
}

func oracleMissing(t lc.Tool, p lc.Policy) oracleOutcome {
	if t.State == lc.Discovered || t.State == lc.Deprecated {
		return oracleOutcome{tool: t}
	}
	t.LastSeen = ""
	t.MissingCrawls++
	out := oracleOutcome{tool: t}
	if p.DeprecateAfter > 0 && t.State != lc.Disabled {
		switch {
		case t.MissingCrawls == p.DeprecateAfter:
			out.tool.State = lc.Deprecated
		case t.MissingCrawls > p.DeprecateAfter:
			// "reaches it" does not say what happens once the counter is past it.
			out.altStates = []lc.State{lc.Deprecated}
		}
	}
	return out
}

// oracleDecide covers Approve (approve=true) and Reject.
func oracleDecide(t lc.Tool, digest, actor string, approve bool, p lc.Policy) oracleOutcome {
	var errs []error
	if actor == "" {
		errs = append(errs, lc.ErrNoActor)
	}
	if digest == "" {
		errs = append(errs, lc.ErrNoDigest)
	}
	if t.State != lc.PendingReview && t.State != lc.ChangedPendingReapproval {
		errs = append(errs, lc.ErrInvalidTransition)
	}
	i := indexOf(t, digest)
	if digest != "" {
		errs = append(errs, versionPreconditionErrors(t, i, actor, approve, p)...)
	}
	if len(errs) > 0 {
		return oracleFail(errs...)
	}
	if !approve {
		t.Versions[i].Status = lc.VersionRejected
		if t.State == lc.ChangedPendingReapproval {
			t.State = lc.Enabled
		}
		return oracleOutcome{tool: t}
	}
	retireApproval(&t)
	t.Versions[i].Status, t.Versions[i].EverApproved = lc.VersionApproved, true
	t.Approved, t.State = digest, lc.Enabled
	return oracleOutcome{tool: t}
}

func versionPreconditionErrors(t lc.Tool, i int, actor string, approve bool, p lc.Policy) []error {
	if i < 0 {
		return []error{lc.ErrUnknownVersion}
	}
	var errs []error
	if t.Versions[i].Status != lc.VersionPending {
		errs = append(errs, lc.ErrStaleVersion)
	}
	if approve && !p.AllowSelfApproval && t.Versions[i].ProposedBy == actor {
		errs = append(errs, lc.ErrSelfApproval)
	}
	return errs
}

func oracleEnable(t lc.Tool, c lc.Enable, p lc.Policy) oracleOutcome {
	if c.Actor == "" {
		return oracleFail(lc.ErrNoActor)
	}
	if t.State != lc.Disabled {
		return oracleFail(lc.ErrInvalidTransition)
	}
	// The text does not say whether Enable resets MissingCrawls.
	out := oracleOutcome{tool: t, skipMissing: true}
	if !p.ReEnableRequiresReview {
		switch {
		case t.Approved == "":
			out.tool.State = lc.PendingReview
		case pendingIndex(t) >= 0:
			out.tool.State = lc.ChangedPendingReapproval
		default:
			out.tool.State = lc.Enabled
		}
		return out
	}
	retireApproval(&out.tool)
	out.tool.State = lc.PendingReview
	i := indexOf(out.tool, t.LastSeen)
	if t.LastSeen != "" && i >= 0 && out.tool.Versions[i].Status != lc.VersionRejected {
		propose(&out.tool, t.LastSeen, c.Actor)
		return out
	}
	// No proposal: the text does not say what becomes of other pending versions.
	out.skipAll = pendingIndex(out.tool) >= 0
	return out
}

func oracleRollback(t lc.Tool, c lc.Rollback) oracleOutcome {
	var errs []error
	if c.Actor == "" {
		errs = append(errs, lc.ErrNoActor)
	}
	if c.To == "" {
		errs = append(errs, lc.ErrNoDigest)
	}
	if t.State != lc.Enabled && t.State != lc.ChangedPendingReapproval {
		errs = append(errs, lc.ErrInvalidTransition)
	}
	i := indexOf(t, c.To)
	switch {
	case c.To == "":
	case i < 0:
		errs = append(errs, lc.ErrUnknownVersion)
	case !t.Versions[i].EverApproved || t.Versions[i].Status == lc.VersionApproved || t.Versions[i].Status == lc.VersionRejected:
		errs = append(errs, lc.ErrNotRollbackTarget)
	}
	if len(errs) > 0 {
		return oracleFail(errs...)
	}
	retireApproval(&t)
	t.Versions[i].Status = lc.VersionApproved
	t.Approved = c.To
	t.State = lc.Enabled
	if pendingIndex(t) >= 0 {
		t.State = lc.ChangedPendingReapproval
	}
	return oracleOutcome{tool: t}
}

// oracleMismatches compares one recorded step with the oracle.
func oracleMismatches(rec stepRecord) []string {
	want := oracle(rec.before, rec.cmd, rec.pol)
	if len(want.wantErrs) > 0 {
		return errorMismatches(rec, want)
	}
	if rec.err != nil {
		return []string{"implementation failed (" + rec.err.Error() + ") where the specification succeeds"}
	}
	if want.skipAll {
		return nil
	}
	got, exp := cloneTool(rec.res.Tool), cloneTool(want.tool)
	if want.skipMissing {
		got.MissingCrawls, exp.MissingCrawls = 0, 0
	}
	if len(want.altStates) > 0 && slices.Contains(want.altStates, got.State) {
		got.State = exp.State
	}
	if !sameTool(got, exp) {
		return []string{"tool differs from the specification"}
	}
	return nil
}

func errorMismatches(rec stepRecord, want oracleOutcome) []string {
	if rec.err == nil {
		return []string{"implementation succeeded where the specification fails"}
	}
	for _, e := range want.wantErrs {
		if errors.Is(rec.err, e) {
			return nil
		}
	}
	return []string{"implementation error " + rec.err.Error() + " is not one the specification allows"}
}
