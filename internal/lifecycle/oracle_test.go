package lifecycle_test

// A second, deliberately naive implementation of the written specification,
// used as an oracle for differential testing against lifecycle.Apply. It is
// written from the specification text (the doc comments on ObserveCrawl,
// Approve, Reject, Disable, Enable, Rollback and Version) only. Where the text
// is ambiguous the oracle says so (altStates) instead of guessing, so a
// mismatch is always a real disagreement with the text.
//
// The oracle compares tools, not events; the event rules are checked by
// eventViolations in event_invariants_test.go.

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

// propose makes digest the single pending version. Spec (Version): the first
// proposer is set once and never changes; the proposer list only grows and the
// crawl's actor joins it.
func propose(t *lc.Tool, digest, actor string) {
	i := indexOf(*t, digest)
	if i < 0 {
		t.Versions = append(t.Versions, lc.Version{Digest: digest})
		i = len(t.Versions) - 1
	}
	v := &t.Versions[i]
	v.Status = lc.VersionPending
	if v.ProposedBy == "" {
		v.ProposedBy = actor
	}
	if v.Proposers.Len() == 0 {
		v.Proposers = lc.ProposersOf(v.ProposedBy)
	}
	v.Proposers = v.Proposers.Add(actor)
	supersedePending(t, i)
}

// isProposer reports whether actor ever proposed v: the first proposer and the
// list both count, because a version stored before the list existed only has
// the former.
func isProposer(v lc.Version, actor string) bool {
	return v.ProposedBy == actor || v.Proposers.Contains(actor)
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
		if t.State == lc.Deprecated {
			// "a deprecated tool's retained approval is retired on the way out"
			retireApproval(&t)
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

// observationErrors lists the preconditions an observation fails: spec
// "Unusable (Present must be true and Digest empty, else
// ErrInvalidObservation)", "Digest is required when Present and Unusable is
// false; it must not be UnusableDigest".
func observationErrors(c lc.ObserveCrawl) []error {
	var errs []error
	if c.Actor == "" {
		errs = append(errs, lc.ErrNoActor)
	}
	switch {
	case c.Unusable && (!c.Present || c.Digest != ""):
		errs = append(errs, lc.ErrInvalidObservation)
	case c.Present && !c.Unusable && c.Digest == "":
		errs = append(errs, lc.ErrNoDigest)
	case c.Present && !c.Unusable && c.Digest == lc.UnusableDigest:
		errs = append(errs, lc.ErrInvalidObservation)
	}
	return errs
}

func oracleObserve(t lc.Tool, c lc.ObserveCrawl, p lc.Policy) oracleOutcome {
	if errs := observationErrors(c); len(errs) > 0 {
		return oracleFail(errs...)
	}
	if !c.Present {
		return oracleMissing(t, p)
	}
	if c.Unusable {
		t.LastSeen, t.MissingCrawls = lc.UnusableDigest, 0
		return oracleOutcome{tool: t}
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

// oracleReappear: "A deprecated tool reappears: the approval is retired, the
// state becomes pending_review and d is proposed unless it was rejected."
func oracleReappear(t lc.Tool, c lc.ObserveCrawl) oracleOutcome {
	retireApproval(&t)
	t.State = lc.PendingReview
	if i := indexOf(t, c.Digest); i >= 0 && t.Versions[i].Status == lc.VersionRejected {
		return oracleOutcome{tool: t}
	}
	propose(&t, c.Digest, c.Actor)
	return oracleOutcome{tool: t}
}

// oracleMissing: "a discovered or deprecated tool only loses an unusable
// marker; any other tool gets LastSeen = "" and MissingCrawls + 1 and is
// deprecated when the count reaches Policy.DeprecateAfter (when > 0), unless
// it is disabled."
func oracleMissing(t lc.Tool, p lc.Policy) oracleOutcome {
	if t.State == lc.Discovered || t.State == lc.Deprecated {
		t.LastSeen = ""
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

// versionPreconditionErrors: the version must be known and pending, and (D4)
// "Nobody whose crawl ever proposed a version can approve it, unless the
// policy allows self-approval."
func versionPreconditionErrors(t lc.Tool, i int, actor string, approve bool, p lc.Policy) []error {
	if i < 0 {
		return []error{lc.ErrUnknownVersion}
	}
	var errs []error
	if t.Versions[i].Status != lc.VersionPending {
		errs = append(errs, lc.ErrStaleVersion)
	}
	if approve && !p.AllowSelfApproval && isProposer(t.Versions[i], actor) {
		errs = append(errs, lc.ErrSelfApproval)
	}
	return errs
}

// oracleEnable follows the Enable doc comment: without re-review and with a
// live digest the retained approval is restored; otherwise the approval is
// retired, the state is pending_review, and a live, non-rejected LastSeen
// digest becomes the single pending version again without gaining a proposer.
func oracleEnable(t lc.Tool, c lc.Enable, p lc.Policy) oracleOutcome {
	if c.Actor == "" {
		return oracleFail(lc.ErrNoActor)
	}
	if t.State != lc.Disabled {
		return oracleFail(lc.ErrInvalidTransition)
	}
	live := isLiveDigest(t.LastSeen)
	if !p.ReEnableRequiresReview && live {
		switch {
		case t.Approved == "":
			t.State = lc.PendingReview
		case pendingIndex(t) >= 0:
			t.State = lc.ChangedPendingReapproval
		default:
			t.State = lc.Enabled
		}
		return oracleOutcome{tool: t}
	}
	retireApproval(&t)
	t.State = lc.PendingReview
	i := indexOf(t, t.LastSeen)
	if live && i >= 0 && t.Versions[i].Status != lc.VersionRejected && t.Versions[i].Status != lc.VersionPending {
		t.Versions[i].Status = lc.VersionPending
		supersedePending(&t, i)
	}
	return oracleOutcome{tool: t}
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
	got, exp := cloneTool(rec.res.Tool), cloneTool(want.tool)
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
