package lifecycle_test

// Per-command effect invariants, including invariant (8): after a successful
// Approve the approver is none of the version's proposers unless
// AllowSelfApproval.

import (
	"fmt"
	"slices"

	lc "github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// effectViolations checks who may move a tool between states and what each
// command must have done when it succeeded.
func effectViolations(rec stepRecord) []string {
	out := stateOwnerViolations(rec)
	switch c := rec.cmd.(type) {
	case lc.Approve:
		out = append(out, approveViolations(c, rec)...)
	case lc.Reject:
		out = append(out, rejectViolations(c, rec)...)
	case lc.Disable:
		out = append(out, disableViolations(rec)...)
	case lc.Enable:
		out = append(out, enableViolations(rec)...)
	case lc.Rollback:
		out = append(out, rollbackViolations(c, rec)...)
	}
	return out
}

// stateOwnerViolations: deprecated is reachable only through a miss, disabled
// only through Disable and left only through Enable, and a deprecated tool is
// left only by a sighting with a digest.
func stateOwnerViolations(rec stepRecord) []string {
	before, after := rec.before.State, rec.res.Tool.State
	crawl, isCrawl := rec.cmd.(lc.ObserveCrawl)
	_, isDisable := rec.cmd.(lc.Disable)
	_, isEnable := rec.cmd.(lc.Enable)
	sighting := isCrawl && crawl.Present && !crawl.Unusable
	switch {
	case after == lc.Deprecated && before != lc.Deprecated && (!isCrawl || crawl.Present):
		return []string{fmt.Sprintf("%T deprecated a tool", rec.cmd)}
	case after == lc.Disabled && before != lc.Disabled && !isDisable:
		return []string{fmt.Sprintf("%T disabled a tool", rec.cmd)}
	case before == lc.Disabled && after != lc.Disabled && !isEnable:
		return []string{fmt.Sprintf("%T re-enabled a tool", rec.cmd)}
	case before == lc.Deprecated && after != lc.Deprecated && !sighting && !isDisable:
		return []string{fmt.Sprintf("%T revived a deprecated tool", rec.cmd)}
	}
	return nil
}

func inReviewState(s lc.State) bool {
	return s == lc.PendingReview || s == lc.ChangedPendingReapproval
}

func approveViolations(c lc.Approve, rec stepRecord) []string {
	before, after := rec.before, rec.res.Tool
	var out []string
	if !inReviewState(before.State) {
		out = append(out, "approved from state "+string(before.State))
	}
	if old, ok := findVersion(before, c.Digest); !ok || old.Status != lc.VersionPending {
		out = append(out, "approved a version that was not pending")
	}
	nv, ok := findVersion(after, c.Digest)
	if !ok || nv.Status != lc.VersionApproved || !nv.EverApproved || after.Approved != c.Digest || after.State != lc.Enabled {
		out = append(out, fmt.Sprintf("approval left %+v in state %s approved=%q", nv, after.State, after.Approved))
	}
	if ok && !rec.pol.AllowSelfApproval && slices.Contains(proposerHistory(nv), c.Actor) {
		out = append(out, fmt.Sprintf("invariant 8: %q approved a version they proposed (%v)", c.Actor, proposerHistory(nv)))
	}
	if before.Approved != "" {
		if prev, found := findVersion(after, before.Approved); !found || prev.Status != lc.VersionSuperseded {
			out = append(out, "the previous approval was not superseded")
		}
	}
	if after.LastSeen != before.LastSeen || after.MissingCrawls != before.MissingCrawls {
		out = append(out, "approval touched LastSeen or MissingCrawls")
	}
	return out
}

func rejectViolations(c lc.Reject, rec stepRecord) []string {
	before, after := rec.before, rec.res.Tool
	var out []string
	if !inReviewState(before.State) {
		out = append(out, "rejected from state "+string(before.State))
	}
	if old, ok := findVersion(before, c.Digest); !ok || old.Status != lc.VersionPending {
		out = append(out, "rejected a version that was not pending")
	}
	if nv, ok := findVersion(after, c.Digest); !ok || nv.Status != lc.VersionRejected {
		out = append(out, "the rejected version is not rejected")
	}
	wantState := lc.PendingReview
	if before.State == lc.ChangedPendingReapproval {
		wantState = lc.Enabled
	}
	if after.State != wantState || after.Approved != before.Approved {
		out = append(out, fmt.Sprintf("reject left state %s approved=%q (was %s %q)", after.State, after.Approved, before.State, before.Approved))
	}
	return out
}

func disableViolations(rec stepRecord) []string {
	want := cloneTool(rec.before)
	want.State = lc.Disabled
	if rec.before.State == lc.Disabled || !sameTool(want, rec.res.Tool) {
		return []string{fmt.Sprintf("disable must change only the state: %+v -> %+v", rec.before, rec.res.Tool)}
	}
	return nil
}

// enableViolations follows the Enable doc comment: the retained approval is
// restored only without re-review and with a live digest in LastSeen; in every
// other case the approval is retired and the tool is pending_review.
func enableViolations(rec stepRecord) []string {
	before, after := rec.before, rec.res.Tool
	var out []string
	if before.State != lc.Disabled {
		out = append(out, "enabled from state "+string(before.State))
	}
	if after.LastSeen != before.LastSeen || after.MissingCrawls != before.MissingCrawls {
		out = append(out, "enable changed LastSeen or MissingCrawls")
	}
	if rec.pol.ReEnableRequiresReview || !isLiveDigest(before.LastSeen) {
		if after.State != lc.PendingReview || after.Approved != "" {
			out = append(out, fmt.Sprintf("enable needing review left state %s approved=%q", after.State, after.Approved))
		}
		return append(out, reviewProposalViolations(rec)...)
	}
	pending, _ := statusCounts(after)
	want := lc.Enabled
	switch {
	case before.Approved == "":
		want = lc.PendingReview
	case pending > 0:
		want = lc.ChangedPendingReapproval
	}
	if after.State != want || after.Approved != before.Approved || !sameVersions(before, after) {
		out = append(out, fmt.Sprintf("enable without review left state %s approved=%q, want %s %q with versions unchanged", after.State, after.Approved, want, before.Approved))
	}
	return out
}

// reviewProposalViolations: the old approval is retired, and a live,
// non-rejected LastSeen digest is pending afterwards with its proposer history
// exactly as before (D4: Enable adds nobody).
func reviewProposalViolations(rec stepRecord) []string {
	before, after := rec.before, rec.res.Tool
	var out []string
	if before.Approved != "" {
		if prev, ok := findVersion(after, before.Approved); !ok || prev.Status == lc.VersionApproved {
			out = append(out, "enable with review did not retire the approval")
		}
	}
	if !isLiveDigest(before.LastSeen) || isRejected(before, before.LastSeen) {
		return out
	}
	old, _ := findVersion(before, before.LastSeen)
	nv, ok := findVersion(after, before.LastSeen)
	if !ok || nv.Status != lc.VersionPending || nv.ProposedBy != old.ProposedBy || nv.Proposers != old.Proposers {
		out = append(out, fmt.Sprintf("LastSeen digest was not re-proposed with its history intact: %+v -> %+v", old, nv))
	}
	return out
}

func rollbackViolations(c lc.Rollback, rec stepRecord) []string {
	before, after := rec.before, rec.res.Tool
	var out []string
	if !isServableState(before.State) {
		out = append(out, "rolled back from state "+string(before.State))
	}
	old, ok := findVersion(before, c.To)
	if !ok || !old.EverApproved || old.Status == lc.VersionApproved || old.Status == lc.VersionRejected {
		out = append(out, fmt.Sprintf("rolled back to an invalid target %+v", old))
	}
	nv, found := findVersion(after, c.To)
	if !found || nv.Status != lc.VersionApproved || after.Approved != c.To {
		out = append(out, "the rollback target is not the approved version")
	}
	if prev, ok := findVersion(after, before.Approved); before.Approved != "" && (!ok || prev.Status != lc.VersionSuperseded) {
		out = append(out, "the previous approval was not superseded")
	}
	pending, _ := statusCounts(after)
	want := lc.Enabled
	if pending > 0 {
		want = lc.ChangedPendingReapproval
	}
	if after.State != want {
		out = append(out, fmt.Sprintf("rollback left state %s, want %s", after.State, want))
	}
	return out
}
