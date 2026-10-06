package lifecycle

import "fmt"

// The decisions: approve, reject and rollback. Each names an exact digest so
// that a proposal which changed under the reviewer is refused.

// approve makes the pending version named by c.Digest the approved one. It
// refuses every principal who ever proposed that version (ProposedBy and
// Proposers alike) unless the policy allows self-approval: the approver must
// differ from whoever introduced the bytes, not merely from the last crawler
// that happened to see them.
func approve(t Tool, c Approve, p Policy) (Result, error) {
	if c.Actor == "" {
		return Result{}, ErrNoActor
	}
	if c.Digest == "" {
		return Result{}, ErrNoDigest
	}
	if t.State != PendingReview && t.State != ChangedPendingReapproval {
		return Result{}, fmt.Errorf("%w: cannot approve in state %s", ErrInvalidTransition, t.State)
	}
	i := find(t, c.Digest)
	if i < 0 {
		return Result{}, ErrUnknownVersion
	}
	v := t.Versions[i]
	if v.Status != VersionPending {
		return Result{}, fmt.Errorf("%w: version is %s", ErrStaleVersion, v.Status)
	}
	if !p.AllowSelfApproval && isProposer(v, c.Actor) {
		return Result{}, ErrSelfApproval
	}
	out := clone(t)
	var ev []Event
	supersedeApproved(&out, &ev)
	out.Versions[i].Status = VersionApproved
	out.Versions[i].EverApproved = true
	out.Approved = c.Digest
	out.State = Enabled
	ev = append(ev, Event{EvApproved, c.Digest})
	return Result{Tool: out, Events: ev}, nil
}

// reject marks the pending version rejected. A tool that had drifted goes back
// to enabled with its old approval; strict mode keeps it hidden while the
// upstream serves the rejected definition.
func reject(t Tool, c Reject) (Result, error) {
	if c.Actor == "" {
		return Result{}, ErrNoActor
	}
	if c.Digest == "" {
		return Result{}, ErrNoDigest
	}
	if t.State != PendingReview && t.State != ChangedPendingReapproval {
		return Result{}, fmt.Errorf("%w: cannot reject in state %s", ErrInvalidTransition, t.State)
	}
	i := find(t, c.Digest)
	if i < 0 {
		return Result{}, ErrUnknownVersion
	}
	if t.Versions[i].Status != VersionPending {
		return Result{}, fmt.Errorf("%w: version is %s", ErrStaleVersion, t.Versions[i].Status)
	}
	out := clone(t)
	out.Versions[i].Status = VersionRejected
	if out.State == ChangedPendingReapproval {
		out.State = Enabled
	}
	return Result{Tool: out, Events: []Event{{EvRejected, c.Digest}}}, nil
}

// rollback re-approves a version that a person approved before. The
// self-approval rule does not apply: the target was already reviewed.
func rollback(t Tool, c Rollback) (Result, error) {
	if c.Actor == "" {
		return Result{}, ErrNoActor
	}
	if c.To == "" {
		return Result{}, ErrNoDigest
	}
	if t.State != Enabled && t.State != ChangedPendingReapproval {
		return Result{}, fmt.Errorf("%w: cannot roll back in state %s", ErrInvalidTransition, t.State)
	}
	i := find(t, c.To)
	if i < 0 {
		return Result{}, ErrUnknownVersion
	}
	v := t.Versions[i]
	if !v.EverApproved || v.Status == VersionApproved || v.Status == VersionRejected {
		return Result{}, fmt.Errorf("%w: version is %s and was approved before: %t", ErrNotRollbackTarget, v.Status, v.EverApproved)
	}
	out := clone(t)
	var ev []Event
	supersedeApproved(&out, &ev)
	out.Versions[i].Status = VersionApproved
	out.Approved = c.To
	if out.Pending() != "" {
		out.State = ChangedPendingReapproval
	} else {
		out.State = Enabled
	}
	ev = append(ev, Event{EvRolledBack, c.To})
	return Result{Tool: out, Events: ev}, nil
}
