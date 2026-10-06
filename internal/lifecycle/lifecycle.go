// Package lifecycle is the pure state machine behind tool approval. It does no
// I/O: callers load a Tool, apply a Command, and persist the Result.
//
// Rules the rest of the system relies on (they are property-tested):
//
//   - A tool is served only while the definition the upstream serves right now
//     (the "live" digest) equals the approved digest. This is strict mode: a
//     changed tool is hidden and its calls denied until a person approves the
//     new digest or the upstream reverts.
//   - A crawl (ObserveCrawl) never approves anything. It can only record a
//     proposal, flag drift, or notice that the upstream went back to the
//     approved digest.
//   - Approval names the exact digest the approver looked at and fails if the
//     pending proposal has since changed.
//   - The person who ran the crawl that proposed a version cannot approve it,
//     unless the policy allows self-approval.
//   - Versions are never edited; only their status moves along fixed edges.
package lifecycle

import (
	"errors"
	"fmt"
)

// State is the lifecycle state of one tool.
type State string

const (
	// Discovered is the state of a tool row before its first observation is
	// applied. ObserveCrawl moves it to PendingReview in the same step, because
	// version 0.1 has no description-generation stage to wait for.
	Discovered State = "discovered"
	// PendingReview: nothing is approved; a person has to approve a digest.
	PendingReview State = "pending_review"
	// Enabled: a digest is approved. It is served only while live == approved.
	Enabled State = "enabled"
	// ChangedPendingReapproval: a digest is approved, but the upstream now
	// serves something else that is waiting for review. Nothing is served
	// unless the upstream goes back to the approved digest.
	ChangedPendingReapproval State = "changed_pending_reapproval"
	// Disabled: an operator switched the tool off. Never served.
	Disabled State = "disabled"
	// Deprecated: the tool was absent from enough consecutive successful
	// crawls. Never served.
	Deprecated State = "deprecated"
)

// VersionStatus is the status of one immutable tool version.
type VersionStatus string

const (
	VersionPending    VersionStatus = "pending"
	VersionApproved   VersionStatus = "approved"
	VersionRejected   VersionStatus = "rejected"
	VersionSuperseded VersionStatus = "superseded"
)

// Version is one immutable definition of a tool, identified by its digest.
type Version struct {
	Digest string
	Status VersionStatus
	// ProposedBy is the principal that ran the crawl that proposed this version.
	ProposedBy string
	// EverApproved is true once any approval or rollback named this version.
	// Only such versions are valid rollback targets.
	EverApproved bool
}

// Tool is the lifecycle-relevant snapshot of one tool.
type Tool struct {
	State State
	// Versions is in insertion order, oldest first. Digests are unique.
	Versions []Version
	// Approved is the digest of the version with status approved, or "".
	Approved string
	// LastSeen is the digest the upstream served in the most recent successful
	// crawl that listed this tool, or "" if it was absent.
	LastSeen string
	// MissingCrawls counts consecutive successful crawls that did not list it.
	MissingCrawls int
}

// Policy holds the knobs that are policy decisions rather than invariants.
type Policy struct {
	// AllowSelfApproval lets the proposer approve their own proposal.
	AllowSelfApproval bool
	// ReEnableRequiresReview makes Enable clear the old approval so that a
	// disabled tool comes back only after a fresh approval of a specific
	// digest. When false, Enable restores the retained approval.
	ReEnableRequiresReview bool
	// DeprecateAfter is the number of consecutive successful crawls that must
	// miss a tool for it to be deprecated: the tool is deprecated on the Nth
	// miss. Zero or less disables deprecation.
	DeprecateAfter int
}

// DefaultPolicy is the safe default: no self-approval, re-review after a
// disable, deprecate after three missed crawls.
func DefaultPolicy() Policy {
	return Policy{AllowSelfApproval: false, ReEnableRequiresReview: true, DeprecateAfter: 3}
}

// Errors returned by Apply. A failed Apply changes nothing.
var (
	ErrInvalidTransition = errors.New("lifecycle: not allowed from this state")
	ErrUnknownVersion    = errors.New("lifecycle: unknown version")
	ErrStaleVersion      = errors.New("lifecycle: version is not the current pending proposal")
	ErrSelfApproval      = errors.New("lifecycle: approver must differ from the proposer")
	ErrNotRollbackTarget = errors.New("lifecycle: not a rollback target")
	ErrNoActor           = errors.New("lifecycle: an actor is required")
	ErrNoDigest          = errors.New("lifecycle: a digest is required")
)

// Command is one input to the state machine.
type Command interface{ command() }

// ObserveCrawl reports what one successful crawl saw for this tool. A failed or
// incomplete crawl must not be reported at all: a crawl failure is not a
// removal.
type ObserveCrawl struct {
	Present bool
	Digest  string // required when Present
	Actor   string // principal that ran the crawl
}

// Approve approves the pending version with the given digest.
type Approve struct {
	Digest string
	Actor  string
}

// Reject rejects the pending version with the given digest.
type Reject struct {
	Digest string
	Actor  string
}

// Disable switches the tool off.
type Disable struct{ Actor string }

// Enable brings a disabled tool back (see Policy.ReEnableRequiresReview).
type Enable struct{ Actor string }

// Rollback re-approves a version that was approved before.
type Rollback struct {
	To    string
	Actor string
}

func (ObserveCrawl) command() {}
func (Approve) command()      {}
func (Reject) command()       {}
func (Disable) command()      {}
func (Enable) command()       {}
func (Rollback) command()     {}

// EventKind names something that happened; the store writes one audit entry
// per event.
type EventKind string

const (
	EvDiscovered EventKind = "tool.discovered"
	EvProposed   EventKind = "version.proposed"
	EvSuperseded EventKind = "version.superseded"
	EvApproved   EventKind = "version.approved"
	EvRejected   EventKind = "version.rejected"
	EvRolledBack EventKind = "version.rolled_back"
	EvDrifted    EventKind = "tool.drifted"
	EvReverted   EventKind = "tool.reverted"
	EvDisabled   EventKind = "tool.disabled"
	EvEnabled    EventKind = "tool.enabled"
	EvMissing    EventKind = "tool.missing"
	EvDeprecated EventKind = "tool.deprecated"
	EvReappeared EventKind = "tool.reappeared"
)

// Event is one state-machine event. Digest is the version it concerns, if any.
type Event struct {
	Kind   EventKind
	Digest string
}

// Result is the new tool snapshot plus the events that produced it.
type Result struct {
	Tool   Tool
	Events []Event
}

// Serves reports whether a tool with this state and approved digest may be
// served when the upstream currently serves the live digest. It is the single
// definition of "served"; the processor must not reimplement it.
func Serves(state State, approved, live string) bool {
	if approved == "" || live == "" || approved != live {
		return false
	}
	return state == Enabled || state == ChangedPendingReapproval
}

// Serves reports whether this tool may be served given the live digest.
func (t Tool) Serves(live string) bool { return Serves(t.State, t.Approved, live) }

// Drifted reports whether the upstream last served something other than the
// approved digest.
func (t Tool) Drifted() bool {
	return t.Approved != "" && t.LastSeen != "" && t.LastSeen != t.Approved
}

// Pending returns the digest of the current pending proposal, or "".
func (t Tool) Pending() string {
	for _, v := range t.Versions {
		if v.Status == VersionPending {
			return v.Digest
		}
	}
	return ""
}

// Apply runs one command. It never mutates its argument. On error the returned
// Result is zero and the caller must keep the old snapshot.
func Apply(t Tool, c Command, p Policy) (Result, error) {
	switch c := c.(type) {
	case ObserveCrawl:
		return observe(t, c, p)
	case Approve:
		return approve(t, c, p)
	case Reject:
		return reject(t, c)
	case Disable:
		return disable(t, c)
	case Enable:
		return enable(t, c, p)
	case Rollback:
		return rollback(t, c)
	default:
		return Result{}, fmt.Errorf("lifecycle: unknown command %T", c)
	}
}

func clone(t Tool) Tool {
	out := t
	out.Versions = append([]Version(nil), t.Versions...)
	return out
}

func find(t Tool, digest string) int {
	for i, v := range t.Versions {
		if v.Digest == digest {
			return i
		}
	}
	return -1
}

// supersedePending marks every pending version superseded and records events.
func supersedePending(t *Tool, except string, ev *[]Event) {
	for i := range t.Versions {
		if t.Versions[i].Status == VersionPending && t.Versions[i].Digest != except {
			t.Versions[i].Status = VersionSuperseded
			*ev = append(*ev, Event{EvSuperseded, t.Versions[i].Digest})
		}
	}
}

func supersedeApproved(t *Tool, ev *[]Event) {
	if t.Approved == "" {
		return
	}
	if i := find(*t, t.Approved); i >= 0 && t.Versions[i].Status == VersionApproved {
		t.Versions[i].Status = VersionSuperseded
		*ev = append(*ev, Event{EvSuperseded, t.Approved})
	}
	t.Approved = ""
}

// propose makes digest the single pending version. A digest seen before and
// since superseded is proposed again under the current crawler.
func propose(t *Tool, digest, actor string, ev *[]Event) {
	supersedePending(t, digest, ev)
	if i := find(*t, digest); i >= 0 {
		t.Versions[i].Status = VersionPending
		t.Versions[i].ProposedBy = actor
	} else {
		t.Versions = append(t.Versions, Version{Digest: digest, Status: VersionPending, ProposedBy: actor})
	}
	*ev = append(*ev, Event{EvProposed, digest})
}

func observe(t Tool, c ObserveCrawl, p Policy) (Result, error) {
	if c.Actor == "" {
		return Result{}, ErrNoActor
	}
	if c.Present && c.Digest == "" {
		return Result{}, ErrNoDigest
	}
	out := clone(t)
	var ev []Event

	if !c.Present {
		if t.State == Deprecated || t.State == Discovered {
			return Result{Tool: out}, nil
		}
		out.LastSeen = ""
		out.MissingCrawls = t.MissingCrawls + 1
		if p.DeprecateAfter > 0 && out.MissingCrawls >= p.DeprecateAfter && t.State != Disabled {
			out.State = Deprecated
			ev = append(ev, Event{EvDeprecated, ""})
		} else {
			ev = append(ev, Event{EvMissing, ""})
		}
		return Result{Tool: out, Events: ev}, nil
	}

	out.MissingCrawls = 0
	out.LastSeen = c.Digest

	// A deprecated tool that reappears is treated as a fresh proposal: the old
	// approval is retired and a person has to approve again.
	if t.State == Deprecated {
		ev = append(ev, Event{EvReappeared, c.Digest})
		supersedeApproved(&out, &ev)
		out.State = PendingReview
		if i := find(out, c.Digest); i < 0 || out.Versions[i].Status != VersionRejected {
			propose(&out, c.Digest, c.Actor, &ev)
		}
		return Result{Tool: out, Events: ev}, nil
	}

	if c.Digest == out.Approved {
		// The upstream is serving the approved definition again.
		if out.State == ChangedPendingReapproval {
			supersedePending(&out, "", &ev)
			out.State = Enabled
			ev = append(ev, Event{EvReverted, c.Digest})
		}
		return Result{Tool: out, Events: ev}, nil
	}

	if i := find(out, c.Digest); i >= 0 {
		switch out.Versions[i].Status {
		case VersionRejected, VersionPending:
			return Result{Tool: out, Events: ev}, nil // already decided or already proposed
		}
	}

	wasNew := len(out.Versions) == 0
	propose(&out, c.Digest, c.Actor, &ev)
	switch out.State {
	case Discovered:
		out.State = PendingReview
		if wasNew {
			ev = append([]Event{{EvDiscovered, c.Digest}}, ev...)
		}
	case Enabled:
		out.State = ChangedPendingReapproval
		ev = append(ev, Event{EvDrifted, c.Digest})
	}
	return Result{Tool: out, Events: ev}, nil
}

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
	if !p.AllowSelfApproval && v.ProposedBy == c.Actor {
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
		out.State = Enabled // the old approval stays; strict mode keeps it hidden while drifted
	}
	return Result{Tool: out, Events: []Event{{EvRejected, c.Digest}}}, nil
}

func disable(t Tool, c Disable) (Result, error) {
	if c.Actor == "" {
		return Result{}, ErrNoActor
	}
	if t.State == Disabled {
		return Result{}, fmt.Errorf("%w: already disabled", ErrInvalidTransition)
	}
	out := clone(t)
	out.State = Disabled
	return Result{Tool: out, Events: []Event{{EvDisabled, ""}}}, nil
}

func enable(t Tool, c Enable, p Policy) (Result, error) {
	if c.Actor == "" {
		return Result{}, ErrNoActor
	}
	if t.State != Disabled {
		return Result{}, fmt.Errorf("%w: cannot enable in state %s", ErrInvalidTransition, t.State)
	}
	out := clone(t)
	var ev []Event
	if p.ReEnableRequiresReview {
		supersedeApproved(&out, &ev)
		out.State = PendingReview
		// The definition the upstream serves now becomes the proposal, unless a
		// person already rejected exactly that definition.
		if out.LastSeen != "" {
			if i := find(out, out.LastSeen); i < 0 || out.Versions[i].Status != VersionRejected {
				propose(&out, out.LastSeen, c.Actor, &ev)
			}
		}
	} else {
		switch {
		case out.Approved == "":
			out.State = PendingReview
		case out.Pending() != "":
			out.State = ChangedPendingReapproval
		default:
			out.State = Enabled
		}
	}
	ev = append(ev, Event{EvEnabled, ""})
	return Result{Tool: out, Events: ev}, nil
}

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
