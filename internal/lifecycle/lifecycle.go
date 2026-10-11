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
//   - Nobody whose crawl ever proposed a version can approve it, unless the
//     policy allows self-approval. A version remembers every proposer
//     (Version.Proposers, append-only): a re-proposal adds one, Enable adds
//     nobody, and nothing ever removes one.
//   - Versions are never edited; only their status moves along fixed edges.
//   - Every change of LastSeen or MissingCrawls comes with an event, so the
//     audit log sees every flip between served and hidden (see ObserveCrawl).
//   - A live definition that cannot be used (invalid, or a name listed twice)
//     is recorded as UnusableDigest in LastSeen: it is never served and no
//     version is made from it.
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
	// Deprecated is the state of a tool that was absent from enough
	// consecutive successful crawls. Never served. (The word is the lifecycle
	// state, not a Go deprecation notice.)
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

// UnusableDigest is the LastSeen marker for a tool that the upstream listed
// with a definition that could not be used: invalid, or the same name listed
// twice in one page. It is not a digest (no version ever carries it), so it
// never equals an approved digest and the tool is never served while it is
// set. It is a constant string rather than a flag so that the catalog's one
// last_seen column and the processor's call-time veto need no new field.
const UnusableDigest = "unusable"

// Version is one immutable definition of a tool, identified by its digest.
type Version struct {
	Digest string
	Status VersionStatus
	// ProposedBy is the principal whose crawl first proposed this version. It
	// is set once and never changes; it equals Proposers.First() whenever the
	// list is populated and exists so that older callers keep compiling.
	ProposedBy string
	// Proposers lists every principal whose crawl proposed this version, oldest
	// first. It only grows: a crawl that proposes a superseded digest again
	// appends its actor, Enable re-proposes without adding anybody, and none of
	// them may approve the version unless Policy.AllowSelfApproval. A version
	// stored before this field existed has an empty list and is treated as
	// proposed by ProposedBy alone.
	Proposers Proposers
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
	// crawl that listed this tool, UnusableDigest if it listed a definition
	// that could not be used, or "" if it was absent.
	LastSeen string
	// MissingCrawls counts consecutive successful crawls that did not list it.
	MissingCrawls int
}

// Policy holds the knobs that are policy decisions rather than invariants.
type Policy struct {
	// AllowSelfApproval lets a proposer approve their own proposal.
	AllowSelfApproval bool
	// ReEnableRequiresReview makes Enable clear the old approval so that a
	// disabled tool comes back only after a fresh approval of a specific
	// digest. When false, Enable restores the retained approval, provided the
	// upstream currently lists a usable definition to compare it with.
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
	ErrSelfApproval      = errors.New("lifecycle: approver must differ from every proposer")
	ErrNotRollbackTarget = errors.New("lifecycle: not a rollback target")
	ErrNoActor           = errors.New("lifecycle: an actor is required")
	ErrNoDigest          = errors.New("lifecycle: a digest is required")
	// ErrInvalidObservation means an ObserveCrawl contradicts itself: Unusable
	// without Present, Unusable with a digest, or UnusableDigest passed as a
	// real digest. Such input is a caller bug, and guessing would either hide
	// or serve the wrong thing.
	ErrInvalidObservation = errors.New("lifecycle: contradictory observation")
)

// Command is one input to the state machine.
type Command interface{ command() }

// ObserveCrawl reports what one successful crawl saw for this tool. A failed or
// incomplete crawl must not be reported at all: a crawl failure is not a
// removal.
//
// Effect on the tool (first match wins):
//
//   - Present with Digest d: LastSeen = d, MissingCrawls = 0. A deprecated
//     tool reappears: the approval is retired, the state becomes
//     pending_review and d is proposed unless it was rejected. Otherwise, if d
//     is the approved digest, a changed_pending_reapproval tool goes back to
//     enabled and its pending proposal is superseded; if d is a rejected or
//     already pending version nothing else changes; any other d is proposed (a
//     superseded version is reused, keeping EverApproved and adding Actor to
//     its proposers), a discovered tool becomes pending_review and an enabled
//     tool becomes changed_pending_reapproval.
//   - Unusable (Present must be true and Digest empty, else
//     ErrInvalidObservation): LastSeen = UnusableDigest, MissingCrawls = 0,
//     nothing else changes. The tool is listed but its definition cannot be
//     used, so it is never served and no version is created.
//   - Not present: a discovered or deprecated tool only loses an unusable
//     marker; any other tool gets LastSeen = "" and MissingCrawls + 1 and is
//     deprecated when the count reaches Policy.DeprecateAfter (when > 0),
//     unless it is disabled.
//
// Events. Every change of LastSeen or MissingCrawls comes with at least one
// event, so the audit log sees every flip between served and hidden:
//
//   - EvReturned when MissingCrawls goes from above zero to zero.
//   - EvReverted when LastSeen moves to the approved digest from anything
//     else, in any state, and whenever changed_pending_reapproval goes back to
//     enabled.
//   - EvDrifted when LastSeen moves to a digest other than the approved one:
//     to a rejected, pending, superseded or new digest alike, from "", from
//     UnusableDigest or from another digest, whether or not anything is
//     approved; and whenever enabled becomes changed_pending_reapproval. The
//     first sighting of a discovered tool and the reappearance of a deprecated
//     tool are the exceptions: EvDiscovered and EvReappeared report those, as
//     there is no earlier sighting, or no surviving approval, to have drifted
//     from.
//   - EvUnusable when LastSeen becomes UnusableDigest.
//   - EvMissing when a miss changes LastSeen or MissingCrawls without
//     deprecating the tool; EvDeprecated when it deprecates it.
//   - EvDiscovered, EvReappeared, EvProposed and EvSuperseded describe the
//     version changes above.
//
// An observation that changes nothing (same LastSeen, MissingCrawls already
// zero) emits nothing.
type ObserveCrawl struct {
	Present bool
	// Digest is required when Present and Unusable is false; it must not be
	// UnusableDigest.
	Digest string
	// Unusable says the tool was listed but its definition could not be used.
	Unusable bool
	// Actor is the principal that ran the crawl.
	Actor string
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

// Disable switches the tool off. LastSeen and MissingCrawls stay as they are,
// so that Enable cannot read a vanished tool as present, and so does every
// version, with one exception: a deprecated tool's retained approval is
// retired on the way out (its version becomes superseded, with an event),
// exactly as a reappearance would retire it. The deprecation had already
// withdrawn that approval in effect; making it final here means that Enable
// needs a fresh review under either policy, where Disable, a crawl that listed
// the old definition while the tool was off (a sighting of the approved digest
// on a disabled tool reverts rather than proposes), and Enable without
// re-review once restored it unreviewed.
type Disable struct{ Actor string }

// Enable brings a disabled tool back. With Policy.ReEnableRequiresReview the
// retained approval is retired and the digest the upstream last served, if it
// is a real digest that was not rejected, becomes the proposal again without
// gaining a proposer (a digest that is already pending stays as it is and no
// event is emitted for it); a person has to approve it. Without it the retained
// approval is restored, except when LastSeen is "" or UnusableDigest: with no
// live definition to compare, the approval is retired and the tool waits in
// pending_review for the next crawl and a fresh approval. A tool that was
// deprecated before it was disabled has no retained approval (Disable retired
// it), so it comes back to pending_review under either policy and only a fresh
// approval serves it again. Enable never changes LastSeen or MissingCrawls.
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
	// EvReturned: the tool is listed again after one or more missed crawls.
	EvReturned EventKind = "tool.returned"
	// EvUnusable: the upstream lists the tool with a definition that cannot be
	// used, so it is hidden until a clean definition appears.
	EvUnusable EventKind = "tool.unusable"
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
// definition of "served"; the processor must not reimplement it. A live value
// of "" or UnusableDigest never matches, whatever is approved, because no
// version carries either.
func Serves(state State, approved, live string) bool {
	if approved == "" || !isDigest(live) || approved != live {
		return false
	}
	return state == Enabled || state == ChangedPendingReapproval
}

// Serves reports whether this tool may be served given the live digest.
func (t Tool) Serves(live string) bool { return Serves(t.State, t.Approved, live) }

// Drifted reports whether the upstream last served something other than the
// approved digest, an unusable definition included.
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

// isDigest reports whether s names a definition: not absent and not the
// unusable marker.
func isDigest(s string) bool { return s != "" && s != UnusableDigest }
