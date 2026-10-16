package catalog

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
	"github.com/sairam0424/toolwarrant/internal/signing"
)

// The binding of one entry to the outcome of the decision.signed entry it
// names (rule 5 as a comparison of two entries, without the walk's memory of
// the transaction), shared by the walk (checkSignedBinding, decisionwalk.go)
// and by the anchor pass (chainMemory.requireSigned, below). Split out of
// decisionwalk.go at the size rule; nothing here changed in the move.

// bindOutcome compares one entry with the outcome of the decision.signed entry
// it names: same subject, actor and time, a kind that writes the event, the
// digest the entry records for an approval, rollback or rejection, and a
// transition or paused flag the kind produces (bindContent). The walk
// (checkSignedBinding) and the anchor pass (requireSigned) share it.
func bindOutcome(e audit.Entry, n int64, o signedOutcome) error {
	if o.subject != e.Subject || o.actor != e.Actor || e.ActorType != string(ActorHuman) || o.ts != e.TS {
		return problemf(ruleSignedBinding, nil, "audit entry %d names %s=%d, a decision.signed about %s by %s at %s, but the entry is about %s by %s at %s; the entries of one decision share its subject, actor and time",
			e.Seq, fieldSigned, n, quote(o.subject), quote(o.actor), o.ts, quote(e.Subject), quote(e.Actor), e.TS)
	}
	if !kindWrites(o.kind, e.Event) {
		return problemf(ruleSignedBinding, nil, "audit entry %d is a %s but names %s=%d, a decision of kind %s, which writes no such entry", e.Seq, quote(e.Event), fieldSigned, n, o.kind)
	}
	recorded, decides := eventDigest(e)
	if decides && recorded != o.digest {
		return problemf(ruleSignedBinding, nil, "audit entry %d is a %s of digest %s but names %s=%d, which decided digest %s", e.Seq, e.Event, shownDigest(recorded), fieldSigned, n, o.digest)
	}
	return bindContent(e, n, o)
}

// bindContent is the last comparison of bindOutcome: what the entry says it
// did is what a decision of the kind can do. An entry of a kind that names a
// tool carries a state=A->B transition kindMayMove admits; an entry of a pause
// or resume carries the paused flag the kind leaves (bindPausedFlag). A tool
// entry without a state field, or whose field is not a transition, is refused
// as such: the entries of a tool decision record its transition, and the
// state anchor reads it.
func bindContent(e audit.Entry, n int64, o signedOutcome) error {
	if !o.kind.NamesTool() {
		return bindPausedFlag(e, n, o)
	}
	state, ok := detailField(e.Detail, fieldState)
	if !ok {
		return problemf(ruleSignedBinding, nil, "audit entry %d names %s=%d, a decision of kind %s about a tool, but carries no %s field; the entries of a tool decision record its transition", e.Seq, fieldSigned, n, o.kind, fieldState)
	}
	from, to, ok := strings.Cut(state, transitionArrow)
	if !ok {
		return problemf(ruleSignedBinding, nil, "audit entry %d about %s carries a %s field %s that is not a transition", e.Seq, quote(e.Subject), fieldState, quote(state))
	}
	if !kindMayMove(o.kind, lifecycle.State(from), lifecycle.State(to)) {
		return problemf(ruleSignedBinding, nil, "audit entry %d moves tool %s from %s to %s under event %s but names %s=%d, a decision of kind %s, which makes no such move; the entry was appended outside toolwarrant", e.Seq, quote(e.Subject), quote(from), quote(to), quote(e.Event), fieldSigned, n, o.kind)
	}
	return nil
}

// bindPausedFlag binds a server.paused or server.resumed entry to the kind of
// the decision it names: the paused flag it records is the one the decision
// leaves, true for a pause and false for a resume, and an entry without the
// flag is refused as such.
func bindPausedFlag(e audit.Entry, n int64, o signedOutcome) error {
	paused, ok := detailBool(e.Detail, fieldPaused)
	if !ok {
		return problemf(ruleSignedBinding, nil, "audit entry %d names %s=%d, a decision of kind %s about a server, but carries no %s flag", e.Seq, fieldSigned, n, o.kind, fieldPaused)
	}
	if want := o.kind == signing.KindPause; paused != want {
		return problemf(ruleSignedBinding, nil, "audit entry %d is a %s saying %s=%t but names %s=%d, a decision of kind %s, which leaves the server %s=%t; the entry was appended outside toolwarrant", e.Seq, e.Event, fieldPaused, paused, fieldSigned, n, o.kind, fieldPaused, want)
	}
	return nil
}

// kindMayMove is the transition table of one decision kind as the binding
// reads it: the five lifecycle commands through lifecycle.DecisionMayMove; the
// budget reset, which touches no state, as a state the lifecycle defines that
// stays (CrawlMayMove admits exactly the known states staying); nothing for
// pause and resume, whose entries carry no state.
func kindMayMove(kind signing.Kind, from, to lifecycle.State) bool {
	switch kind {
	case signing.KindApprove:
		return lifecycle.DecisionMayMove(lifecycle.Approve{}, from, to)
	case signing.KindReject:
		return lifecycle.DecisionMayMove(lifecycle.Reject{}, from, to)
	case signing.KindRollback:
		return lifecycle.DecisionMayMove(lifecycle.Rollback{}, from, to)
	case signing.KindDisable:
		return lifecycle.DecisionMayMove(lifecycle.Disable{}, from, to)
	case signing.KindEnable:
		return lifecycle.DecisionMayMove(lifecycle.Enable{}, from, to)
	case signing.KindBudgetReset:
		return from == to && lifecycle.CrawlMayMove(from, to)
	}
	return false
}

// eventDigest is the digest an entry's event decided, when it decided one:
// the after_hash of an approval or rollback, the digest token of a rejection.
// decides is false for every other event.
func eventDigest(e audit.Entry) (digest string, decides bool) {
	switch e.Event {
	case string(lifecycle.EvApproved), string(lifecycle.EvRolledBack):
		return e.AfterHash, true
	case string(lifecycle.EvRejected):
		d, _ := detailField(e.Detail, fieldDigest)
		return d, true
	}
	return "", false
}

// lookupSigned returns the outcome the walk recorded for a verified
// decision.signed entry.
func (c *chainMemory) lookupSigned(seq int64) (signedOutcome, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	o, ok := c.signed[seq]
	return o, ok
}

// requireSigned is rule 5 as the anchor pass applies it to one entry the
// verified chain holds (entryChecker.verify): when a bootstrap is in force
// below the entry and its event is one only a human command writes, the entry
// must carry signed=N and N must be a verified decision.signed entry whose
// outcome binds it (bindOutcome). Two token parses (the signed= token, then
// the state field or the paused flag bindContent compares) and one map
// lookup; nothing is read from the file and nothing is hashed, so the
// hashes/op of the reload benchmarks are unchanged
// (TestBenchmarkSnapshotHashesOnlyAuditEntries).
// The contiguity of rule 5 was checked by the walk that recorded the entry.
func (c *chainMemory) requireSigned(e audit.Entry) error {
	if !isHumanOnlyEvent(e.Event) {
		return nil
	}
	c.mu.RLock()
	bootstrap := c.trust.state.BootstrapSeq
	c.mu.RUnlock()
	if bootstrap == 0 || e.Seq <= bootstrap {
		return nil
	}
	token, ok := detailField(e.Detail, fieldSigned)
	if !ok {
		return fmt.Errorf("%w: %w", ErrCorrupt, errUnsignedDecision(e, bootstrap))
	}
	n, err := strconv.ParseInt(token, 10, 64)
	if err != nil || n < 1 || n >= e.Seq {
		return fmt.Errorf("%w: %w", ErrCorrupt, problemf(ruleSignedBinding, nil, "audit entry %d names %s=%s, which is not the seq of a decision.signed entry below it", e.Seq, fieldSigned, quote(token)))
	}
	o, ok := c.lookupSigned(n)
	if !ok {
		return fmt.Errorf("%w: %w", ErrCorrupt, problemf(ruleSignedBinding, nil, "audit entry %d names %s=%d, which is not a verified decision.signed entry", e.Seq, fieldSigned, n))
	}
	if err := bindOutcome(e, n, o); err != nil {
		return fmt.Errorf("%w: %w", ErrCorrupt, err)
	}
	return nil
}
