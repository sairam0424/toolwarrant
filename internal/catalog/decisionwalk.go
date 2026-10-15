package catalog

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
	"github.com/sairam0424/toolwarrant/internal/signing"
	"github.com/sairam0424/toolwarrant/internal/trust"
)

// What every chain walk requires of a decision and of the entries after the
// bootstrap (D22 (b) and (d); the v0.4 plan, section 1, rules 2, 4, 5 and 6).
// Rule 2 and rule 4, checkDecisionRecord: a decision.signed entry's record is
// a canonical decision bound to the entry (rule 1, trustwalk.go), its kind,
// server, tool and digest are the entry's subject and tokens, a list is in
// force and it names the signing key for the entry's actor; the writer
// (Decide) runs the same function on the entry it is about to store, so the
// reader and the writer cannot drift. Rule 5, checkSignedBinding: after the
// bootstrap, every entry whose event only a human command writes carries
// signed=N, where N is a verified decision.signed entry of the same
// transaction, which the walk knows as the entry at N itself or the entries
// right after it that carry the same token (the write lock makes a
// transaction's entries contiguous), about the same subject, by the same
// actor, at the same time, whose kind writes that event, for an approval,
// rollback or rejection, whose digest is the one the entry records, and whose
// content is what the kind does (bindContent): a tool entry's state=A->B is a
// transition the kind can make (lifecycle.DecisionMayMove; a budget reset
// stays) and a server entry's paused flag is the one the kind leaves. The
// contiguity rule is what refuses a replay: a correctly sealed version.approved
// appended later, naming a decision.signed that alice did make, with her time
// and her digest, would otherwise undo a disable she made since. The content
// rule is what refuses a borrowed token: a sealed tool.disabled or
// version.superseded with state=disabled->enabled, or a server.paused with
// paused=false, naming the decision.signed of the disable or pause whose
// transaction is still open at the head, with the actor and the time copied,
// would otherwise pass every other comparison and the state anchor would
// serve the tool or the server again. Rule 6,
// checkCrawlTransition: after the bootstrap, an entry about a tool that
// carries no token moves the tool's state only along a transition a crawl can
// make (lifecycle.CrawlMayMove), so a sealed tool.reverted with
// state=disabled->enabled appended without a key re-enables nothing. Before
// the bootstrap nothing changes (O-12): approvals made then stand by chain
// anchoring alone, and the legacy residual is stated. Every failure is
// ErrCorrupt with a fixed sentence naming the entry; the walk stops at the
// first and records nothing of its page. The anchor pass applies rule 5 to
// every entry it anchors (chainMemory.requireSigned) with one detailField
// parse and one map lookup, and reads no bytes.

// isHumanOnlyEvent reports whether only a human command writes this event:
// the eight events of the eight decisions (O-16). Every other lifecycle event
// is one a crawl may write, and crawls are not signed (L20).
func isHumanOnlyEvent(event string) bool {
	switch event {
	case string(lifecycle.EvApproved), string(lifecycle.EvRejected), string(lifecycle.EvRolledBack),
		string(lifecycle.EvDisabled), string(lifecycle.EvEnabled), evBudgetReset, evServerPaused, evServerResumed:
		return true
	}
	return false
}

// kindWrites reports whether a decision of kind k writes event in its own
// transaction: its own event, and for approve, rollback, disable and enable
// the version.superseded of the approval or proposal they retire, and for
// enable the version.proposed of the definition it re-proposes under
// re-review (lifecycle: supersedeApproved, supersedePending, repropose).
func kindWrites(k signing.Kind, event string) bool {
	switch event {
	case string(lifecycle.EvApproved):
		return k == signing.KindApprove
	case string(lifecycle.EvRejected):
		return k == signing.KindReject
	case string(lifecycle.EvRolledBack):
		return k == signing.KindRollback
	case string(lifecycle.EvDisabled):
		return k == signing.KindDisable
	case string(lifecycle.EvEnabled):
		return k == signing.KindEnable
	case evBudgetReset:
		return k == signing.KindBudgetReset
	case evServerPaused:
		return k == signing.KindPause
	case evServerResumed:
		return k == signing.KindResume
	case string(lifecycle.EvSuperseded):
		return k == signing.KindApprove || k == signing.KindRollback || k == signing.KindDisable || k == signing.KindEnable
	case string(lifecycle.EvProposed):
		return k == signing.KindEnable
	}
	return false
}

// decisionSubject is the subject of a decision's entries: the server for
// pause and resume, server/tool for every other kind.
func decisionSubject(kind signing.Kind, server, tool string) string {
	if !kind.NamesTool() {
		return server
	}
	return server + "/" + tool
}

// checkDecisionRecord is rule 1, rule 2 and rule 4 for one decision.signed
// entry whose signature verified: the payload is a canonical decision bound
// to the entry and its actor, the kind and digest tokens and the subject say
// what the payload says, a list is in force and it names the signing key for
// the entry's actor. It returns the outcome the signed= binding of the
// lifecycle entries compares (rule 5).
func checkDecisionRecord(e audit.Entry, rec signing.Record, state trust.State, identity string) (*signedOutcome, error) {
	d, err := signing.ParseDecision(rec.Payload)
	if err != nil {
		return nil, problemf(ruleBinding, err, "signed record of entry %d is not a canonical decision: %v", e.Seq, err)
	}
	if err := checkPayloadBinding(e, rec.Signer, d.Signer, d.Catalog, d.PrevHead, identity); err != nil {
		return nil, err
	}
	if d.Actor != e.Actor {
		return nil, problemf(ruleBinding, nil, "signed record of entry %d names actor %s but the entry's actor is %s", e.Seq, quote(d.Actor), quote(e.Actor))
	}
	if err := checkDecisionTokens(e, d); err != nil {
		return nil, err
	}
	if state.Current == nil {
		return nil, problemf(ruleDecision, trust.ErrNoList, "audit entry %d is a %s but no trust list is in force at that entry; a signed record has no list to be verified against", e.Seq, e.Event)
	}
	if err := state.Current.Authorize(rec.Signer, e.Actor); err != nil {
		if name, ok := state.Current.Lookup(rec.Signer); ok {
			return nil, problemf(ruleDecision, err, "signed record of entry %d: signer %s belongs to %s but the entry and payload name %s", e.Seq, rec.Signer, quote(name), quote(e.Actor))
		}
		return nil, problemf(ruleDecision, err, "signed record of entry %d: signer %s is not in trust list v%d in force at that entry", e.Seq, rec.Signer, state.Current.Version)
	}
	return &signedOutcome{kind: d.Kind, subject: e.Subject, actor: e.Actor, ts: e.TS, digest: d.Digest}, nil
}

// checkDecisionTokens is rule 2: the entry's kind and digest tokens and its
// subject are the decision the payload holds.
func checkDecisionTokens(e audit.Entry, d signing.Decision) error {
	if k, ok := detailField(e.Detail, fieldKind); !ok || k != string(d.Kind) {
		return problemf(ruleBinding, nil, "audit entry %d says %s=%s but its signed decision is a %s", e.Seq, fieldKind, quote(k), d.Kind)
	}
	if digest, ok := detailField(e.Detail, fieldDigest); !ok || digest != orNoDigest(d.Digest) {
		return problemf(ruleBinding, nil, "audit entry %d says %s=%s but its signed decision names digest %s", e.Seq, fieldDigest, quote(digest), orNoDigest(d.Digest))
	}
	if subject := decisionSubject(d.Kind, d.Server, d.Tool); e.Subject != subject {
		return problemf(ruleBinding, nil, "audit entry %d is about %s but its signed decision is about %s", e.Seq, quote(e.Subject), quote(subject))
	}
	return nil
}

// decisionWalk is what rules 5 and 6 carry from one entry to the next: the
// seq of the bootstrap in force (0 when none, so the rules do not apply), the
// decision.signed entry whose transaction is open at this point of the chain
// (0 when the last entry belonged to none) and how to find the outcome the
// walk recorded for a verified decision.signed entry.
type decisionWalk struct {
	bootstrap int64
	open      int64
	lookup    func(seq int64) (signedOutcome, bool)
}

// checkLifecycleEntry applies rule 5 and rule 6 to one entry that carries no
// signed record itself and returns the decision.signed entry whose
// transaction is open after it: the one the entry named when it carries a
// token, none otherwise. Before the bootstrap it accepts everything (O-12).
func checkLifecycleEntry(e audit.Entry, w decisionWalk) (int64, error) {
	if w.bootstrap == 0 || e.Seq <= w.bootstrap {
		return 0, nil
	}
	token, signed := detailField(e.Detail, fieldSigned)
	switch {
	case signed:
		if err := checkSignedBinding(e, token, w); err != nil {
			return 0, err
		}
		return w.open, nil
	case isHumanOnlyEvent(e.Event):
		return 0, errUnsignedDecision(e, w.bootstrap)
	}
	return 0, checkCrawlTransition(e)
}

// errUnsignedDecision is rule 5's refusal of a human-only event after the
// bootstrap that names no signed record.
func errUnsignedDecision(e audit.Entry, bootstrap int64) error {
	return problemf(ruleSignedBinding, nil, "audit entry %d is a %s after the trust bootstrap (entry %d) and names no signed record; the entry was appended outside toolwarrant", e.Seq, e.Event, bootstrap)
}

// checkSignedBinding is rule 5 for one entry that carries signed=token: the
// token names a verified decision.signed entry below it whose transaction is
// still open, and the outcome binds the entry (bindOutcome).
func checkSignedBinding(e audit.Entry, token string, w decisionWalk) error {
	n, err := strconv.ParseInt(token, 10, 64)
	if err != nil || n < 1 || n >= e.Seq {
		return problemf(ruleSignedBinding, nil, "audit entry %d names %s=%s, which is not the seq of a decision.signed entry below it", e.Seq, fieldSigned, quote(token))
	}
	o, ok := w.lookup(n)
	if !ok {
		return problemf(ruleSignedBinding, nil, "audit entry %d names %s=%d, which is not a verified decision.signed entry", e.Seq, fieldSigned, n)
	}
	if n != w.open {
		return problemf(ruleSignedBinding, nil, "audit entry %d names %s=%d, whose transaction ended before it; a signed record attests the entries of its own transaction only, and the entry was appended outside toolwarrant", e.Seq, fieldSigned, n)
	}
	return bindOutcome(e, n, o)
}

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
		return problemf(ruleSignedBinding, nil, "audit entry %d is a %s but names %s=%d, a decision of kind %s, which writes no such entry", e.Seq, e.Event, fieldSigned, n, o.kind)
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
		return problemf(ruleSignedBinding, nil, "audit entry %d moves tool %s from %s to %s under event %s but names %s=%d, a decision of kind %s, which makes no such move; the entry was appended outside toolwarrant", e.Seq, quote(e.Subject), from, to, e.Event, fieldSigned, n, o.kind)
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

// checkCrawlTransition is rule 6 for one entry after the bootstrap that
// carries no token: an entry about a tool (its detail has a state field) moves
// the state only along a transition a crawl can make. An entry with no state
// field is about a server, a crawl or a rejected name and moves no tool.
func checkCrawlTransition(e audit.Entry) error {
	state, ok := detailField(e.Detail, fieldState)
	if !ok {
		return nil
	}
	from, to, ok := strings.Cut(state, transitionArrow)
	if !ok {
		return problemf(ruleCrawl, nil, "audit entry %d about %s carries a %s field %s that is not a transition", e.Seq, quote(e.Subject), fieldState, quote(state))
	}
	if !lifecycle.CrawlMayMove(lifecycle.State(from), lifecycle.State(to)) {
		return problemf(ruleCrawl, nil, "audit entry %d moves tool %s from %s to %s under event %s, which no crawl can do; the entry was appended outside toolwarrant", e.Seq, quote(e.Subject), from, to, e.Event)
	}
	return nil
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
