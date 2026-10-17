package catalog

import (
	"strconv"

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
// content is what the kind does (bindContent, decisionbind.go): a tool entry's
// state=A->B is a transition the kind can make (lifecycle.DecisionMayMove; a
// budget reset stays) and a server entry's paused flag is the one the kind
// leaves; then the entry moves its tool from the state the newest entry about
// the tool left it in (checkContinuity, decisioncontinuity.go) and fits the
// shape of its transaction, one transition, one after_hash, each event once
// (checkTransactionShape). The contiguity rule is what refuses a replay: a
// correctly sealed version.approved appended later, naming a decision.signed
// that alice did make, with her time and her digest, would otherwise undo a
// disable she made since. The content rule is what refuses a borrowed token
// that says the opposite of its decision; the continuity rule is what refuses
// a borrowed token that says what the decision could have done under another
// policy but did not, such as a tool.enabled saying disabled->enabled while
// the enable's own entries left the tool in pending_review. Rule 6,
// checkCrawlTransition: after the bootstrap, an entry about a tool that
// carries no token moves the tool's state only along a transition a crawl can
// make (lifecycle.CrawlMayMove), and from the state the chain left it in, so
// neither a sealed tool.reverted with state=disabled->enabled nor one with
// state=changed_pending_reapproval->enabled appended without a key re-enables
// anything; a tool entry that records no transition at all is refused as
// such, since every entry the catalog writes about a tool carries one, so it
// cannot blank the memory the next entry is checked against (the third
// review). Before the bootstrap nothing is refused (O-12): approvals made
// then stand by chain anchoring alone, and the legacy residual is stated; the
// memory of every tool's state is kept from the genesis all the same. Every
// failure is ErrCorrupt with a fixed sentence naming the entry; the walk stops
// at the first and records nothing of its page. Every value a sentence prints
// that it read from the entry and did not first match against a known
// constant (a state half; the event of the crawl guard's, the content
// binding's and the kind sentence) goes through quote: the bytes were chosen
// by whoever wrote the entry, and the sentence ends in a terminal or a log
// (CLAUDE.md, strconv.Quote in logs). The event names of the sentences whose
// match already proved them (the unsigned-decision, digest, paused-flag,
// shape-rule and no-trust-list sentences) stay bare, as does the lifecycle
// constant the first-entry sentence names. The anchor pass applies the
// binding of rule 5 to every entry it anchors
// (chainMemory.requireSigned, decisionbind.go) with two token parses (the
// signed= token, then the state field or the paused flag) and one map lookup,
// reads no bytes, and leaves the continuity and shape rules to the walk that
// recorded the entry.

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

// checkDecisionRecord is rule 2 and rule 4 for one decision.signed entry whose
// signature verified and whose payload checkSignedEntryCrypto parsed as d and
// bound to the entry (rule 1, trustwalk.go): the payload names the entry's
// actor, the kind and digest tokens and the subject say what the payload says,
// a list is in force and it names the signing key for the entry's actor. It
// returns the outcome the signed= binding of the lifecycle entries compares
// (rule 5).
func checkDecisionRecord(e audit.Entry, rec signing.Record, d signing.Decision, state trust.State) (*signedOutcome, error) {
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
// decision transaction open at this point of the chain (openTxn; seq 0 when
// the last entry belonged to none), how to find the outcome the walk recorded
// for a verified decision.signed entry, and what the newest entry about a tool
// left it (decisioncontinuity.go).
type decisionWalk struct {
	bootstrap int64
	open      openTxn
	lookup    func(seq int64) (signedOutcome, bool)
	lastState func(subject string) (toolLast, bool)
}

// lifecycleStep is what checkLifecycleEntry hands back for one accepted entry:
// the decision transaction open after it (the one the entry named when it
// carries a token, none otherwise) and, when the entry is about a tool, what
// it left the tool, which the caller records.
type lifecycleStep struct {
	open openTxn
	left toolLast
	tool bool
}

// checkLifecycleEntry applies rule 5 and rule 6 to one entry that carries no
// signed record itself. Before the bootstrap it accepts everything and only
// records what the entry left its tool (O-12).
func checkLifecycleEntry(e audit.Entry, w decisionWalk) (lifecycleStep, error) {
	f := readStateField(e.Detail)
	step := lifecycleStep{}
	step.left, step.tool = leftState(e, f)
	if w.bootstrap == 0 || e.Seq <= w.bootstrap {
		return step, nil
	}
	token, signed := detailField(e.Detail, fieldSigned)
	switch {
	case signed:
		open, err := checkSignedBinding(e, token, f, w)
		if err != nil {
			return lifecycleStep{}, err
		}
		step.open = open
		return step, nil
	case isHumanOnlyEvent(e.Event):
		return lifecycleStep{}, errUnsignedDecision(e, w.bootstrap)
	}
	if err := checkCrawlTransition(e, f); err != nil {
		return lifecycleStep{}, err
	}
	if err := checkContinuity(e, f, w, ruleCrawl); err != nil {
		return lifecycleStep{}, err
	}
	return step, nil
}

// errUnsignedDecision is rule 5's refusal of a human-only event after the
// bootstrap that names no signed record.
func errUnsignedDecision(e audit.Entry, bootstrap int64) error {
	return problemf(ruleSignedBinding, nil, "audit entry %d is a %s after the trust bootstrap (entry %d) and names no signed record; the entry was appended outside toolwarrant", e.Seq, e.Event, bootstrap)
}

// checkSignedBinding is rule 5 for one entry that carries signed=token: the
// token names a verified decision.signed entry below it whose transaction is
// still open, the outcome binds the entry (bindOutcome), the entry moves its
// tool from the state the chain left it in (checkContinuity) and it fits the
// shape of its transaction (checkTransactionShape). It returns the transaction
// with the entry recorded.
func checkSignedBinding(e audit.Entry, token string, f stateField, w decisionWalk) (openTxn, error) {
	n, err := strconv.ParseInt(token, 10, 64)
	if err != nil || n < 1 || n >= e.Seq {
		return openTxn{}, problemf(ruleSignedBinding, nil, "audit entry %d names %s=%s, which is not the seq of a decision.signed entry below it", e.Seq, fieldSigned, quote(token))
	}
	o, ok := w.lookup(n)
	if !ok {
		return openTxn{}, problemf(ruleSignedBinding, nil, "audit entry %d names %s=%d, which is not a verified decision.signed entry", e.Seq, fieldSigned, n)
	}
	if n != w.open.seq {
		return openTxn{}, problemf(ruleSignedBinding, nil, "audit entry %d names %s=%d, whose transaction ended before it; a signed record attests the entries of its own transaction only, and the entry was appended outside toolwarrant", e.Seq, fieldSigned, n)
	}
	if err := bindOutcome(e, n, o); err != nil {
		return openTxn{}, err
	}
	if err := checkContinuity(e, f, w, ruleSignedBinding); err != nil {
		return openTxn{}, err
	}
	if err := checkTransactionShape(e, w.open); err != nil {
		return openTxn{}, err
	}
	return w.open.extend(e), nil
}

// checkCrawlTransition is rule 6 for one entry after the bootstrap that
// carries no token: an entry about a tool moves the state only along a
// transition a crawl can make; checkContinuity then requires the from half to
// be where the chain left the tool. A tool entry (its detail starts with
// digest=, as every entry auditTool and the budget reset write) that carries
// no state field is refused as such: every entry the catalog writes about a
// tool records its transition, and an entry that records none would otherwise
// become the newest entry about the tool with nothing for the continuity rule
// to compare the next entry with (the third review of PR 7.5). An entry with
// no state field whose detail is not a tool detail is about a server, a crawl
// or a rejected name and moves no tool.
func checkCrawlTransition(e audit.Entry, f stateField) error {
	if !f.present {
		if isToolDetail(e.Detail) {
			return problemf(ruleCrawl, nil, "audit entry %d about %s is a tool entry (its detail starts with %s=) but carries no %s field; every entry the catalog writes about a tool records its transition, so the entry was appended outside toolwarrant", e.Seq, quote(e.Subject), fieldDigest, fieldState)
		}
		return nil
	}
	if !f.transition {
		return f.notATransition(e, ruleCrawl)
	}
	if !lifecycle.CrawlMayMove(f.from, f.to) {
		return problemf(ruleCrawl, nil, "audit entry %d moves tool %s from %s to %s under event %s, which no crawl can do; the entry was appended outside toolwarrant", e.Seq, quote(e.Subject), quote(string(f.from)), quote(string(f.to)), quote(e.Event))
	}
	return nil
}
