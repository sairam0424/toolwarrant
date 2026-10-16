package catalog

import (
	"slices"
	"strings"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// The two rules of the walk that read what the chain said before the entry
// (the adversarial review of PR 7.5, findings 1 and 2). Rules 5 and 6 as
// first written compared an entry's state=A->B with a transition table and
// took the A half from the entry itself, so a forger who can write the file
// re-enabled a disabled tool with a correctly sealed crawl-shaped entry that
// lied about where the tool was (state=changed_pending_reapproval->enabled,
// a move a crawl may make) plus one UPDATE of the column, and re-served a
// tool its own enable had put under review with a sealed tool.enabled saying
// disabled->enabled (a move the enable kind may make under the other policy)
// that borrowed the open enable's token. The continuity rule (checkContinuity)
// makes the A half trustworthy: the walk carries, per tool subject, what the
// newest entry about the tool left it (toolLast, chainMemory.states, tracked
// from the genesis so the first entry after the bootstrap is checked against
// the state before it), and after the bootstrap every entry about a tool must
// move it from that state, unless it is a sibling of that entry: auditTool
// writes one entry per lifecycle event of one operation, each with the
// operation's before and after, so the entries of one operation repeat its
// transition at its time. The transaction-shape rule (checkTransactionShape,
// openTxn) is the second belt on the token: every entry naming signed=N
// carries the state=A->B and the after_hash of the first entry that named it,
// and writes each (event, digest) pair once (a crawl's reappearance writes two
// version.superseded of two digests in one operation; a decision never
// repeats a pair). Both rules run in the walk only; the anchor pass
// (requireSigned) is unchanged, so the serving path still reads no bytes and
// parses two tokens per anchored entry. Before the bootstrap the memory is
// kept and nothing is refused (O-12); a tool whose newest entry carries no
// transition, which only a legacy history writes, is not checked.

// toolLast is what the newest entry about a tool left: the entry's seq and
// time and the transition its state field records, from and to both empty
// when the field is absent or not a transition.
type toolLast struct {
	seq      int64
	ts       string
	from, to lifecycle.State
}

// stateField is the state field of one entry as the walk reads it once:
// whether the detail carries one, whether it is a transition, and its halves.
type stateField struct {
	raw        string
	present    bool
	transition bool
	from, to   lifecycle.State
}

// readStateField parses the state field of a detail.
func readStateField(detail string) stateField {
	raw, present := detailField(detail, fieldState)
	if !present {
		return stateField{}
	}
	from, to, ok := strings.Cut(raw, transitionArrow)
	return stateField{raw: raw, present: true, transition: ok, from: lifecycle.State(from), to: lifecycle.State(to)}
}

// notATransition is the refusal of a state field that is not A->B.
func (f stateField) notATransition(e audit.Entry, rule signedRule) error {
	return problemf(rule, nil, "audit entry %d about %s carries a %s field %s that is not a transition", e.Seq, quote(e.Subject), fieldState, quote(f.raw))
}

// leftState is what one entry left its tool, for the memory: false when the
// entry is about no tool, that is, its detail is neither a tool detail nor
// carries a state field (a server, crawl, rejected-name or signed entry).
func leftState(e audit.Entry, f stateField) (toolLast, bool) {
	if !f.present && !isToolDetail(e.Detail) {
		return toolLast{}, false
	}
	l := toolLast{seq: e.Seq, ts: e.TS}
	if f.transition {
		l.from, l.to = f.from, f.to
	}
	return l, true
}

// checkContinuity is the from half of rules 5 and 6: after the bootstrap an
// entry about a tool moves it from the state the newest entry about the tool
// left it in, unless it is a sibling of that entry (the same transition at the
// same time, the entries of one operation). An entry without a state field is
// about no tool; a tool whose newest entry recorded no transition is not
// checked. rule is the counter Integrity files the refusal under.
func checkContinuity(e audit.Entry, f stateField, w decisionWalk, rule signedRule) error {
	if !f.present {
		return nil
	}
	if !f.transition {
		return f.notATransition(e, rule)
	}
	last, ok := w.lastState(e.Subject)
	if !ok || last.to == "" || f.from == last.to || last.isSibling(e.TS, f) {
		return nil
	}
	return problemf(rule, nil, "audit entry %d says tool %s moves from %s but the newest entry about it (seq %d) left it %s; the entry was appended outside toolwarrant",
		e.Seq, quote(e.Subject), f.from, last.seq, last.to)
}

// isSibling reports whether an entry at ts recording f belongs to the same
// operation as the newest entry: the same transition at the same time.
func (l toolLast) isSibling(ts string, f stateField) bool {
	return l.ts == ts && l.from == f.from && l.to == f.to
}

// openTxn is the decision transaction open at a point of the chain: the seq
// of its decision.signed entry (0 when none is open), the seq of the first
// entry that named it with that entry's state field and after_hash (first is
// 0 until one did), and the (event, digest) pairs its entries wrote so far.
type openTxn struct {
	seq    int64
	first  int64
	state  string
	after  string
	events []txnEvent
}

// txnEvent is one entry of a decision transaction as the shape rule remembers
// it.
type txnEvent struct {
	seq    int64
	event  string
	digest string
}

// extend returns the transaction with e recorded as one of its entries; o is
// left as it was.
func (o openTxn) extend(e audit.Entry) openTxn {
	digest, _ := detailField(e.Detail, fieldDigest)
	next := o
	next.events = append(slices.Clone(o.events), txnEvent{seq: e.Seq, event: e.Event, digest: digest})
	if o.first == 0 {
		next.first = e.Seq
		next.state, _ = detailField(e.Detail, fieldState)
		next.after = e.AfterHash
	}
	return next
}

// checkTransactionShape holds one entry naming signed=o.seq to the shape of
// its transaction: no (event, digest) pair twice, and the state field and the
// after_hash of the first entry that named the token, because auditTool
// writes the whole operation's before and after on every event.
func checkTransactionShape(e audit.Entry, o openTxn) error {
	digest, _ := detailField(e.Detail, fieldDigest)
	for _, ev := range o.events {
		if ev.event == e.Event && ev.digest == digest {
			return problemf(ruleSignedBinding, nil, "audit entry %d is a second %s of digest %s under %s=%d (entry %d wrote the first); a decision writes each of its events once",
				e.Seq, e.Event, shownDigest(fromNoDigest(digest)), fieldSigned, o.seq, ev.seq)
		}
	}
	if o.first == 0 {
		return nil
	}
	if state, _ := detailField(e.Detail, fieldState); state != o.state {
		return problemf(ruleSignedBinding, nil, "audit entry %d names %s=%d and says %s=%s but the first entry of that transaction (seq %d) says %s=%s; the entries of one decision record one transition",
			e.Seq, fieldSigned, o.seq, fieldState, quote(state), o.first, fieldState, quote(o.state))
	}
	if e.AfterHash != o.after {
		return problemf(ruleSignedBinding, nil, "audit entry %d names %s=%d and records after_hash %s but the first entry of that transaction (seq %d) records %s; the entries of one decision record one approved digest",
			e.Seq, fieldSigned, o.seq, shownDigest(e.AfterHash), o.first, shownDigest(o.after))
	}
	return nil
}

// lookupState returns what the walk recorded as the newest entry about a tool.
func (c *chainMemory) lookupState(subject string) (toolLast, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	l, ok := c.states[subject]
	return l, ok
}
