package catalog

import (
	"fmt"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
	"github.com/sairam0424/toolwarrant/internal/signing"
	"github.com/sairam0424/toolwarrant/internal/trust"
)

// The anchor rule as a property (D22 (d), decision 3): rule 5's binding, as
// the anchor pass (chainMemory.requireSigned) and the walk (checkSignedBinding
// through checkLifecycleEntry) apply it, against an oracle written out field by
// field, bindContent's transition table and paused flag included.

// probeKinds are the kinds the anchor-rule property draws its outcome from:
// one of each shape the binding compares (a digest, a tool without one, a
// server), so bindContent is driven on both of its branches.
func probeKinds() []signing.Kind {
	return []signing.Kind{signing.KindApprove, signing.KindReject, signing.KindRollback, signing.KindDisable,
		signing.KindEnable, signing.KindBudgetReset, signing.KindPause, signing.KindResume}
}

// probeEvents are the events the property draws when it mutates the entry's.
func probeEvents() []string {
	return []string{string(lifecycle.EvApproved), string(lifecycle.EvRejected), string(lifecycle.EvRolledBack),
		string(lifecycle.EvSuperseded), string(lifecycle.EvProposed), string(lifecycle.EvDisabled), string(lifecycle.EvEnabled),
		string(lifecycle.EvDrifted), evBudgetReset, evServerPaused, evServerResumed}
}

// probeStates are the six lifecycle states the property draws transitions from.
func probeStates() []lifecycle.State {
	return []lifecycle.State{lifecycle.Discovered, lifecycle.PendingReview, lifecycle.Enabled,
		lifecycle.ChangedPendingReapproval, lifecycle.Disabled, lifecycle.Deprecated}
}

// mutate draws whether one field of the faithful entry is changed: one in
// eight, so that most checks sit at the boundary of the binding with zero,
// one or two fields off.
func mutate(rt *rapid.T, field string) bool {
	return rapid.IntRange(0, 7).Draw(rt, "mutate "+field) == 0
}

// drawnContent is what the drawn entry's detail says: a tool shape with the
// digest token and, unless the field is dropped, a state transition; or a
// server shape with, unless dropped, the paused flag.
type drawnContent struct {
	tool     bool
	hasField bool
	digest   string
	from, to lifecycle.State
	paused   bool
}

// detail renders the content as the Store would, followed by the token.
func (d drawnContent) detail(token int64) string {
	note := signedNote(token)
	switch {
	case d.tool && d.hasField:
		return fmt.Sprintf("digest=%s state=%s->%s last_seen=- proposals=0->0%s", orNoDigest(d.digest), d.from, d.to, note)
	case d.tool:
		return fmt.Sprintf("digest=%s last_seen=- proposals=0->0%s", orNoDigest(d.digest), note)
	case d.hasField:
		return pausedDetail(d.paused) + note
	}
	return strings.TrimSpace(note)
}

// decisionMoves is the oracle of the transition a kind's entries record: the
// lifecycle's own table for the five commands, and staying put for the budget
// reset, which touches no state.
func decisionMoves(kind signing.Kind, from, to lifecycle.State) bool {
	cmds := map[signing.Kind]lifecycle.Command{
		signing.KindApprove: lifecycle.Approve{}, signing.KindReject: lifecycle.Reject{}, signing.KindRollback: lifecycle.Rollback{},
		signing.KindDisable: lifecycle.Disable{}, signing.KindEnable: lifecycle.Enable{},
	}
	if cmd, ok := cmds[kind]; ok {
		return lifecycle.DecisionMayMove(cmd, from, to)
	}
	return from == to
}

// admittedMoves lists the transitions decisionMoves admits for kind.
func admittedMoves(kind signing.Kind) [][2]lifecycle.State {
	var out [][2]lifecycle.State
	for _, from := range probeStates() {
		for _, to := range probeStates() {
			if decisionMoves(kind, from, to) {
				out = append(out, [2]lifecycle.State{from, to})
			}
		}
	}
	return out
}

// drawContent draws the content of an entry of kind: faithful (the shape of
// the kind, the field present, an admitted transition or the flag the kind
// leaves) unless a mutation flips the shape, drops the field, draws any pair
// of states or flips the flag.
func drawContent(rt *rapid.T, kind signing.Kind, digest string) drawnContent {
	d := drawnContent{tool: kind.NamesTool(), hasField: true, digest: digest, paused: kind == signing.KindPause}
	if mutate(rt, "shape") {
		d.tool = !d.tool
	}
	if mutate(rt, "field") {
		d.hasField = false
	}
	if moves := admittedMoves(kind); len(moves) > 0 && !mutate(rt, "move") {
		m := rapid.SampledFrom(moves).Draw(rt, "admitted move")
		d.from, d.to = m[0], m[1]
	} else {
		d.from = rapid.SampledFrom(probeStates()).Draw(rt, "from")
		d.to = rapid.SampledFrom(probeStates()).Draw(rt, "to")
	}
	if mutate(rt, "paused") {
		d.paused = !d.paused
	}
	return d
}

// contentBinds is the oracle of bindContent: a tool kind's entry is a tool
// entry with a state field the kind can produce, a server kind's entry is a
// server entry whose paused flag is the one the kind leaves.
func contentBinds(kind signing.Kind, d drawnContent) bool {
	if kind.NamesTool() {
		return d.tool && d.hasField && decisionMoves(kind, d.from, d.to)
	}
	return !d.tool && d.hasField && d.paused == (kind == signing.KindPause)
}

// digestRecorded is the oracle of eventDigest: the after_hash of an approval
// or rollback, the digest token of a rejection (a tool detail carries one, a
// server detail does not), nothing for any other event.
func digestRecorded(e audit.Entry, d drawnContent) (string, bool) {
	switch e.Event {
	case string(lifecycle.EvApproved), string(lifecycle.EvRolledBack):
		return e.AfterHash, true
	case string(lifecycle.EvRejected):
		if d.tool {
			return d.digest, true
		}
		return "", true
	}
	return "", false
}

// drawEntry draws one entry against the outcome at n: faithful in every field
// (above n, the outcome's time, actor, subject and a digest it decided, a
// human, an event the kind writes, faithful content, the token n) unless a
// mutation changes the field. It returns the entry, its content and its token.
func drawEntry(rt *rapid.T, o signedOutcome, n int64, other string) (audit.Entry, drawnContent, int64) {
	e := audit.Entry{Seq: n + int64(rapid.IntRange(1, 4).Draw(rt, "above")), TS: o.ts, Actor: o.actor, ActorType: string(ActorHuman), Subject: o.subject}
	if mutate(rt, "seq") {
		e.Seq = int64(rapid.IntRange(1, int(n)).Draw(rt, "seq at or below n"))
	}
	if mutate(rt, "ts") {
		e.TS = "2026-10-16T10:00:01.000000000Z"
	}
	if mutate(rt, "actor") {
		e.Actor = "bob"
	}
	if mutate(rt, "type") {
		e.ActorType = string(ActorSystem)
	}
	if mutate(rt, "subject") {
		e.Subject = rapid.SampledFrom([]string{"alpha/sum", "beta"}).Draw(rt, "other subject")
	}
	written := make([]string, 0, len(probeEvents()))
	for _, ev := range probeEvents() {
		if kindWrites(o.kind, ev) {
			written = append(written, ev)
		}
	}
	e.Event = rapid.SampledFrom(written).Draw(rt, "written event")
	if mutate(rt, "event") {
		e.Event = rapid.SampledFrom(probeEvents()).Draw(rt, "any event")
	}
	digest := o.digest
	if mutate(rt, "digest") {
		digest = other
	}
	e.AfterHash = digest
	token := n
	if mutate(rt, "token") {
		token = rapid.SampledFrom([]int64{n - 1, 0}).Draw(rt, "other token")
	}
	content := drawContent(rt, o.kind, digest)
	e.Detail = content.detail(token)
	return e, content, token
}

// stateField renders the state field the content's detail carries, "" when
// it carries none, for the shape oracle.
func (d drawnContent) stateField() string {
	if d.tool && d.hasField {
		return fmt.Sprintf("%s->%s", d.from, d.to)
	}
	return ""
}

// drawnHistory is what the property draws about the chain before the entry:
// what the newest entry about the subject left it, when there is one, and the
// open transaction, with the first entry of it the walk saw when it saw one.
type drawnHistory struct {
	hasLast bool
	last    toolLast
	open    openTxn
}

// drawHistory draws the history around a drawn entry: faithful (the newest
// entry about the subject left the tool where the entry says it starts, and
// the transaction has no entry yet) unless a mutation forgets the newest
// entry, blanks its transition, makes it a sibling of the entry, moves the
// state it left, or gives the transaction a first entry (drawFirst).
func drawHistory(rt *rapid.T, e audit.Entry, kind signing.Kind, d drawnContent, n int64, other string) drawnHistory {
	h := drawnHistory{hasLast: true, open: openTxn{seq: n},
		last: toolLast{seq: n - 2, ts: "2026-10-16T09:00:00.000000000Z", from: lifecycle.Discovered, to: d.from}}
	switch {
	case mutate(rt, "no last"):
		h.hasLast = false
	case mutate(rt, "unknown last"):
		h.last.to = ""
	case mutate(rt, "sibling"):
		h.last = toolLast{seq: n + 1, ts: e.TS, from: d.from, to: d.to}
	case mutate(rt, "last to"):
		h.last.to = rapid.SampledFrom(probeStates()).Draw(rt, "last to")
	}
	if mutate(rt, "first") {
		h.open = drawFirst(rt, e, kind, d, n, other)
	}
	return h
}

// ownEvent is the human-only event of kind, the one its transaction writes
// last.
func ownEvent(kind signing.Kind) string {
	for _, ev := range probeEvents() {
		if isHumanOnlyEvent(ev) && kindWrites(kind, ev) {
			return ev
		}
	}
	return ""
}

// drawFirst draws the first entry of the open transaction: faithful to the
// drawn entry (the same state field and after_hash, another event written)
// unless a mutation draws its transition from the kind's own table, which the
// decision may not have taken, another after_hash, the entry's own event and
// digest among the events already written, or the decision's own event among
// them, which ends the transaction.
func drawFirst(rt *rapid.T, e audit.Entry, kind signing.Kind, d drawnContent, n int64, other string) openTxn {
	o := openTxn{seq: n, first: n + 1, state: d.stateField(), after: e.AfterHash,
		events: []txnEvent{{seq: n + 1, event: string(lifecycle.EvDiscovered), digest: orNoDigest(d.digest)}}}
	if moves := admittedMoves(kind); len(moves) > 0 && mutate(rt, "first move") {
		m := rapid.SampledFrom(moves).Draw(rt, "first move")
		o.state = fmt.Sprintf("%s->%s", m[0], m[1])
	}
	if mutate(rt, "first after") {
		o.after = other
	}
	if mutate(rt, "repeat") {
		digest, _ := detailField(e.Detail, fieldDigest)
		o.events = append(o.events, txnEvent{seq: n + 2, event: e.Event, digest: digest})
	}
	if mutate(rt, "ended") {
		o.events = append(o.events, txnEvent{seq: n + 3, event: ownEvent(kind), digest: orNoDigest(d.digest)})
	}
	return o
}

// continuityHolds is the oracle of checkContinuity, written to the rule and
// not to the code: an entry about no tool is not checked; one whose subject has
// no newest entry starts from discovered; one whose newest entry recorded no
// transition is refused; otherwise the entry starts where that entry left the
// tool, or repeats that entry's transition at its time.
func continuityHolds(e audit.Entry, d drawnContent, h drawnHistory) bool {
	if !d.tool || !d.hasField {
		return true
	}
	if !h.hasLast {
		return d.from == lifecycle.Discovered
	}
	if h.last.to == "" {
		return false
	}
	return d.from == h.last.to || (h.last.ts == e.TS && h.last.from == d.from && h.last.to == d.to)
}

// shapeHolds is the oracle of checkTransactionShape: no event and digest the
// transaction wrote already, no decision's own event written before the entry,
// and the first entry's state field and after_hash when there is one.
func shapeHolds(e audit.Entry, d drawnContent, o openTxn) bool {
	digest, _ := detailField(e.Detail, fieldDigest)
	for _, ev := range o.events {
		if (ev.event == e.Event && ev.digest == digest) || isHumanOnlyEvent(ev.event) {
			return false
		}
	}
	return o.first == 0 || (o.state == d.stateField() && o.after == e.AfterHash)
}

// The anchor rule accepts an entry only when it names the decision.signed
// entry of its own transaction and says what that decision does: for an
// outcome of every kind and an entry faithful to it in every field unless
// mutated (seq, subject, actor, type, time, event, digest, token, the state
// transition or the paused flag, the field's presence, the entry's shape),
// requireSigned accepts exactly the entries whose every field is the recorded
// outcome's, whose event the kind writes, whose digest the kind decided and
// whose content the kind produces, and the walk's checkSignedBinding accepts
// those only while that transaction is open, only when the entry starts where
// the newest entry about the tool left it or repeats that entry's transition
// at its time (the continuity rule), and only when it carries the transition
// and the after_hash of the transaction's first entry, repeats no event of it
// and comes before the decision's own event (the shape rule). A human-only
// event without a token is refused after the
// bootstrap and accepted before it; a token-less tool entry is held to the
// crawl table and to the continuity rule, and one without a state field is
// refused (the third review: the oracle had encoded the code's skip of such an
// entry as correct, and the property passed while the forgery was served).
func TestProperty_anchorRuleAcceptsOnlyTheSignedEntryOfTheSameTransaction(t *testing.T) {
	t.Parallel()
	const (
		bootstrap = 2
		n         = 5
	)
	ech, other := digestOf(t, "echo", "v1"), digestOf(t, "echo", "v2")
	rapid.Check(t, func(rt *rapid.T) {
		kind := rapid.SampledFrom(probeKinds()).Draw(rt, "kind")
		o := signedOutcome{kind: kind, subject: decisionSubject(kind, "alpha", "echo"), actor: "alice", ts: "2026-10-16T10:00:00.000000000Z"}
		if kind.NamesVersion() {
			o.digest = ech
		}
		c := newChainMemory()
		c.trust.state = trust.State{BootstrapSeq: bootstrap, ListSeq: bootstrap}
		c.signed[n] = o
		e, content, token := drawEntry(rt, o, n, other)
		h := drawHistory(rt, e, kind, content, n, other)
		if mutate(rt, "open") {
			h.open = openTxn{}
		}
		recorded, decides := digestRecorded(e, content)
		binds := token == n && e.Seq > n && e.Subject == o.subject && e.Actor == o.actor && e.ActorType == string(ActorHuman) && e.TS == o.ts &&
			kindWrites(o.kind, e.Event) && (!decides || recorded == o.digest) && contentBinds(o.kind, content)
		after := e.Seq > bootstrap
		wantAnchor := !after || !isHumanOnlyEvent(e.Event) || binds
		if got := c.requireSigned(e) == nil; got != wantAnchor {
			rt.Fatalf("requireSigned(%+v) accepted = %v, want %v (binds %v, content %+v)", e, got, wantAnchor, binds, content)
		}
		crawlOK := !content.tool || (content.hasField && lifecycle.CrawlMayMove(content.from, content.to))
		continuous := continuityHolds(e, content, h)
		w := decisionWalk{bootstrap: bootstrap, open: h.open, lookup: c.lookupSigned,
			lastState: func(string) (toolLast, bool) { return h.last, h.hasLast }}
		_, err := checkLifecycleEntry(e, w)
		wantWalk := !after || (token != 0 && binds && h.open.seq == n && continuous && shapeHolds(e, content, h.open)) ||
			(token == 0 && !isHumanOnlyEvent(e.Event) && crawlOK && continuous)
		if got := err == nil; got != wantWalk {
			rt.Fatalf("checkLifecycleEntry(%+v, history %+v) accepted = %v, want %v (content %+v): %v", e, h, got, wantWalk, content, err)
		}
	})
}
