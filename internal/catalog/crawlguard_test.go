package catalog

import (
	"fmt"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
	"github.com/sairam0424/toolwarrant/internal/signing"
)

// Rule 6, the crawl-transition guard, and the continuity rule that makes its
// from half trustworthy (decisioncontinuity.go), probed with the access D14
// grants: after a signed disable of echo, whoever can write the file appends a
// correctly sealed crawl-shaped entry about echo and edits the state column to
// what the entry says it left, which the state anchor would otherwise take.
// The adversarial review of PR 7.5 (finding 1) showed that rule 6 as first
// written read the from half from the forged entry itself, so an entry that
// confessed from=disabled was refused while one that lied about where the tool
// was (changed_pending_reapproval->enabled, enabled->enabled,
// enabled->changed_pending_reapproval, each a move a crawl may make) was
// served on every path with Integrity clean.

// crawlSentence is rule 6's sentence for a transition no crawl makes.
func crawlSentence(seq int64, subject string, from, to lifecycle.State, event string) string {
	return fmt.Sprintf("audit entry %d moves tool %s from %s to %s under event %s, which no crawl can do; the entry was appended outside toolwarrant", seq, quote(subject), from, to, event)
}

// continuitySentence is the continuity rule's sentence: the entry says the
// tool moves from `from`, but the newest entry about it (seq newest) left it
// in `left`.
func continuitySentence(seq int64, subject string, from lifecycle.State, newest int64, left lifecycle.State) string {
	return fmt.Sprintf("audit entry %d says tool %s moves from %s but the newest entry about it (seq %d) left it %s; the entry was appended outside toolwarrant", seq, quote(subject), from, newest, left)
}

// crawlShaped is a sealed entry about alpha/echo under a crawl's event by by,
// keeping the approved digest d and saying state=from->to.
func crawlShaped(by Actor, event, d string, from, to lifecycle.State) audit.Entry {
	return toolEntry{by: by, event: event, subject: "alpha/echo", digest: d, before: d, after: d, from: from, to: to, lastSeen: d}.entry()
}

// crawlProbe is one crawl-shaped forgery against a disabled echo: the event
// and the transition it claims. A probe that confesses from=disabled is refused
// by the crawl table; one that lies about the from half, with a move the table
// admits, is refused by the continuity rule against the disable's own entry.
type crawlProbe struct {
	event    string
	from, to lifecycle.State
}

// crawlProbes are the confessing probe and the four lying ones of the review.
func crawlProbes() []crawlProbe {
	return []crawlProbe{
		{string(lifecycle.EvReverted), lifecycle.Disabled, lifecycle.Enabled},
		{string(lifecycle.EvReverted), lifecycle.ChangedPendingReapproval, lifecycle.Enabled},
		{string(lifecycle.EvReverted), lifecycle.Enabled, lifecycle.Enabled},
		{string(lifecycle.EvReturned), lifecycle.Enabled, lifecycle.Enabled},
		{string(lifecycle.EvDrifted), lifecycle.Enabled, lifecycle.ChangedPendingReapproval},
	}
}

// sentence is the fixed sentence the probe is refused with: the crawl table's
// when it starts from disabled, the continuity rule's otherwise, naming the
// disable's lifecycle entry at disabled.
func (p crawlProbe) sentence(seq, disabled int64) string {
	if p.from == lifecycle.Disabled {
		return crawlSentence(seq, "alpha/echo", p.from, p.to, p.event)
	}
	return continuitySentence(seq, "alpha/echo", p.from, disabled, lifecycle.Disabled)
}

// Rule 6 and the continuity rule: a correctly sealed crawl-shaped entry about
// a disabled tool, with the column edited to what it says it left, is refused
// after the bootstrap whether its actor is the crawler or a person and whether
// it confesses from=disabled (the crawl table) or lies about the from half
// with a move the table admits (the continuity rule: the newest entry about
// the tool, the disable's own, left it disabled); Integrity counts each under
// CrawlTransitionsForged. Before the bootstrap the confessing entry is
// accepted and, with the column edited to match, the disabled tool is served
// again: the legacy residual the v0.4 plan states (section 5, rule 6 applied
// after the bootstrap only), recorded here as the code has it.
func TestWalk_RefusesACrawlShapedEntryThatLeavesDisabled(t *testing.T) {
	t.Parallel()
	for _, p := range crawlProbes() {
		for name, by := range map[string]Actor{"the system actor": crawler, "a human actor": alice} {
			t.Run(fmt.Sprintf("%s %s->%s by %s", p.event, p.from, p.to, name), func(t *testing.T) {
				t.Parallel()
				s, path, alice, _ := trustedCatalog(t)
				d := digestOf(t, "echo", "v1")
				r := mustDecide(t, s, alice, signing.KindDisable, "alpha", "echo", "")
				db := rawDB(t, path)
				seq := appendEntry(t, db, crawlShaped(by, p.event, d, p.from, p.to))
				mustExec(t, db, `UPDATE tools SET state = ? WHERE name = 'echo'`, string(p.to))
				rep := walkRefuses(t, s, path, seq, p.sentence(seq, r.Seq+1))
				if rep.CrawlTransitionsForged != 1 || rep.UnsignedDecisionsAfterBootstrap != 0 {
					t.Errorf("Integrity = %+v, want exactly one forged crawl transition", rep)
				}
			})
		}
	}
	t.Run("before the bootstrap, the legacy residual", func(t *testing.T) {
		t.Parallel()
		s, path := newStoreAt(t, lifecycle.DefaultPolicy())
		d := approvedEcho(t, s)
		if err := s.Disable(bg, "alpha", "echo", alice); err != nil {
			t.Fatal(err)
		}
		db := rawDB(t, path)
		appendEntry(t, db, crawlShaped(crawler, string(lifecycle.EvReverted), d, lifecycle.Disabled, lifecycle.Enabled))
		mustExec(t, db, `UPDATE tools SET state = 'enabled' WHERE name = 'echo'`)
		snap, err := s.Snapshot(bg, "alpha")
		if err != nil || !snap.Serves("echo", d) {
			t.Errorf("before any bootstrap the forged revert is served = %v, %v; this is the stated legacy residual, and this assertion records it", snap.Serves("echo", d), err)
		}
		fresh, err := OpenWith(path, OpenOptions{ReadOnly: true})
		if err != nil {
			t.Fatalf("a fresh open before any bootstrap = %v; rule 6 applies after the bootstrap only", err)
		}
		_ = fresh.Close()
	})
}
