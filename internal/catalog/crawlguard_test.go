package catalog

import (
	"database/sql"
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
	return fmt.Sprintf("audit entry %d moves tool %s from %s to %s under event %s, which no crawl can do; the entry was appended outside toolwarrant", seq, quote(subject), quote(string(from)), quote(string(to)), quote(event))
}

// continuitySentence is the continuity rule's sentence: the entry says the
// tool moves from `from`, but the newest entry about it (seq newest) left it
// in `left`.
func continuitySentence(seq int64, subject string, from lifecycle.State, newest int64, left lifecycle.State) string {
	return fmt.Sprintf("audit entry %d says tool %s moves from %s but the newest entry about it (seq %d) left it %s; the entry was appended outside toolwarrant", seq, quote(subject), quote(string(from)), newest, quote(string(left)))
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

// statelessProbe is one sealed tool entry about alpha/echo without a state
// field: its event and its detail, which starts with digest= as every entry
// the catalog writes about a tool does. The third review of PR 7.5 sealed such
// an entry after a signed disable: the walk accepted it (rule 6 and the
// continuity rule read nothing from an entry without a state field), recorded
// it as the newest entry about echo with no transition, and the continuity
// rule then skipped the next entry, which claimed any start a crawl admits.
type statelessProbe struct {
	name   string
	event  string
	detail string
}

// statelessProbes are the four vehicles of the review, each keeping the
// approved digest d.
func statelessProbes(d string) []statelessProbe {
	return []statelessProbe{
		{"the full tool detail minus its state field", string(lifecycle.EvReverted),
			fmt.Sprintf("%s=%s %s=%s %s=0->0", fieldDigest, d, fieldLastSeen, d, fieldProposals)},
		{"the digest field alone, naming no digest", string(lifecycle.EvReverted), fieldDigest + "=" + noDigest},
		{"the digest field alone under tool.returned", string(lifecycle.EvReturned), fieldDigest + "=" + d},
		{"the digest field alone under tool.drifted", string(lifecycle.EvDrifted), fieldDigest + "=" + d},
	}
}

// entry is the probe sealed by the crawler about alpha/echo, keeping d.
func (p statelessProbe) entry(d string) audit.Entry {
	return audit.Entry{Actor: crawler.Name, ActorType: string(crawler.Type), Event: p.event, Subject: "alpha/echo",
		BeforeHash: d, AfterHash: d, Detail: p.detail}
}

// statelessSentence is rule 6's sentence for a tool entry without a state
// field.
func statelessSentence(seq int64, subject string) string {
	return fmt.Sprintf("audit entry %d about %s is a tool entry (its detail starts with digest=) but carries no state field; every entry the catalog writes about a tool records its transition, so the entry was appended outside toolwarrant", seq, quote(subject))
}

// noTransitionSentence is the continuity rule's sentence when the newest
// entry about the tool (seq newest) recorded no transition.
func noTransitionSentence(seq int64, subject string, from lifecycle.State, newest int64) string {
	return fmt.Sprintf("audit entry %d says tool %s moves from %s but the newest entry about it (seq %d) records no transition; the entry was appended outside toolwarrant", seq, quote(subject), quote(string(from)), newest)
}

// noEarlierEntrySentence is the continuity rule's sentence for a tool the
// chain holds no entry about whose first entry does not start from discovered.
func noEarlierEntrySentence(seq int64, subject string, from lifecycle.State) string {
	return fmt.Sprintf("audit entry %d says tool %s moves from %s but no earlier entry is about the tool, and the first entry about a tool starts from discovered; the entry was appended outside toolwarrant", seq, quote(subject), quote(string(from)))
}

// lyingRevert is the lie of the review: a sealed tool.reverted by the crawler
// about alpha/echo saying changed_pending_reapproval->enabled, a move a crawl
// may make, with the column edited to match.
func lyingRevert(t *testing.T, db *sql.DB, d string) int64 {
	t.Helper()
	seq := appendEntry(t, db, crawlShaped(crawler, string(lifecycle.EvReverted), d, lifecycle.ChangedPendingReapproval, lifecycle.Enabled))
	mustExec(t, db, `UPDATE tools SET state = 'enabled' WHERE name = 'echo'`)
	return seq
}

// Rule 6 and the continuity rule: a correctly sealed crawl-shaped entry about
// a disabled tool, with the column edited to what it says it left, is refused
// after the bootstrap whether its actor is the crawler or a person and whether
// it confesses from=disabled (the crawl table) or lies about the from half
// with a move the table admits (the continuity rule: the newest entry about
// the tool, the disable's own, left it disabled); Integrity counts each under
// CrawlTransitionsForged. A tool entry without a state field is refused as
// such, so it cannot blank the memory the lie after it is checked against;
// Integrity counts the stateless entry and the lie built on it, each a forgery
// of its own. The state the rule compares with is tracked from the genesis, so
// a tool disabled before the bootstrap is protected by its pre-bootstrap entry
// against a lying entry appended after it, and a stateless entry planted
// before the bootstrap refuses every entry about the tool after it rather than
// freeing them. A tool the chain holds no entry about may start from
// discovered only, where every tool is created. Before the bootstrap the
// confessing entry is accepted and, with the column edited to match, the
// disabled tool is served again: the legacy residual the v0.4 plan states
// (section 5, rule 6 applied after the bootstrap only), recorded here as the
// code has it.
func TestWalk_RefusesACrawlShapedEntryThatLeavesDisabled(t *testing.T) {
	t.Parallel()
	for _, p := range statelessProbes(digestOf(t, "echo", "v1")) {
		t.Run("a tool entry without a state field ("+p.name+"), then a lying revert", func(t *testing.T) {
			t.Parallel()
			s, path, alice, _ := trustedCatalog(t)
			d := digestOf(t, "echo", "v1")
			mustDecide(t, s, alice, signing.KindDisable, "alpha", "echo", "")
			db := rawDB(t, path)
			seq := appendEntry(t, db, p.entry(d))
			lie := lyingRevert(t, db, d)
			rep := walkRefuses(t, s, path, seq, statelessSentence(seq, "alpha/echo"))
			problemMentioning(t, rep, noTransitionSentence(lie, "alpha/echo", lifecycle.ChangedPendingReapproval, seq))
			if rep.CrawlTransitionsForged != 2 || rep.UnsignedDecisionsAfterBootstrap != 0 {
				t.Errorf("Integrity = %+v, want the stateless entry and the lie built on it each counted as a forged crawl transition", rep)
			}
		})
	}
	t.Run("a tool entry without a state field before the bootstrap, lied about after it", func(t *testing.T) {
		t.Parallel()
		s, path := newStoreAt(t, lifecycle.DefaultPolicy())
		d := approvedEcho(t, s)
		if err := s.Disable(bg, "alpha", "echo", alice); err != nil {
			t.Fatal(err)
		}
		db := rawDB(t, path)
		stateless := appendEntry(t, db, statelessProbes(d)[0].entry(d))
		op := newOperator(t, "alice")
		mustSetTrust(t, s, 1, op, op)
		seq := lyingRevert(t, db, d)
		rep := walkRefuses(t, s, path, seq, noTransitionSentence(seq, "alpha/echo", lifecycle.ChangedPendingReapproval, stateless))
		if rep.CrawlTransitionsForged != 1 || rep.UnsignedDecisionsAfterBootstrap != 0 {
			t.Errorf("Integrity = %+v, want exactly one forged crawl transition", rep)
		}
	})
	t.Run("a tool the chain holds no entry about, starting from enabled", func(t *testing.T) {
		t.Parallel()
		s, path, _, _ := trustedCatalog(t)
		d := digestOf(t, "ghost", "v1")
		ghost := toolEntry{by: crawler, event: string(lifecycle.EvReturned), subject: "alpha/ghost", digest: d, before: d, after: d,
			from: lifecycle.Enabled, to: lifecycle.Enabled, lastSeen: d}
		seq := appendEntry(t, rawDB(t, path), ghost.entry())
		rep := walkRefuses(t, s, path, seq, noEarlierEntrySentence(seq, "alpha/ghost", lifecycle.Enabled))
		if rep.CrawlTransitionsForged != 1 || rep.UnsignedDecisionsAfterBootstrap != 0 {
			t.Errorf("Integrity = %+v, want exactly one forged crawl transition", rep)
		}
	})
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
	t.Run("disabled before the bootstrap, lied about after it", func(t *testing.T) {
		t.Parallel()
		s, path := newStoreAt(t, lifecycle.DefaultPolicy())
		d := approvedEcho(t, s)
		if err := s.Disable(bg, "alpha", "echo", alice); err != nil {
			t.Fatal(err)
		}
		disabled := int64(auditCount(t, s))
		op := newOperator(t, "alice")
		mustSetTrust(t, s, 1, op, op)
		db := rawDB(t, path)
		seq := appendEntry(t, db, crawlShaped(crawler, string(lifecycle.EvReverted), d, lifecycle.ChangedPendingReapproval, lifecycle.Enabled))
		mustExec(t, db, `UPDATE tools SET state = 'enabled' WHERE name = 'echo'`)
		rep := walkRefuses(t, s, path, seq, continuitySentence(seq, "alpha/echo", lifecycle.ChangedPendingReapproval, disabled, lifecycle.Disabled))
		if rep.CrawlTransitionsForged != 1 || rep.UnsignedDecisionsAfterBootstrap != 0 {
			t.Errorf("Integrity = %+v, want exactly one forged crawl transition", rep)
		}
	})
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
