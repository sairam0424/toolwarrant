package catalog

import (
	"fmt"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
	"github.com/sairam0424/toolwarrant/internal/signing"
)

// Rule 5's binding (decisionwalk.go, bindOutcome), probed token by token with
// the access D14 grants: after a real signed decision whose transaction is
// open at the head, whoever can write the file appends a correctly sealed
// entry naming its token, and edits the column the entry would anchor. The
// chain is intact; the binding is what refuses the entry, and Integrity
// counts it under UnsignedDecisionsAfterBootstrap.

// bindingProbe is one forgery against the binding: the real decision that
// opens the transaction (an approval of sum unless decide says otherwise),
// whether a crawl separates it from the forgery, the sealed entry the forger
// appends given the decision.signed seq and its time, the column edit that
// would make the forgery served, and the fixed sentence.
type bindingProbe struct {
	name     string
	decide   func(t *testing.T, s *Store, alice operator) Receipt
	between  bool
	forge    func(n int64, ts string) audit.Entry
	update   string
	sentence func(seq, n int64, ts string) string
}

// approveSum, disableEcho, pauseAlpha and resetEchoBudget are the real
// decisions the probes borrow a token from; the last one has a crawl propose
// echo v2 (a budget to reset) and disables echo first, so the budget reset's
// transaction is the one open at the head.
func approveSum(t *testing.T, s *Store, alice operator) Receipt {
	return mustDecide(t, s, alice, signing.KindApprove, "alpha", "sum", pendingSum(t))
}

func disableEcho(t *testing.T, s *Store, alice operator) Receipt {
	return mustDecide(t, s, alice, signing.KindDisable, "alpha", "echo", "")
}

func pauseAlpha(t *testing.T, s *Store, alice operator) Receipt {
	return mustDecide(t, s, alice, signing.KindPause, "alpha", "", "")
}

func resetEchoBudget(t *testing.T, s *Store, alice operator) Receipt {
	mustCrawl(t, s, "alpha", tool("echo", "v2"), tool("sum", "v1"))
	disableEcho(t, s, alice)
	return mustDecide(t, s, alice, signing.KindBudgetReset, "alpha", "echo", "")
}

// echoLeavesDisabled is a sealed entry about alpha/echo under event, by alice
// at ts, with state=disabled->enabled and the borrowed token: what the state
// anchor would take as echo's state after the column is edited to match.
func echoLeavesDisabled(event, digest, approved, lastSeen string, n int64, ts string) audit.Entry {
	return toolEntry{by: alice, event: event, subject: "alpha/echo", digest: digest, before: approved, after: approved,
		from: lifecycle.Disabled, to: lifecycle.Enabled, lastSeen: lastSeen, note: signedNote(n), ts: ts}.entry()
}

// serverEntry is a sealed entry about alpha by alice at ts with detail.
func serverEntry(event, detail string, ts string) audit.Entry {
	return audit.Entry{TS: ts, Actor: "alice", ActorType: string(ActorHuman), Event: event, Subject: "alpha", Detail: detail}
}

// noSuchMove is the sentence of a tool entry whose transition the kind cannot
// make.
func noSuchMove(seq int64, event string, n int64, kind signing.Kind) string {
	return fmt.Sprintf(`audit entry %d moves tool "alpha/echo" from disabled to enabled under event %s but names signed=%d, a decision of kind %s, which makes no such move; the entry was appended outside toolwarrant`, seq, event, n, kind)
}

const (
	enableEcho   = `UPDATE tools SET state = 'enabled' WHERE name = 'echo'`
	unpauseAlpha = `UPDATE servers SET paused = 0 WHERE name = 'alpha'`
)

// tokenProbes are the probes of the token itself: one that names no
// decision.signed entry, one of another subject, another actor, another
// transaction (a replay of alice's own record after a crawl, with her time
// copied), one whose kind writes no such event, and one whose digest is not
// the one decided.
func tokenProbes(t *testing.T) []bindingProbe {
	t.Helper()
	d, d2 := digestOf(t, "sum", "v1"), digestOf(t, "sum", "v2")
	return []bindingProbe{
		{"a token above the entry", approveSum, false,
			func(n int64, ts string) audit.Entry { return forgedApproval(alice, "sum", d, " signed=9999").entry() }, "",
			func(seq, n int64, ts string) string {
				return fmt.Sprintf(`audit entry %d names signed="9999", which is not the seq of a decision.signed entry below it`, seq)
			}},
		{"a token naming a crawl entry", approveSum, false,
			func(n int64, ts string) audit.Entry { return forgedApproval(alice, "sum", d, " signed=1").entry() }, "",
			func(seq, n int64, ts string) string {
				return fmt.Sprintf("audit entry %d names signed=1, which is not a verified decision.signed entry", seq)
			}},
		{"another subject", approveSum, false,
			func(n int64, ts string) audit.Entry {
				f := forgedApproval(alice, "echo", digestOf(t, "echo", "v1"), signedNote(n))
				f.ts = ts
				return f.entry()
			}, "",
			func(seq, n int64, ts string) string {
				return fmt.Sprintf("audit entry %d names signed=%d, a decision.signed about \"alpha/sum\" by \"alice\" at %s, but the entry is about \"alpha/echo\"", seq, n, ts)
			}},
		{"another actor", approveSum, false,
			func(n int64, ts string) audit.Entry {
				f := forgedApproval(bob, "sum", d, signedNote(n))
				f.ts = ts
				return f.entry()
			}, "",
			func(seq, n int64, ts string) string {
				return "the entries of one decision share its subject, actor and time"
			}},
		{"another transaction, alice's time copied", approveSum, true,
			func(n int64, ts string) audit.Entry {
				f := forgedApproval(alice, "sum", d, signedNote(n))
				f.ts = ts
				return f.entry()
			}, "",
			func(seq, n int64, ts string) string {
				return fmt.Sprintf("audit entry %d names signed=%d, whose transaction ended before it", seq, n)
			}},
		{"a kind that writes no such event", approveSum, false,
			func(n int64, ts string) audit.Entry {
				return toolEntry{by: alice, event: string(lifecycle.EvEnabled), subject: "alpha/sum", before: d, after: d,
					from: lifecycle.Enabled, to: lifecycle.Enabled, lastSeen: d, note: signedNote(n), ts: ts}.entry()
			}, "",
			func(seq, n int64, ts string) string {
				return fmt.Sprintf("audit entry %d is a tool.enabled but names signed=%d, a decision of kind approve, which writes no such entry", seq, n)
			}},
		{"a digest that was not decided", approveSum, false,
			func(n int64, ts string) audit.Entry {
				f := forgedApproval(alice, "sum", d2, signedNote(n))
				f.ts = ts
				return f.entry()
			}, "",
			func(seq, n int64, ts string) string {
				return fmt.Sprintf("audit entry %d is a version.approved of digest %s but names signed=%d, which decided digest %s", seq, d2, n, d)
			}},
	}
}

// contentProbes are the probes of the entry's content against the kind: the
// token of the disable, budget reset or pause whose transaction is open at the
// head, borrowed by a sealed entry that says the opposite of what the kind
// does (a tool.disabled, version.superseded or tool.budget_reset with
// state=disabled->enabled, a server.paused with paused=false), with the column
// edited to match, which the state anchor would otherwise serve; and an entry
// of a tool kind without a state field, or of a server kind without the
// paused flag.
func contentProbes(t *testing.T) []bindingProbe {
	t.Helper()
	ech, ech2, d := digestOf(t, "echo", "v1"), digestOf(t, "echo", "v2"), digestOf(t, "sum", "v1")
	return []bindingProbe{
		{"a disable token on a tool.disabled that leaves disabled", disableEcho, false,
			func(n int64, ts string) audit.Entry {
				return echoLeavesDisabled(string(lifecycle.EvDisabled), "", ech, ech, n, ts)
			}, enableEcho,
			func(seq, n int64, ts string) string {
				return noSuchMove(seq, string(lifecycle.EvDisabled), n, signing.KindDisable)
			}},
		{"a disable token on a version.superseded that leaves disabled", disableEcho, false,
			func(n int64, ts string) audit.Entry {
				return echoLeavesDisabled(string(lifecycle.EvSuperseded), ech, ech, ech, n, ts)
			}, enableEcho,
			func(seq, n int64, ts string) string {
				return noSuchMove(seq, string(lifecycle.EvSuperseded), n, signing.KindDisable)
			}},
		{"a budget_reset token on a tool.budget_reset that leaves disabled", resetEchoBudget, false,
			func(n int64, ts string) audit.Entry { return echoLeavesDisabled(evBudgetReset, "", ech, ech2, n, ts) }, enableEcho,
			func(seq, n int64, ts string) string {
				return noSuchMove(seq, evBudgetReset, n, signing.KindBudgetReset)
			}},
		{"a pause token on a server.paused saying paused=false", pauseAlpha, false,
			func(n int64, ts string) audit.Entry {
				return serverEntry(evServerPaused, pausedDetail(false)+signedNote(n), ts)
			}, unpauseAlpha,
			func(seq, n int64, ts string) string {
				return fmt.Sprintf("audit entry %d is a server.paused saying paused=false but names signed=%d, a decision of kind pause, which leaves the server paused=true; the entry was appended outside toolwarrant", seq, n)
			}},
		{"a tool entry without a state field", approveSum, false,
			func(n int64, ts string) audit.Entry {
				detail := fmt.Sprintf("%s=%s %s=%s %s=0->0%s", fieldDigest, d, fieldLastSeen, d, fieldProposals, signedNote(n))
				return audit.Entry{TS: ts, Actor: "alice", ActorType: string(ActorHuman), Event: string(lifecycle.EvApproved), Subject: "alpha/sum", AfterHash: d, Detail: detail}
			}, "",
			func(seq, n int64, ts string) string {
				return fmt.Sprintf("audit entry %d names signed=%d, a decision of kind approve about a tool, but carries no state field; the entries of a tool decision record its transition", seq, n)
			}},
		{"a server entry without the paused flag", pauseAlpha, false,
			func(n int64, ts string) audit.Entry {
				return serverEntry(evServerPaused, fmt.Sprintf("%s=%d", fieldSigned, n), ts)
			}, "",
			func(seq, n int64, ts string) string {
				return fmt.Sprintf("audit entry %d names signed=%d, a decision of kind pause about a server, but carries no paused flag", seq, n)
			}},
	}
}

// Rule 5's binding, probed token by token and then content by content after a
// real signed decision whose transaction is open at the head: every probe is
// refused by the long-lived Store, every fresh open and the forensic view with
// its fixed sentence, the chain verifies, and Integrity counts exactly one
// unsigned decision. The content probes are the borrowed token: without
// bindContent a sealed tool.disabled with state=disabled->enabled naming the
// disable's own token, plus one UPDATE of the column, re-enabled the tool
// under a clean chain, and a server.paused saying paused=false un-paused the
// server the same way.
func TestWalk_RefusesASignedTokenThatDoesNotBindTheEntry(t *testing.T) {
	t.Parallel()
	for _, p := range append(tokenProbes(t), contentProbes(t)...) {
		t.Run(p.name, func(t *testing.T) {
			t.Parallel()
			s, path, alice, _ := trustedCatalog(t)
			r := p.decide(t, s, alice)
			if p.between {
				mustCrawl(t, s, "alpha", tool("echo", "v1"), tool("sum", "v1"), tool("new", "v1"))
			}
			mustSnapshot(t, s, "alpha")
			db := rawDB(t, path)
			ts := rawEntryAt(t, db, r.Seq).TS
			seq := appendEntry(t, db, p.forge(r.Seq, ts))
			if p.update != "" {
				mustExec(t, db, p.update)
			}
			rep := walkRefuses(t, s, path, seq, p.sentence(seq, r.Seq, ts))
			if rep.UnsignedDecisionsAfterBootstrap != 1 || rep.SignedRecordsInvalid != 0 || rep.CrawlTransitionsForged != 0 {
				t.Errorf("Integrity = %+v, want exactly one unsigned decision", rep)
			}
		})
	}
}
