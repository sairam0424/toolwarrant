package catalog

import (
	"fmt"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
	"github.com/sairam0424/toolwarrant/internal/signing"
)

// The refusal sentences of the walk print what they read from the entry (a
// state half, an event name) through quote, as the shape rule's state sentence
// and the state anchor's sentence do: the bytes were chosen by whoever wrote
// the entry, and a sentence ends in a terminal or a log. The halves come from
// Fields(), so they hold no whitespace, but any other byte, a control
// character included (orchestrator decision 23 after the third review of PR
// 7.5). The ESC byte is built at run time; the file holds no literal one.

// hostileProbe is one correctly sealed entry appended after a signed disable
// of echo with a control character where a state half or the event name goes:
// how it is forged, given the disable's decision.signed seq and time, and the
// sentence it is refused with, the character escaped.
type hostileProbe struct {
	name     string
	forge    func(n int64, ts string) audit.Entry
	sentence func(seq, n int64) string
}

// hostileProbes reach each sentence that prints a state half or an event name
// read from the entry with an ESC byte in that value: the crawl sentence
// through its from half, its to half and its event, the content-binding
// sentence through its from half, and the kind sentence of the signed=
// binding through its event.
func hostileProbes(esc, d string) []hostileProbe {
	hostile, hostileEvent := lifecycle.State(esc+"disabled"), string(lifecycle.EvDisabled)+esc
	borrowed := func(event string, from, to lifecycle.State, n int64, ts string) audit.Entry {
		return toolEntry{by: alice, event: event, subject: "alpha/echo", before: d, after: d, from: from, to: to,
			lastSeen: d, note: signedNote(n), ts: ts}.entry()
	}
	return []hostileProbe{
		{"the from half of a crawl-shaped entry",
			func(int64, string) audit.Entry {
				return crawlShaped(crawler, string(lifecycle.EvReverted), d, hostile, lifecycle.Enabled)
			},
			func(seq, _ int64) string {
				return crawlSentence(seq, "alpha/echo", hostile, lifecycle.Enabled, string(lifecycle.EvReverted))
			}},
		{"the to half of a crawl-shaped entry",
			func(int64, string) audit.Entry {
				return crawlShaped(crawler, string(lifecycle.EvReverted), d, lifecycle.Disabled, hostile)
			},
			func(seq, _ int64) string {
				return crawlSentence(seq, "alpha/echo", lifecycle.Disabled, hostile, string(lifecycle.EvReverted))
			}},
		{"the event of a crawl-shaped entry",
			func(int64, string) audit.Entry {
				return crawlShaped(crawler, string(lifecycle.EvReverted)+esc, d, lifecycle.Disabled, lifecycle.Enabled)
			},
			func(seq, _ int64) string {
				return crawlSentence(seq, "alpha/echo", lifecycle.Disabled, lifecycle.Enabled, string(lifecycle.EvReverted)+esc)
			}},
		{"the from half of an entry borrowing the disable's token",
			func(n int64, ts string) audit.Entry {
				return borrowed(string(lifecycle.EvDisabled), hostile, lifecycle.Enabled, n, ts)
			},
			func(seq, n int64) string {
				return fmt.Sprintf(`audit entry %d moves tool "alpha/echo" from %s to "enabled" under event "tool.disabled" but names signed=%d, a decision of kind disable, which makes no such move; the entry was appended outside toolwarrant`, seq, quote(string(hostile)), n)
			}},
		{"the event of an entry borrowing the disable's token",
			func(n int64, ts string) audit.Entry {
				return borrowed(hostileEvent, lifecycle.Enabled, lifecycle.Disabled, n, ts)
			},
			func(seq, n int64) string {
				return fmt.Sprintf("audit entry %d is a %s but names signed=%d, a decision of kind disable, which writes no such entry", seq, quote(hostileEvent), n)
			}},
	}
}

// A sealed entry whose state half or event carries a control character is
// refused by the rule its value fails, and the sentence shows the character
// escaped (`\x1b`), never raw: in the walk's error on every path and in every
// line of Integrity's report. The continuity sentence prints the state the
// newest entry left from the walk's memory, so its probe plants the hostile
// half before the bootstrap, where nothing is refused, and lies after it.
func TestWalk_RefusalSentencesQuoteHostileStateHalves(t *testing.T) {
	t.Parallel()
	esc := string(rune(0x1b))
	for _, p := range hostileProbes(esc, digestOf(t, "echo", "v1")) {
		t.Run(p.name, func(t *testing.T) {
			t.Parallel()
			s, path, alice, _ := trustedCatalog(t)
			r := mustDecide(t, s, alice, signing.KindDisable, "alpha", "echo", "")
			mustSnapshot(t, s, "alpha")
			db := rawDB(t, path)
			seq := appendEntry(t, db, p.forge(r.Seq, rawEntryAt(t, db, r.Seq).TS))
			refusedEscaped(t, s, path, seq, p.sentence(seq, r.Seq), esc)
		})
	}
	t.Run("the state the newest entry left, planted before the bootstrap", func(t *testing.T) {
		t.Parallel()
		s, path := newStoreAt(t, lifecycle.DefaultPolicy())
		d := approvedEcho(t, s)
		db := rawDB(t, path)
		hostile := lifecycle.State(esc + "enabled")
		planted := appendEntry(t, db, crawlShaped(crawler, string(lifecycle.EvDrifted), d, lifecycle.Enabled, hostile))
		op := newOperator(t, "alice")
		mustSetTrust(t, s, 1, op, op)
		seq := appendEntry(t, db, crawlShaped(crawler, string(lifecycle.EvReturned), d, lifecycle.Enabled, lifecycle.Enabled))
		refusedEscaped(t, s, path, seq, continuitySentence(seq, "alpha/echo", lifecycle.Enabled, planted, hostile), esc)
	})
}

// refusedEscaped is walkRefuses plus the point of the test: the expected
// sentence spells the control character escaped, and neither the walk's error
// nor any line of Integrity's report carries it raw.
func refusedEscaped(t *testing.T, s *Store, path string, seq int64, sentence, esc string) {
	t.Helper()
	if !strings.Contains(sentence, `\x1b`) || strings.Contains(sentence, esc) {
		t.Fatalf("the expected sentence %q does not spell the control character escaped", sentence)
	}
	rep := walkRefuses(t, s, path, seq, sentence)
	for _, p := range rep.Problems {
		if strings.Contains(p, esc) {
			t.Errorf("Integrity printed a control character raw: %q", p)
		}
	}
	_, err := s.Snapshot(bg, "alpha")
	if err == nil || strings.Contains(err.Error(), esc) {
		t.Errorf("Snapshot = %v; want the refusal with the control character escaped, never raw", err)
	}
}
