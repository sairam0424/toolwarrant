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
// state half, an event name) and from its signed_records row before the
// signature was verified (the row's signer) through quote, as the shape
// rule's state sentence and the state anchor's sentence do: the bytes were
// chosen by whoever wrote the file, and a sentence ends in a terminal or a
// log. The halves come from Fields(), so they hold no whitespace, but any
// other byte, a control character included (orchestrator decisions 23 and 29
// after the third review of PR 7.5 and the review of its follow-up). The ESC
// byte is built at run time; the file holds no literal one.

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

// A signed_records row whose signer carries a control character meets the two
// sentences that print a record's signer before signing.Verify has pinned it
// to the fingerprint of the key that signed: the record binding's, when the
// entry's signer token names another signer than the row holds, and the
// signature's, when the token agrees with the row and the key that signed is
// not the one the row names. Each is refused with the character escaped
// (`\x1b`) on every path and in every line of Integrity's report, never raw;
// the sentences after Verify print a fingerprint the signature proved.
func TestWalk_RefusalSentencesQuoteAHostileSigner(t *testing.T) {
	t.Parallel()
	esc := string(rune(0x1b))
	t.Run("the signature sentence, the entry's token agreeing with the row", func(t *testing.T) {
		t.Parallel()
		s, path, alice, _ := trustedCatalog(t)
		mustSnapshot(t, s, "alpha") // the memory is warm up to the head
		db := rawDB(t, path)
		rec := *signDecisionPayload(t, decisionOf(s.identity, rawHead(t, db), alice, signing.KindDisable, "alpha", "echo", ""), alice)
		rec.Signer = hostileSigner(esc, rec.Signer)
		f := forgedEntry{by: alice.actor(), event: evDecisionSigned, subject: decisionSubject(signing.KindDisable, "alpha", "echo"),
			detail: decisionDetail(signing.KindDisable, "")}
		seq := appendSigned(t, db, f, rec)
		sentence := fmt.Sprintf("signed record of entry %d: the signature by %s does not verify over the stored payload", seq, quote(rec.Signer))
		refusedEscaped(t, s, path, seq, sentence, esc)
	})
	t.Run("the record binding's sentence, the entry's token naming the key", func(t *testing.T) {
		t.Parallel()
		s, path, alice, bob := trustedCatalog(t)
		mustSnapshot(t, s, "alpha")
		db := rawDB(t, path)
		rec := signList(t, listFor(s.identity, rawHead(t, db), 3, alice, alice, bob), alice.key)
		rec.Signer = hostileSigner(esc, rec.Signer)
		raw := fmt.Sprintf("%s=3 %s=2 %s=%s %s=%s", fieldVersion, fieldSigners, fieldSigner, alice.fp(), fieldSigref, signing.RecordDigest(rec))
		seq := appendSigned(t, db, forgedEntry{by: alice.actor(), event: evTrustRotated, subject: trustSubject, rawDetail: raw}, rec)
		sentence := fmt.Sprintf("audit entry %d names signer %s but its signed record was made with %s", seq, quote(alice.fp()), quote(rec.Signer))
		refusedEscaped(t, s, path, seq, sentence, esc)
	})
}

// hostileSigner is fp with a control character right after the fingerprint
// prefix: the schema admits a row's signer by that prefix alone (schemav7.go,
// GLOB), so this is the hostile value a forger with a SQLite shell can store.
func hostileSigner(esc, fp string) string {
	return fingerprintPrefix + esc + strings.TrimPrefix(fp, fingerprintPrefix)
}

// refusedEscaped is walkRefuses plus the point of the test: the expected
// sentence spells the control character escaped, and neither the walk's error
// on any path (the long-lived Store's Snapshot, a read-only and a read-write
// open, a forensic open's first view) nor any line of Integrity's report
// carries it raw.
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
	for label, err := range readerErrors(t, s, path) {
		if err == nil || !strings.Contains(err.Error(), sentence) || strings.Contains(err.Error(), esc) {
			t.Errorf("%s = %v; want the refusal with the control character escaped, never raw", label, err)
		}
	}
}

// readerErrors reads the file once more on every path walkRefuses checks and
// returns what each refused with, under its name: the long-lived Store's
// Snapshot, a read-only and a read-write open, and a forensic open's first
// view. walkRefuses judges those errors; this hands them back for the bytes.
func readerErrors(t *testing.T, s *Store, path string) map[string]error {
	t.Helper()
	errs := openErrors(t, path)
	_, errs["the long-lived Store's Snapshot"] = s.Snapshot(bg, "alpha")
	_, errs["forensic Tools"] = forensicOpen(t, path, "").Tools(bg, "")
	return errs
}
