package catalog

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
	"github.com/sairam0424/toolwarrant/internal/signing"
)

// The walk's rules for decisions and for the entries after the bootstrap
// (D22 (b) and (d); plan section 1, rules 2, 4, 5 and 6), each probed with the
// access D14 grants: whoever can write the file appends a correctly sealed
// entry past the head, with a row when it is a signed one, signed by a key
// they hold or by none. The chain is intact, so audit.Verify passes; the rules
// are what refuse the entry: the long-lived Store on its next reload, every
// fresh open, and Integrity, which names it.

// walkRefuses requires the long-lived Store's next Snapshot, a read-only and
// a read-write open and a forensic open's first view to refuse with sentence,
// the pin to stay below seq, the chain to verify, and Integrity to print the
// sentence.
func walkRefuses(t *testing.T, s *Store, path string, seq int64, sentence string) IntegrityReport {
	t.Helper()
	_, err := s.Snapshot(bg, "alpha")
	wantCorruptNaming(t, "the long-lived Store's next Snapshot", err, sentence)
	if pin := s.loadPin(); pin.seq >= seq {
		t.Errorf("the pin advanced to %d past the refused entry at %d; nothing of a refused page may be recorded", pin.seq, seq)
	}
	opensRefuseNaming(t, path, sentence)
	f := forensicOpen(t, path, "")
	if _, err := f.VerifyAudit(bg); err != nil {
		t.Errorf("VerifyAudit = %v; the chain is intact, the rule is what refuses the entry", err)
	}
	_, err = f.Tools(bg, "")
	wantCorruptNaming(t, "forensic Tools", err, sentence)
	rep := mustIntegrity(t, f)
	problemMentioning(t, rep, sentence)
	if rep.ChainBreaks != 0 {
		t.Errorf("Integrity.ChainBreaks = %d, want 0", rep.ChainBreaks)
	}
	return rep
}

// unsignedSentence is rule 5's sentence for an unsigned human-only entry.
func unsignedSentence(seq int64, event string, bootstrap int64) string {
	return fmt.Sprintf("audit entry %d is a %s after the trust bootstrap (entry %d) and names no signed record; the entry was appended outside toolwarrant", seq, event, bootstrap)
}

// An approval appended after the bootstrap without a signed record, correctly
// sealed (the fifth review's technique plus the v0.4 rule): the long-lived
// Store refuses on its next reload, a read-only Store that had walked to the
// head refuses on its next read, every fresh open refuses at open, and
// Integrity names it under UnsignedDecisionsAfterBootstrap.
func TestWalk_RefusesAnUnsignedApprovalAppendedAfterTheBootstrap(t *testing.T) {
	t.Parallel()
	s, path, _, _ := trustedCatalog(t)
	ro, err := OpenWith(path, OpenOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ro.Close() }()
	mustSnapshot(t, ro, "alpha")
	bootstrap := mustTrustList(t, s).BootstrapSeq
	seq := appendEntry(t, rawDB(t, path), forgedApproval(alice, "sum", pendingSum(t), "").entry())
	sentence := unsignedSentence(seq, string(lifecycle.EvApproved), bootstrap)
	_, err = ro.Snapshot(bg, "alpha")
	wantCorruptNaming(t, "the read-only Store's next Snapshot", err, sentence)
	rep := walkRefuses(t, s, path, seq, sentence)
	if rep.UnsignedDecisionsAfterBootstrap != 1 || rep.CrawlTransitionsForged != 0 || rep.SignedRecordsInvalid != 0 {
		t.Errorf("Integrity = %+v, want exactly one unsigned decision", rep)
	}
}

// An enable or a resume appended without a record after the bootstrap, the
// two commands that undo a revocation (O-16): both refused with the unsigned
// sentence, so a forged tool.enabled or server.resumed re-serves nothing.
func TestWalk_RefusesAnUnsignedEnableOrResumeAppendedAfterTheBootstrap(t *testing.T) {
	t.Parallel()
	t.Run("enable", func(t *testing.T) {
		t.Parallel()
		s, path, alice, _ := trustedCatalog(t)
		mustDecide(t, s, alice, signing.KindDisable, "alpha", "echo", "")
		d := digestOf(t, "echo", "v1")
		f := toolEntry{by: alice.actor(), event: string(lifecycle.EvEnabled), subject: "alpha/echo", before: d, after: d,
			from: lifecycle.Disabled, to: lifecycle.Enabled, lastSeen: d}
		seq := appendEntry(t, rawDB(t, path), f.entry())
		rep := walkRefuses(t, s, path, seq, unsignedSentence(seq, string(lifecycle.EvEnabled), mustTrustListSeq(t, path)))
		if rep.UnsignedDecisionsAfterBootstrap != 1 {
			t.Errorf("Integrity = %+v", rep)
		}
	})
	t.Run("resume", func(t *testing.T) {
		t.Parallel()
		s, path, alice, _ := trustedCatalog(t)
		mustDecide(t, s, alice, signing.KindPause, "alpha", "", "")
		e := audit.Entry{Actor: "alice", ActorType: string(ActorHuman), Event: evServerResumed, Subject: "alpha", Detail: pausedDetail(false)}
		db := rawDB(t, path)
		seq := appendEntry(t, db, e)
		mustExec(t, db, `UPDATE servers SET paused = 0 WHERE name = 'alpha'`)
		sentence := unsignedSentence(seq, evServerResumed, mustTrustListSeq(t, path))
		rep := walkRefuses(t, s, path, seq, sentence)
		if rep.UnsignedDecisionsAfterBootstrap != 1 {
			t.Errorf("Integrity = %+v", rep)
		}
		_, err := s.Servers(bg)
		wantCorruptNaming(t, "Servers", err, sentence)
	})
}

// Rule 4 on a complete forgery: an unlisted key signs an approval and the
// forger appends the decision.signed entry with its row and the
// version.approved naming it. The record is refused where the walk meets it;
// Integrity counts the record and the approval that names it.
func TestWalk_RefusesAValidSignatureFromAKeyOutsideTheTrustList(t *testing.T) {
	t.Parallel()
	s, path, _, _ := trustedCatalog(t)
	carol := newOperator(t, "carol")
	d := pendingSum(t)
	db := rawDB(t, path)
	seq, _ := forgeDecision(t, db, s.identity, carol, carol.actor(), signing.KindApprove, "alpha", "sum", d)
	f := forgedApproval(carol.actor(), "sum", d, signedNote(seq))
	f.ts = rawEntryAt(t, db, seq).TS
	appendEntry(t, db, f.entry())
	sentence := fmt.Sprintf("signed record of entry %d: signer %s is not in trust list v2 in force at that entry", seq, carol.fp())
	rep := walkRefuses(t, s, path, seq, sentence)
	if rep.SignedRecordsInvalid != 1 || rep.UnsignedDecisionsAfterBootstrap != 1 {
		t.Errorf("Integrity = %+v, want the record refused and the approval that names it counted as unsigned", rep)
	}
	problemMentioning(t, rep, fmt.Sprintf("audit entry %d names signed=%d, which is not a verified decision.signed entry", seq+1, seq))
}

// Rule 4: alice's key under bob's name is a valid signature by another
// operator, refused with both names.
func TestWalk_RefusesASignatureWhoseKeyBelongsToAnotherName(t *testing.T) {
	t.Parallel()
	s, path, alice, bob := trustedCatalog(t)
	seq, _ := forgeDecision(t, rawDB(t, path), s.identity, operator{name: bob.name, key: alice.key}, bob.actor(), signing.KindApprove, "alpha", "sum", pendingSum(t))
	rep := walkRefuses(t, s, path, seq, fmt.Sprintf(`signed record of entry %d: signer %s belongs to "alice" but the entry and payload name "bob"`, seq, alice.fp()))
	if rep.SignedRecordsInvalid != 1 {
		t.Errorf("Integrity = %+v", rep)
	}
}

// A decision signed for another catalog, copied byte for byte with its
// signature and its row, is refused by the catalog it was not made for: the
// identity is inside the signed bytes.
func TestWalk_RefusesAPayloadCopiedFromAnotherCatalog(t *testing.T) {
	t.Parallel()
	s, path, alice, _ := trustedCatalog(t)
	other, _, _, _ := trustedCatalog(t)
	db := rawDB(t, path)
	d := pendingSum(t)
	rec := signDecisionPayload(t, decisionOf(other.identity, rawHead(t, db), alice, signing.KindApprove, "alpha", "sum", d), alice)
	seq := appendSigned(t, db, forgedEntry{by: alice.actor(), event: evDecisionSigned, subject: "alpha/sum", detail: decisionDetail(signing.KindApprove, d)}, *rec)
	rep := walkRefuses(t, s, path, seq, fmt.Sprintf("signed record of entry %d names catalog %s, not this one", seq, other.identity))
	if rep.SignedRecordsInvalid != 1 {
		t.Errorf("Integrity = %+v", rep)
	}
}

// Rule 2: a decision.signed entry whose kind token, digest token or subject
// disagrees with its signed payload is refused with the token named, so a
// record cannot be re-labelled by editing the entry it binds.
func TestWalk_RefusesAPayloadWhoseKindOrDigestDisagreesWithTheEntry(t *testing.T) {
	t.Parallel()
	d1, d2 := digestOf(t, "sum", "v1"), digestOf(t, "sum", "v2")
	cases := []struct {
		name     string
		subject  string
		detail   string
		sentence func(seq int64) string
	}{
		{"the digest token", "alpha/sum", decisionDetail(signing.KindApprove, d2),
			func(seq int64) string {
				return fmt.Sprintf("audit entry %d says digest=%s but its signed decision names digest %s", seq, quote(d2), d1)
			}},
		{"the kind token", "alpha/sum", decisionDetail(signing.KindRollback, d1),
			func(seq int64) string {
				return fmt.Sprintf(`audit entry %d says kind="rollback" but its signed decision is a approve`, seq)
			}},
		{"the subject", "alpha/echo", decisionDetail(signing.KindApprove, d1),
			func(seq int64) string {
				return fmt.Sprintf(`audit entry %d is about "alpha/echo" but its signed decision is about "alpha/sum"`, seq)
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, path, alice, _ := trustedCatalog(t)
			db := rawDB(t, path)
			rec := signDecisionPayload(t, decisionOf(s.identity, rawHead(t, db), alice, signing.KindApprove, "alpha", "sum", d1), alice)
			seq := appendSigned(t, db, forgedEntry{by: alice.actor(), event: evDecisionSigned, subject: tc.subject, detail: tc.detail}, *rec)
			rep := walkRefuses(t, s, path, seq, tc.sentence(seq))
			if rep.SignedRecordsInvalid != 1 {
				t.Errorf("Integrity = %+v", rep)
			}
		})
	}
}

// Revocation by omission is not retroactive (finding 10): bob's approval under
// list v2 stands after v3 removes him, is served and verifies clean, while a
// record his key signs after the rotation is refused against v3.
func TestWalk_ARemovedKeysEarlierDecisionsStandAndItsLaterOnesAreRefused(t *testing.T) {
	t.Parallel()
	s, path, alice, bob := trustedCatalog(t)
	d := pendingSum(t)
	mustDecide(t, s, bob, signing.KindApprove, "alpha", "sum", d)
	mustSetTrust(t, s, 3, alice, alice)
	if snap := mustSnapshot(t, s, "alpha"); !snap.Serves("sum", d) {
		t.Fatal("bob's approval is not served after his removal")
	}
	fresh, err := OpenWith(path, OpenOptions{ReadOnly: true})
	if err != nil {
		t.Fatalf("fresh open after the removal: %v", err)
	}
	if snap := mustSnapshot(t, fresh, "alpha"); !snap.Serves("sum", d) {
		t.Error("a fresh Store does not serve bob's earlier approval")
	}
	_ = fresh.Close()
	mustBeClean(t, s, "after the removal")
	db := rawDB(t, path)
	seq, _ := forgeDecision(t, db, s.identity, bob, bob.actor(), signing.KindDisable, "alpha", "echo", "")
	rep := walkRefuses(t, s, path, seq, fmt.Sprintf("signed record of entry %d: signer %s is not in trust list v3 in force at that entry", seq, bob.fp()))
	if rep.SignedRecordsInvalid != 1 {
		t.Errorf("Integrity = %+v", rep)
	}
}

// Approvals made before the bootstrap need no record (O-12): a long unsigned
// history, bootstrapped afterwards, verifies clean, is served, and its
// approvals in force are listed as legacy; nothing before the bootstrap is
// held to rules 5 or 6.
func TestWalk_LegacyApprovalsBeforeTheBootstrapNeedNoRecord(t *testing.T) {
	t.Parallel()
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	richHistory(t, s)
	alice := newOperator(t, "alice")
	mustSetTrust(t, s, 1, alice, alice)
	mustBeClean(t, s, "after the bootstrap over an unsigned history")
	rep := mustIntegrity(t, s)
	if len(rep.LegacyApprovalsInService) == 0 || !strings.HasPrefix(rep.LegacyApprovalsInService[0], "alpha/") {
		t.Errorf("LegacyApprovalsInService = %v, want the approvals in force before the bootstrap", rep.LegacyApprovalsInService)
	}
	snap := mustSnapshot(t, s, "alpha")
	if !snap.Serves("echo", digestOf(t, "echo", "v1")) {
		t.Errorf("the legacy approval of echo is not served: %+v", snap.Tools["echo"])
	}
	fresh, err := OpenWith(path, OpenOptions{ReadOnly: true})
	if err != nil {
		t.Fatalf("fresh open: %v", err)
	}
	defer func() { _ = fresh.Close() }()
	if n := fresh.chain.verifiedSignatures(); n != 1 {
		t.Errorf("a fresh open verified %d signatures, want 1: the bootstrap alone", n)
	}
	if err := s.Disable(bg, "alpha", "echo", alice.actor()); !errors.Is(err, ErrSignatureRequired) {
		t.Errorf("an unsigned decision after the bootstrap = %v, want ErrSignatureRequired", err)
	}
}
