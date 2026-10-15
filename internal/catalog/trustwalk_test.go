package catalog

import (
	"database/sql"
	"errors"
	"fmt"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
	"github.com/sairam0424/toolwarrant/internal/signing/sigtest"
)

// The walk's rules for trust records (D22 (c); plan section 1, rules 1 and
// 3), each probed with the access D14 grants: whoever can write the file
// appends a correctly sealed entry past the head, with its row, signed by a
// key they hold. The chain is intact, so audit.Verify passes; the rules are
// what refuse the record: the long-lived Store on its next reload (the suffix
// walk meets the entry), every fresh open, and Integrity, which names it. The
// actor of a forged entry may be spelled as the Store never spells it: the
// Store writes the canonical name, so "ALICE" under alice's key is refused.

// trustForgery is one forged trust record and the sentence the walk must say.
type trustForgery struct {
	name string
	// fresh forges against a catalog without a trust list instead of the
	// trusted one (the bootstrap rules).
	fresh bool
	forge func(t *testing.T, s *Store, db *sql.DB, alice, bob, carol operator) int64
	// sentence renders the fixed sentence for the forged entry's seq and the
	// two operators of the trusted catalog.
	sentence func(seq int64, alice, bob operator) string
}

// rotationForgeries are the rule 3 probes.
func rotationForgeries() []trustForgery {
	return []trustForgery{
		{"a skipped version", false,
			func(t *testing.T, s *Store, db *sql.DB, alice, bob, carol operator) int64 {
				return forgeTrust(t, db, s.identity, evTrustRotated, 4, alice, alice.actor(), alice, bob, carol)
			},
			func(seq int64, alice, bob operator) string {
				return fmt.Sprintf("trust list at entry %d has version 4, expected 3 (exactly one above the list in force)", seq)
			}},
		{"a repeated version", false,
			func(t *testing.T, s *Store, db *sql.DB, alice, bob, carol operator) int64 {
				return forgeTrust(t, db, s.identity, evTrustRotated, 2, alice, alice.actor(), alice, bob, carol)
			},
			func(seq int64, alice, bob operator) string {
				return fmt.Sprintf("trust list at entry %d has version 2, expected 3 (exactly one above the list in force)", seq)
			}},
		{"a signer only in the new list", false,
			func(t *testing.T, s *Store, db *sql.DB, alice, bob, carol operator) int64 {
				return forgeTrust(t, db, s.identity, evTrustRotated, 3, carol, carol.actor(), alice, bob, carol)
			},
			func(seq int64, alice, bob operator) string {
				return fmt.Sprintf("the trust list at entry %d is not signed by a key of both the list in force and the new list", seq)
			}},
		{"a signer only in the list in force", false,
			func(t *testing.T, s *Store, db *sql.DB, alice, bob, carol operator) int64 {
				return forgeTrust(t, db, s.identity, evTrustRotated, 3, alice, alice.actor(), bob, carol)
			},
			func(seq int64, alice, bob operator) string {
				return fmt.Sprintf("the trust list at entry %d is not signed by a key of both the list in force and the new list", seq)
			}},
		{"a second bootstrap", false,
			func(t *testing.T, s *Store, db *sql.DB, alice, bob, carol operator) int64 {
				return forgeTrust(t, db, s.identity, evTrustBootstrap, 1, carol, carol.actor(), carol)
			},
			func(seq int64, alice, bob operator) string {
				return fmt.Sprintf("a second trust bootstrap at entry %d; the trust list cannot start twice", seq)
			}},
		{"an actor that is not the key's name", false,
			func(t *testing.T, s *Store, db *sql.DB, alice, bob, carol operator) int64 {
				return forgeTrust(t, db, s.identity, evTrustRotated, 3, alice, bob.actor(), alice, bob, carol)
			},
			func(seq int64, alice, bob operator) string {
				return fmt.Sprintf(`the trust list at entry %d is signed by %s, which it names for "alice", but the entry's actor is "bob"`, seq, alice.fp())
			}},
		{"an actor spelled non-canonically", false,
			func(t *testing.T, s *Store, db *sql.DB, alice, bob, carol operator) int64 {
				shouting := Actor{Name: "ALICE", Type: ActorHuman} // folds to alice, which only a forger writes
				return forgeTrust(t, db, s.identity, evTrustRotated, 3, alice, shouting, alice, bob, carol)
			},
			func(seq int64, alice, bob operator) string {
				return fmt.Sprintf(`the trust list at entry %d is signed by %s, which it names for "alice", but the entry's actor is "ALICE"`, seq, alice.fp())
			}},
		{"a bootstrap of version 2", true,
			func(t *testing.T, s *Store, db *sql.DB, alice, bob, carol operator) int64 {
				return forgeTrust(t, db, s.identity, evTrustBootstrap, 2, alice, alice.actor(), alice)
			},
			func(seq int64, alice, bob operator) string {
				return fmt.Sprintf("the trust bootstrap at entry %d has version 2, expected 1", seq)
			}},
		{"a rotation before any bootstrap", true,
			func(t *testing.T, s *Store, db *sql.DB, alice, bob, carol operator) int64 {
				return forgeTrust(t, db, s.identity, evTrustRotated, 2, alice, alice.actor(), alice)
			},
			func(seq int64, alice, bob operator) string {
				return fmt.Sprintf("a trust rotation at entry %d before any bootstrap; no list is in force", seq)
			}},
		{"a list naming a key outside the policy", false,
			func(t *testing.T, s *Store, db *sql.DB, alice, bob, carol operator) int64 {
				weak := operator{name: "carol", key: sigtest.GenerateRSA(t, 2048)}
				return forgeTrust(t, db, s.identity, evTrustRotated, 3, alice, alice.actor(), alice, bob, weak)
			},
			func(seq int64, alice, bob operator) string {
				return fmt.Sprintf("the trust list at entry %d is not a valid list", seq)
			}},
		{"a bootstrap not signed by a key of its own list", true,
			func(t *testing.T, s *Store, db *sql.DB, alice, bob, carol operator) int64 {
				return forgeTrust(t, db, s.identity, evTrustBootstrap, 1, alice, alice.actor(), bob)
			},
			func(seq int64, alice, bob operator) string {
				return fmt.Sprintf("the trust bootstrap at entry %d is not signed by a key of its own list", seq)
			}},
	}
}

// Every rule 3 refusal, with its fixed sentence: the long-lived Store refuses
// on its next read, a read-only and a read-write open refuse at open, and a
// forensic open's Integrity counts one invalid trust list and prints the
// sentence while the chain itself verifies.
func TestWalk_RefusesATrustListWithTheWrongVersionOrSigner(t *testing.T) {
	t.Parallel()
	for _, tc := range rotationForgeries() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runTrustForgery(t, tc, 0, 1)
		})
	}
}

// runTrustForgery applies one forgery and checks every reader; wantBinding
// and wantTrust are the Integrity counters the forgery must raise.
func runTrustForgery(t *testing.T, tc trustForgery, wantBinding, wantTrust int) {
	t.Helper()
	var (
		s          *Store
		path       string
		alice, bob operator
	)
	if tc.fresh {
		s, path = newStoreAt(t, lifecycle.DefaultPolicy())
		approvedEcho(t, s)
		alice, bob = newOperator(t, "alice"), newOperator(t, "bob")
	} else {
		s, path, alice, bob = trustedCatalog(t)
	}
	carol := newOperator(t, "carol")
	before := mustTrustList(t, s)
	mustSnapshot(t, s, "alpha") // the memory is warm up to the head
	seq := tc.forge(t, s, rawDB(t, path), alice, bob, carol)
	sentence := tc.sentence(seq, alice, bob)

	_, err := s.Snapshot(bg, "alpha")
	wantCorruptNaming(t, "the long-lived Store's next Snapshot", err, sentence)
	_, err = s.TrustList(bg)
	wantCorruptNaming(t, "the long-lived Store's TrustList", err, sentence)
	if pin := s.loadPin(); pin.seq >= seq {
		t.Errorf("the pin advanced to %d past the refused record at %d; nothing of a refused page may be recorded", pin.seq, seq)
	}
	opensRefuseNaming(t, path, sentence)

	f := forensicOpen(t, path, "")
	if _, err := f.VerifyAudit(bg); err != nil {
		t.Errorf("VerifyAudit = %v; the chain is intact, the trust rule is what refuses the record", err)
	}
	rep := mustIntegrity(t, f)
	if rep.TrustListsInvalid != wantTrust || rep.SignedRecordsInvalid != wantBinding || rep.ChainBreaks != 0 || rep.SignedRecordsOrphaned != 0 {
		t.Errorf("Integrity = %+v, want %d invalid trust lists and %d invalid records", rep, wantTrust, wantBinding)
	}
	problemMentioning(t, rep, sentence)
	_, err = f.Tools(bg, "")
	wantCorruptNaming(t, "forensic Tools", err, sentence)
	if !tc.fresh && (!before.InForce() || before.Version != 2) {
		t.Errorf("test setup: the list in force before the forgery was %+v, want version 2", before)
	}
}

// Two rows swapped under their entries (the no-update guard dropped and
// restored): each entry's sigref token no longer matches its row, so every
// fresh open refuses at the first, the checked read of the records refuses,
// and Integrity names both. The long-lived Store keeps its verified memory:
// the rows lie below its pin and the suffix walk does not read them (O-15),
// which is the processor's designed behaviour; the restart, the recorded head
// and audit verify are what catch a swap made under a running reader.
func TestWalk_RefusesASwappedSignedRecordBecauseTheTokenDisagrees(t *testing.T) {
	t.Parallel()
	s, path, _, _ := trustedCatalog(t)
	view := mustTrustList(t, s)
	a, b := view.BootstrapSeq, view.ListSeq
	db := rawDB(t, path)
	rows, err := readSignedRecords(bg, db, []int64{a, b})
	if err != nil || len(rows) != 2 {
		t.Fatalf("read the two rows: %d, %v", len(rows), err)
	}
	mustExec(t, db, `DROP TRIGGER signed_records_no_update`)
	for from, to := range map[int64]int64{a: b, b: a} {
		rec := rows[from]
		mustExec(t, db, `UPDATE signed_records SET payload = ?, signer_fingerprint = ?, signature = ? WHERE seq = ?`, rec.Payload, rec.Signer, rec.Signature, to)
	}
	restoreGuard(t, db, "signed_records_no_update")
	mustExec(t, db, `UPDATE meta SET value = value + 1 WHERE key = 'generation'`)
	sentence := fmt.Sprintf("the signed record of audit entry %d was replaced", a)

	if _, err := s.Snapshot(bg, "alpha"); err != nil {
		t.Errorf("the long-lived Store's Snapshot = %v; the swapped rows lie below its pin and the serving path reads none of them", err)
	}
	_, err = s.SignedRecords(bg, []int64{a, b})
	wantCorruptNaming(t, "the checked read of the records", err, sentence)
	opensRefuseNaming(t, path, sentence)
	f := forensicOpen(t, path, "")
	if _, err := f.VerifyAudit(bg); err != nil {
		t.Errorf("VerifyAudit = %v; the chain is intact", err)
	}
	rep := mustIntegrity(t, f)
	if rep.SignedRecordsInvalid != 2 || rep.TrustListsInvalid != 0 {
		t.Errorf("Integrity = %+v, want both swapped records named", rep)
	}
	problemMentioning(t, rep, sentence, fmt.Sprintf("the signed record of audit entry %d was replaced", b))
}

// A signed_records row copied under the seq of an entry that carries no signed
// record (the plan's break-check "copy a row under a new seq") is refused by
// the walk at the page that holds the entry, naming the row and the entry: the
// long-lived read-only Store and the writer on their next read (the row sits
// in the suffix neither has walked), every fresh open at open, a forensic
// open on its first view; the pin stays below the page. VerifyAudit passes
// (the chain is intact) and Integrity counts the row as an orphan with the
// same sentence. The row's own bytes are never read for this: one primary-key
// range seek of seqs per walked page.
func TestWalk_RefusesASignedRecordRowUnderAnEntryThatCarriesNone(t *testing.T) {
	t.Parallel()
	s, path, _, _ := trustedCatalog(t)
	ro, err := OpenWith(path, OpenOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ro.Close() }()
	mustSnapshot(t, ro, "alpha")
	below := len(rawEntries(t, rawDB(t, path)))
	mustCrawl(t, s, "alpha", tool("echo", "v2"), tool("sum", "v1"))
	db := rawDB(t, path)
	entries := rawEntries(t, db)
	target := entries[len(entries)-1]
	if len(entries) == below || isSignedEvent(target.Event) {
		t.Fatalf("test setup: %d entries after %d, the newest a %s; want an unsigned entry appended past both pins", len(entries), below, target.Event)
	}
	rotated := entryOf(t, s, evTrustRotated) // the writer's checked read advances its pin, but not past the new entries
	rows, err := readSignedRecords(bg, db, []int64{rotated.Seq})
	if err != nil || len(rows) != 1 {
		t.Fatalf("read the rotation's row: %d, %v", len(rows), err)
	}
	rec := rows[rotated.Seq]
	mustExec(t, db, insertSignedRecordSQL, target.Seq, rec.Payload, rec.Signer, rec.Signature)
	mustExec(t, db, `UPDATE meta SET value = value + 1 WHERE key = 'generation'`)
	sentence := errOrphanRecord(target.Seq, target.Event).Error()

	_, err = ro.Snapshot(bg, "alpha")
	wantCorruptNaming(t, "the long-lived read-only Store's Snapshot", err, sentence)
	if pin := ro.loadPin(); pin.seq >= target.Seq {
		t.Errorf("the pin advanced to %d past the refused page holding %d", pin.seq, target.Seq)
	}
	_, err = s.Snapshot(bg, "alpha")
	wantCorruptNaming(t, "the writer's Snapshot", err, sentence)
	opensRefuseNaming(t, path, sentence)
	f := forensicOpen(t, path, "")
	if _, err := f.VerifyAudit(bg); err != nil {
		t.Errorf("VerifyAudit = %v; the chain is intact, the row is what the walk refuses", err)
	}
	rep := mustIntegrity(t, f)
	if rep.SignedRecordsOrphaned != 1 || rep.SignedRecordsInvalid != 0 || rep.TrustListsInvalid != 0 || rep.ChainBreaks != 0 {
		t.Errorf("Integrity = %+v, want exactly one orphan row", rep)
	}
	problemMentioning(t, rep, sentence)
	_, err = f.Tools(bg, "")
	wantCorruptNaming(t, "forensic Tools", err, sentence)
}

// A bootstrap copied from another catalog, byte for byte with its signature,
// is refused by the catalog it was not made for: the identity is inside the
// signed bytes, so a staging list cannot be replayed into production even
// over the same head (both logs are empty here, so the heads agree).
func TestWalk_RefusesAReplayedTrustRecordFromAnotherCatalog(t *testing.T) {
	t.Parallel()
	a, pathA := newStoreAt(t, lifecycle.DefaultPolicy())
	b, pathB := newStoreAt(t, lifecycle.DefaultPolicy())
	alice := newOperator(t, "alice")
	rb := mustSetTrust(t, b, 1, alice, alice)
	rows, err := readSignedRecords(bg, rawDB(t, pathB), []int64{rb.Seq})
	if err != nil || len(rows) != 1 {
		t.Fatalf("read b's record: %v", err)
	}
	seq := appendSigned(t, rawDB(t, pathA), forgedEntry{by: alice.actor(), event: evTrustBootstrap, subject: trustSubject, detail: "version=1 signers=1"}, rows[rb.Seq])
	sentence := fmt.Sprintf("signed record of entry %d names catalog %s, not this one", seq, b.identity)
	_, err = a.TrustList(bg)
	wantCorruptNaming(t, "the long-lived Store's TrustList", err, sentence)
	opensRefuseNaming(t, pathA, sentence)
	rep := mustIntegrity(t, forensicOpen(t, pathA, ""))
	if rep.SignedRecordsInvalid != 1 {
		t.Errorf("Integrity = %+v", rep)
	}
	problemMentioning(t, rep, sentence)
	if view := mustTrustList(t, b); view.Version != 1 || view.Root != alice.fp() {
		t.Errorf("b's own list = %+v", view)
	}
	if !errors.Is(err, ErrCorrupt) {
		t.Fatal("the replayed record was accepted")
	}
}
