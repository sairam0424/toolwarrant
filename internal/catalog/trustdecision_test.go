package catalog

import (
	"database/sql"
	"fmt"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
	"github.com/sairam0424/toolwarrant/internal/signing"
)

// The checked read of the signed records (SignedRecords) and the walk's rules
// over a decision.signed entry ahead of Decide (rule 1 and rule 4).

// SignedRecords is the checked read behind audit list --json: it returns the
// record of every signed entry named, leaves out the entries that carry none
// and the seqs the log does not hold, and refuses a row the chain memory does
// not vouch for (TestWalk_RefusesASwappedSignedRecordBecauseTheTokenDisagrees).
func TestSignedRecords_ReturnsTheRecordsOfSignedEntriesAndSkipsTheOthers(t *testing.T) {
	t.Parallel()
	s, path, alice, _ := trustedCatalog(t)
	view := mustTrustList(t, s)
	entries, err := s.AuditEntries(bg, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	seqs := make([]int64, 0, len(entries)+1)
	for _, e := range entries {
		seqs = append(seqs, e.Seq)
	}
	seqs = append(seqs, 10_000) // no such entry
	got, err := s.SignedRecords(bg, seqs)
	if err != nil {
		t.Fatalf("SignedRecords: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("SignedRecords returned %d records, want the bootstrap and the rotation", len(got))
	}
	rows, err := readSignedRecords(bg, rawDB(t, path), []int64{view.BootstrapSeq, view.ListSeq})
	if err != nil {
		t.Fatal(err)
	}
	for _, seq := range []int64{view.BootstrapSeq, view.ListSeq} {
		rec, ok := got[seq]
		if !ok || rec.Seq != seq || rec.Signer != alice.fp() || string(rec.Payload) != string(rows[seq].Payload) || string(rec.Signature) != string(rows[seq].Signature) {
			t.Errorf("record at %d = %+v, want the stored row signed by alice", seq, rec)
		}
	}
	ro, err := OpenWith(path, OpenOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ro.Close() }()
	if got, err := ro.SignedRecords(bg, []int64{view.ListSeq}); err != nil || len(got) != 1 {
		t.Errorf("a read-only Store's SignedRecords = %d, %v", len(got), err)
	}
}

// Rule 1 and rule 4 for a decision.signed entry, ahead of Decide: a record
// signed by a listed key and bound to its entry is accepted and counted, one
// by an unlisted key is refused as unauthorised, one whose kind token
// disagrees with the payload is refused, and one on a catalog with no list is
// refused because there is no list to verify it against.
func TestWalk_DecisionRecordsAreBoundAndAuthorisedAgainstTheListInForce(t *testing.T) {
	t.Parallel()
	decision := func(t *testing.T, s *Store, db *sql.DB, by operator, actor string) signing.Record {
		t.Helper()
		d := signing.Decision{Actor: actor, Catalog: s.identity, Digest: digestOf(t, "echo", "v1"), Kind: signing.KindApprove,
			PrevHead: rawHead(t, db), Server: "alpha", SignedAt: listSignedAt(), Signer: by.fp(), Tool: "echo"}
		payload, err := signing.MarshalDecision(d)
		if err != nil {
			t.Fatal(err)
		}
		return signBytes(t, payload, by.key, signing.NamespaceDecision)
	}
	entry := func(by Actor, detail string) forgedEntry {
		return forgedEntry{by: by, event: evDecisionSigned, subject: "alpha/echo", detail: detail}
	}
	t.Run("a listed key's record is accepted and counted", func(t *testing.T) {
		t.Parallel()
		s, path, alice, _ := trustedCatalog(t)
		db := rawDB(t, path)
		appendSigned(t, db, entry(alice.actor(), "kind=approve digest="+digestOf(t, "echo", "v1")), decision(t, s, db, alice, "alice"))
		view := mustTrustList(t, s)
		if view.SignedDecisions != 1 || view.Version != 2 {
			t.Errorf("TrustList = %+v, want one signed decision under version 2", view)
		}
		mustBeClean(t, s, "with a well-formed decision record")
	})
	t.Run("an unlisted key is not authorisation", func(t *testing.T) {
		t.Parallel()
		s, path, _, _ := trustedCatalog(t)
		carol := newOperator(t, "carol")
		db := rawDB(t, path)
		seq := appendSigned(t, db, entry(carol.actor(), "kind=approve digest="+digestOf(t, "echo", "v1")), decision(t, s, db, carol, "carol"))
		sentence := fmt.Sprintf("signed record of entry %d: signer %s is not in trust list v2 in force at that entry", seq, carol.fp())
		_, err := s.Snapshot(bg, "alpha")
		wantCorruptNaming(t, "Snapshot", err, sentence)
		opensRefuseNaming(t, path, sentence)
		rep := mustIntegrity(t, forensicOpen(t, path, ""))
		if rep.SignedRecordsInvalid != 1 || rep.TrustListsInvalid != 0 {
			t.Errorf("Integrity = %+v", rep)
		}
		problemMentioning(t, rep, sentence)
	})
	t.Run("another operator's key is named", func(t *testing.T) {
		t.Parallel()
		s, path, alice, bob := trustedCatalog(t)
		db := rawDB(t, path)
		seq := appendSigned(t, db, entry(bob.actor(), "kind=approve digest="+digestOf(t, "echo", "v1")), decision(t, s, db, alice, "bob"))
		sentence := fmt.Sprintf(`signed record of entry %d: signer %s belongs to "alice" but the entry and payload name "bob"`, seq, alice.fp())
		_, err := s.Snapshot(bg, "alpha")
		wantCorruptNaming(t, "Snapshot", err, sentence)
		opensRefuseNaming(t, path, sentence)
	})
	t.Run("the kind token disagrees", func(t *testing.T) {
		t.Parallel()
		s, path, alice, _ := trustedCatalog(t)
		db := rawDB(t, path)
		seq := appendSigned(t, db, entry(alice.actor(), "kind=reject digest="+digestOf(t, "echo", "v1")), decision(t, s, db, alice, "alice"))
		sentence := fmt.Sprintf(`audit entry %d says kind="reject" but its signed decision is a approve`, seq)
		_, err := s.Snapshot(bg, "alpha")
		wantCorruptNaming(t, "Snapshot", err, sentence)
	})
	t.Run("no list to verify against", func(t *testing.T) {
		t.Parallel()
		s, path := newStoreAt(t, lifecycle.DefaultPolicy())
		approvedEcho(t, s)
		alice := newOperator(t, "alice")
		db := rawDB(t, path)
		seq := appendSigned(t, db, entry(alice.actor(), "kind=approve digest="+digestOf(t, "echo", "v1")), decision(t, s, db, alice, "alice"))
		sentence := fmt.Sprintf("audit entry %d is a decision.signed but no trust list is in force at that entry", seq)
		_, err := s.Snapshot(bg, "alpha")
		wantCorruptNaming(t, "Snapshot", err, sentence)
		opensRefuseNaming(t, path, sentence)
	})
}
