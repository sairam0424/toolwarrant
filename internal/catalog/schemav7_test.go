package catalog

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// The signed_records table of schema version 7 (D22 g) and its guards, probed
// with a SQLite shell's powers, as the other history tables are in
// triggers_test.go and integrity_test.go. The rows here are planted under
// entries that carry no signed record, to show what the guards and the column
// CHECKs refuse and what the ghost-row check and Integrity report; the rows
// the Store writes, and the walk's rules over them, are trust_test.go and
// trustwalk_test.go.

// insertSignedRecord is the statement a shell would use to plant a row.
const insertSignedRecord = `INSERT INTO signed_records (seq, payload, signer_fingerprint, signature) VALUES (?, ?, ?, ?)`

// sampleFingerprint is a well-formed signer fingerprint; the catalog stores
// no other key text.
const sampleFingerprint = "SHA256:0000000000000000000000000000000000000000000"

// Modelled on TestTriggers_RowidAliasUpdatesAreRefused: a planted row cannot
// be updated (any column, the seq, or a rowid alias), deleted or replaced, a
// row of no audit entry is refused by the foreign key, a row below seq 1 is
// refused by the positive-id guard, and a well-formed row planted under an
// entry that carries no signed record is refused by the walk where it meets
// the entry, so the next read of the Store names the row (D22 c;
// TestWalk_RefusesASignedRecordRowUnderAnEntryThatCarriesNone has every
// reader and Integrity). What a row planted under a dropped guard does is
// TestSchema_SignedRecordsGhostRowIsCorruptAndCountedByIntegrity.
func TestSchema_SignedRecordsGuardsRefuseUpdateDeleteReplaceAndGhostRows(t *testing.T) {
	t.Parallel()
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	mustAddServer(t, s, "alpha") // audit seq 1 exists for the row to reference
	db := rawDB(t, path)
	mustExec(t, db, insertSignedRecord, 1, []byte(`{}`), sampleFingerprint, []byte{0})
	for name, stmt := range map[string]string{
		"update payload":     `UPDATE signed_records SET payload = x'5b5d'`,
		"update fingerprint": `UPDATE signed_records SET signer_fingerprint = 'SHA256:1111111111111111111111111111111111111111111'`,
		"update signature":   `UPDATE signed_records SET signature = x'01'`,
		"update seq":         `UPDATE signed_records SET seq = 2`,
		"update rowid":       `UPDATE signed_records SET rowid = rowid + 1000`,
		"update _rowid_":     `UPDATE signed_records SET _rowid_ = _rowid_ + 1000`,
		"update oid":         `UPDATE signed_records SET oid = oid + 1000`,
		"delete":             `DELETE FROM signed_records`,
		"replace":            `INSERT OR REPLACE INTO signed_records (seq, payload, signer_fingerprint, signature) VALUES (1, x'5b5d', 'SHA256:2222222222222222222222222222222222222222222', x'02')`,
		"row of no entry":    `INSERT INTO signed_records (seq, payload, signer_fingerprint, signature) VALUES (2, x'7b7d', 'SHA256:3333333333333333333333333333333333333333333', x'03')`,
	} {
		if _, err := db.ExecContext(bg, stmt); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	noFK := rawDBNoFK(t, path)
	if _, err := noFK.ExecContext(bg, insertSignedRecord, -1, []byte(`{}`), sampleFingerprint, []byte{0}); err == nil || !strings.Contains(err.Error(), "signed_records seqs start at 1") {
		t.Errorf("a row at seq -1 = %v, want the positive-id guard's refusal", err)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM signed_records`); n != 1 {
		t.Fatalf("%d rows after the refused statements, want the planted one", n)
	}
	_, err := s.Snapshot(bg, "alpha")
	if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), orphanRowUnderServerAdded) {
		t.Errorf("Snapshot with a planted row under an unsigned entry = %v, want ErrCorrupt saying %q", err, orphanRowUnderServerAdded)
	}
}

// orphanRowUnderServerAdded is the sentence the walk and Integrity say about a
// row planted at seq 1 of a catalog whose first entry is the server.added.
const orphanRowUnderServerAdded = `signed_records row 1 belongs to audit entry 1, a "server.added", which carries no signed record; the row was inserted by hand`

// A row planted under a dropped positive-id guard is a ghost row like one in
// any history table: Snapshot and a write refuse the file naming the table,
// so does the first read of a fresh Store (Open verifies the chain and the
// guards; the ghost-row check is the first thing every read and write runs,
// as for the other history tables), and a forensic open's Integrity counts
// the row in GhostRows and names its seq.
func TestSchema_SignedRecordsGhostRowIsCorruptAndCountedByIntegrity(t *testing.T) {
	t.Parallel()
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	mustAddServer(t, s, "alpha")
	noFK := rawDBNoFK(t, path)
	mustExec(t, noFK, `DROP TRIGGER signed_records_positive_id`)
	mustExec(t, noFK, insertSignedRecord, -1, []byte(`{}`), sampleFingerprint, []byte{0})
	restoreGuard(t, noFK, "signed_records_positive_id")
	const want = "signed_records holds a row whose seq is below 1"
	if _, err := s.Snapshot(bg, "alpha"); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), want) {
		t.Errorf("Snapshot with a ghost row = %v, want ErrCorrupt saying %q", err, want)
	}
	if err := s.Disable(bg, "alpha", "echo", alice); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), want) {
		t.Errorf("a write with a ghost row = %v, want ErrCorrupt saying %q", err, want)
	}
	_ = s.Close()
	fresh := openStore(t, path, lifecycle.DefaultPolicy())
	if _, err := fresh.Snapshot(bg, "alpha"); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), want) {
		t.Errorf("first read of a fresh Store with a ghost row = %v, want ErrCorrupt saying %q", err, want)
	}
	if _, err := fresh.Approved(bg); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), want) {
		t.Errorf("Approved with a ghost row = %v, want ErrCorrupt saying %q", err, want)
	}
	forensic, err := OpenWith(path, OpenOptions{Forensic: true})
	if err != nil {
		t.Fatalf("forensic open: %v", err)
	}
	defer func() { _ = forensic.Close() }()
	rep := mustIntegrity(t, forensic)
	if rep.GhostRows != 1 {
		t.Errorf("Integrity.GhostRows = %d, want 1: %+v", rep.GhostRows, rep)
	}
	problemMentioning(t, rep, "signed_records row -1 has a seq below 1")
}

// The column CHECKs bound what raw SQL can plant: an empty or oversized
// payload or signature and a fingerprint that is not SHA256: are refused,
// while a row at both bounds goes in, so the refusals are the constraints'
// doing. The bounds are the ones schemav7.go names, pinned here as numbers
// so that a changed bound changes this test too.
func TestSchema_SignedRecordsRefusesOversizedRows(t *testing.T) {
	t.Parallel()
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	mustAddServer(t, s, "alpha")
	db := rawDB(t, path)
	const maxPayload, maxSignature = 65536, 4096
	for name, row := range map[string]struct {
		payload, signature []byte
		signer             string
	}{
		"empty payload":         {nil, []byte{0}, sampleFingerprint},
		"oversized payload":     {make([]byte, maxPayload+1), []byte{0}, sampleFingerprint},
		"empty signature":       {[]byte(`{}`), nil, sampleFingerprint},
		"oversized signature":   {[]byte(`{}`), make([]byte, maxSignature+1), sampleFingerprint},
		"lower-case prefix":     {[]byte(`{}`), []byte{0}, "sha256:0000000000000000000000000000000000000000000"},
		"another hash":          {[]byte(`{}`), []byte{0}, "MD5:00:11:22"},
		"empty fingerprint":     {[]byte(`{}`), []byte{0}, ""},
		"fingerprint elsewhere": {[]byte(`{}`), []byte{0}, " SHA256:0000000000000000000000000000000000000000000"},
	} {
		if _, err := db.ExecContext(bg, insertSignedRecord, 1, row.payload, row.signer, row.signature); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM signed_records`); n != 0 {
		t.Fatalf("%d rows after the refused inserts, want none", n)
	}
	mustExec(t, db, insertSignedRecord, 1, make([]byte, maxPayload), sampleFingerprint, make([]byte, maxSignature))
	if n := mustCount(t, db, fmt.Sprintf(`SELECT COUNT(*) FROM signed_records WHERE length(payload) = %d AND length(signature) = %d`, maxPayload, maxSignature)); n != 1 {
		t.Errorf("a row at both bounds was not stored as given")
	}
	// The row sits under the server.added entry, which carries no signed
	// record: since the trust-list round the walk refuses it where it meets
	// the entry and Integrity names it as an orphan (D22 c).
	_, err := s.Snapshot(bg, "alpha")
	if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), orphanRowUnderServerAdded) {
		t.Errorf("Snapshot with a planted row under an unsigned entry = %v, want ErrCorrupt saying %q", err, orphanRowUnderServerAdded)
	}
	rep := mustIntegrity(t, s)
	if rep.SignedRecordsOrphaned != 1 || len(rep.Problems) != 1 {
		t.Errorf("Integrity = %+v, want exactly the orphan row", rep)
	}
	problemMentioning(t, rep, orphanRowUnderServerAdded)
}
