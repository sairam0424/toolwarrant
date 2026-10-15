package catalog

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// Schema version 7 (D22 g): the signed_records table, its guards, and the
// in-place migration of a version 6 file, the first released schema. The
// table holds one row per signed audit entry, keyed by the entry's seq: the
// exact RFC 8785 bytes that were signed, the signer's SHA256: fingerprint and
// the sshsig wire blob. Nothing in this schema round writes a row; the
// trust-list and signed-decision rounds do, and bind each row to the chain
// through the sigref token of the owning entry's detail, so that a swapped
// row no longer matches the entry the chain verified. The column CHECKs bound
// a row raw SQL plants (an oversized payload or signature would otherwise be
// read and parsed at open), and the four guards make the table append-only
// like every history table: no update, no delete, no replace of a seq, no
// row below seq 1 (an AFTER INSERT guard, for the reason guards.go gives).

const (
	// signedRecordsTable is the table's name, as sqlite_master lists it.
	signedRecordsTable = "signed_records"
	// maxSignedPayloadBytes bounds the signed bytes of one record: a decision
	// or a trust list is a few hundred bytes, and a list of every permitted
	// signer stays far below 64 KiB, so a larger row was planted.
	maxSignedPayloadBytes = 64 << 10
	// maxSignatureBytes bounds the sshsig blob: an RSA-4096 signature inside
	// the envelope is about 1 KiB and an Ed25519 one about 200 bytes.
	maxSignatureBytes = 4 << 10
	// fingerprintPrefix starts every signer fingerprint, as ssh-keygen -l
	// prints it; a fingerprint is the only key text the catalog stores
	// outside a signed trust record.
	fingerprintPrefix = "SHA256:"
)

// signedRecordsDDL is the CREATE TABLE statement of signed_records, built
// from the named bounds so that the DDL and the bounds cannot drift apart.
func signedRecordsDDL() string {
	return fmt.Sprintf(`CREATE TABLE %s (
			seq                INTEGER PRIMARY KEY REFERENCES audit_log (seq),
			payload            BLOB NOT NULL CHECK (length(payload) BETWEEN 1 AND %d),
			signer_fingerprint TEXT NOT NULL CHECK (signer_fingerprint GLOB '%s*'),
			signature          BLOB NOT NULL CHECK (length(signature) BETWEEN 1 AND %d)
		)`, signedRecordsTable, maxSignedPayloadBytes, fingerprintPrefix, maxSignatureBytes)
}

// signedRecordsGuards are the four guard triggers of signed_records, in
// creation order. guardStatements lists them after every other guard, and
// the migration creates them after the table, so a fresh file and a migrated
// one hold the same objects in the same order.
func signedRecordsGuards() []string {
	return []string{
		triggerAbort("signed_records_no_update", "BEFORE UPDATE ON signed_records", "", "signed_records are append-only"),
		triggerAbort("signed_records_no_delete", "BEFORE DELETE ON signed_records", "", "signed_records are append-only"),
		triggerAbort("signed_records_no_replace", "BEFORE INSERT ON signed_records",
			"WHEN EXISTS (SELECT 1 FROM signed_records WHERE seq = NEW.seq)", "signed_records cannot be replaced"),
		triggerAbort("signed_records_positive_id", "AFTER INSERT ON signed_records", "WHEN NEW.seq < 1",
			"signed_records seqs start at 1"),
	}
}

// v7Statements is what the migration adds to a version 6 file: the table,
// then its guards.
func v7Statements() []string {
	return append([]string{signedRecordsDDL()}, signedRecordsGuards()...)
}

// migrateV6ToV7 turns a version 6 file into a version 7 file inside the
// immediate transaction migrate holds: it adds signed_records and its four
// guards and sets user_version, and reads or rewrites nothing else, so every
// row of every other table and the audit head stay what they were. SQLite's
// DDL is transactional, so a crash in the middle leaves a version 6 file that
// migrates on the next read-write open, and a second process opening the
// same file waits on the transaction and then finds version 7. A file that
// already holds an object under one of the names the migration creates was
// edited outside toolwarrant (no version 6 build created one) and is refused
// as corrupt with nothing written; the caller's guard check then compares
// the whole migrated schema with version 7's.
func migrateV6ToV7(ctx context.Context, tx *sql.Tx) error {
	if err := refuseForeignV7Objects(ctx, tx); err != nil {
		return err
	}
	for _, stmt := range v7Statements() {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("catalog: migrate schema %d to %d: %w", migratableFrom, schemaVersion, err)
		}
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, schemaVersion)); err != nil {
		return fmt.Errorf("catalog: migrate schema %d to %d: set schema version: %w", migratableFrom, schemaVersion, err)
	}
	return nil
}

// refuseForeignV7Objects is ErrCorrupt when the version 6 file already holds
// a table, index, trigger or view under a name the migration is about to
// create, naming the first such object as sqlite_master lists it.
func refuseForeignV7Objects(ctx context.Context, q queryer) error {
	stmts := v7Statements()
	marks := make([]string, 0, len(stmts))
	args := make([]any, 0, len(stmts))
	for _, stmt := range stmts {
		_, name := parseGuardDDL(stmt)
		marks = append(marks, "?")
		args = append(args, name)
	}
	var kind, name string
	err := q.QueryRowContext(ctx, `SELECT type, name FROM sqlite_master WHERE name IN (`+strings.Join(marks, ", ")+`) ORDER BY rowid LIMIT 1`, args...).Scan(&kind, &name)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil
	case err != nil:
		return fmt.Errorf("catalog: inspect the schema %d file before its migration: %w", migratableFrom, err)
	}
	return fmt.Errorf("%w: the schema %d file already holds %s %s, which no build of that schema created; the file was edited outside toolwarrant and is not migrated, nothing was written", ErrCorrupt, migratableFrom, kind, name)
}
