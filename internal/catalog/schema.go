package catalog

import (
	"context"
	"database/sql"
	"fmt"
	"slices"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// schemaVersion is stored in PRAGMA user_version. A database with another
// number is refused: a higher one was written by a newer build, a lower one by
// an unreleased build, and there is no migration code for either (nothing has
// shipped), so the operator deletes the file and runs init again.
//
// Version 2 added digest_profile and proposals_since_decision, the
// tool_version_proposers table, servers.paused and the unusable marker.
// Version 3 added the last_seen field to the detail of every tool audit entry
// (see toolDetail); Integrity reads it to cross-check tools.last_seen_digest
// against the log, and a log written without it cannot be cross-checked.
// Version 4 added the proposals field to every tool detail and the url_sha256
// field to the server.added detail (D13): Integrity compares every mutable
// column the log describes (state, proposal budget, paused flag, allow_private
// and the URL) with the latest entry about its subject, which a version 3 log
// does not carry. The tables themselves did not change.
const schemaVersion = 4

// migrate creates the schema in an empty database, or checks that an existing
// one is ours. It runs in one immediate transaction, so two processes opening
// a fresh file at the same time cannot both create it.
func migrate(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("catalog: begin migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // a no-op once committed
	version, err := readUserVersion(ctx, tx)
	if err != nil {
		return err
	}
	switch version {
	case schemaVersion:
		if err := checkOurs(ctx, tx, true); err != nil {
			return err
		}
	case 0:
		if err := createSchema(ctx, tx); err != nil {
			return err
		}
	default:
		return schemaError(version)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("catalog: commit migration: %w", err)
	}
	return nil
}

func readUserVersion(ctx context.Context, q queryer) (int, error) {
	var version int
	if err := q.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return 0, fmt.Errorf("catalog: read schema version: %w", err)
	}
	return version, nil
}

// schemaError explains a user_version this build cannot use.
func schemaError(version int) error {
	if version > 0 && version < schemaVersion {
		return fmt.Errorf("%w: database is schema version %d from an unreleased build and this build uses %d; there is no migration: delete the file and run init again", ErrSchema, version, schemaVersion)
	}
	return fmt.Errorf("%w: database is version %d, this build supports %d", ErrSchema, version, schemaVersion)
}

// checkOurs verifies that a database at our version really is ours and, when
// requireGuards is set, still carries every guard object. A dropped trigger
// would silently turn history tables mutable, so its absence is corruption,
// not a missing feature; only a forensic open reads past it.
func checkOurs(ctx context.Context, q queryer, requireGuards bool) error {
	if _, err := readGeneration(ctx, q); err != nil {
		return fmt.Errorf("%w: not a toolwarrant database", ErrSchema)
	}
	if !requireGuards {
		return nil
	}
	return verifyGuards(ctx, q)
}

// countObjects returns how many tables, indexes, triggers and views the file holds.
func countObjects(ctx context.Context, q queryer) (int, error) {
	var objects int
	if err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master`).Scan(&objects); err != nil {
		return 0, fmt.Errorf("catalog: inspect database: %w", err)
	}
	return objects, nil
}

func createSchema(ctx context.Context, tx *sql.Tx) error {
	objects, err := countObjects(ctx, tx)
	if err != nil {
		return err
	}
	if objects > 0 {
		return fmt.Errorf("%w: the file holds another application's tables", ErrSchema)
	}
	for _, stmt := range schemaStatements() {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("catalog: create schema: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, schemaVersion)); err != nil {
		return fmt.Errorf("catalog: set schema version: %w", err)
	}
	return nil
}

const (
	digestCheck = `length(digest) = 64 AND digest NOT GLOB '*[^0-9a-f]*'`
	stateList   = `'discovered','pending_review','enabled','changed_pending_reapproval','disabled','deprecated'`
)

// schemaStatements lists the DDL in dependency order: tables and indexes, then
// the triggers that make the database refuse edits to history through ordinary
// SQL. Triggers do not stop someone who can drop a trigger, which is why Open
// checks that every guard object still exists (verifyGuards), VerifyAudit
// checks the hash chain, and every read of a definition re-hashes its
// canonical bytes against the stored digest (loadTool, Versions, Snapshot and
// Approved, see checkCanonical and scanPolicy). Nothing guards the tools
// table: its columns are the current policy and must change. Only Integrity
// binds them to the append-only history.
func schemaStatements() []string {
	return slices.Concat(catalogTables(), historyTables(), guardIndexStatements(), guardStatements())
}

// catalogTables holds the mutable registry: servers, crawls and tools.
func catalogTables() []string {
	return []string{
		`CREATE TABLE meta (
			key   TEXT PRIMARY KEY,
			value INTEGER NOT NULL
		) WITHOUT ROWID`,
		`INSERT INTO meta (key, value) VALUES ('generation', 0)`,
		`CREATE TABLE servers (
			id            INTEGER PRIMARY KEY,
			name          TEXT NOT NULL UNIQUE,
			url           TEXT NOT NULL,
			owner_group   TEXT NOT NULL,
			allow_private INTEGER NOT NULL CHECK (allow_private IN (0, 1)),
			paused        INTEGER NOT NULL CHECK (paused IN (0, 1)),
			created_at    TEXT NOT NULL
		)`,
		// error holds a class token, optionally followed by a quoted fragment
		// of the caller's text (see crawlErrorRecord); never raw text.
		`CREATE TABLE crawls (
			id         INTEGER PRIMARY KEY,
			server_id  INTEGER NOT NULL REFERENCES servers (id),
			started_at TEXT NOT NULL,
			complete   INTEGER NOT NULL CHECK (complete IN (0, 1)),
			error      TEXT NOT NULL,
			tool_count INTEGER NOT NULL CHECK (tool_count >= 0),
			actor      TEXT NOT NULL
		)`,
		`CREATE TABLE tools (
			id                       INTEGER PRIMARY KEY,
			server_id                INTEGER NOT NULL REFERENCES servers (id),
			name                     TEXT NOT NULL,
			state                    TEXT NOT NULL CHECK (state IN (` + stateList + `)),
			approved_version_id      INTEGER REFERENCES tool_versions (id),
			last_seen_digest         TEXT NOT NULL
				CHECK (last_seen_digest IN ('', '` + lifecycle.UnusableDigest + `')
				       OR (length(last_seen_digest) = 64 AND last_seen_digest NOT GLOB '*[^0-9a-f]*')),
			missing_crawls           INTEGER NOT NULL CHECK (missing_crawls >= 0),
			proposals_since_decision INTEGER NOT NULL CHECK (proposals_since_decision >= 0),
			UNIQUE (server_id, name),
			CHECK (state NOT IN ('enabled', 'changed_pending_reapproval') OR approved_version_id IS NOT NULL)
		)`,
	}
}

// historyTables holds the records that are only ever appended to: versions,
// their proposers, approvals and the audit log. Their indexes are guard
// objects (guardIndexStatements) and are created after them.
func historyTables() []string {
	return []string{
		`CREATE TABLE tool_versions (
			id             INTEGER PRIMARY KEY,
			tool_id        INTEGER NOT NULL REFERENCES tools (id),
			version_no     INTEGER NOT NULL CHECK (version_no >= 1),
			digest         TEXT NOT NULL CHECK (` + digestCheck + `),
			digest_profile TEXT NOT NULL CHECK (digest_profile <> ''),
			canonical      BLOB NOT NULL,
			raw            BLOB NOT NULL,
			status         TEXT NOT NULL CHECK (status IN ('pending','approved','rejected','superseded')),
			proposed_by    TEXT NOT NULL,
			ever_approved  INTEGER NOT NULL CHECK (ever_approved IN (0, 1)),
			first_seen_at  TEXT NOT NULL,
			crawl_id       INTEGER NOT NULL REFERENCES crawls (id),
			UNIQUE (tool_id, digest),
			UNIQUE (tool_id, version_no)
		)`,
		// position 0 is the original proposer, equal to tool_versions.proposed_by.
		`CREATE TABLE tool_version_proposers (
			version_id INTEGER NOT NULL REFERENCES tool_versions (id),
			position   INTEGER NOT NULL CHECK (position >= 0),
			actor      TEXT NOT NULL CHECK (actor <> ''),
			PRIMARY KEY (version_id, position),
			UNIQUE (version_id, actor)
		) WITHOUT ROWID`,
		`CREATE TABLE approvals (
			id         INTEGER PRIMARY KEY,
			version_id INTEGER NOT NULL REFERENCES tool_versions (id),
			decision   TEXT NOT NULL CHECK (decision IN ('approve','reject','rollback')),
			approver   TEXT NOT NULL,
			actor_type TEXT NOT NULL CHECK (actor_type IN ('human','system')),
			hash_seen  TEXT NOT NULL,
			at         TEXT NOT NULL
		)`,
		`CREATE TABLE audit_log (
			seq        INTEGER PRIMARY KEY,
			ts         TEXT NOT NULL,
			actor      TEXT NOT NULL,
			actor_type TEXT NOT NULL,
			event      TEXT NOT NULL,
			subject    TEXT NOT NULL,
			before_hash TEXT NOT NULL,
			after_hash  TEXT NOT NULL,
			detail     TEXT NOT NULL,
			prev_hash  TEXT NOT NULL,
			hash       TEXT NOT NULL
		)`,
	}
}
