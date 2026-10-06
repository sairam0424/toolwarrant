package catalog

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
)

// schemaVersion is stored in PRAGMA user_version. A database with a higher
// number was written by a newer build and must not be touched.
const schemaVersion = 1

// migrate creates the schema in an empty database, or checks that an existing
// one is ours. It runs in one immediate transaction, so two processes opening
// a fresh file at the same time cannot both create it.
func migrate(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("catalog: begin migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // a no-op once committed
	var version int
	if err := tx.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("catalog: read schema version: %w", err)
	}
	switch version {
	case schemaVersion:
		if _, err := readGeneration(ctx, tx); err != nil {
			return fmt.Errorf("%w: not a toolwarrant database", ErrSchema)
		}
	case 0:
		if err := createSchema(ctx, tx); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: database is version %d, this build supports %d", ErrSchema, version, schemaVersion)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("catalog: commit migration: %w", err)
	}
	return nil
}

func createSchema(ctx context.Context, tx *sql.Tx) error {
	var objects int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master`).Scan(&objects); err != nil {
		return fmt.Errorf("catalog: inspect database: %w", err)
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
// SQL. Triggers do not stop someone who can drop a trigger, which is what
// VerifyAudit's hash chain and the digest re-check on every read are for.
func schemaStatements() []string {
	return slices.Concat(catalogTables(), historyTables(), guardStatements())
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
			created_at    TEXT NOT NULL
		)`,
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
			id                  INTEGER PRIMARY KEY,
			server_id           INTEGER NOT NULL REFERENCES servers (id),
			name                TEXT NOT NULL,
			state               TEXT NOT NULL CHECK (state IN (` + stateList + `)),
			approved_version_id INTEGER REFERENCES tool_versions (id),
			last_seen_digest    TEXT NOT NULL
				CHECK (last_seen_digest = '' OR (length(last_seen_digest) = 64 AND last_seen_digest NOT GLOB '*[^0-9a-f]*')),
			missing_crawls      INTEGER NOT NULL CHECK (missing_crawls >= 0),
			UNIQUE (server_id, name),
			CHECK (state NOT IN ('enabled', 'changed_pending_reapproval') OR approved_version_id IS NOT NULL)
		)`,
	}
}

// historyTables holds the records that are only ever appended to: versions,
// approvals and the audit log.
func historyTables() []string {
	return []string{
		`CREATE TABLE tool_versions (
			id            INTEGER PRIMARY KEY,
			tool_id       INTEGER NOT NULL REFERENCES tools (id),
			version_no    INTEGER NOT NULL CHECK (version_no >= 1),
			digest        TEXT NOT NULL CHECK (` + digestCheck + `),
			canonical     BLOB NOT NULL,
			raw           BLOB NOT NULL,
			status        TEXT NOT NULL CHECK (status IN ('pending','approved','rejected','superseded')),
			proposed_by   TEXT NOT NULL,
			ever_approved INTEGER NOT NULL CHECK (ever_approved IN (0, 1)),
			first_seen_at TEXT NOT NULL,
			crawl_id      INTEGER NOT NULL REFERENCES crawls (id),
			UNIQUE (tool_id, digest),
			UNIQUE (tool_id, version_no)
		)`,
		`CREATE UNIQUE INDEX one_pending_version ON tool_versions (tool_id) WHERE status = 'pending'`,
		`CREATE UNIQUE INDEX one_approved_version ON tool_versions (tool_id) WHERE status = 'approved'`,
		`CREATE TABLE approvals (
			id         INTEGER PRIMARY KEY,
			version_id INTEGER NOT NULL REFERENCES tool_versions (id),
			decision   TEXT NOT NULL CHECK (decision IN ('approve','reject','rollback')),
			approver   TEXT NOT NULL,
			actor_type TEXT NOT NULL CHECK (actor_type IN ('human','system')),
			hash_seen  TEXT NOT NULL,
			at         TEXT NOT NULL
		)`,
		`CREATE INDEX approvals_by_version ON approvals (version_id, id)`,
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

// guardStatements adds the append-only and immutability triggers.
func guardStatements() []string {
	return []string{
		triggerAbort("audit_log_no_update", "BEFORE UPDATE ON audit_log", "", "audit_log is append-only"),
		triggerAbort("audit_log_no_delete", "BEFORE DELETE ON audit_log", "", "audit_log is append-only"),
		triggerAbort("audit_log_sequential", "BEFORE INSERT ON audit_log",
			"WHEN NEW.seq IS NOT (SELECT COALESCE(MAX(seq), 0) + 1 FROM audit_log)",
			"audit_log entries must be appended in sequence"),
		triggerAbort("tool_versions_no_delete", "BEFORE DELETE ON tool_versions", "", "tool_versions are immutable"),
		triggerAbort("tool_versions_immutable",
			"BEFORE UPDATE OF id, tool_id, version_no, digest, canonical, raw, first_seen_at, crawl_id ON tool_versions",
			"", "tool_versions are immutable"),
		triggerAbort("tool_versions_no_replace", "BEFORE INSERT ON tool_versions",
			`WHEN EXISTS (SELECT 1 FROM tool_versions WHERE id = NEW.id)
			   OR EXISTS (SELECT 1 FROM tool_versions WHERE tool_id = NEW.tool_id AND digest = NEW.digest)
			   OR EXISTS (SELECT 1 FROM tool_versions WHERE tool_id = NEW.tool_id AND version_no = NEW.version_no)`,
			"tool_versions cannot be replaced"),
		triggerAbort("approvals_no_update", "BEFORE UPDATE ON approvals", "", "approvals are append-only"),
		triggerAbort("approvals_no_delete", "BEFORE DELETE ON approvals", "", "approvals are append-only"),
		triggerAbort("approvals_no_replace", "BEFORE INSERT ON approvals",
			"WHEN EXISTS (SELECT 1 FROM approvals WHERE id = NEW.id)", "approvals cannot be replaced"),
	}
}

// triggerAbort builds a trigger whose only job is to abort the statement.
func triggerAbort(name, event, when, message string) string {
	return fmt.Sprintf("CREATE TRIGGER %s %s %s BEGIN SELECT RAISE(ABORT, '%s'); END", name, event, when, message)
}
