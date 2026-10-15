package catalog

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// The schema of version 6 as the v0.3.0 release wrote it, frozen here so that
// the migration tests build a version 6 file without the live schema: the
// statements are the stored DDL of a fresh catalog the published
// toolwarrant_0.3.0_darwin_arm64 binary initialised on 2026-10-15 (tag v0.3.0,
// merge 4c718ed; internal/catalog/schema.go and guards.go at that commit),
// copied verbatim, with the one meta row init writes. A later change to the
// live DDL must still migrate what the release wrote, which these tests then
// show.

const (
	// v6Version is the user_version the v0.3.0 release wrote.
	v6Version = 6
	// v6Objects is how many rows sqlite_master holds in a fresh v0.3.0 file:
	// eight tables, five automatic indexes, four guard indexes, fifteen guard
	// triggers.
	v6Objects = 32
	// v7Added names what the migration adds, as a LIKE pattern over
	// sqlite_master.name; a version 6 file holds no object of that shape.
	v7Added = "signed_records%"
)

// v6Statements is the version 6 DDL in creation order: the catalog tables,
// the generation row, the history tables, the guard indexes and the guard
// triggers.
func v6Statements() []string {
	return []string{
		`CREATE TABLE meta (
			key   TEXT PRIMARY KEY,
			value NOT NULL
		) WITHOUT ROWID`,
		`INSERT INTO meta (key, value) VALUES ('generation', 0)`,
		`CREATE TABLE servers (
			id             INTEGER PRIMARY KEY,
			name           TEXT NOT NULL UNIQUE,
			url            TEXT NOT NULL,
			owner_group    TEXT NOT NULL,
			allow_private  INTEGER NOT NULL CHECK (allow_private IN (0, 1)),
			paused         INTEGER NOT NULL CHECK (paused IN (0, 1)),
			processor_addr TEXT NOT NULL DEFAULT '',
			created_at     TEXT NOT NULL
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
			id                       INTEGER PRIMARY KEY,
			server_id                INTEGER NOT NULL REFERENCES servers (id),
			name                     TEXT NOT NULL,
			state                    TEXT NOT NULL CHECK (state IN ('discovered','pending_review','enabled','changed_pending_reapproval','disabled','deprecated')),
			approved_version_id      INTEGER REFERENCES tool_versions (id),
			last_seen_digest         TEXT NOT NULL
				CHECK (last_seen_digest IN ('', 'unusable')
				       OR (length(last_seen_digest) = 64 AND last_seen_digest NOT GLOB '*[^0-9a-f]*')),
			missing_crawls           INTEGER NOT NULL CHECK (missing_crawls >= 0),
			proposals_since_decision INTEGER NOT NULL CHECK (proposals_since_decision >= 0),
			UNIQUE (server_id, name),
			CHECK (state NOT IN ('enabled', 'changed_pending_reapproval') OR approved_version_id IS NOT NULL)
		)`,
		`CREATE TABLE tool_versions (
			id             INTEGER PRIMARY KEY,
			tool_id        INTEGER NOT NULL REFERENCES tools (id),
			version_no     INTEGER NOT NULL CHECK (version_no >= 1),
			digest         TEXT NOT NULL CHECK (length(digest) = 64 AND digest NOT GLOB '*[^0-9a-f]*'),
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
		`CREATE UNIQUE INDEX one_pending_version ON tool_versions (tool_id) WHERE status = 'pending'`,
		`CREATE UNIQUE INDEX one_approved_version ON tool_versions (tool_id) WHERE status = 'approved'`,
		`CREATE INDEX approvals_by_version ON approvals (version_id, id)`,
		`CREATE INDEX audit_log_by_subject ON audit_log (subject, event, seq)`,
		`CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log  BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END`,
		`CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log  BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END`,
		`CREATE TRIGGER audit_log_sequential BEFORE INSERT ON audit_log WHEN NEW.seq IS NOT (SELECT COALESCE(MAX(seq), 0) + 1 FROM audit_log) BEGIN SELECT RAISE(ABORT, 'audit_log entries must be appended in sequence'); END`,
		`CREATE TRIGGER tool_versions_no_delete BEFORE DELETE ON tool_versions  BEGIN SELECT RAISE(ABORT, 'tool_versions are immutable'); END`,
		`CREATE TRIGGER tool_versions_immutable BEFORE UPDATE ON tool_versions WHEN NEW.id IS NOT OLD.id OR NEW.tool_id IS NOT OLD.tool_id OR NEW.version_no IS NOT OLD.version_no OR NEW.digest IS NOT OLD.digest OR NEW.digest_profile IS NOT OLD.digest_profile OR NEW.canonical IS NOT OLD.canonical OR NEW.raw IS NOT OLD.raw OR NEW.proposed_by IS NOT OLD.proposed_by OR NEW.first_seen_at IS NOT OLD.first_seen_at OR NEW.crawl_id IS NOT OLD.crawl_id BEGIN SELECT RAISE(ABORT, 'tool_versions are immutable'); END`,
		`CREATE TRIGGER tool_versions_no_replace BEFORE INSERT ON tool_versions WHEN EXISTS (SELECT 1 FROM tool_versions WHERE id = NEW.id)
			   OR EXISTS (SELECT 1 FROM tool_versions WHERE tool_id = NEW.tool_id AND digest = NEW.digest)
			   OR EXISTS (SELECT 1 FROM tool_versions WHERE tool_id = NEW.tool_id AND version_no = NEW.version_no)
			   OR (NEW.status IN ('pending', 'approved')
			       AND EXISTS (SELECT 1 FROM tool_versions WHERE tool_id = NEW.tool_id AND status = NEW.status)) BEGIN SELECT RAISE(ABORT, 'tool_versions cannot be replaced'); END`,
		`CREATE TRIGGER tool_versions_positive_id AFTER INSERT ON tool_versions WHEN NEW.id < 1 BEGIN SELECT RAISE(ABORT, 'tool_versions ids start at 1'); END`,
		`CREATE TRIGGER proposers_no_update BEFORE UPDATE ON tool_version_proposers  BEGIN SELECT RAISE(ABORT, 'proposers are append-only'); END`,
		`CREATE TRIGGER proposers_no_delete BEFORE DELETE ON tool_version_proposers  BEGIN SELECT RAISE(ABORT, 'proposers are append-only'); END`,
		`CREATE TRIGGER proposers_append_only BEFORE INSERT ON tool_version_proposers WHEN EXISTS (SELECT 1 FROM tool_version_proposers WHERE version_id = NEW.version_id AND actor = NEW.actor)
			   OR NEW.position IS NOT (SELECT COUNT(*) FROM tool_version_proposers WHERE version_id = NEW.version_id) BEGIN SELECT RAISE(ABORT, 'proposers are appended once, in order'); END`,
		`CREATE TRIGGER approvals_no_update BEFORE UPDATE ON approvals  BEGIN SELECT RAISE(ABORT, 'approvals are append-only'); END`,
		`CREATE TRIGGER approvals_no_delete BEFORE DELETE ON approvals  BEGIN SELECT RAISE(ABORT, 'approvals are append-only'); END`,
		`CREATE TRIGGER approvals_no_replace BEFORE INSERT ON approvals WHEN EXISTS (SELECT 1 FROM approvals WHERE id = NEW.id) BEGIN SELECT RAISE(ABORT, 'approvals cannot be replaced'); END`,
		`CREATE TRIGGER approvals_positive_id AFTER INSERT ON approvals WHEN NEW.id < 1 BEGIN SELECT RAISE(ABORT, 'approvals ids start at 1'); END`,
		`CREATE TRIGGER tools_no_delete BEFORE DELETE ON tools  BEGIN SELECT RAISE(ABORT, 'tools are never deleted'); END`,
	}
}

// v6Tables lists the version 6 tables in the order their rows can be copied
// with foreign keys off; the history tables follow their guards' order rules
// (seq, id and position ascending).
var v6Tables = []struct{ name, order string }{
	{"servers", "id"}, {"crawls", "id"}, {"tools", "id"}, {"tool_versions", "id"},
	{"tool_version_proposers", "version_id, position"}, {"approvals", "id"}, {"audit_log", "seq"},
}

// v6Fixture describes the version 6 file newV6File built: the digest the
// legacy approval serves, the pending one, the audit head and the row count
// of every table, all read from the Store that produced the rows.
type v6Fixture struct {
	path, approved, pending, head string
	rows                          map[string]int
}

// newV6File builds a version 6 file as v0.3.0 left one: the frozen DDL, in
// WAL mode and owner-only, holding one server (alpha) with one tool (echo)
// that has two versions, the first approved by bob and the second pending,
// and the sealed audit entries of those writes. The rows come from a Store
// the live writers filled and are copied into the frozen schema table by
// table (no writer of internal/catalog changed between v0.3.0 and the
// version 7 round, so they are the rows the release wrote); the schema is
// the release's own, so the migration tests do not pass merely because the
// live code created the file.
func newV6File(t *testing.T) v6Fixture {
	t.Helper()
	src, srcPath := newStoreAt(t, lifecycle.DefaultPolicy())
	d1, d2 := twoVersionsOneApproved(t, src)
	head, err := src.AuditHead(bg)
	if err != nil {
		t.Fatal(err)
	}
	if err := src.Close(); err != nil {
		t.Fatal(err)
	}
	f := v6Fixture{path: dbPath(t), approved: d1, pending: d2, head: head, rows: map[string]int{}}
	db := rawDBNoFK(t, f.path)
	for _, stmt := range v6Statements() {
		mustExec(t, db, stmt)
	}
	mustExec(t, db, `ATTACH DATABASE ? AS src`, srcPath)
	mustExec(t, db, `DELETE FROM meta`)
	mustExec(t, db, `INSERT INTO meta (key, value) SELECT key, value FROM src.meta`)
	for _, tbl := range v6Tables {
		mustExec(t, db, `INSERT INTO `+tbl.name+` SELECT * FROM src.`+tbl.name+` ORDER BY `+tbl.order)
		f.rows[tbl.name] = mustCount(t, db, `SELECT COUNT(*) FROM `+tbl.name)
		if n := mustCount(t, db, `SELECT COUNT(*) FROM src.`+tbl.name); n != f.rows[tbl.name] {
			t.Fatalf("fixture: copied %d rows of %s, the source holds %d", f.rows[tbl.name], tbl.name, n)
		}
	}
	mustExec(t, db, `DETACH DATABASE src`)
	mustExec(t, db, `PRAGMA user_version = `+itoa(v6Version))
	var mode string
	if err := db.QueryRowContext(bg, `PRAGMA journal_mode = WAL`).Scan(&mode); err != nil || !strings.EqualFold(mode, walMode) {
		t.Fatalf("fixture: journal mode %q, %v", mode, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	makePrivate(t, f.path)
	assertV6Shape(t, f.path)
	return f
}

// twoVersionsOneApproved builds alpha/echo with v1 approved by bob and v2
// pending after a second crawl; it returns the two digests.
func twoVersionsOneApproved(t *testing.T, s *Store) (string, string) {
	t.Helper()
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("echo", "v1"))
	d1 := digestOf(t, "echo", "v1")
	mustApprove(t, s, "alpha", "echo", d1)
	mustCrawl(t, s, "alpha", tool("echo", "v2"))
	mustBeClean(t, s, "with one approved and one pending version")
	return d1, digestOf(t, "echo", "v2")
}

// assertV6Shape checks that a file is a version 6 file as v0.3.0 wrote it:
// user_version 6, the 32 objects of the frozen DDL and nothing the migration
// adds.
func assertV6Shape(t *testing.T, path string) {
	t.Helper()
	db := rawDB(t, path)
	if v := mustCount(t, db, `PRAGMA user_version`); v != v6Version {
		t.Fatalf("user_version = %d, want %d", v, v6Version)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM sqlite_master`); n != v6Objects {
		t.Fatalf("sqlite_master holds %d objects, a v0.3.0 file holds %d", n, v6Objects)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM sqlite_master WHERE name LIKE ?`, v7Added); n != 0 {
		t.Fatalf("%d objects named %s exist in the version 6 file", n, v7Added)
	}
}

// rowCounts reads the row count of every version 6 table.
func rowCounts(t *testing.T, db *sql.DB) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, tbl := range v6Tables {
		out[tbl.name] = mustCount(t, db, `SELECT COUNT(*) FROM `+tbl.name)
	}
	return out
}
