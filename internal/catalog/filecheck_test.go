package catalog

import (
	"database/sql"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// The fifth review's probes 3 and 4 against what every read checks about the
// file (D15 d and e): the catalog identity was compared by Generation alone
// while the documents said every read compared it, and a table re-created
// with an extra constraint was seen by nothing while every later write failed
// on it.

// A file whose catalog identity changed under a running Store is refused by
// every read, not only by Generation: a long-lived reader that calls Snapshot
// without Generation (the canary) sees ErrReplaced too.
func TestSnapshot_ComparesTheStoredIdentityOnEveryRead(t *testing.T) {
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	approvedEcho(t, s)
	mustSnapshot(t, s, "alpha")
	db := rawDB(t, path)
	other, err := newIdentity()
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `UPDATE meta SET value = ? WHERE key = 'identity'`, other)
	if _, err := s.Generation(bg); !errors.Is(err, ErrReplaced) {
		t.Errorf("Generation with another identity = %v, want ErrReplaced", err)
	}
	for name, err := range allPaths(s, "alpha", "echo") {
		if !errors.Is(err, ErrReplaced) || !strings.Contains(err.Error(), "another catalog identity") {
			t.Errorf("%s with another identity = %v, want ErrReplaced naming the identity", name, err)
		}
	}
	mustExec(t, db, `UPDATE meta SET value = ? WHERE key = 'identity'`, s.identity)
	for name, err := range allPaths(s, "alpha", "echo") {
		if err != nil {
			t.Errorf("%s after the identity was restored = %v", name, err)
		}
	}
}

// recreateWithExtraConstraint rebuilds table with its original column list
// plus one table constraint, copies the rows, and re-creates the guard objects
// that DROP TABLE removed, byte for byte: the review's edit.
func recreateWithExtraConstraint(t *testing.T, db *sql.DB, table, constraint string) {
	t.Helper()
	var ddl string
	if err := db.QueryRowContext(bg, `SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&ddl); err != nil {
		t.Fatal(err)
	}
	rows, err := db.QueryContext(bg, `SELECT sql FROM sqlite_master WHERE tbl_name = ? AND type IN ('trigger', 'index') AND sql IS NOT NULL`, table)
	if err != nil {
		t.Fatal(err)
	}
	var dependents []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			t.Fatal(err)
		}
		dependents = append(dependents, d)
	}
	_ = rows.Close()
	body := strings.TrimSuffix(strings.TrimSpace(ddl), ")")
	tmp := table + "_tmp"
	mustExec(t, db, strings.Replace(body, "CREATE TABLE "+table, "CREATE TABLE "+tmp, 1)+", "+constraint+")")
	mustExec(t, db, `INSERT INTO `+tmp+` SELECT * FROM `+table)
	mustExec(t, db, `DROP TABLE `+table)
	mustExec(t, db, `ALTER TABLE `+tmp+` RENAME TO `+table)
	for _, d := range dependents {
		mustExec(t, db, d)
	}
}

// audit_log re-created with UNIQUE (event): the table's DDL differs from the
// schema's and SQLite keeps an automatic index for the constraint. The
// long-lived Store's next crawl fails on the constraint with the table named,
// its reads refuse the file naming the redefined table and the foreign index,
// a fresh open refuses, and Integrity lists both while the chain (rows copied)
// still verifies.
func TestOpen_TableRecreatedWithAnExtraConstraintIsCorrupt(t *testing.T) {
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	approvedEcho(t, s)
	mustBeClean(t, s, "before the edit")
	recreateWithExtraConstraint(t, rawDBNoFK(t, path), "audit_log", "UNIQUE (event)")

	_, cerr := s.RecordCrawl(bg, crawlOf(tool("echo", "v1")), crawler)
	if !errors.Is(cerr, ErrCorrupt) || !strings.Contains(cerr.Error(), "a write to table audit_log failed a constraint (UNIQUE constraint failed: audit_log.event)") {
		t.Errorf("RecordCrawl = %v, want ErrCorrupt naming the table and the constraint", cerr)
	}
	const redefined, foreign = "table audit_log was redefined", "unexpected index sqlite_autoindex_audit_log_1"
	for name, err := range allPaths(s, "alpha", "echo") {
		if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), redefined) || !strings.Contains(err.Error(), foreign) {
			t.Errorf("%s = %v, want ErrCorrupt naming the redefined table and the automatic index", name, err)
		}
	}
	_ = s.Close()
	for name, opts := range map[string]OpenOptions{"read-write": {Policy: lifecycle.DefaultPolicy()}, "read-only": {ReadOnly: true}} {
		s2, err := OpenWith(path, opts)
		if s2 != nil {
			_ = s2.Close()
		}
		if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), redefined) || !strings.Contains(err.Error(), foreign) {
			t.Errorf("%s Open = %v, want ErrCorrupt naming the redefined table and the automatic index", name, err)
		}
	}
	f, err := OpenWith(path, OpenOptions{Forensic: true})
	if err != nil {
		t.Fatalf("forensic Open = %v", err)
	}
	defer func() { _ = f.Close() }()
	rep := mustIntegrity(t, f)
	if !slices.Contains(rep.GuardsRedefined, "table audit_log") || !slices.Contains(rep.ForeignObjects, "index sqlite_autoindex_audit_log_1") {
		t.Errorf("Integrity = redefined %v, foreign %v; want the table and its automatic index", rep.GuardsRedefined, rep.ForeignObjects)
	}
	problemMentioning(t, rep, redefined, foreign+": the schema did not create it")
	if _, err := f.VerifyAudit(bg); err != nil {
		t.Errorf("VerifyAudit = %v; the rows were copied, the chain itself holds", err)
	}
}

// A CHECK constraint added the same way refuses one decision: the error names
// the constraint SQLite reports, and the reads name the redefined table.
func TestDisable_CheckConstraintFromARecreatedTableIsNamed(t *testing.T) {
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	approvedEcho(t, s)
	recreateWithExtraConstraint(t, rawDBNoFK(t, path), "tools", "CHECK (state <> 'disabled')")
	err := s.Disable(bg, "alpha", "echo", alice)
	if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "a write failed a CHECK constraint (CHECK constraint failed: state <> 'disabled')") {
		t.Errorf("Disable = %v, want ErrCorrupt naming the CHECK constraint", err)
	}
	if _, err := s.Snapshot(bg, "alpha"); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "table tools was redefined") {
		t.Errorf("Snapshot = %v, want ErrCorrupt naming the redefined table", err)
	}
	var state string
	if err := rawDB(t, path).QueryRowContext(bg, `SELECT state FROM tools WHERE name = 'echo'`).Scan(&state); err != nil || state != string(lifecycle.Enabled) {
		t.Errorf("state after the refused disable = %q, %v; nothing may commit", state, err)
	}
}

// The expected automatic indexes are a list the schema cannot derive at run
// time (SQLite numbers them), so a fresh file pins the list, and the tables the
// check compares are exactly the tables a fresh file holds.
func TestSchema_AutomaticIndexesArePinned(t *testing.T) {
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	mustAddServer(t, s, "alpha")
	db := rawDB(t, path)
	read := func(query string) []string {
		t.Helper()
		rows, err := db.QueryContext(bg, query)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		var names []string
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				t.Fatal(err)
			}
			names = append(names, name)
		}
		return names
	}
	var want []string
	for _, g := range automaticIndexes() {
		want = append(want, g.name)
	}
	if got := read(`SELECT name FROM sqlite_master WHERE type = 'index' AND sql IS NULL ORDER BY name`); !slices.Equal(got, slices.Sorted(slices.Values(want))) {
		t.Errorf("automatic indexes in a fresh file = %v, the schema lists %v", got, want)
	}
	var tables []string
	for _, g := range schemaTables() {
		tables = append(tables, g.name)
	}
	if got := read(`SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name`); !slices.Equal(got, slices.Sorted(slices.Values(tables))) {
		t.Errorf("tables in a fresh file = %v, the schema lists %v", got, tables)
	}
	for _, g := range schemaObjects() {
		if g.name == "" || g.kind == "" {
			t.Errorf("schema object without a kind or name: %+v", g)
		}
	}
	mustBeClean(t, s, "on a fresh file")
}
