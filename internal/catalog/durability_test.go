package catalog

import (
	"database/sql"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// The durability settings and the index the anchor reads rest on (PR 1.3 of
// the 2026-10-14 plan, owner decision O-3). SQLite applies a PRAGMA to the
// connection that ran it, and database/sql hands out whichever pooled
// connection is free, so a setting the catalog relies on must travel in the
// connection string, where the driver applies it to every connection it opens.
// These two tests pin what the catalog relies on: every connection of every
// pool runs WAL, synchronous FULL and foreign keys, and every read that anchors
// a row to the newest audit entry about its subject is an index seek, never a
// scan of the log.

const (
	// wantSynchronousFull is what PRAGMA synchronous returns for FULL.
	wantSynchronousFull = 2
	// wantForeignKeysOn is what PRAGMA foreign_keys returns when enforced.
	wantForeignKeysOn = 1
	// synchronousPragma is the DSN value every connection kind must carry,
	// spelled out here so that the test pins the level and not a constant.
	synchronousPragma = "synchronous(FULL)"
)

// TestOpen_EveryPooledConnectionIsSynchronousFullWithForeignKeysInWAL borrows
// every connection of every pool of a read-write, a read-only and a forensic
// store at once and reads the three pragmas back from each, so that a setting
// applied to one connection and not the others, or left at a build's default,
// is caught. The DSN of all four connection kinds is checked as well, since
// the immutable kind opens only a file that is no longer in WAL mode.
func TestOpen_EveryPooledConnectionIsSynchronousFullWithForeignKeysInWAL(t *testing.T) {
	rw, path := newStoreAt(t, lifecycle.DefaultPolicy())
	mustAddServer(t, rw, "alpha")
	mustCrawl(t, rw, "alpha", tool("echo", "v1"))
	mustApprove(t, rw, "alpha", "echo", digestOf(t, "echo", "v1"))
	ro, err := OpenWith(path, OpenOptions{ReadOnly: true})
	if err != nil {
		t.Fatalf("read-only open: %v", err)
	}
	defer func() { _ = ro.Close() }()
	forensic, err := OpenWith(path, OpenOptions{Forensic: true})
	if err != nil {
		t.Fatalf("forensic open: %v", err)
	}
	defer func() { _ = forensic.Close() }()

	pools := []struct {
		name string
		db   *sql.DB
	}{
		{"read-write writer", rw.wdb},
		{"read-write reader", rw.rdb},
		{"read-only reader", ro.rdb},
		{"forensic reader", forensic.rdb},
	}
	for _, p := range pools {
		checkEveryConnection(t, p.name, p.db)
	}
	for _, kind := range []connKind{connWriter, connReader, connReadOnlyFile, connImmutableFile} {
		checkDSNPragma(t, kind, dsnFor(path, kind, DefaultBusyTimeout))
	}
}

// checkEveryConnection takes every connection the pool may open and holds
// them together, so that each PRAGMA is read on a distinct connection.
func checkEveryConnection(t *testing.T, pool string, db *sql.DB) {
	t.Helper()
	n := db.Stats().MaxOpenConnections
	if n < 1 {
		t.Fatalf("%s: the pool has no connection limit, so not every connection can be reached", pool)
	}
	conns := make([]*sql.Conn, 0, n)
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()
	for i := range n {
		c, err := db.Conn(bg)
		if err != nil {
			t.Fatalf("%s: take connection %d of %d: %v", pool, i+1, n, err)
		}
		conns = append(conns, c)
	}
	for i, c := range conns {
		checkConnectionPragmas(t, fmt.Sprintf("%s, connection %d of %d", pool, i+1, n), c)
	}
}

// checkConnectionPragmas reads synchronous, foreign_keys and journal_mode back
// from one connection.
func checkConnectionPragmas(t *testing.T, conn string, c *sql.Conn) {
	t.Helper()
	var (
		synchronous, foreignKeys int
		journal                  string
	)
	if err := c.QueryRowContext(bg, `PRAGMA synchronous`).Scan(&synchronous); err != nil {
		t.Fatalf("%s: PRAGMA synchronous: %v", conn, err)
	}
	if err := c.QueryRowContext(bg, `PRAGMA foreign_keys`).Scan(&foreignKeys); err != nil {
		t.Fatalf("%s: PRAGMA foreign_keys: %v", conn, err)
	}
	if err := c.QueryRowContext(bg, `PRAGMA journal_mode`).Scan(&journal); err != nil {
		t.Fatalf("%s: PRAGMA journal_mode: %v", conn, err)
	}
	if synchronous != wantSynchronousFull {
		t.Errorf("%s: PRAGMA synchronous = %d, want %d (FULL): the WAL sync at commit is what makes a returned decision survive a power loss", conn, synchronous, wantSynchronousFull)
	}
	if foreignKeys != wantForeignKeysOn {
		t.Errorf("%s: PRAGMA foreign_keys = %d, want %d", conn, foreignKeys, wantForeignKeysOn)
	}
	if !strings.EqualFold(journal, walMode) {
		t.Errorf("%s: PRAGMA journal_mode = %q, want %q", conn, journal, walMode)
	}
}

// checkDSNPragma requires the connection string of one kind to carry the
// synchronous pragma, which is how it reaches every pooled connection.
func checkDSNPragma(t *testing.T, kind connKind, dsn string) {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("connection kind %d: parse DSN: %v", kind, err)
	}
	if !slices.Contains(u.Query()["_pragma"], synchronousPragma) {
		t.Errorf("connection kind %d: the DSN %q does not carry %s", kind, dsn, synchronousPragma)
	}
}

// anchorQuery is one read the serving path or a decision runs against the
// log, with what its plan must say about the log: a MAX(seq) form needs only
// the index (covering), a form that returns whole entries seeks the index and
// then reads the rows.
type anchorQuery struct {
	name string
	sql  string
	want string
}

const (
	planCovering = "USING COVERING INDEX audit_log_by_subject"
	planSeek     = "USING INDEX audit_log_by_subject"
	// logTable and logAlias are how EXPLAIN QUERY PLAN names the audit log:
	// by its name in a plain query, by the alias l inside the correlated
	// subqueries of anchor.go and stateanchor.go.
	logTable = "audit_log"
	logAlias = "l"
)

// anchorQueries lists every statement that reads the newest entry or entries
// about a subject: the stand-alone forms, the snapshot's one-pass form, the
// two views that embed the correlated forms, and the two full-row forms.
func anchorQueries() []anchorQuery {
	return []anchorQuery{
		{"decisionEntryOfSubject (anchorOne)", `SELECT ` + decisionEntryOfSubject, planCovering},
		{"stateEntryOfSubject (anchorToolState)", `SELECT ` + stateEntryOfSubject, planCovering},
		{"snapshotQuery (Snapshot; newestEntriesOfServer, one range read per reload)", snapshotQuery, planCovering},
		{"toolViewQuery (Tool; decisionEntryOfServerTool and stateEntryOfServerTool)", toolViewQuery, planCovering},
		{"toolViewsQuery (Tools)", toolViewsQuery, planCovering},
		{"approvedQuery (Approved; decisionEntryOfServerTool)", approvedQuery, planCovering},
		{"newestServerEntryQuery (anchorServer)", newestServerEntryQuery, planSeek},
		{"versionEntriesQuery (versionsFromLog)", versionEntriesQuery, planSeek},
	}
}

// TestAnchorQueries_StayOnTheAuditLogBySubjectIndex runs EXPLAIN QUERY PLAN
// over every read that anchors a tool, a server or a version to the newest
// audit entry about it and requires each to reach the log through the
// audit_log_by_subject index: the MAX(seq) forms as a covering index, the
// forms that return whole entries as an index seek, and none as a scan. The
// research pass of 2026-10-14 measured ten thousand of these probes at 0.07 s
// with the index and 58.9 s without it, a cliff that a schema change or a
// rewritten query could bring back without any other test noticing.
func TestAnchorQueries_StayOnTheAuditLogBySubjectIndex(t *testing.T) {
	s := newStore(t)
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("echo", "v1"))
	mustApprove(t, s, "alpha", "echo", digestOf(t, "echo", "v1"))
	for _, q := range anchorQueries() {
		checkPlan(t, q, explain(t, s, q.sql))
	}
}

// explain returns the detail column of every EXPLAIN QUERY PLAN row of the
// query, bound with one empty string per parameter; the plan of these
// statements does not depend on the values.
func explain(t *testing.T, s *Store, query string) []string {
	t.Helper()
	args := make([]any, strings.Count(query, "?"))
	for i := range args {
		args[i] = ""
	}
	var plan []string
	err := s.inRead(bg, func(q queryer) error {
		rows, err := q.QueryContext(bg, `EXPLAIN QUERY PLAN `+query, args...)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var (
				id, parent, unused int
				detail             string
			)
			if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
				return err
			}
			plan = append(plan, detail)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatalf("EXPLAIN QUERY PLAN %s: %v", query, err)
	}
	return plan
}

// checkPlan requires every plan line about the log to be a seek that uses the
// index as wanted, never a scan, and at least one such line to exist (a query
// that never touched the log would make the check vacuous). A line with no
// USING clause at all is a walk of the log in rowid order: SQLite labels the
// walk behind a MIN or MAX a SEARCH because it stops at the first match, but
// without the index it reads the log up to that match.
func checkPlan(t *testing.T, q anchorQuery, plan []string) {
	t.Helper()
	shown := strings.Join(plan, "\n")
	touched := 0
	for _, line := range plan {
		if !aboutLog(line) {
			continue
		}
		touched++
		switch {
		case strings.HasPrefix(line, "SCAN "):
			t.Errorf("%s: the plan scans the audit log: %q; the full plan:\n%s", q.name, line, shown)
		case !strings.Contains(line, "USING"):
			t.Errorf("%s: the plan reaches the audit log with no index at all: %q; the full plan:\n%s", q.name, line, shown)
		case !strings.Contains(line, q.want):
			t.Errorf("%s: the plan reaches the audit log without %q: %q; the full plan:\n%s", q.name, q.want, line, shown)
		}
	}
	if touched == 0 {
		t.Errorf("%s: no plan line reads the audit log; the full plan:\n%s", q.name, shown)
	}
}

// aboutLog reports whether a plan line reads the audit log, under its name or
// under the alias l of the correlated subqueries.
func aboutLog(line string) bool {
	f := strings.Fields(line)
	if len(f) < 2 || (f[0] != "SCAN" && f[0] != "SEARCH") {
		return false
	}
	return f[1] == logTable || f[1] == logAlias
}
