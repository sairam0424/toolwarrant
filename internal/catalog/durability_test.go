package catalog

import (
	"strings"
	"testing"
)

// The index the anchor reads rest on (PR 1.3 of the 2026-10-14 plan). Every
// read that anchors a row to the newest audit entry about its subject costs
// one probe of audit_log_by_subject only while that index exists and the
// statements keep a shape the planner can use; nothing else in the suite would
// notice a schema or query change that brings the walk of the log back, so
// this test pins the plan of every such read.

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
// about a subject: the stand-alone forms, the three queries that embed the
// correlated forms, and the two full-row forms.
func anchorQueries() []anchorQuery {
	return []anchorQuery{
		{"decisionEntryOfSubject (anchorOne)", `SELECT ` + decisionEntryOfSubject, planCovering},
		{"stateEntryOfSubject (anchorToolState)", `SELECT ` + stateEntryOfSubject, planCovering},
		{"snapshotQuery (Snapshot; decisionEntryOfTool and stateEntryOfTool)", snapshotQuery, planCovering},
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
