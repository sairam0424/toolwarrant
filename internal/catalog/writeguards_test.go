package catalog

import (
	"errors"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// Third review, cli-docs-3 (catalog half): RecordCrawl and the decisions did
// not re-check the guard objects, so a crawl scheduled every minute kept
// writing crawls rows, tool state and audit entries into a file that every
// other command refused as ErrCorrupt. Now every write transaction verifies
// the guards before it commits.

// A guard dropped between two RecordCrawl calls on one open Store: the second
// crawl is refused and leaves no crawls row, no tool change and no audit entry.
func TestRecordCrawl_RefusesToCommitAfterAGuardWasDropped(t *testing.T) {
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("echo", "v1"))
	db := rawDB(t, path)
	before := fingerprint(t, s, path)
	mustExec(t, db, `DROP TRIGGER audit_log_no_update`)

	_, err := s.RecordCrawl(bg, crawlOf(tool("echo", "v2"), tool("fresh", "v1")), crawler)
	if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "guard trigger audit_log_no_update is missing") {
		t.Fatalf("RecordCrawl with a guard dropped = %v, want ErrCorrupt naming the guard", err)
	}
	if _, err := s.RecordCrawl(bg, CrawlInput{Server: "alpha", Error: "down"}, crawler); !errors.Is(err, ErrCorrupt) {
		t.Errorf("an incomplete crawl is refused too: %v", err)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM crawls`); n != 1 {
		t.Errorf("crawls rows = %d, want the one from before the drop", n)
	}
	restoreGuard(t, db, "audit_log_no_update")
	if after := fingerprint(t, s, path); after != before {
		t.Errorf("a refused crawl left state behind\nbefore: %s\nafter:  %s", before, after)
	}
	// With the guard back the same Store writes again.
	if rep := mustCrawl(t, s, "alpha", tool("echo", "v2"), tool("fresh", "v1")); len(rep.Changes) != 2 {
		t.Errorf("crawl after restoring the guard = %+v", rep)
	}
}

// Every decision and every other write is refused the same way, whichever
// guard is gone, and a redefined guard counts as gone.
func TestDecisions_RefuseToCommitAfterAGuardWasDroppedOrRedefined(t *testing.T) {
	// Every write below is valid from the state this sets up: echo is on d2
	// with d1 to roll back to and d3 pending (a budget of 1), sum is disabled,
	// alpha runs and beta is paused.
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	mustAddServer(t, s, "alpha")
	mustAddServer(t, s, "beta")
	mustCrawl(t, s, "alpha", tool("echo", "v1"), tool("sum", "v1"))
	d1, d2, d3 := digestOf(t, "echo", "v1"), digestOf(t, "echo", "v2"), digestOf(t, "echo", "v3")
	mustApprove(t, s, "alpha", "echo", d1)
	mustApprove(t, s, "alpha", "sum", digestOf(t, "sum", "v1"))
	mustCrawl(t, s, "alpha", tool("echo", "v2"), tool("sum", "v1"))
	mustApprove(t, s, "alpha", "echo", d2)
	mustCrawl(t, s, "alpha", tool("echo", "v3"), tool("sum", "v1"))
	if err := s.Disable(bg, "alpha", "sum", alice); err != nil {
		t.Fatal(err)
	}
	if err := s.PauseServer(bg, "beta", alice); err != nil {
		t.Fatal(err)
	}
	db := rawDB(t, path)
	cases := map[string]struct{ tamper, restore func() }{
		"index dropped": {
			func() { mustExec(t, db, `DROP INDEX approvals_by_version`) },
			func() { mustExec(t, db, guardIndexStatements()[2]) },
		},
		"trigger redefined": {
			func() {
				mustExec(t, db, `DROP TRIGGER approvals_no_update`)
				mustExec(t, db, `CREATE TRIGGER approvals_no_update BEFORE UPDATE ON approvals WHEN 0 BEGIN SELECT RAISE(ABORT, 'x'); END`)
			},
			func() {
				mustExec(t, db, `DROP TRIGGER approvals_no_update`)
				restoreGuard(t, db, "approvals_no_update")
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			before := fingerprint(t, s, path)
			tc.tamper()
			writes := map[string]error{
				"Approve":             s.Approve(bg, "alpha", "echo", d3, bob),
				"Reject":              s.Reject(bg, "alpha", "echo", d3, bob),
				"Rollback":            s.Rollback(bg, "alpha", "echo", d1, alice),
				"Disable":             s.Disable(bg, "alpha", "echo", alice),
				"Enable":              s.Enable(bg, "alpha", "sum", alice),
				"PauseServer":         s.PauseServer(bg, "alpha", alice),
				"ResumeServer":        s.ResumeServer(bg, "beta", alice),
				"ResetProposalBudget": s.ResetProposalBudget(bg, "alpha", "echo", alice),
				"AddServer": func() error {
					_, err := s.AddServer(bg, ServerSpec{Name: "gamma", URL: "https://g.example.com"}, alice)
					return err
				}(),
			}
			for op, err := range writes {
				if !errors.Is(err, ErrCorrupt) {
					t.Errorf("%s = %v, want ErrCorrupt", op, err)
				}
			}
			tc.restore()
			if after := fingerprint(t, s, path); after != before {
				t.Errorf("refused writes left state behind\nbefore: %s\nafter:  %s", before, after)
			}
		})
	}
	// Whole again, the same Store decides.
	mustApprove(t, s, "alpha", "echo", d3)
}
