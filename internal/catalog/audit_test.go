package catalog

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sairam0424/toolwarrant/internal/audit"
)

// seededStore returns a store whose log holds several entries of every kind.
func seededStore(t *testing.T) (*Store, string) {
	t.Helper()
	s, path := newStoreAt(t, defaultPolicyForTests())
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("echo", "v1"), tool("sum", "v1"))
	mustApprove(t, s, "alpha", "echo", digestOf(t, "echo", "v1"))
	mustCrawl(t, s, "alpha", tool("echo", "v2"))
	if err := s.Disable(bg, "alpha", "echo", alice); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordCrawl(bg, CrawlInput{Server: "alpha", Error: "down"}, crawler); err != nil {
		t.Fatal(err)
	}
	return s, path
}

func TestVerifyAudit_EmptyAndPopulated(t *testing.T) {
	s := newStore(t)
	sum, err := s.VerifyAudit(bg)
	if err != nil || sum.Entries != 0 || sum.Head != audit.Genesis {
		t.Fatalf("empty log: %+v, %v", sum, err)
	}

	s, _ = seededStore(t)
	entries, err := s.AuditEntries(bg, 0, 0)
	if err != nil || len(entries) < 10 {
		t.Fatalf("entries = %d, %v", len(entries), err)
	}
	sum, err = s.VerifyAudit(bg)
	if err != nil || sum.Entries != len(entries) || sum.Head != entries[len(entries)-1].Hash {
		t.Fatalf("summary = %+v, %v", sum, err)
	}
	if entries[0].PrevHash != audit.Genesis {
		t.Errorf("first prev_hash = %s", entries[0].PrevHash)
	}
	for i, e := range entries {
		ts, err := time.Parse(time.RFC3339Nano, e.TS)
		if err != nil || !strings.HasSuffix(e.TS, "Z") || ts.Location() != time.UTC || len(e.TS) != len("2006-01-02T15:04:05.000000000Z") {
			t.Errorf("entry %d ts = %q (%v)", e.Seq, e.TS, err)
		}
		if e.Seq != int64(i+1) || e.Actor == "" || (e.ActorType != "human" && e.ActorType != "system") || e.Event == "" || e.Subject == "" {
			t.Errorf("entry %d = %+v", i, e)
		}
		if strings.Contains(e.Detail, "description") || strings.Contains(e.Detail, "inputSchema") {
			t.Errorf("entry %d carries tool text in its detail: %q", e.Seq, e.Detail)
		}
	}
}

func TestAuditEntries_PagingAndLimits(t *testing.T) {
	s, _ := seededStore(t)
	all, _ := s.AuditEntries(bg, 0, 0)
	page, err := s.AuditEntries(bg, 2, 3)
	if err != nil || len(page) != 3 || page[0].Seq != 3 || page[2].Seq != 5 {
		t.Fatalf("page = %+v, %v", page, err)
	}
	if neg, _ := s.AuditEntries(bg, 0, -5); len(neg) != len(all) {
		t.Errorf("a negative limit returned %d of %d", len(neg), len(all))
	}
	tail, err := s.AuditEntries(bg, int64(len(all)), 10)
	if err != nil || tail == nil || len(tail) != 0 {
		t.Errorf("past the end = %#v, %v", tail, err)
	}
	var _ AuditReader = s // the Store is the read side the verifier needs
}

func TestVerifyAudit_PagesThroughLargeLogs(t *testing.T) {
	if testing.Short() {
		t.Skip("writes about 5000 audit entries")
	}
	s := newStore(t)
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", bigCrawl(2600, "v1")...)
	sum, err := s.VerifyAudit(bg)
	if err != nil || sum.Entries != 1+2*2600+1 {
		t.Fatalf("summary = %+v, %v", sum, err)
	}
}

func brokenAt(t *testing.T, err error) *audit.BrokenError {
	t.Helper()
	var broken *audit.BrokenError
	if !errors.As(err, &broken) {
		t.Fatalf("err = %v, want *audit.BrokenError", err)
	}
	if direct, ok := err.(*audit.BrokenError); !ok || direct != broken {
		t.Fatalf("VerifyAudit must return the *audit.BrokenError itself, got %T", err)
	}
	return broken
}

func TestVerifyAudit_DetectsEditingWithTheTriggerDropped(t *testing.T) {
	s, path := seededStore(t)
	db := rawDB(t, path)

	mustExec(t, db, `DROP TRIGGER audit_log_no_update`)
	mustExec(t, db, `UPDATE audit_log SET actor = 'mallory' WHERE seq = 4`)
	if b := brokenAt(t, verifyErr(s)); b.Seq != 4 || !strings.Contains(b.Reason, "hash") {
		t.Errorf("edit: %+v", b)
	}
}

func TestVerifyAudit_DetectsDeletionAndReordering(t *testing.T) {
	s, path := seededStore(t)
	db := rawDB(t, path)
	mustExec(t, db, `DROP TRIGGER audit_log_no_delete`)
	mustExec(t, db, `DELETE FROM audit_log WHERE seq = 5`)
	if b := brokenAt(t, verifyErr(s)); b.Seq != 6 || !strings.Contains(b.Reason, "gap") {
		t.Errorf("deleted entry: %+v", b)
	}
}

func TestVerifyAudit_DetectsRewrittenLinks(t *testing.T) {
	s, path := seededStore(t)
	db := rawDB(t, path)
	mustExec(t, db, `DROP TRIGGER audit_log_no_update`)
	mustExec(t, db, `UPDATE audit_log SET prev_hash = ? WHERE seq = 3`, strings.Repeat("a", 64))
	if b := brokenAt(t, verifyErr(s)); b.Seq != 3 || !strings.Contains(b.Reason, "prev_hash") {
		t.Errorf("relinked entry: %+v", b)
	}
}

func TestVerifyAudit_ChainAloneCannotSeeTruncation(t *testing.T) {
	s, path := seededStore(t)
	before, err := s.VerifyAudit(bg)
	if err != nil {
		t.Fatal(err)
	}
	db := rawDB(t, path)
	mustExec(t, db, `DROP TRIGGER audit_log_no_delete`)
	mustExec(t, db, `DELETE FROM audit_log WHERE seq = ?`, before.Entries)
	after, err := s.VerifyAudit(bg)
	if err != nil {
		t.Fatalf("a truncated chain is still a valid chain: %v", err)
	}
	if after.Head == before.Head || after.Entries != before.Entries-1 {
		t.Errorf("truncation must at least change the head that operators record elsewhere: %+v -> %+v", before, after)
	}
}

func verifyErr(s *Store) error {
	_, err := s.VerifyAudit(bg)
	return err
}

// versionInsert is the full INSERT prefix for tool_versions, so a forged row
// fails on a guard and not on a missing NOT NULL column.
const versionInsert = `INSERT OR REPLACE INTO tool_versions (tool_id, version_no, digest, digest_profile, canonical, raw, status, proposed_by, ever_approved, first_seen_at, crawl_id)`

func TestTriggers_RefuseEditsToHistoryThroughOrdinarySQL(t *testing.T) {
	_, path := seededStore(t)
	db := rawDB(t, path)
	insertAudit := func(seq int) string {
		return fmt.Sprintf(`INSERT OR REPLACE INTO audit_log VALUES (%d,'t','a','human','e','s','','','d','p','h')`, seq)
	}
	versionID := func() int { return mustCount(t, db, `SELECT MIN(id) FROM tool_versions`) }
	toolID := mustCount(t, db, `SELECT MIN(tool_id) FROM tool_versions`)
	digest := func() string {
		var d string
		if err := db.QueryRowContext(bg, `SELECT digest FROM tool_versions WHERE id = ?`, versionID()).Scan(&d); err != nil {
			t.Fatal(err)
		}
		return d
	}

	refused := map[string]string{
		"audit update":               `UPDATE audit_log SET detail = 'x' WHERE seq = 1`,
		"audit delete one":           `DELETE FROM audit_log WHERE seq = 1`,
		"audit delete all":           `DELETE FROM audit_log`,
		"audit replace existing seq": insertAudit(2),
		"audit insert with a gap":    insertAudit(99999),
		"audit insert seq zero":      insertAudit(0),
		"version delete":             `DELETE FROM tool_versions`,
		"version digest":             `UPDATE tool_versions SET digest = '` + strings.Repeat("0", 64) + `'`,
		"version profile":            `UPDATE tool_versions SET digest_profile = 'other'`,
		"version canonical":          `UPDATE tool_versions SET canonical = x'7b7d'`,
		"version raw":                `UPDATE tool_versions SET raw = x'7b7d'`,
		"version proposed_by":        `UPDATE tool_versions SET proposed_by = 'mallory'`,
		"version tool_id":            fmt.Sprintf(`UPDATE tool_versions SET tool_id = %d`, toolID+1),
		"version version_no":         `UPDATE tool_versions SET version_no = version_no + 10`,
		"version first_seen_at":      `UPDATE tool_versions SET first_seen_at = '2000-01-01T00:00:00.000000000Z'`,
		"version crawl_id":           `UPDATE tool_versions SET crawl_id = 1`,
		"version id":                 `UPDATE tool_versions SET id = id + 1000`,
		"version replace by digest": fmt.Sprintf(versionInsert+`
			VALUES (%d, 77, '%s', 'full-v1', x'7b7d', x'7b7d', 'pending', 'x', 0, 't', 1)`, toolID, digest()),
		"version replace by number": fmt.Sprintf(versionInsert+`
			VALUES (%d, 1, '%s', 'full-v1', x'7b7d', x'7b7d', 'superseded', 'x', 0, 't', 1)`, toolID, strings.Repeat("1", 64)),
		"version replace by id": fmt.Sprintf(`INSERT OR REPLACE INTO tool_versions (id, tool_id, version_no, digest, digest_profile, canonical, raw, status, proposed_by, ever_approved, first_seen_at, crawl_id)
			VALUES (%d, %d, 78, '%s', 'full-v1', x'7b7d', x'7b7d', 'superseded', 'x', 0, 't', 1)`, versionID(), toolID, strings.Repeat("2", 64)),
		"approval update":        `UPDATE approvals SET approver = 'mallory'`,
		"approval delete":        `DELETE FROM approvals`,
		"approval replace by id": `INSERT OR REPLACE INTO approvals (id, version_id, decision, approver, actor_type, hash_seen, at) SELECT id, version_id, 'approve', 'mallory', 'human', hash_seen, at FROM approvals`,
		"proposer update":        `UPDATE tool_version_proposers SET actor = 'mallory'`,
		"proposer delete":        `DELETE FROM tool_version_proposers`,
		"proposer replace":       fmt.Sprintf(`INSERT OR REPLACE INTO tool_version_proposers (version_id, position, actor) VALUES (%d, 0, 'mallory')`, versionID()),
		"proposer out of order":  fmt.Sprintf(`INSERT INTO tool_version_proposers (version_id, position, actor) VALUES (%d, 5, 'mallory')`, versionID()),
	}
	for name, stmt := range refused {
		if _, err := db.ExecContext(bg, stmt); err == nil {
			t.Errorf("%s was accepted: %s", name, stmt)
		}
	}

	// The fields that are allowed to move still move; the chain is unaffected by them.
	mustExec(t, db, `UPDATE tool_versions SET status = status, ever_approved = ever_approved WHERE id = ?`, versionID())
	mustExec(t, db, `UPDATE tool_versions SET proposed_by = proposed_by WHERE id = ?`, versionID()) // same value: no change
	// And every refusal left the data as it was.
	for _, s := range []string{`SELECT COUNT(*) FROM audit_log`, `SELECT COUNT(*) FROM tool_versions`, `SELECT COUNT(*) FROM approvals`,
		`SELECT COUNT(*) FROM tool_version_proposers`} {
		if mustCount(t, db, s) == 0 {
			t.Errorf("%s is empty after refused statements", s)
		}
	}
	if mustCount(t, db, `SELECT COUNT(*) FROM tool_version_proposers WHERE actor = 'mallory'`) != 0 {
		t.Error("mallory got into the proposers")
	}
}

func TestTriggers_StoreOperationsStillWork(t *testing.T) {
	// The guards must not get in the way of the store's own writes: a long mixed
	// history goes through with the triggers in place.
	s, _ := seededStore(t)
	mustCrawl(t, s, "alpha", tool("echo", "v3"), tool("sum", "v2"), tool("new", "v1"))
	if err := s.Enable(bg, "alpha", "echo", bob); err != nil {
		t.Fatal(err)
	}
	mustCrawl(t, s, "alpha", tool("echo", "v1"), tool("sum", "v2"), tool("new", "v1")) // v1 re-proposed: proposer appended
	if _, err := s.VerifyAudit(bg); err != nil {
		t.Fatal(err)
	}
}
