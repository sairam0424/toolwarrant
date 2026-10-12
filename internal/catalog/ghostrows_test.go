package catalog

import (
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// Rows below id 1 (D17 b, g). SQLite evaluates an unsupplied id as -1 inside
// a BEFORE INSERT trigger, so the seventh review planted an approvals row at
// id -1 with plain SQL and every later decision that records a row failed
// under approvals_no_replace with a message that named the wrong cause, and a
// tool_versions row at id -1 did the same to the next crawl. The positive-id
// guards now refuse the insert, and a row planted under a dropped and
// re-created guard is refused by every read and write with its cause named.

// plantGhostApproval stores an approvals row at a negative id for a version,
// as a forger who drops and re-creates the positive-id guard does.
func plantGhostApproval(t *testing.T, db *sql.DB, id, versionID int64, digest string) {
	t.Helper()
	ddl := triggerDDL(t, db, "approvals_positive_id")
	mustExec(t, db, `DROP TRIGGER approvals_positive_id`)
	mustExec(t, db, `INSERT INTO approvals (id, version_id, decision, approver, actor_type, hash_seen, at) VALUES (?, ?, 'approve', 'mallory', 'human', ?, ?)`,
		id, versionID, digest, forgedTS)
	mustExec(t, db, ddl)
	mustExec(t, db, `UPDATE meta SET value = value + 1 WHERE key = 'generation'`)
}

// ghostVersionInsert copies a version row to id -1 under version number 999
// and a digest nobody proposed.
const ghostVersionInsert = `INSERT INTO tool_versions (id, tool_id, version_no, digest, digest_profile, canonical, raw, status, proposed_by, first_seen_at, crawl_id, ever_approved)
	SELECT -1, tool_id, 999, 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', digest_profile, canonical, raw, 'superseded', proposed_by, first_seen_at, crawl_id, 0
	FROM tool_versions WHERE id = ?`

// The positive-id guards refuse a row at id 0 or below from plain SQL and name
// the rule; the Store's own inserts, which supply no id, pass them.
func TestGuards_RowsBelowIdOneAreRefusedByThePositiveIdGuards(t *testing.T) {
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	approvedEcho(t, s)
	mustCrawl(t, s, "alpha", tool("echo", "v2"))
	d2 := digestOf(t, "echo", "v2")
	db := rawDB(t, path)
	v2 := versionRowID(t, db, d2)
	for _, id := range []int64{-1, 0} {
		_, err := db.ExecContext(bg, `INSERT INTO approvals (id, version_id, decision, approver, actor_type, hash_seen, at) VALUES (?, ?, 'approve', 'mallory', 'human', ?, ?)`,
			id, v2, d2, forgedTS)
		if err == nil || !strings.Contains(err.Error(), "approvals ids start at 1") {
			t.Errorf("approvals row at id %d = %v, want the positive-id guard to refuse it", id, err)
		}
	}
	if _, err := db.ExecContext(bg, ghostVersionInsert, v2); err == nil || !strings.Contains(err.Error(), "tool_versions ids start at 1") {
		t.Errorf("tool_versions row at id -1 = %v, want the positive-id guard to refuse it", err)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM approvals WHERE id < 1`) + mustCount(t, db, `SELECT COUNT(*) FROM tool_versions WHERE id < 1`); n != 0 {
		t.Errorf("%d rows below id 1 remain after the refused inserts", n)
	}
	if err := s.Reject(bg, "alpha", "echo", d2, bob); err != nil {
		t.Errorf("Reject after the refused inserts = %v; the guards must not touch the Store's own rows", err)
	}
	mustBeClean(t, s, "after the refused inserts")
}

// A ghost approvals row planted under a re-created guard made every decision
// that records a row fail under approvals_no_replace; now every decision,
// Disable included, and every read refuse the file naming the row below id 1,
// Integrity counts it, and removing it restores service.
func TestDecisions_GhostApprovalsRowIsNamedNotMistakenForAReplace(t *testing.T) {
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	d1 := approvedEcho(t, s)
	mustCrawl(t, s, "alpha", tool("echo", "v2"))
	d2 := digestOf(t, "echo", "v2")
	db := rawDB(t, path)
	plantGhostApproval(t, db, -1, versionRowID(t, db, d2), d2)

	const cause = "approvals holds a row whose id is below 1"
	wantCause := func(what string, err error) {
		t.Helper()
		if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), cause) || strings.Contains(err.Error(), "cannot be replaced") {
			t.Errorf("%s = %v, want ErrCorrupt naming the row below id 1 and not the no-replace guard", what, err)
		}
	}
	wantCause("Reject by bob", s.Reject(bg, "alpha", "echo", d2, bob))
	wantCause("Approve by bob", s.Approve(bg, "alpha", "echo", d2, bob))
	wantCause("Disable by bob", s.Disable(bg, "alpha", "echo", bob))
	_, err := s.RecordCrawl(bg, crawlOf(tool("echo", "v3")), crawler)
	wantCause("RecordCrawl", err)
	for name, err := range allPaths(s, "alpha", "echo") {
		wantCause(name, err)
	}
	rep := mustIntegrity(t, s)
	if rep.GhostRows != 1 {
		t.Errorf("Integrity.GhostRows = %d, want 1; %q", rep.GhostRows, rep.Problems)
	}
	problemMentioning(t, rep, "approvals row -1", "below 1", "not a decision")

	mustExec(t, db, `DROP TRIGGER approvals_no_delete`)
	mustExec(t, db, `DELETE FROM approvals WHERE id = -1`)
	restoreGuard(t, db, "approvals_no_delete")
	if err := s.Reject(bg, "alpha", "echo", d2, bob); err != nil {
		t.Errorf("Reject after the repair = %v", err)
	}
	if snap := mustSnapshot(t, s, "alpha"); !snap.Serves("echo", d1) {
		t.Errorf("Snapshot after the repair = %+v", snap.Tools["echo"])
	}
	mustBeClean(t, s, "after the repair")
}

// The same for a tool_versions row at id -1, which made the next crawl that
// stores a version fail under tool_versions_no_replace.
func TestRecordCrawl_GhostVersionRowIsNamedNotMistakenForAReplace(t *testing.T) {
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	approvedEcho(t, s)
	db := rawDB(t, path)
	v1 := versionRowID(t, db, digestOf(t, "echo", "v1"))
	ddl := triggerDDL(t, db, "tool_versions_positive_id")
	mustExec(t, db, `DROP TRIGGER tool_versions_positive_id`)
	mustExec(t, db, ghostVersionInsert, v1)
	mustExec(t, db, `INSERT INTO tool_version_proposers (version_id, position, actor) SELECT -1, 0, proposed_by FROM tool_versions WHERE id = -1`)
	mustExec(t, db, ddl)
	mustExec(t, db, `UPDATE meta SET value = value + 1 WHERE key = 'generation'`)

	const cause = "tool_versions holds a row whose id is below 1"
	_, err := s.RecordCrawl(bg, crawlOf(tool("echo", "v3")), crawler)
	if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), cause) || strings.Contains(err.Error(), "cannot be replaced") {
		t.Errorf("RecordCrawl = %v, want ErrCorrupt naming the row below id 1 and not the no-replace guard", err)
	}
	if _, err := s.Snapshot(bg, "alpha"); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), cause) {
		t.Errorf("Snapshot = %v, want ErrCorrupt naming the row below id 1", err)
	}
	rep := mustIntegrity(t, s)
	if rep.GhostRows != 1 {
		t.Errorf("Integrity.GhostRows = %d, want 1; %q", rep.GhostRows, rep.Problems)
	}
	problemMentioning(t, rep, "version row -1", "below 1")
}
