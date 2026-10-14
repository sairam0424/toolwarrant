package catalog

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Reviewers' "INSERT OR REPLACE via the partial unique indexes deletes a
// version": the BEFORE INSERT guard mirrors the partial indexes, so REPLACE
// never reaches conflict resolution, with or without foreign keys.
func TestTriggers_ReplaceViaPartialIndexesIsRefused(t *testing.T) {
	s, path := newStoreAt(t, defaultPolicyForTests())
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("echo", "v1"))
	mustApprove(t, s, "alpha", "echo", digestOf(t, "echo", "v1"))
	mustCrawl(t, s, "alpha", tool("echo", "v2")) // v1 approved, v2 pending
	for _, fk := range []bool{true, false} {
		t.Run(fmt.Sprintf("foreign_keys=%t", fk), func(t *testing.T) {
			db := rawDB(t, path)
			if !fk {
				db = rawDBNoFK(t, path)
			}
			toolID := mustCount(t, db, `SELECT id FROM tools WHERE name = 'echo'`)
			crawlID := mustCount(t, db, `SELECT MIN(id) FROM crawls`)
			for _, status := range []string{"pending", "approved"} {
				stmt := fmt.Sprintf(versionInsert+` VALUES (%d, 99, '%s', 'full-v1', x'7b7d', x'7b7d', '%s', 'mallory', 1, 't', %d)`,
					toolID, strings.Repeat("e", 64), status, crawlID)
				if _, err := db.ExecContext(bg, stmt); err == nil {
					t.Errorf("INSERT OR REPLACE conflicting only on the %s partial index was accepted", status)
				}
			}
			if n := mustCount(t, db, `SELECT COUNT(*) FROM tool_versions WHERE proposed_by = 'mallory'`); n != 0 {
				t.Errorf("mallory rows = %d", n)
			}
			if n := mustCount(t, db, `SELECT COUNT(*) FROM tool_versions`); n != 2 {
				t.Errorf("versions = %d, want the original 2", n)
			}
		})
	}
	if _, err := s.Snapshot(bg, "alpha"); err != nil {
		t.Errorf("Snapshot after the attempts: %v", err)
	}
	if list, err := s.Approved(bg); err != nil || len(list) != 1 {
		t.Errorf("Approved after the attempts = %+v, %v", list, err)
	}
}

// Reviewers' "UPDATE ... SET rowid rewrites id without firing UPDATE OF id":
// the guards compare values, so every alias of the rowid is caught, on every
// history table.
func TestTriggers_RowidAliasUpdatesAreRefused(t *testing.T) {
	s, path := seededStore(t)
	if err := s.Enable(bg, "alpha", "echo", bob); err != nil {
		t.Fatal(err)
	}
	db := rawDB(t, path)
	for _, table := range []string{"tool_versions", "audit_log", "approvals"} {
		before := mustCount(t, db, fmt.Sprintf(`SELECT COALESCE(SUM(rowid), 0) FROM %s`, table))
		for _, alias := range []string{"rowid", "_rowid_", "oid"} {
			if _, err := db.ExecContext(bg, fmt.Sprintf(`UPDATE %s SET %s = %s + 1000`, table, alias, alias)); err == nil {
				t.Errorf("%s: SET %s was accepted", table, alias)
			}
		}
		if after := mustCount(t, db, fmt.Sprintf(`SELECT COALESCE(SUM(rowid), 0) FROM %s`, table)); after != before {
			t.Errorf("%s: row ids moved from %d to %d", table, before, after)
		}
	}
	if _, err := db.ExecContext(bg, `UPDATE tool_version_proposers SET position = position + 1`); err == nil {
		t.Error("proposer positions could be moved")
	}
	// The store still works on the untouched rows.
	mustCrawl(t, s, "alpha", tool("echo", "v3"), tool("sum", "v1"))
	if _, err := s.VerifyAudit(bg); err != nil {
		t.Fatal(err)
	}
}

// Reviewers' "a dangling approved pointer is invisible to readers": every read
// path that hands out an approval reports it as corrupt.
func TestTriggers_DanglingApprovedPointerIsCorrupt(t *testing.T) {
	s, path := newStoreAt(t, defaultPolicyForTests())
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("echo", "v1"))
	mustApprove(t, s, "alpha", "echo", digestOf(t, "echo", "v1"))
	db := rawDBNoFK(t, path)
	mustExec(t, db, `DROP TRIGGER tool_versions_no_delete`)
	mustExec(t, db, `DROP TRIGGER proposers_no_delete`)
	mustExec(t, db, `DELETE FROM tool_version_proposers`)
	mustExec(t, db, `DELETE FROM tool_versions`)
	if _, err := s.Snapshot(bg, "alpha"); !errors.Is(err, ErrCorrupt) {
		t.Errorf("Snapshot = %v, want ErrCorrupt", err)
	}
	if _, err := s.Approved(bg); !errors.Is(err, ErrCorrupt) {
		t.Errorf("Approved = %v, want ErrCorrupt", err)
	}
	if err := s.Disable(bg, "alpha", "echo", alice); !errors.Is(err, ErrCorrupt) {
		t.Errorf("Disable = %v, want ErrCorrupt", err)
	}
}

// rewriteDigestAndHashSeen rewrites every version's digest column and every
// approvals row's hash_seen to digest under dropped and re-created guards, the
// consistent forgery of the fourth review, and the canonical bytes too when
// canonical is not nil.
func rewriteDigestAndHashSeen(t *testing.T, db *sql.DB, digest string, canonical []byte) {
	t.Helper()
	mustExec(t, db, `DROP TRIGGER tool_versions_immutable`)
	if canonical == nil {
		mustExec(t, db, `UPDATE tool_versions SET digest = ?`, digest)
	} else {
		mustExec(t, db, `UPDATE tool_versions SET digest = ?, canonical = ?`, digest, canonical)
	}
	restoreGuard(t, db, "tool_versions_immutable")
	mustExec(t, db, `DROP TRIGGER approvals_no_update`)
	mustExec(t, db, `UPDATE approvals SET hash_seen = ?`, digest)
	restoreGuard(t, db, "approvals_no_update")
}

// Reviewers' "Snapshot has no digest re-check", answered since D21 (d) by the
// anchor rather than by the bytes: the processor's read path hands out the
// digest the verified approval entry recorded, so a rewritten digest column,
// even with hash_seen rewritten to match under re-created guards, is never
// served; and the paths that hand out bytes hash them on every call, so a
// rewritten definition behind an intact digest is never exported, while the
// snapshot keeps serving the anchored digest that the rewrite cannot change.
func TestSnapshot_AnchorsTheDigestAndApprovedCatchesTamperedBytes(t *testing.T) {
	s, path := newStoreAt(t, defaultPolicyForTests())
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("echo", "good"))
	good := digestOf(t, "echo", "good")
	mustApprove(t, s, "alpha", "echo", good)
	evil := digestOf(t, "echo", "EVIL")
	db := rawDB(t, path)
	if _, err := db.ExecContext(bg, `UPDATE tool_versions SET digest = ?`, evil); err == nil {
		t.Fatal("the immutability trigger did not block the update")
	}
	rewriteDigestAndHashSeen(t, db, evil, nil)
	if _, err := s.Snapshot(bg, "alpha"); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "is not the one its newest approval entry") {
		t.Fatalf("Snapshot after the digest rewrite = %v, want ErrCorrupt naming the anchor (it would have served %s)", err, evil[:12])
	}
	if _, err := s.Approved(bg); !errors.Is(err, ErrCorrupt) {
		t.Errorf("Approved = %v, want ErrCorrupt", err)
	}
	if _, err := s.Versions(bg, "alpha", "echo"); !errors.Is(err, ErrCorrupt) {
		t.Errorf("Versions = %v, want ErrCorrupt", err)
	}
	// The digest column and hash_seen put back, the bytes alone rewritten:
	// the snapshot does not read them and serves the anchored digest; the
	// export hashes them and refuses.
	rewriteDigestAndHashSeen(t, db, good, []byte(`{"name":"echo"}`))
	if snap, err := s.Snapshot(bg, "alpha"); err != nil || snap.Tools["echo"].Approved != good {
		t.Errorf("Snapshot after a bytes-only rewrite = %+v, %v; want the anchored digest %s served", snap.Tools["echo"], err, good[:12])
	}
	if _, err := s.Approved(bg); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "does not hash to its digest") {
		t.Errorf("Approved after a bytes-only rewrite = %v, want ErrCorrupt naming the bytes", err)
	}
	// A dropped guard is reported on every load and not only at Open (review
	// finding: guards are verified by DDL on each Snapshot); once it and the
	// bytes are back the tool is served and exported again.
	mustExec(t, db, `DROP TRIGGER tool_versions_immutable`)
	if _, err := s.Snapshot(bg, "alpha"); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "tool_versions_immutable is missing") {
		t.Errorf("Snapshot with the guard dropped = %v, want ErrCorrupt naming it", err)
	}
	mustExec(t, db, `UPDATE tool_versions SET canonical = ?`, canonicalFor(t, "echo", "good"))
	restoreGuard(t, db, "tool_versions_immutable")
	if _, err := s.Snapshot(bg, "alpha"); err != nil {
		t.Errorf("Snapshot after restoring the bytes and the guard: %v", err)
	}
	if _, err := s.Approved(bg); err != nil {
		t.Errorf("Approved after restoring the bytes and the guard: %v", err)
	}
}
