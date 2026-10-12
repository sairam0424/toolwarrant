package catalog

import (
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// The seventh hostile review's probes against the decision path (D17 a). The
// status and ever_approved columns of tool_versions were what lifecycle.Apply
// read, backed by any approvals row about the version, so two plain
// statements (ever_approved set to 1, an approvals row the newest-decision
// rule never ranks) made a sole proposer's own pending bytes a rollback
// target, and a rejected version flipped back to pending was approvable by a
// second person (the D14 residual). Every decision and the Versions view now
// reconstruct both columns from the verified version.* entries about the
// tool, with the rule Integrity applies, and refuse a column that disagrees.

// forgedTS is the timestamp a forger writes into a row or an entry.
const forgedTS = "2026-10-12T00:00:00.000000000Z"

// appendSealed appends an entry to the log as a forger with write access who
// keeps the chain intact would: sealed from the current head, in sequence.
// Nothing inside the file refutes such an entry (D14); this is what the
// recorded head is for.
func appendSealed(t *testing.T, db *sql.DB, e audit.Entry) audit.Entry {
	t.Helper()
	entries := rawEntries(t, db)
	prev := audit.Entry{}
	if len(entries) > 0 {
		prev = entries[len(entries)-1]
	}
	e.Seq = prev.Seq + 1
	sealed, err := audit.Seal(prev, e)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, insertAudit, sealed.Seq, sealed.TS, sealed.Actor, sealed.ActorType, sealed.Event, sealed.Subject,
		sealed.BeforeHash, sealed.AfterHash, sealed.Detail, sealed.PrevHash, sealed.Hash)
	return sealed
}

// versionRowID returns the row id of the version with this digest.
func versionRowID(t *testing.T, db *sql.DB, digest string) int64 {
	t.Helper()
	var id int64
	if err := db.QueryRowContext(bg, `SELECT id FROM tool_versions WHERE digest = ?`, digest).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// twoApprovedVersions builds alpha/echo with v1 approved then v2 approved, both
// proposed by alice and approved by bob, so that v1 is superseded and was
// approved before. It returns the two digests.
func twoApprovedVersions(t *testing.T, s *Store) (string, string) {
	t.Helper()
	mustAddServer(t, s, "alpha")
	if _, err := s.RecordCrawl(bg, crawlOf(tool("echo", "v1")), alice); err != nil {
		t.Fatal(err)
	}
	d1 := digestOf(t, "echo", "v1")
	mustApprove(t, s, "alpha", "echo", d1)
	if _, err := s.RecordCrawl(bg, crawlOf(tool("echo", "v2")), alice); err != nil {
		t.Fatal(err)
	}
	d2 := digestOf(t, "echo", "v2")
	mustApprove(t, s, "alpha", "echo", d2)
	mustBeClean(t, s, "after two approvals")
	return d1, d2
}

// A rejected version put back to pending by one UPDATE was approvable by a
// second person; now every decision and Versions refuse the column, and the
// restored column makes the decision path answer as the lifecycle does.
func TestApprove_RejectedVersionFlippedToPendingIsCorrupt(t *testing.T) {
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("echo", "v1"))
	d1 := digestOf(t, "echo", "v1")
	if err := s.Reject(bg, "alpha", "echo", d1, carol); err != nil {
		t.Fatal(err)
	}
	db := rawDB(t, path)
	mustExec(t, db, `UPDATE tool_versions SET status = 'pending' WHERE digest = ?`, d1)
	err := s.Approve(bg, "alpha", "echo", d1, bob)
	if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), `status "pending"`) || !strings.Contains(err.Error(), "leave it rejected") {
		t.Fatalf("Approve of the flipped version = %v, want ErrCorrupt naming the status the verified entries leave", err)
	}
	if _, err := s.Versions(bg, "alpha", "echo"); !errors.Is(err, ErrCorrupt) {
		t.Errorf("Versions = %v, want ErrCorrupt", err)
	}
	if snap := mustSnapshot(t, s, "alpha"); snap.Serves("echo", d1) {
		t.Errorf("Snapshot serves the rejected version")
	}
	mustExec(t, db, `UPDATE tool_versions SET status = 'rejected' WHERE digest = ?`, d1)
	if err := s.Approve(bg, "alpha", "echo", d1, bob); !errors.Is(err, lifecycle.ErrStaleVersion) {
		t.Errorf("Approve of the rejected version once the column is restored = %v, want the lifecycle's ErrStaleVersion", err)
	}
	mustBeClean(t, s, "after the restore")
}

// Each status column a decision reads is compared with the verified entries:
// a superseded version marked never approved, a superseded version flipped to
// pending, an approved version flipped to pending and a pending version marked
// approved before are each ErrCorrupt on the decision that would act on them
// and on Versions, whatever the approvals table says.
func TestDecisions_VersionColumnsMustMatchTheVerifiedChain(t *testing.T) {
	cases := map[string]struct {
		edit   string
		target int // 1 or 2: the version the edit and the decision concern
		decide func(s *Store, digest string) error
		want   []string
	}{
		"superseded version marked never approved": {
			`UPDATE tool_versions SET ever_approved = 0 WHERE digest = ?`, 1,
			func(s *Store, d string) error { return s.Rollback(bg, "alpha", "echo", d, carol) },
			[]string{`status "superseded" (ever_approved false)`, "verified audit entries", "leave it superseded (ever_approved true)"},
		},
		"superseded version flipped to pending": {
			`UPDATE tool_versions SET status = 'pending' WHERE digest = ?`, 1,
			func(s *Store, d string) error { return s.Approve(bg, "alpha", "echo", d, carol) },
			[]string{`status "pending"`, "leave it superseded"},
		},
		"approved version flipped to pending": {
			`UPDATE tool_versions SET status = 'pending' WHERE digest = ?`, 2,
			func(s *Store, d string) error { return s.Approve(bg, "alpha", "echo", d, carol) },
			[]string{"disagree"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s, path := newStoreAt(t, lifecycle.DefaultPolicy())
			d1, d2 := twoApprovedVersions(t, s)
			target := d1
			if tc.target == 2 {
				target = d2
			}
			mustExec(t, rawDB(t, path), tc.edit, target)
			err := tc.decide(s, target)
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("decision on the edited version = %v, want ErrCorrupt", err)
			}
			for _, fragment := range tc.want {
				if !strings.Contains(err.Error(), fragment) {
					t.Errorf("error %q does not mention %q", err, fragment)
				}
			}
			if _, err := s.Versions(bg, "alpha", "echo"); !errors.Is(err, ErrCorrupt) {
				t.Errorf("Versions = %v, want ErrCorrupt", err)
			}
			if err := s.Disable(bg, "alpha", "echo", carol); !errors.Is(err, ErrCorrupt) {
				t.Errorf("Disable, which reads the same columns, = %v, want ErrCorrupt", err)
			}
		})
	}
}

// The seventh review's rollback forgery: the sole proposer's pending version
// gets ever_approved = 1 and an approvals row at id -2 (or -1), which the
// newest-decision rule never ranks, and she rolls back to her own bytes with
// the chain untouched. The positive-id guard refuses the plain insert; a row
// planted under a dropped and re-created guard is refused by every read and
// every decision with its cause named (D17 b, g), Integrity reports it, and
// once it is removed the rollback is refused as it was before the forgery.
func TestRollback_TargetForgedWithAGhostApprovalsRowIsCorrupt(t *testing.T) {
	for _, ghostID := range []int64{-2, -1} {
		t.Run("ghost approvals row id "+itoa(ghostID), func(t *testing.T) { rollbackForgery(t, ghostID) })
	}
}

func rollbackForgery(t *testing.T, ghostID int64) {
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	mustAddServer(t, s, "alpha")
	if _, err := s.RecordCrawl(bg, crawlOf(tool("echo", "v1")), alice); err != nil {
		t.Fatal(err)
	}
	mustApprove(t, s, "alpha", "echo", digestOf(t, "echo", "v1"))
	if _, err := s.RecordCrawl(bg, crawlOf(tool("echo", "v2")), alice); err != nil {
		t.Fatal(err)
	}
	d2 := digestOf(t, "echo", "v2")
	if err := s.Approve(bg, "alpha", "echo", d2, alice); !errors.Is(err, lifecycle.ErrSelfApproval) {
		t.Fatalf("Approve by the sole proposer = %v, want ErrSelfApproval", err)
	}
	if err := s.Rollback(bg, "alpha", "echo", d2, alice); !errors.Is(err, lifecycle.ErrNotRollbackTarget) {
		t.Fatalf("Rollback before the forgery = %v, want ErrNotRollbackTarget", err)
	}
	mustBeClean(t, s, "before the forgery")
	recorded, err := s.VerifyAudit(bg)
	if err != nil {
		t.Fatal(err)
	}
	db := rawDB(t, path)
	v2 := versionRowID(t, db, d2)
	mustExec(t, db, `UPDATE tool_versions SET ever_approved = 1 WHERE id = ?`, v2)
	const ghostInsert = `INSERT INTO approvals (id, version_id, decision, approver, actor_type, hash_seen, at) VALUES (?, ?, 'approve', 'mallory', 'human', ?, ?)`
	if _, err := db.ExecContext(bg, ghostInsert, ghostID, v2, d2, forgedTS); err == nil || !strings.Contains(err.Error(), "approvals ids start at 1") {
		t.Fatalf("the plain insert of approvals row %d = %v, want the positive-id guard to refuse it", ghostID, err)
	}
	ddl := triggerDDL(t, db, "approvals_positive_id")
	mustExec(t, db, `DROP TRIGGER approvals_positive_id`)
	mustExec(t, db, ghostInsert, ghostID, v2, d2, forgedTS)
	mustExec(t, db, ddl)
	mustExec(t, db, `UPDATE meta SET value = value + 1 WHERE key = 'generation'`)

	const cause = "approvals holds a row whose id is below 1"
	for name, err := range allPaths(s, "alpha", "echo") {
		if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), cause) {
			t.Errorf("%s = %v, want ErrCorrupt naming the row below id 1", name, err)
		}
	}
	if err := s.Rollback(bg, "alpha", "echo", d2, alice); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), cause) {
		t.Errorf("Rollback by the sole proposer = %v, want ErrCorrupt naming the row below id 1", err)
	}
	if after, err := s.VerifyAudit(bg); err != nil || after.Head != recorded.Head || after.Entries != recorded.Entries {
		t.Errorf("VerifyAudit = %+v, %v; the log was not touched, so the recorded head stands", after, err)
	}
	rep := mustIntegrity(t, s)
	if rep.GhostRows != 1 {
		t.Errorf("Integrity.GhostRows = %d, want 1; %q", rep.GhostRows, rep.Problems)
	}
	problemMentioning(t, rep, "approvals row "+itoa(ghostID), "below 1")
	for name, opts := range map[string]OpenOptions{"read-only": {ReadOnly: true}, "read-write": {Policy: lifecycle.DefaultPolicy()}} {
		fresh, err := OpenWith(path, opts)
		if err != nil {
			t.Fatalf("%s Open = %v", name, err)
		}
		if _, err := fresh.Snapshot(bg, "alpha"); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), cause) {
			t.Errorf("%s fresh Snapshot = %v, want ErrCorrupt naming the row below id 1", name, err)
		}
		_ = fresh.Close()
	}
	// The repair: the row goes, the flag goes back, and the rollback is refused
	// as it was.
	mustExec(t, db, `DROP TRIGGER approvals_no_delete`)
	mustExec(t, db, `DELETE FROM approvals WHERE id = ?`, ghostID)
	restoreGuard(t, db, "approvals_no_delete")
	mustExec(t, db, `UPDATE tool_versions SET ever_approved = 0 WHERE id = ?`, v2)
	if err := s.Rollback(bg, "alpha", "echo", d2, alice); !errors.Is(err, lifecycle.ErrNotRollbackTarget) {
		t.Errorf("Rollback after the repair = %v, want ErrNotRollbackTarget", err)
	}
	mustBeClean(t, s, "after the repair")
}
