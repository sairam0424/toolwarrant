package catalog

import (
	"errors"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// The seventh hostile review's probe against the export (D17 e): Approved took
// ApprovedBy and ApprovedAt from the approvals row, which one UPDATE under a
// re-created approvals_no_update rewrote while the chain, the recorded head
// and every serving-path check stayed clean, so the git export named the
// wrong approver. The export now takes both from the verified approval entry
// and refuses a row that disagrees with it.

// rewriteApprover edits the approve row's approver and time under a dropped
// and re-created guard, as the forger does.
func rewriteApprover(t *testing.T, path, approver, at string) {
	t.Helper()
	db := rawDB(t, path)
	ddl := triggerDDL(t, db, "approvals_no_update")
	mustExec(t, db, `DROP TRIGGER approvals_no_update`)
	mustExec(t, db, `UPDATE approvals SET approver = ?, at = ? WHERE decision = 'approve'`, approver, at)
	mustExec(t, db, ddl)
	mustExec(t, db, `UPDATE meta SET value = value + 1 WHERE key = 'generation'`)
}

func TestApproved_ApproverAndTimeComeFromTheVerifiedEntry(t *testing.T) {
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	d1 := approvedEcho(t, s)
	entry := entryOf(t, s, string(lifecycle.EvApproved))
	when, err := parseTime(entry.TS)
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.Approved(bg)
	if err != nil || len(out) != 1 || out[0].Digest != d1 || out[0].ApprovedBy != entry.Actor || !out[0].ApprovedAt.Equal(when) {
		t.Fatalf("Approved = %+v, %v; want echo approved by %q at %s, as the verified entry says", out, err, entry.Actor, entry.TS)
	}
	recorded, err := s.VerifyAudit(bg)
	if err != nil {
		t.Fatal(err)
	}

	rewriteApprover(t, path, "alice", entry.TS)
	_, err = s.Approved(bg)
	if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "approver or time") || !strings.Contains(err.Error(), "approvals row was rewritten") {
		t.Fatalf("Approved with the approver rewritten = %v, want ErrCorrupt naming the rewritten row", err)
	}
	if after, err := s.VerifyAudit(bg); err != nil || after.Head != recorded.Head {
		t.Errorf("VerifyAudit = %+v, %v; the chain was not touched", after, err)
	}
	if rep := mustIntegrity(t, s); rep.ApprovalsWithoutAuditEntry != 1 || rep.AuditEntriesWithoutApproval != 1 {
		t.Errorf("Integrity = %+v, want the row and the entry reported as unmatched", rep)
	}
	for label, opts := range map[string]OpenOptions{"read-only": {ReadOnly: true}, "read-write": {Policy: lifecycle.DefaultPolicy()}} {
		fresh, err := OpenWith(path, opts)
		if err != nil {
			t.Fatalf("%s Open = %v", label, err)
		}
		if _, err := fresh.Approved(bg); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s fresh Approved = %v, want ErrCorrupt", label, err)
		}
		_ = fresh.Close()
	}

	rewriteApprover(t, path, entry.Actor, forgedTS)
	if _, err := s.Approved(bg); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "approver or time") {
		t.Errorf("Approved with the time rewritten = %v, want ErrCorrupt naming the rewritten row", err)
	}
	rewriteApprover(t, path, entry.Actor, entry.TS)
	if out, err := s.Approved(bg); err != nil || len(out) != 1 || out[0].ApprovedBy != entry.Actor {
		t.Errorf("Approved once the row is restored = %+v, %v", out, err)
	}
	mustBeClean(t, s, "after the restore")
}
