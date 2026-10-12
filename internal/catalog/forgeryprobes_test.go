package catalog

import (
	"errors"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// The seventh hostile review's probes that the catalog refused as it stood,
// kept so that the cover does not slip: a ghost proposer appended in order, a
// ghost approvals row with a positive id, and two tools' names swapped.

// A proposer appended with plain SQL (proposers_append_only allows an in-order
// append) cannot silence the two-person rule nor fake a proposer: the decision
// path compares the table with the verified version.proposed entries.
func TestApprove_GhostProposerAppendedWithPlainSQLIsRefused(t *testing.T) {
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	mustAddServer(t, s, "alpha")
	if _, err := s.RecordCrawl(bg, crawlOf(tool("echo", "v1")), alice); err != nil {
		t.Fatal(err)
	}
	d1 := digestOf(t, "echo", "v1")
	db := rawDB(t, path)
	mustExec(t, db, `INSERT INTO tool_version_proposers (version_id, position, actor) VALUES (?, 1, 'bob')`, versionRowID(t, db, d1))
	err := s.Approve(bg, "alpha", "echo", d1, bob)
	if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "proposer history was rewritten") {
		t.Errorf("Approve by bob after a ghost proposer row = %v, want ErrCorrupt naming the proposer history", err)
	}
	if _, err := s.Versions(bg, "alpha", "echo"); !errors.Is(err, ErrCorrupt) {
		t.Errorf("Versions = %v, want ErrCorrupt", err)
	}
	if rep := mustIntegrity(t, s); rep.ProposerMismatches != 1 {
		t.Errorf("Integrity.ProposerMismatches = %d, want 1; %q", rep.ProposerMismatches, rep.Problems)
	}
}

// A ghost approvals row with a positive id becomes the newest decision and
// breaks the current approval on every path; it cannot approve anything.
func TestSnapshot_GhostApprovalsRowWithAPositiveIDBreaksTheCurrentApproval(t *testing.T) {
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	approvedEcho(t, s)
	mustCrawl(t, s, "alpha", tool("echo", "v2"))
	d2 := digestOf(t, "echo", "v2")
	db := rawDB(t, path)
	mustExec(t, db, `INSERT INTO approvals (version_id, decision, approver, actor_type, hash_seen, at) VALUES (?, 'approve', 'mallory', 'human', ?, ?)`,
		versionRowID(t, db, d2), d2, forgedTS)
	for name, err := range allPaths(s, "alpha", "echo") {
		if !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s = %v, want ErrCorrupt", name, err)
		}
	}
	if err := s.Approve(bg, "alpha", "echo", d2, bob); !errors.Is(err, ErrCorrupt) {
		t.Errorf("Approve = %v, want ErrCorrupt", err)
	}
}

// Swapping two tools' names on the mutable tools table is caught by the chain
// anchor: the newest approval entry about the subject names the other digest.
func TestSnapshot_SwappingToolNamesIsCaughtByTheAnchor(t *testing.T) {
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("echo", "v1"), tool("wipe", "v1"))
	mustApprove(t, s, "alpha", "echo", digestOf(t, "echo", "v1"))
	mustApprove(t, s, "alpha", "wipe", digestOf(t, "wipe", "v1"))
	db := rawDB(t, path)
	mustExec(t, db, `UPDATE tools SET name = 'tmp' WHERE name = 'echo'`)
	mustExec(t, db, `UPDATE tools SET name = 'echo' WHERE name = 'wipe'`)
	mustExec(t, db, `UPDATE tools SET name = 'wipe' WHERE name = 'tmp'`)
	for name, err := range allPaths(s, "alpha", "echo") {
		if !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s = %v, want ErrCorrupt", name, err)
		}
	}
}
