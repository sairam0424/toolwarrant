package catalog

import (
	"errors"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// The fourth review's list finding (D14 f): Tools and Tool read the approved
// digest straight from the tools row, so after a pointer flip to a retired
// version the list command showed the tool as enabled on the retired digest
// while Snapshot, Approved and Versions refused the same file, and the
// operations guide told the operator to run list against a suspect file. The
// views now apply the serving path's evidence and return ErrCorrupt.
func TestTools_ForgedApprovedPointerIsCorrupt(t *testing.T) {
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("echo", "v1"), tool("sum", "v1"))
	d1 := digestOf(t, "echo", "v1")
	mustApprove(t, s, "alpha", "echo", d1)
	mustCrawl(t, s, "alpha", tool("echo", "v2"), tool("sum", "v1"))
	d2 := digestOf(t, "echo", "v2")
	mustApprove(t, s, "alpha", "echo", d2)
	if views, err := s.Tools(bg, "alpha"); err != nil || len(views) != 2 || views[0].Approved != d2 {
		t.Fatalf("precondition: Tools = %+v, %v", views, err)
	}

	db := rawDB(t, path)
	mustExec(t, db, `UPDATE tool_versions SET status = 'superseded' WHERE digest = ?`, d2)
	mustExec(t, db, `UPDATE tool_versions SET status = 'approved' WHERE digest = ?`, d1)
	mustExec(t, db, `UPDATE tools SET approved_version_id = (SELECT id FROM tool_versions WHERE digest = ?) WHERE name = 'echo'`, d1)
	for name, err := range map[string]error{
		"Tools (server)": func() error { _, err := s.Tools(bg, "alpha"); return err }(),
		"Tools (all)":    func() error { _, err := s.Tools(bg, ""); return err }(),
		"Tool":           func() error { _, err := s.Tool(bg, "alpha", "echo"); return err }(),
		"Snapshot":       func() error { _, err := s.Snapshot(bg, "alpha"); return err }(),
	} {
		if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "newest approval decision") {
			t.Errorf("%s after the pointer flip = %v, want ErrCorrupt naming the newest decision", name, err)
		}
	}
	// The unaffected tool is still shown on its own; the forged one is not.
	if v, err := s.Tool(bg, "alpha", "sum"); err != nil || v.State != lifecycle.PendingReview {
		t.Errorf("Tool(sum) = %+v, %v", v, err)
	}
}

// The views refuse the other forgeries the serving path refuses: a dangling
// pointer, a pointer at another tool's version, a foreign digest profile and
// an approved version without an approvals row. A rewritten canonical form is
// not among them since D21 (d): the list hands out the digest, which the
// anchor binds, and reads no bytes, as the snapshot does; show reads
// Versions, which hashes every version it hands out
// (TestVersions_TamperedBytesAreCaughtAtOnce).
func TestTools_ApplyTheServingPathEvidence(t *testing.T) {
	cases := map[string]struct {
		tamper func(t *testing.T, path, d string)
		want   string
	}{
		"dangling pointer": {func(t *testing.T, path, _ string) {
			mustExec(t, rawDBNoFK(t, path), `UPDATE tools SET approved_version_id = 999 WHERE name = 'echo'`)
		}, "does not exist"},
		"another tool's version": {func(t *testing.T, path, _ string) {
			mustExec(t, rawDB(t, path), `UPDATE tools SET approved_version_id = (SELECT id FROM tool_versions WHERE digest = ?) WHERE name = 'echo'`, digestOf(t, "sum", "v1"))
		}, "not its own"},
		"foreign profile": {func(t *testing.T, path, d string) {
			db := rawDB(t, path)
			mustExec(t, db, `DROP TRIGGER tool_versions_immutable`)
			mustExec(t, db, `UPDATE tool_versions SET digest_profile = 'legacy-v0' WHERE digest = ?`, d)
			restoreGuard(t, db, "tool_versions_immutable")
		}, "digested under profile"},
		"approval rows deleted": {func(t *testing.T, path, _ string) {
			db := rawDB(t, path)
			mustExec(t, db, `DROP TRIGGER approvals_no_delete`)
			mustExec(t, db, `DELETE FROM approvals`)
			restoreGuard(t, db, "approvals_no_delete")
		}, "newest approval decision"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s, path := newStoreAt(t, lifecycle.DefaultPolicy())
			mustAddServer(t, s, "alpha")
			mustCrawl(t, s, "alpha", tool("echo", "v1"), tool("sum", "v1"))
			d := digestOf(t, "echo", "v1")
			mustApprove(t, s, "alpha", "echo", d)
			tc.tamper(t, path, d)
			for p, err := range map[string]error{
				"Tools": func() error { _, err := s.Tools(bg, "alpha"); return err }(),
				"Tool":  func() error { _, err := s.Tool(bg, "alpha", "echo"); return err }(),
			} {
				if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), tc.want) {
					t.Errorf("%s = %v, want ErrCorrupt mentioning %q", p, err, tc.want)
				}
			}
		})
	}
}
