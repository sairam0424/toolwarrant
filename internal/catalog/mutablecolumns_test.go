package catalog

import (
	"errors"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// The third hostile review's probes against the integrity cross-check
// (D13(b)): tools.state, servers.paused, the proposal budget, allow_private
// and the URL are mutable columns the log describes and Integrity did not
// compare, and a trigger that is not a guard was ignored. Each probe flips a
// column with a SQLite shell's powers and asserts what now reports it.

// approvedEcho registers alpha, crawls and approves echo v1 and returns the digest.
func approvedEcho(t *testing.T, s *Store) string {
	t.Helper()
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("echo", "v1"))
	d1 := digestOf(t, "echo", "v1")
	mustApprove(t, s, "alpha", "echo", d1)
	return d1
}

// A disabled tool is re-enabled by one UPDATE on tools.state. Integrity names
// it from the latest entry about the tool (state=enabled->disabled), and since
// the eighth review the serving path refuses it too (D17 c, the state anchor)
// instead of serving the genuine approval under a forged state.
func TestIntegrity_StateFlipReenablingADisabledToolIsReported(t *testing.T) {
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	d1 := approvedEcho(t, s)
	if err := s.Disable(bg, "alpha", "echo", alice); err != nil {
		t.Fatal(err)
	}
	mustBeClean(t, s, "after the disable")
	mustExec(t, rawDB(t, path), `UPDATE tools SET state = 'enabled' WHERE name = 'echo'`)

	if _, err := s.Snapshot(bg, "alpha"); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "state column was edited") {
		t.Errorf("Snapshot with the state flipped = %v, want ErrCorrupt naming the edited column (d1 %s)", err, d1)
	}
	rep := mustIntegrity(t, s)
	if rep.StateMismatches != 1 || len(rep.Problems) != 1 {
		t.Errorf("Integrity = %+v, want exactly the state mismatch", rep)
	}
	problemMentioning(t, rep, `"alpha/echo"`, `state is "enabled"`, `left it as "disabled"`)
	_ = s.Close()
	s2, err := Open(path, lifecycle.DefaultPolicy())
	if err != nil {
		t.Fatalf("reopen: %v (the guards are intact; the forgery is in the data)", err)
	}
	defer func() { _ = s2.Close() }()
	if rep := mustIntegrity(t, s2); rep.StateMismatches != 1 {
		t.Errorf("Integrity after reopen = %+v", rep)
	}
	// With foreign keys off, as in the sqlite3 shell, the same flip is seen.
	mustExec(t, rawDBNoFK(t, path), `UPDATE tools SET state = 'disabled' WHERE name = 'echo'`)
	mustBeClean(t, s2, "after restoring the column")
	mustExec(t, rawDBNoFK(t, path), `UPDATE tools SET state = 'enabled' WHERE name = 'echo'`)
	if rep := mustIntegrity(t, s2); rep.StateMismatches != 1 {
		t.Errorf("Integrity with foreign keys off = %+v", rep)
	}
}

// A deprecated tool keeps its approval; one UPDATE on tools.state puts it back
// into the snapshot. The latest entry about it says state=enabled->deprecated.
func TestIntegrity_StateFlipRevivingADeprecatedToolIsReported(t *testing.T) {
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("echo", "v1"), tool("keep", "v1"))
	mustApprove(t, s, "alpha", "echo", digestOf(t, "echo", "v1"))
	for i := 0; i < lifecycle.DefaultPolicy().DeprecateAfter; i++ {
		mustCrawl(t, s, "alpha", tool("keep", "v1"))
	}
	if st := stateOf(t, s, "alpha", "echo"); st != lifecycle.Deprecated {
		t.Fatalf("precondition: state = %s, want deprecated", st)
	}
	mustBeClean(t, s, "after the deprecation")
	mustExec(t, rawDB(t, path), `UPDATE tools SET state = 'enabled' WHERE name = 'echo'`)
	rep := mustIntegrity(t, s)
	if rep.StateMismatches != 1 || len(rep.Problems) != 1 {
		t.Errorf("Integrity = %+v, want exactly the state mismatch", rep)
	}
	problemMentioning(t, rep, `"alpha/echo"`, `state is "enabled"`, `left it as "deprecated"`)
}

// servers.paused is flipped by one UPDATE; the latest server entry says
// paused=true.
func TestIntegrity_PausedFlagFlipUnpausingAServerIsReported(t *testing.T) {
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	approvedEcho(t, s)
	if err := s.PauseServer(bg, "alpha", alice); err != nil {
		t.Fatal(err)
	}
	mustBeClean(t, s, "after the pause")
	mustExec(t, rawDB(t, path), `UPDATE servers SET paused = 0 WHERE name = 'alpha'`)
	rep := mustIntegrity(t, s)
	if rep.ServersMismatched != 1 || len(rep.Problems) != 1 {
		t.Errorf("Integrity = %+v, want exactly the server mismatch", rep)
	}
	problemMentioning(t, rep, `server "alpha"`, "paused is false", "left it as true")
	// Resume by the Store, then flip the other way.
	mustExec(t, rawDB(t, path), `UPDATE servers SET paused = 1 WHERE name = 'alpha'`)
	if err := s.ResumeServer(bg, "alpha", bob); err != nil {
		t.Fatal(err)
	}
	mustBeClean(t, s, "after the resume")
	mustExec(t, rawDB(t, path), `UPDATE servers SET paused = 1 WHERE name = 'alpha'`)
	if rep := mustIntegrity(t, s); rep.ServersMismatched != 1 {
		t.Errorf("Integrity after the reverse flip = %+v", rep)
	}
}

// tools.proposals_since_decision is granted back by one UPDATE without the
// tool.budget_reset entry that ResetProposalBudget writes; every tool detail
// now carries the budget, so the latest entry says proposals=19->20.
func TestIntegrity_BudgetColumnResetByRawSQLIsReported(t *testing.T) {
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	mustAddServer(t, s, "alpha")
	for i := 0; i <= MaxProposalsPerDecision; i++ {
		mustCrawl(t, s, "alpha", CrawledTool{Name: "echo", Raw: def("echo", "variant "+string(rune('a'+i)))})
	}
	if v := mustTool(t, s, "alpha", "echo"); !v.Unusable || v.Versions != MaxProposalsPerDecision {
		t.Fatalf("precondition: %+v, want the budget exhausted", v)
	}
	mustBeClean(t, s, "with the budget exhausted")
	mustExec(t, rawDB(t, path), `UPDATE tools SET proposals_since_decision = 0 WHERE name = 'echo'`)
	rep := mustIntegrity(t, s)
	if rep.BudgetMismatches != 1 || len(rep.Problems) != 1 {
		t.Errorf("Integrity = %+v, want exactly the budget mismatch", rep)
	}
	problemMentioning(t, rep, `"alpha/echo"`, "proposals_since_decision is 0", "left it as 20")
	// The legitimate reset is clean and its entry carries the transition.
	mustExec(t, rawDB(t, path), `UPDATE tools SET proposals_since_decision = 20 WHERE name = 'echo'`)
	if err := s.ResetProposalBudget(bg, "alpha", "echo", alice); err != nil {
		t.Fatal(err)
	}
	if e := entryOf(t, s, evBudgetReset); !strings.HasSuffix(e.Detail, " proposals=20->0") {
		t.Errorf("tool.budget_reset detail = %q", e.Detail)
	}
	mustBeClean(t, s, "after the real reset")
}

// A trigger that is not a guard rewrites the unguarded tools table: this one
// undoes every disable inside the operator's own transaction. Open refuses the
// file, a Store that is already open refuses to commit the disable and to
// serve, a forensic open tolerates the trigger and Integrity names it.
func TestOpen_ForeignTriggerIsCorrupt(t *testing.T) {
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	d1 := approvedEcho(t, s)
	const keepServing = `CREATE TRIGGER keep_serving AFTER UPDATE OF state ON tools
		WHEN NEW.state = 'disabled' BEGIN UPDATE tools SET state = 'enabled' WHERE id = NEW.id; END`
	mustExec(t, rawDB(t, path), keepServing)

	// The open Store: the disable is refused before it commits, the row and
	// the log stay as they were, and nothing is served.
	before := auditCount(t, s)
	if err := s.Disable(bg, "alpha", "echo", alice); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "unexpected trigger keep_serving") {
		t.Errorf("Disable with a foreign trigger = %v, want ErrCorrupt naming it", err)
	}
	if auditCount(t, s) != before || countEvents(t, s, string(lifecycle.EvDisabled)) != 0 {
		t.Error("a refused disable left an audit entry")
	}
	if _, err := s.Snapshot(bg, "alpha"); !errors.Is(err, ErrCorrupt) {
		t.Errorf("Snapshot = %v, want ErrCorrupt", err)
	}
	if _, err := s.Approved(bg); !errors.Is(err, ErrCorrupt) {
		t.Errorf("Approved = %v, want ErrCorrupt", err)
	}
	if _, err := s.RecordCrawl(bg, crawlOf(tool("echo", "v1")), crawler); !errors.Is(err, ErrCorrupt) {
		t.Errorf("RecordCrawl = %v, want ErrCorrupt", err)
	}
	_ = s.Close()

	for name, opts := range map[string]OpenOptions{"read-write": {Policy: lifecycle.DefaultPolicy()}, "read-only": {ReadOnly: true}} {
		if s2, err := OpenWith(path, opts); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "unexpected trigger keep_serving") {
			if s2 != nil {
				_ = s2.Close()
			}
			t.Errorf("%s Open with a foreign trigger = %v, want ErrCorrupt naming it", name, err)
		}
	}
	forensic, err := OpenWith(path, OpenOptions{Forensic: true})
	if err != nil {
		t.Fatalf("forensic Open: %v", err)
	}
	defer func() { _ = forensic.Close() }()
	rep := mustIntegrity(t, forensic)
	if len(rep.ForeignObjects) != 1 || rep.ForeignObjects[0] != "trigger keep_serving" || len(rep.Problems) != 1 {
		t.Errorf("Integrity = %+v, want the foreign trigger alone", rep)
	}
	problemMentioning(t, rep, "unexpected trigger keep_serving")
	if _, err := forensic.VerifyAudit(bg); err != nil {
		t.Errorf("VerifyAudit = %v", err)
	}
	// Dropping the trigger makes the file whole again; the approval stands.
	mustExec(t, rawDB(t, path), `DROP TRIGGER keep_serving`)
	s3 := openStore(t, path, lifecycle.DefaultPolicy())
	if !mustSnapshot(t, s3, "alpha").Serves("echo", d1) {
		t.Error("the untouched approval is not served after the trigger is gone")
	}
	mustBeClean(t, s3, "after dropping the trigger")
}

// A view is refused the same way: it cannot change rows, but nothing the
// schema did not create may exist in the file.
func TestOpen_ForeignViewIsCorrupt(t *testing.T) {
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	approvedEcho(t, s)
	_ = s.Close()
	mustExec(t, rawDB(t, path), `CREATE VIEW spy AS SELECT name, state FROM tools`)
	if _, err := Open(path, lifecycle.DefaultPolicy()); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "unexpected view spy") {
		t.Errorf("Open with a foreign view = %v, want ErrCorrupt naming it", err)
	}
	forensic, err := OpenWith(path, OpenOptions{Forensic: true})
	if err != nil {
		t.Fatalf("forensic Open: %v", err)
	}
	defer func() { _ = forensic.Close() }()
	if rep := mustIntegrity(t, forensic); len(rep.ForeignObjects) != 1 || rep.ForeignObjects[0] != "view spy" {
		t.Errorf("Integrity = %+v", rep)
	}
	// An index that is not a guard is tolerated: it cannot change an answer.
	mustExec(t, rawDB(t, path), `DROP VIEW spy`)
	mustExec(t, rawDB(t, path), `CREATE INDEX tools_by_state ON tools (state)`)
	s2 := openStore(t, path, lifecycle.DefaultPolicy())
	mustBeClean(t, s2, "with a foreign index")
}
