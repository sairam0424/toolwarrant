package catalog

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// richHistory drives one server through every kind of event the catalog
// writes: discovery, approval, drift, reject, revert, unusable, missing,
// deprecation, re-approval, rollback, disable and enable, reappearance,
// pause and resume, an exhausted proposal budget and its reset. Integrity
// must find nothing wrong with the result, whatever the Store did.
func richHistory(t *testing.T, s *Store) {
	t.Helper()
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("echo", "v1"), tool("sum", "v1"), tool("gone", "v1"))
	for _, name := range []string{"echo", "sum", "gone"} {
		mustApprove(t, s, "alpha", name, digestOf(t, name, "v1"))
	}
	mustCrawl(t, s, "alpha", tool("echo", "v2"), tool("sum", "v1")) // echo drifts, gone misses once
	if err := s.Reject(bg, "alpha", "echo", digestOf(t, "echo", "v2"), bob); err != nil {
		t.Fatal(err)
	}
	mustCrawl(t, s, "alpha", tool("echo", "v1"), tool("sum", "v1")) // echo reverts, gone misses twice
	if _, err := s.RecordCrawl(bg, CrawlInput{Server: "alpha", Complete: true, Tools: []CrawledTool{tool("echo", "v3")},
		Unusable: []UnusableTool{unusableOf("sum", "not-canonical")}}, crawler); err != nil { // gone is deprecated
		t.Fatal(err)
	}
	mustApprove(t, s, "alpha", "echo", digestOf(t, "echo", "v3"))
	if err := s.Rollback(bg, "alpha", "echo", digestOf(t, "echo", "v1"), alice); err != nil {
		t.Fatal(err)
	}
	if err := s.Disable(bg, "alpha", "echo", alice); err != nil {
		t.Fatal(err)
	}
	if err := s.Enable(bg, "alpha", "echo", alice); err != nil { // the approval is retired
		t.Fatal(err)
	}
	mustCrawl(t, s, "alpha", tool("echo", "v1"), tool("sum", "v1"), tool("gone", "v1")) // gone reappears
	mustApprove(t, s, "alpha", "echo", digestOf(t, "echo", "v1"))
	if err := s.PauseServer(bg, "alpha", alice); err != nil {
		t.Fatal(err)
	}
	if err := s.ResumeServer(bg, "alpha", bob); err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= MaxProposalsPerDecision; i++ { // the last one is over budget
		mustCrawl(t, s, "alpha", tool("echo", "v1"), tool("sum", "v1"), tool("gone", fmt.Sprintf("g%02d", i)))
	}
	if v := mustTool(t, s, "alpha", "gone"); !v.Unusable {
		t.Fatalf("gone should be over budget: %+v", v)
	}
	if err := s.ResetProposalBudget(bg, "alpha", "gone", alice); err != nil {
		t.Fatal(err)
	}
	mustCrawl(t, s, "alpha", tool("echo", "v1"), tool("sum", "v1"), tool("gone", fmt.Sprintf("g%02d", MaxProposalsPerDecision)))
}

func TestIntegrity_ACatalogWrittenByTheStoreHasNoProblems(t *testing.T) {
	s, path := newStoreAt(t, defaultPolicyForTests())
	richHistory(t, s)
	mustBeClean(t, s, "after a long mixed history")
	if _, err := s.VerifyAudit(bg); err != nil {
		t.Fatal(err)
	}
	// The same report from a read-only and from a forensic open of the file.
	want := mustIntegrity(t, s)
	for name, opts := range map[string]OpenOptions{"read-only": {ReadOnly: true}, "forensic": {Forensic: true}} {
		other, err := OpenWith(path, opts)
		if err != nil {
			t.Fatalf("%s open: %v", name, err)
		}
		if got := mustIntegrity(t, other); !reflect.DeepEqual(got, want) {
			t.Errorf("%s Integrity = %+v, want %+v", name, got, want)
		}
		_ = other.Close()
	}
}

// Every counter of the report, one tamper at a time. Each case edits the file
// the way a SQLite shell would, with any guard it needs dropped and restored
// so that the report shows the data problem alone.
func TestIntegrity_ReportsEachKindOfDisagreement(t *testing.T) {
	type want struct {
		rep       IntegrityReport // counters only; Problems is checked by fragments
		fragments []string
	}
	cases := map[string]struct {
		tamper func(t *testing.T, s *Store, path string, d string)
		want   want
	}{
		"approvals rows deleted": {
			func(t *testing.T, s *Store, path, _ string) {
				mustCrawl(t, s, "alpha", tool("echo", "v2"), tool("sum", "v1"))
				if err := s.Reject(bg, "alpha", "echo", digestOf(t, "echo", "v2"), bob); err != nil {
					t.Fatal(err)
				}
				db := rawDB(t, path)
				mustExec(t, db, `DROP TRIGGER approvals_no_delete`)
				mustExec(t, db, `DELETE FROM approvals`)
				restoreGuard(t, db, "approvals_no_delete")
			},
			want{IntegrityReport{ApprovalsWithoutRecord: 1, AuditEntriesWithoutApproval: 2},
				[]string{"no approval record", "version.approved", "version.rejected", "no matching approvals row"}},
		},
		"approved version status rewritten": {
			func(t *testing.T, _ *Store, path, d string) {
				mustExec(t, rawDB(t, path), `UPDATE tool_versions SET status = 'superseded' WHERE digest = ?`, d)
			},
			want{IntegrityReport{ApprovedDigestMismatches: 1}, []string{`"alpha/echo"`, `status is "superseded", not approved`}},
		},
		"digest profile rewritten": {
			func(t *testing.T, _ *Store, path, d string) {
				db := rawDB(t, path)
				mustExec(t, db, `DROP TRIGGER tool_versions_immutable`)
				mustExec(t, db, `UPDATE tool_versions SET digest_profile = 'legacy-v0' WHERE digest = ?`, d)
				restoreGuard(t, db, "tool_versions_immutable")
			},
			want{IntegrityReport{}, []string{`"alpha/echo"`, "digested under profile", `"legacy-v0"`}},
		},
		"tool row for a missing server": {
			func(t *testing.T, _ *Store, path, _ string) {
				mustExec(t, rawDBNoFK(t, path), `INSERT INTO tools (server_id, name, state, approved_version_id, last_seen_digest, missing_crawls, proposals_since_decision)
					VALUES (999, 'orphan', 'pending_review', NULL, '', 0, 0)`)
			},
			want{IntegrityReport{StaleLastSeen: 1}, []string{`"/orphan"`, "server that does not exist", "no entry about it"}},
		},
		"audit entry forged without a last_seen field": {
			func(t *testing.T, _ *Store, path, d string) {
				mustExec(t, rawDB(t, path), forgedAuditEntry, d, d, "digest=- state=enabled->enabled")
			},
			want{IntegrityReport{}, []string{"audit entry", `"alpha/echo"`, "has no last_seen field"}},
		},
		"audit entry forged with a value that is no digest": {
			func(t *testing.T, _ *Store, path, d string) {
				mustExec(t, rawDB(t, path), forgedAuditEntry, d, d, "digest=- state=enabled->enabled last_seen=bogus")
			},
			want{IntegrityReport{StaleLastSeen: 1}, []string{`"alpha/echo"`, "last_seen_digest is ", `recorded "bogus"`}},
		},
		"approver rewritten": {
			func(t *testing.T, _ *Store, path, _ string) {
				db := rawDB(t, path)
				mustExec(t, db, `DROP TRIGGER approvals_no_update`)
				mustExec(t, db, `UPDATE approvals SET approver = 'mallory'`)
				restoreGuard(t, db, "approvals_no_update")
			},
			want{IntegrityReport{ApprovalsWithoutAuditEntry: 1, AuditEntriesWithoutApproval: 1}, []string{`"mallory"`, "no matching audit entry", "by bob"}},
		},
		"approvals row forged": {
			func(t *testing.T, _ *Store, path, d string) {
				mustExec(t, rawDB(t, path), `INSERT INTO approvals (version_id, decision, approver, actor_type, hash_seen, at)
					VALUES ((SELECT id FROM tool_versions WHERE digest = ?), 'rollback', 'mallory', 'human', 'not-the-digest', 't')`, d)
			},
			want{IntegrityReport{ApprovalsWithoutAuditEntry: 1}, []string{"hash_seen", `"not-the-digest"`, "no matching audit entry"}},
		},
		"approvals row pointing nowhere": {
			func(t *testing.T, _ *Store, path, _ string) {
				mustExec(t, rawDBNoFK(t, path), `INSERT INTO approvals (version_id, decision, approver, actor_type, hash_seen, at)
					VALUES (999999, 'approve', 'mallory', 'human', 'h', 't')`)
			},
			want{IntegrityReport{ApprovalsWithoutAuditEntry: 1}, []string{"approvals row", "does not exist"}},
		},
		"registry lost its approval": {
			func(t *testing.T, _ *Store, path, _ string) {
				mustExec(t, rawDB(t, path), `UPDATE tools SET approved_version_id = NULL, state = 'pending_review' WHERE name = 'echo'`)
			},
			want{IntegrityReport{ApprovedDigestMismatches: 1}, []string{`"alpha/echo"`, "approved digest is none", "left it as"}},
		},
		"approved pointer dangles": {
			func(t *testing.T, _ *Store, path, _ string) {
				mustExec(t, rawDBNoFK(t, path), `UPDATE tools SET approved_version_id = 999999 WHERE name = 'echo'`)
			},
			want{IntegrityReport{ApprovedDigestMismatches: 1}, []string{`"alpha/echo"`, "does not exist"}},
		},
		"approved pointer at another tool's version": {
			func(t *testing.T, _ *Store, path, _ string) {
				mustExec(t, rawDB(t, path), `UPDATE tools SET approved_version_id = (SELECT id FROM tool_versions WHERE digest = ?) WHERE name = 'echo'`, digestOf(t, "sum", "v1"))
			},
			want{IntegrityReport{ApprovedDigestMismatches: 1}, []string{`"alpha/echo"`, "not its own"}},
		},
		"last_seen rewritten": {
			func(t *testing.T, _ *Store, path, _ string) {
				mustExec(t, rawDB(t, path), `UPDATE tools SET last_seen_digest = 'unusable' WHERE name = 'echo'`)
			},
			want{IntegrityReport{StaleLastSeen: 1}, []string{`"alpha/echo"`, "last_seen_digest is unusable", "recorded"}},
		},
		"tool row forged": {
			func(t *testing.T, _ *Store, path, _ string) {
				mustExec(t, rawDB(t, path), `INSERT INTO tools (server_id, name, state, approved_version_id, last_seen_digest, missing_crawls, proposals_since_decision)
					VALUES ((SELECT id FROM servers), 'ghost', 'pending_review', NULL, '', 0, 0)`)
			},
			want{IntegrityReport{StaleLastSeen: 1}, []string{`"alpha/ghost"`, "no entry about it"}},
		},
		"guard dropped": {
			func(t *testing.T, _ *Store, path, _ string) {
				mustExec(t, rawDB(t, path), `DROP TRIGGER audit_log_no_update`)
			},
			want{IntegrityReport{GuardsMissing: []string{"trigger audit_log_no_update"}}, []string{"guard trigger audit_log_no_update is missing"}},
		},
		"guard index redefined": {
			func(t *testing.T, _ *Store, path, _ string) {
				db := rawDB(t, path)
				mustExec(t, db, `DROP INDEX approvals_by_version`)
				mustExec(t, db, `CREATE INDEX approvals_by_version ON approvals (version_id)`)
			},
			want{IntegrityReport{GuardsRedefined: []string{"index approvals_by_version"}}, []string{"guard index approvals_by_version was redefined"}},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s, path := newStoreAt(t, defaultPolicyForTests())
			mustAddServer(t, s, "alpha")
			mustCrawl(t, s, "alpha", tool("echo", "v1"), tool("sum", "v1"))
			d := digestOf(t, "echo", "v1")
			mustApprove(t, s, "alpha", "echo", d)
			mustBeClean(t, s, "before the tamper")
			tc.tamper(t, s, path, d)
			got := mustIntegrity(t, s)
			problems := got.Problems
			got.Problems = nil
			if !reflect.DeepEqual(got, tc.want.rep) {
				t.Errorf("counters = %+v, want %+v; problems %q", got, tc.want.rep, problems)
			}
			if len(problems) == 0 {
				t.Fatal("no Problems reported")
			}
			problemMentioning(t, IntegrityReport{Problems: problems}, tc.want.fragments...)
			for _, p := range problems {
				if strings.Contains(p, "description") || strings.Contains(p, "inputSchema") {
					t.Errorf("a Problems line carries tool text: %q", p)
				}
			}
		})
	}
}

// forgedAuditEntry appends one entry about alpha/echo past the chain's head
// (the sequential guard only insists on the next number); its before_hash,
// after_hash and detail are the arguments. VerifyAudit would refuse the chain;
// Integrity reads the entries as they are and must not be fooled by one.
const forgedAuditEntry = `INSERT INTO audit_log (seq, ts, actor, actor_type, event, subject, before_hash, after_hash, detail, prev_hash, hash)
	VALUES ((SELECT MAX(seq) + 1 FROM audit_log), 't', 'mallory', 'human', 'tool.drifted', 'alpha/echo', ?, ?, ?, 'p', 'h')`

// Integrity reports an error, never a clean report, when the check itself
// cannot run: a cancelled context, or a table one of its passes needs renamed
// away, which also shows that each pass fails on its own query.
func TestIntegrity_ReportsWhenTheCheckItselfCannotRun(t *testing.T) {
	for _, table := range []string{"", "audit_log", "tools", "approvals"} {
		t.Run("missing "+table, func(t *testing.T) {
			s, path := newStoreAt(t, defaultPolicyForTests())
			mustAddServer(t, s, "alpha")
			mustCrawl(t, s, "alpha", tool("echo", "v1"))
			mustApprove(t, s, "alpha", "echo", digestOf(t, "echo", "v1"))
			ctx := bg
			if table == "" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(bg)
				cancel()
			} else {
				mustExec(t, rawDBNoFK(t, path), fmt.Sprintf(`ALTER TABLE %s RENAME TO gone_%s`, table, table))
			}
			if rep, err := s.Integrity(ctx); err == nil {
				t.Errorf("Integrity = %+v, <nil>; want an error, not a report that could read as clean", rep)
			}
		})
	}
}

// Integrity re-hashes approved definitions without the Store's memory, so a
// rewritten canonical form is reported at once, and a redefined guard is
// caught by Snapshot and Approved on the next load, not only by Open.
func TestIntegrity_RehashesApprovedBytesAndReadsGuardsOnEveryLoad(t *testing.T) {
	s, path := newStoreAt(t, defaultPolicyForTests())
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("echo", "v1"))
	d := digestOf(t, "echo", "v1")
	mustApprove(t, s, "alpha", "echo", d)
	mustSnapshot(t, s, "alpha") // the row is remembered for RecheckTTL
	tamperCanonical(t, path, d, []byte(`{"name":"echo"}`))
	if _, err := s.Snapshot(bg, "alpha"); err != nil {
		t.Fatalf("Snapshot within RecheckTTL = %v; the documented window", err)
	}
	rep := mustIntegrity(t, s)
	problemMentioning(t, rep, `"alpha/echo"`, "does not hash to its digest")
	if rep.ApprovedDigestMismatches != 0 || rep.StaleLastSeen != 0 {
		t.Errorf("a rewritten canonical form is a bytes problem, not a log disagreement: %+v", rep)
	}

	db := rawDB(t, path)
	mustExec(t, db, `DROP TRIGGER audit_log_no_update`)
	mustExec(t, db, `CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log WHEN 0 BEGIN SELECT RAISE(ABORT, 'x'); END`)
	for name, read := range map[string]func() error{
		"Snapshot": func() error { _, err := s.Snapshot(bg, "alpha"); return err },
		"Approved": func() error { _, err := s.Approved(bg); return err },
	} {
		if err := read(); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "trigger audit_log_no_update was redefined") {
			t.Errorf("%s with a redefined guard = %v, want ErrCorrupt naming it", name, err)
		}
	}
	if _, err := s.Tools(bg, ""); err != nil {
		t.Errorf("Tools (a view, for inspection) = %v", err)
	}
	// A guard re-created from the schema's own statement, however it is laid
	// out, is the same guard: whitespace is not a redefinition.
	mustExec(t, db, `DROP TRIGGER audit_log_no_update`)
	mustExec(t, db, "CREATE TRIGGER audit_log_no_update\n\tBEFORE UPDATE ON audit_log\n\tBEGIN  SELECT RAISE(ABORT, 'audit_log is append-only');  END")
	if _, err := s.Approved(bg); err != nil {
		t.Errorf("Approved after restoring the guard with other whitespace = %v", err)
	}
	if rep := mustIntegrity(t, s); len(rep.GuardsMissing)+len(rep.GuardsRedefined) != 0 {
		t.Errorf("guards after the restore = %v %v", rep.GuardsMissing, rep.GuardsRedefined)
	}
}

// The detail format Integrity reads is fixed by the writer: three fields first,
// values without spaces, a note after. The reader must not be fooled by a
// quoted class in the note or by a detail of another shape.
func TestToolDetail_FieldsRoundTrip(t *testing.T) {
	before := lifecycle.Tool{State: lifecycle.Enabled, LastSeen: strings.Repeat("a", 64)}
	after := lifecycle.Tool{State: lifecycle.ChangedPendingReapproval, LastSeen: lifecycle.UnusableDigest}
	detail := toolDetail("", before, after, ` reason="http status 401" budget=20`)
	if want := `digest=- state=enabled->changed_pending_reapproval last_seen=unusable reason="http status 401" budget=20`; detail != want {
		t.Fatalf("toolDetail = %q, want %q", detail, want)
	}
	for key, want := range map[string]string{fieldDigest: "-", fieldLastSeen: "unusable", fieldState: "enabled->changed_pending_reapproval", "budget": "20"} {
		if got, ok := detailField(detail, key); !ok || got != want {
			t.Errorf("detailField(%s) = %q, %t; want %q", key, got, ok, want)
		}
	}
	if _, ok := detailField(detail, "reason=http"); ok {
		t.Error("a quoted class must not read as a field")
	}
	absent := toolDetail(strings.Repeat("b", 64), before, lifecycle.Tool{State: lifecycle.Deprecated}, "")
	if v, _ := detailField(absent, fieldLastSeen); v != noDigest || fromNoDigest(v) != "" {
		t.Errorf("an absent tool must record last_seen=%s, got %q", noDigest, v)
	}
	for _, other := range []string{"crawl=1 tools=2 changes=0 rejected=0", "allow_private=true", "paused=true", "crawl=3 reason=invalid-name name=<unprintable>"} {
		if isToolDetail(other) {
			t.Errorf("%q is not a tool detail", other)
		}
	}
	// The decision names and guard statements the reader relies on.
	for decision, event := range map[string]string{decisionApprove: "version.approved", decisionReject: "version.rejected", decisionRollback: "version.rolled_back", "bless": ""} {
		if got := decisionEvent(decision); got != event || (event != "" && !isDecisionEvent(got)) {
			t.Errorf("decisionEvent(%s) = %q, want %q", decision, got, event)
		}
	}
	if kind, name := parseGuardDDL("CREATE"); kind != "" || name != "" {
		t.Errorf("parseGuardDDL of a fragment = %q %q", kind, name)
	}
	if kind, name := parseGuardDDL("CREATE UNIQUE INDEX idx ON t (c)"); kind != "index" || name != "idx" {
		t.Errorf("parseGuardDDL(unique index) = %q %q", kind, name)
	}
	if !slices.Equal(guardTriggers(), []string{
		"audit_log_no_update", "audit_log_no_delete", "audit_log_sequential",
		"tool_versions_no_delete", "tool_versions_immutable", "tool_versions_no_replace",
		"proposers_no_update", "proposers_no_delete", "proposers_append_only",
		"approvals_no_update", "approvals_no_delete", "approvals_no_replace",
	}) || !slices.Equal(guardIndexes(), []string{"one_pending_version", "one_approved_version", "approvals_by_version"}) {
		t.Errorf("guard names parsed from the DDL = %v, %v", guardTriggers(), guardIndexes())
	}
}
