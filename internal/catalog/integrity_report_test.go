package catalog

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
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
			// D14 (c): the status is also compared with what the log leaves behind.
			want{IntegrityReport{ApprovedDigestMismatches: 1, VersionStatusMismatches: 1},
				[]string{`"alpha/echo"`, `status is "superseded", not approved`, "the audit log (latest entry seq", "leaves it approved"}},
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
			// D14 (c): a row the log never discovered is reported as such too.
			want{IntegrityReport{StaleLastSeen: 1, DiscoveryMismatches: 1}, []string{`"/orphan"`, "server that does not exist", "no entry about it", "no tool.discovered entry"}},
		},
		"audit entry forged without a last_seen field": {
			func(t *testing.T, _ *Store, path, d string) {
				mustExec(t, rawDB(t, path), forgedAuditEntry, d, d, "digest=- state=enabled->enabled")
			},
			want{IntegrityReport{ChainBreaks: 2}, []string{"audit entry", `"alpha/echo"`, "has no last_seen field", "does not continue the chain from entry", "does not re-seal"}},
		},
		"audit entry forged with a value that is no digest": {
			func(t *testing.T, _ *Store, path, d string) {
				mustExec(t, rawDB(t, path), forgedAuditEntry, d, d, "digest=- state=enabled->enabled last_seen=bogus proposals=0->0")
			},
			want{IntegrityReport{ChainBreaks: 2, StaleLastSeen: 1}, []string{`"alpha/echo"`, "last_seen_digest is ", `recorded "bogus"`, "does not re-seal"}},
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
			// D13: the state column is cross-checked too, so the row's move to
			// pending_review is its own finding next to the lost approval.
			want{IntegrityReport{ApprovedDigestMismatches: 1, StateMismatches: 1}, []string{`"alpha/echo"`, "approved digest is none", "left it as", `state is "pending_review"`}},
		},
		"state rewritten": {
			func(t *testing.T, _ *Store, path, _ string) {
				mustExec(t, rawDB(t, path), `UPDATE tools SET state = 'disabled' WHERE name = 'echo'`)
			},
			want{IntegrityReport{StateMismatches: 1}, []string{`"alpha/echo"`, `state is "disabled"`, `left it as "enabled"`}},
		},
		"proposal budget rewritten": {
			func(t *testing.T, _ *Store, path, _ string) {
				mustExec(t, rawDB(t, path), `UPDATE tools SET proposals_since_decision = 7 WHERE name = 'echo'`)
			},
			want{IntegrityReport{BudgetMismatches: 1}, []string{`"alpha/echo"`, "proposals_since_decision is 7", "left it as 0"}},
		},
		"audit entry forged without a proposals field": {
			func(t *testing.T, _ *Store, path, d string) {
				mustExec(t, rawDB(t, path), forgedAuditEntry, d, d, "digest=- state=enabled->enabled last_seen="+d)
			},
			want{IntegrityReport{ChainBreaks: 2}, []string{"audit entry", `"alpha/echo"`, "has no proposals field", "does not re-seal"}},
		},
		"server paused flag rewritten": {
			func(t *testing.T, _ *Store, path, _ string) {
				mustExec(t, rawDB(t, path), `UPDATE servers SET paused = 1 WHERE name = 'alpha'`)
			},
			want{IntegrityReport{ServersMismatched: 1}, []string{`server "alpha"`, "paused is true", "left it as false"}},
		},
		"server allow_private rewritten": {
			func(t *testing.T, _ *Store, path, _ string) {
				mustExec(t, rawDB(t, path), `UPDATE servers SET allow_private = 1 WHERE name = 'alpha'`)
			},
			want{IntegrityReport{ServersMismatched: 1}, []string{`server "alpha"`, "allow_private is true", "recorded false"}},
		},
		"server url rewritten": {
			func(t *testing.T, _ *Store, path, _ string) {
				mustExec(t, rawDB(t, path), `UPDATE servers SET url = 'https://evil.example.net/mcp?token=SECRET' WHERE name = 'alpha'`)
			},
			want{IntegrityReport{ServersMismatched: 1}, []string{`server "alpha"`, "URL is not the one", "hash differs"}},
		},
		"server row forged": {
			func(t *testing.T, _ *Store, path, _ string) {
				mustExec(t, rawDB(t, path), `INSERT INTO servers (name, url, owner_group, allow_private, paused, created_at)
					VALUES ('ghost', 'https://ghost.example.com/mcp', '', 1, 0, '2026-10-11T00:00:00.000000000Z')`)
			},
			want{IntegrityReport{ServersMismatched: 1}, []string{`server "ghost"`, "no server.added entry"}},
		},
		"server row deleted": {
			func(t *testing.T, s *Store, path, _ string) {
				mustAddServer(t, s, "beta")
				mustExec(t, rawDB(t, path), `DELETE FROM servers WHERE name = 'beta'`)
			},
			want{IntegrityReport{ServersMismatched: 1}, []string{`server "beta"`, "registered by audit entry", "no servers row exists"}},
		},
		"server entry forged without a paused field": {
			func(t *testing.T, _ *Store, path, _ string) {
				mustExec(t, rawDB(t, path), forgedServerEntry, "server.paused", "paused=maybe")
			},
			want{IntegrityReport{ChainBreaks: 2}, []string{"audit entry", `server "alpha"`, "has no paused field", "does not re-seal"}},
		},
		"server.added entry forged without a url hash": {
			func(t *testing.T, _ *Store, path, _ string) {
				mustExec(t, rawDB(t, path), forgedServerEntry, "server.added", "allow_private=false url_sha256=short")
			},
			want{IntegrityReport{ChainBreaks: 2}, []string{"audit entry", `server "alpha"`, "has no url_sha256 field", "does not re-seal"}},
		},
		"server.added entry forged without a policy flag": {
			func(t *testing.T, _ *Store, path, _ string) {
				mustExec(t, rawDB(t, path), forgedServerEntry, "server.added", "url_sha256="+urlSHA256("https://alpha.example.com/mcp"))
			},
			want{IntegrityReport{ChainBreaks: 2}, []string{"audit entry", `server "alpha"`, "has no allow_private field", "does not re-seal"}},
		},
		"foreign trigger": {
			func(t *testing.T, _ *Store, path, _ string) {
				mustExec(t, rawDB(t, path), `CREATE TRIGGER keep_serving AFTER UPDATE OF state ON tools
					WHEN NEW.state = 'disabled' BEGIN UPDATE tools SET state = 'enabled' WHERE id = NEW.id; END`)
			},
			want{IntegrityReport{ForeignObjects: []string{"trigger keep_serving"}}, []string{"unexpected trigger keep_serving"}},
		},
		"foreign view": {
			func(t *testing.T, _ *Store, path, _ string) {
				mustExec(t, rawDB(t, path), `CREATE VIEW spy AS SELECT name FROM tools`)
			},
			want{IntegrityReport{ForeignObjects: []string{"view spy"}}, []string{"unexpected view spy"}},
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
			want{IntegrityReport{StaleLastSeen: 1, DiscoveryMismatches: 1}, []string{`"alpha/ghost"`, "no entry about it", "no tool.discovered entry"}},
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
				if strings.Contains(p, "description") || strings.Contains(p, "inputSchema") || strings.Contains(p, "SECRET") || strings.Contains(p, "evil.example") {
					t.Errorf("a Problems line carries tool text or a URL: %q", p)
				}
			}
		})
	}
}

// forgedServerEntry appends one entry about server alpha past the chain's head
// with the given event and detail; see forgedAuditEntry.
const forgedServerEntry = `INSERT INTO audit_log (seq, ts, actor, actor_type, event, subject, before_hash, after_hash, detail, prev_hash, hash)
	VALUES ((SELECT MAX(seq) + 1 FROM audit_log), 't', 'mallory', 'human', ?, 'alpha', '', '', ?, 'p', 'h')`

// forgedAuditEntry appends one entry about alpha/echo past the chain's head
// (the sequential guard only insists on the next number); its before_hash,
// after_hash and detail are the arguments. VerifyAudit would refuse the chain;
// Integrity reports the two breaks (the entry neither links nor re-seals, D15
// c) and still reads the entry as it is, so a forged field cannot fool it.
const forgedAuditEntry = `INSERT INTO audit_log (seq, ts, actor, actor_type, event, subject, before_hash, after_hash, detail, prev_hash, hash)
	VALUES ((SELECT MAX(seq) + 1 FROM audit_log), 't', 'mallory', 'human', 'tool.drifted', 'alpha/echo', ?, ?, ?, 'p', 'h')`

// Integrity reports an error, never a clean report, when the check itself
// cannot run: a cancelled context, or a table one of its passes needs renamed
// away, which also shows that each pass fails on its own query.
func TestIntegrity_ReportsWhenTheCheckItselfCannotRun(t *testing.T) {
	for _, table := range []string{"", "audit_log", "servers", "tools", "approvals"} {
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
	// D14 (f): the list view applies the same checks as the serving path, so
	// it refuses the file as well; inspection of such a file is a forensic
	// open's job.
	if _, err := s.Tools(bg, ""); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "trigger audit_log_no_update was redefined") {
		t.Errorf("Tools with a redefined guard = %v, want ErrCorrupt naming it", err)
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
