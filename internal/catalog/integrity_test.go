package catalog

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// fingerprint captures everything a rolled-back transaction must not change.
func fingerprint(t *testing.T, s *Store, path string) string {
	t.Helper()
	db := rawDB(t, path)
	var parts []string
	for _, table := range []string{"servers", "crawls", "tools", "tool_versions", "approvals", "audit_log"} {
		parts = append(parts, fmt.Sprintf("%s=%d", table, mustCount(t, db, `SELECT COUNT(*) FROM `+table)))
	}
	tools, err := s.Tools(bg, "")
	if err != nil {
		t.Fatal(err)
	}
	parts = append(parts, fmt.Sprintf("gen=%d", mustGeneration(t, s)), fmt.Sprintf("%+v", tools))
	sum, err := s.VerifyAudit(bg)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(parts, " ") + " head=" + sum.Head
}

func TestAtomicity_FailureMidTransactionLeavesNothingBehind(t *testing.T) {
	s, path := newStoreAt(t, defaultPolicyForTests())
	db := rawDB(t, path)
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("echo", "v1"))
	mustApprove(t, s, "alpha", "echo", digestOf(t, "echo", "v1"))
	mustCrawl(t, s, "alpha", tool("echo", "v2")) // echo now waits for re-approval
	dV2 := digestOf(t, "echo", "v2")

	cases := map[string]struct {
		trigger string // a trigger that makes one late statement of the operation fail
		run     func() error
	}{
		"crawl fails on its very last audit entry": {
			`CREATE TRIGGER boom BEFORE INSERT ON audit_log WHEN NEW.event = 'crawl.completed' BEGIN SELECT RAISE(ABORT, 'boom'); END`,
			func() error {
				_, err := s.RecordCrawl(bg, crawlOf(tool("echo", "v3"), tool("fresh", "v1")), crawler)
				return err
			},
		},
		"crawl fails half way through its tools": {
			`CREATE TRIGGER boom BEFORE INSERT ON tools WHEN NEW.name = 'poison' BEGIN SELECT RAISE(ABORT, 'boom'); END`,
			func() error {
				_, err := s.RecordCrawl(bg, crawlOf(tool("a-first", "v1"), tool("echo", "v3"), tool("poison", "v1")), crawler)
				return err
			},
		},
		"approve fails after the state was written": {
			`CREATE TRIGGER boom BEFORE INSERT ON audit_log WHEN NEW.event = 'version.approved' BEGIN SELECT RAISE(ABORT, 'boom'); END`,
			func() error { return s.Approve(bg, "alpha", "echo", dV2, bob) },
		},
		"reject fails on its approvals row": {
			`CREATE TRIGGER boom BEFORE INSERT ON approvals BEGIN SELECT RAISE(ABORT, 'boom'); END`,
			func() error { return s.Reject(bg, "alpha", "echo", dV2, bob) },
		},
		"disable fails on its audit entry": {
			`CREATE TRIGGER boom BEFORE INSERT ON audit_log WHEN NEW.event = 'tool.disabled' BEGIN SELECT RAISE(ABORT, 'boom'); END`,
			func() error { return s.Disable(bg, "alpha", "echo", alice) },
		},
		"add server fails on its audit entry": {
			`CREATE TRIGGER boom BEFORE INSERT ON audit_log WHEN NEW.event = 'server.added' BEGIN SELECT RAISE(ABORT, 'boom'); END`,
			func() error {
				_, err := s.AddServer(bg, ServerSpec{Name: "beta", URL: "https://b.example.com"}, alice)
				return err
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			before := fingerprint(t, s, path)
			mustExec(t, db, tc.trigger)
			err := tc.run()
			mustExec(t, db, `DROP TRIGGER boom`)
			if err == nil || !strings.Contains(err.Error(), "boom") {
				t.Fatalf("operation = %v, want the injected failure", err)
			}
			if after := fingerprint(t, s, path); after != before {
				t.Fatalf("a failed operation left partial state\nbefore: %s\nafter:  %s", before, after)
			}
		})
	}

	// The same operations succeed once the fault is gone, and version numbers
	// continue without a hole left by the rolled-back attempts.
	rep := mustCrawl(t, s, "alpha", tool("a-first", "v1"), tool("echo", "v3"), tool("poison", "v1"))
	if len(rep.Changes) != 3 {
		t.Fatalf("report = %+v", rep)
	}
	vs, _ := s.Versions(bg, "alpha", "echo")
	if len(vs) != 3 || vs[2].No != 3 {
		t.Errorf("versions of echo = %+v", vs)
	}
	if _, err := s.VerifyAudit(bg); err != nil {
		t.Error(err)
	}
}

func TestIntegrity_TamperedCanonicalFormIsCaughtBeforeItIsTrusted(t *testing.T) {
	s, path := seededStore(t)
	db := rawDB(t, path)
	mustApproveTool := func() {
		t.Helper()
		if err := s.Approve(bg, "alpha", "sum", digestOf(t, "sum", "v1"), bob); err != nil {
			t.Fatal(err)
		}
	}
	mustApproveTool()
	if list, err := s.Approved(bg); err != nil || len(list) != 1 {
		t.Fatalf("Approved = %+v, %v", list, err)
	}
	mustExec(t, db, `DROP TRIGGER tool_versions_immutable`)
	mustExec(t, db, `UPDATE tool_versions SET canonical = x'7b226e616d65223a2273756d227d' WHERE digest = ?`, digestOf(t, "sum", "v1"))

	if _, err := s.Versions(bg, "alpha", "sum"); !errors.Is(err, ErrCorrupt) {
		t.Errorf("Versions = %v, want ErrCorrupt", err)
	}
	if _, err := s.Approved(bg); !errors.Is(err, ErrCorrupt) {
		t.Errorf("Approved = %v, want ErrCorrupt: a tampered definition must not be exported", err)
	}
	if err := s.Disable(bg, "alpha", "sum", alice); !errors.Is(err, ErrCorrupt) {
		t.Errorf("Disable = %v, want ErrCorrupt", err)
	}
}

func TestIntegrity_InconsistentRowsAreReportedNotServed(t *testing.T) {
	setup := func(t *testing.T) (*Store, string) {
		s, path := newStoreAt(t, defaultPolicyForTests())
		mustAddServer(t, s, "alpha")
		mustCrawl(t, s, "alpha", tool("echo", "v1"), tool("sum", "v1"))
		mustApprove(t, s, "alpha", "echo", digestOf(t, "echo", "v1"))
		return s, path
	}
	t.Run("approved pointer and version status disagree", func(t *testing.T) {
		s, path := setup(t)
		mustExec(t, rawDB(t, path), `UPDATE tool_versions SET status = 'superseded' WHERE digest = ?`, digestOf(t, "echo", "v1"))
		if err := s.Disable(bg, "alpha", "echo", alice); !errors.Is(err, ErrCorrupt) {
			t.Errorf("Disable = %v, want ErrCorrupt", err)
		}
		if _, err := s.RecordCrawl(bg, crawlOf(tool("echo", "v1")), crawler); !errors.Is(err, ErrCorrupt) {
			t.Errorf("RecordCrawl = %v, want ErrCorrupt", err)
		}
	})
	t.Run("approved pointer at another tool's version", func(t *testing.T) {
		s, path := setup(t)
		mustExec(t, rawDB(t, path), `UPDATE tools SET approved_version_id = (SELECT id FROM tool_versions WHERE digest = ?) WHERE name = 'echo'`,
			digestOf(t, "sum", "v1"))
		if err := s.Disable(bg, "alpha", "echo", alice); !errors.Is(err, ErrCorrupt) {
			t.Errorf("Disable = %v, want ErrCorrupt", err)
		}
	})
	t.Run("approved version without an approval record", func(t *testing.T) {
		s, path := setup(t)
		db := rawDB(t, path)
		mustExec(t, db, `DROP TRIGGER approvals_no_delete`)
		mustExec(t, db, `DELETE FROM approvals`)
		if _, err := s.Approved(bg); !errors.Is(err, ErrCorrupt) {
			t.Errorf("Approved = %v, want ErrCorrupt", err)
		}
	})
	t.Run("generation counter missing", func(t *testing.T) {
		s, path := setup(t)
		mustExec(t, rawDB(t, path), `DELETE FROM meta`)
		if _, err := s.Generation(bg); !errors.Is(err, ErrCorrupt) {
			t.Errorf("Generation = %v, want ErrCorrupt", err)
		}
		before := auditCount(t, s)
		if _, err := s.AddServer(bg, ServerSpec{Name: "beta", URL: "https://b.example.com"}, alice); !errors.Is(err, ErrCorrupt) {
			t.Errorf("AddServer = %v, want ErrCorrupt", err)
		}
		if auditCount(t, s) != before {
			t.Error("a write that could not bump the generation must not commit")
		}
	})
	t.Run("unreadable timestamp", func(t *testing.T) {
		s, path := setup(t)
		mustExec(t, rawDB(t, path), `UPDATE servers SET created_at = 'yesterday'`)
		if _, err := s.Server(bg, "alpha"); !errors.Is(err, ErrCorrupt) {
			t.Errorf("Server = %v, want ErrCorrupt", err)
		}
		if _, err := s.Servers(bg); !errors.Is(err, ErrCorrupt) {
			t.Errorf("Servers = %v, want ErrCorrupt", err)
		}
	})
}

func TestSchema_ConstraintsHoldAgainstDirectSQL(t *testing.T) {
	_, path := seededStore(t)
	db := rawDB(t, path)
	echoID := mustCount(t, db, `SELECT id FROM tools WHERE name = 'echo'`)
	crawlID := mustCount(t, db, `SELECT MIN(id) FROM crawls`)
	newVersion := func(no int, digest, status string) string {
		return fmt.Sprintf(`INSERT INTO tool_versions (tool_id, version_no, digest, canonical, raw, status, proposed_by, ever_approved, first_seen_at, crawl_id)
			VALUES (%d, %d, '%s', x'7b7d', x'7b7d', '%s', 'x', 0, 't', %d)`, echoID, no, digest, status, crawlID)
	}
	for name, stmt := range map[string]string{
		"unknown state":                  `UPDATE tools SET state = 'bogus'`,
		"enabled without approval":       `UPDATE tools SET state = 'enabled', approved_version_id = NULL WHERE name = 'sum'`,
		"negative missing count":         `UPDATE tools SET missing_crawls = -1`,
		"malformed last seen":            `UPDATE tools SET last_seen_digest = 'xyz'`,
		"duplicate tool name":            fmt.Sprintf(`INSERT INTO tools (server_id, name, state, last_seen_digest, missing_crawls) SELECT server_id, name, 'pending_review', '', 0 FROM tools WHERE id = %d`, echoID),
		"tool for a missing server":      `INSERT INTO tools (server_id, name, state, last_seen_digest, missing_crawls) VALUES (999, 'x', 'pending_review', '', 0)`,
		"version with upper-case digest": newVersion(10, strings.Repeat("A", 64), "superseded"),
		"version with short digest":      newVersion(11, "abc", "superseded"),
		"version with unknown status":    newVersion(12, strings.Repeat("3", 64), "bogus"),
		"second pending version":         newVersion(13, strings.Repeat("4", 64), "pending"),
		"second approved version":        newVersion(14, strings.Repeat("5", 64), "approved"),
		"version for a missing crawl":    strings.Replace(newVersion(15, strings.Repeat("6", 64), "superseded"), fmt.Sprintf(", %d)", crawlID), ", 999999)", 1),
		"approval of a missing version":  `INSERT INTO approvals (version_id, decision, approver, actor_type, hash_seen, at) VALUES (999999, 'approve', 'x', 'human', 'h', 't')`,
		"approval with unknown decision": `INSERT INTO approvals (version_id, decision, approver, actor_type, hash_seen, at) VALUES (1, 'bless', 'x', 'human', 'h', 't')`,
		"server with a duplicate name":   `INSERT INTO servers (name, url, owner_group, allow_private, created_at) VALUES ('alpha', 'https://x', '', 0, 't')`,
		"server with bad private flag":   `INSERT INTO servers (name, url, owner_group, allow_private, created_at) VALUES ('zzz', 'https://x', '', 2, 't')`,
	} {
		if _, err := db.ExecContext(bg, stmt); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// A version that breaks no rule does go in, so the refusals above are the constraints' doing.
	mustExec(t, db, newVersion(20, strings.Repeat("7", 64), "superseded"))
}
