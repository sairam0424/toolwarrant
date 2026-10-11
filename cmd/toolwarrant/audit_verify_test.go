package main

import (
	"regexp"
	"strings"
	"testing"
)

var headLine = regexp.MustCompile(`audit log ok: (\d+) entries, head ([0-9a-f]{64})`)

func TestAuditVerifyAndList(t *testing.T) {
	c, _ := fixture(t)
	out := c.ok("audit", "verify")
	m := headLine.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("audit verify output:\n%s", out)
	}
	wantContains(t, "verify", out, "integrity ok: guard objects intact, every approval recorded in the log", "record this head outside the database")
	head := m[2]
	c.ok("audit", "verify", "--expect-head", strings.ToUpper(head))
	r := c.fail(exitFailure, "audit", "verify", "--expect-head", strings.Repeat("0", 64))
	wantContains(t, "stderr", r.stderr, "audit head mismatch", head)
	wantContains(t, "stdout", r.stdout, "integrity ok")
	wantNotContains(t, "stdout", r.stdout, headReminder)

	out = c.ok("audit", "list")
	wantContains(t, "audit list", out, "SEQ", "server.added", "crawl.completed", "tool.discovered", "s1/echo", "crawler", "system", "human")
	all := c.auditEntries()
	if len(all) < 4 || all[0].Seq != 1 || all[0].Event != "server.added" {
		t.Fatalf("entries = %+v", all)
	}
	var two []auditRow
	c.jsonInto(&two, "audit", "list", "--limit", "2", "--json")
	if len(two) != 2 || two[1].Seq != 2 {
		t.Errorf("--limit 2 gave %+v", two)
	}
	var tail []auditRow
	c.jsonInto(&tail, "audit", "list", "--after", "2", "--json")
	if len(tail) != len(all)-2 || tail[0].Seq != 3 {
		t.Errorf("--after 2 gave %d entries starting at %d, want %d from 3", len(tail), tail[0].Seq, len(all)-2)
	}
	lines := strings.Split(strings.TrimSpace(c.ok("audit", "list", "--limit", "3")), "\n")
	if len(lines) != 4 {
		t.Errorf("audit list --limit 3 printed %d lines, want header plus 3", len(lines))
	}
}

// A database whose guard trigger was dropped is corrupt for every command but
// the audit ones, which open it forensically so the broken entry can be named
// and the rows examined.
func TestAuditVerifyDetectsATamperedDatabase(t *testing.T) {
	c, _ := fixture(t)
	execSQL(t, c.db, "DROP TRIGGER audit_log_no_update", "UPDATE audit_log SET detail = 'nothing happened' WHERE seq = 2")
	r := c.fail(exitFailure, "audit", "verify")
	wantContains(t, "stderr", r.stderr, "audit log is broken at entry 2", "changed outside toolwarrant")
	wantNotContains(t, "stdout", r.stdout, "audit log ok")
	wantContains(t, "audit list", c.ok("audit", "list"), "nothing happened")
	r = c.fail(exitFailure, "list")
	wantContains(t, "stderr", r.stderr, "integrity", adviceCorrupt)
	r = c.fail(exitFailure, "--as", "alice", "approve", "s1", "echo", "--hash", strings.Repeat("0", 64))
	wantContains(t, "stderr", r.stderr, adviceCorrupt)
}

// The chain proves that the log was not edited, not that the registry agrees
// with it: a rewritten tools row or a deleted approvals row leaves every link
// intact and "audit log ok" alone said nothing about the file (second
// review). audit verify runs Store.Integrity after the chain check and exits 1
// when it reports a problem; the head reminder is withheld, because a head of
// a file not to be trusted is not worth recording.
func TestAuditVerifyReportsIntegrityProblemsTheChainCannotSee(t *testing.T) {
	c, _ := fixture(t)
	v1 := c.tool("s1", "echo").Pending
	c.approve("alice", "s1", "echo", v1)
	wantContains(t, "clean", c.ok("audit", "verify"), "audit log ok", "integrity ok", headReminder)

	// The tools table has no guard trigger, so a rewritten last_seen leaves
	// the chain intact.
	execSQL(t, c.db, "UPDATE tools SET last_seen_digest = 'unusable' WHERE name = 'echo'")
	r := c.fail(exitFailure, "audit", "verify")
	wantContains(t, "stdout", r.stdout, "audit log ok", "integrity problem: ", `"s1/echo"`, "last_seen_digest")
	wantNotContains(t, "stdout", r.stdout, "integrity ok", headReminder)
	wantContains(t, "stderr", r.stderr, "1 problem(s) listed above", "edited outside toolwarrant", adviceCorrupt)
	execSQL(t, c.db, "UPDATE tools SET last_seen_digest = '"+v1+"' WHERE name = 'echo'")
	wantContains(t, "repaired", c.ok("audit", "verify"), "integrity ok")

	// The approvals row behind the approved version deleted, with the guard
	// trigger put back so that only the forgery remains.
	var ddl string
	queryRow(t, c.db, "SELECT sql FROM sqlite_master WHERE name = 'approvals_no_delete'", &ddl)
	execSQL(t, c.db, "DROP TRIGGER approvals_no_delete", "DELETE FROM approvals", ddl)
	r = c.fail(exitFailure, "audit", "verify")
	wantContains(t, "stdout", r.stdout, "audit log ok", "integrity problem: ", "no approval record")
	wantNotContains(t, "stdout", r.stdout, "integrity ok", "guard trigger")
	wantContains(t, "stderr", r.stderr, "problem(s) listed above", adviceCorrupt)
	// The serving-side reads refuse the same file as corrupt.
	r = c.fail(exitFailure, "show", "s1", "echo")
	wantContains(t, "stderr", r.stderr, adviceCorrupt)

	// A dropped guard alone, with nothing edited, is a problem too.
	c2, _ := fixture(t)
	execSQL(t, c2.db, "DROP TRIGGER audit_log_no_update")
	r = c2.fail(exitFailure, "audit", "verify")
	wantContains(t, "stdout", r.stdout, "audit log ok", "integrity problem: guard trigger audit_log_no_update is missing")
	wantContains(t, "stderr", r.stderr, "1 problem(s) listed above")
}

// Third review (cli-docs-4): with --expect-head and a head that no longer
// matched, audit verify returned before the integrity report ran, so the run
// an operator makes when they suspect tampering showed the one symptom (the
// head moved) and withheld the diagnosis (which rows disagree with the log).
// Both are reported now, in one error, and the head reminder stays withheld.
func TestAuditVerifyReportsIntegrityWhenTheHeadMismatches(t *testing.T) {
	c, _ := fixture(t)
	v1 := c.tool("s1", "echo").Pending
	c.approve("alice", "s1", "echo", v1)
	execSQL(t, c.db, "UPDATE tools SET last_seen_digest = 'unusable' WHERE name = 'echo'")
	r := c.fail(exitFailure, "audit", "verify", "--expect-head", strings.Repeat("0", 64))
	wantContains(t, "stdout", r.stdout, "audit log ok", "integrity problem: ", `"s1/echo"`, "last_seen_digest")
	wantNotContains(t, "stdout", r.stdout, "integrity ok", headReminder)
	wantContains(t, "stderr", r.stderr, "audit head mismatch", "1 problem(s) listed above", adviceCorrupt)
	if n := strings.Count(r.stderr, programName+": "); n != 1 {
		t.Errorf("both findings must be one error line, got %d:\n%s", n, r.stderr)
	}
}
