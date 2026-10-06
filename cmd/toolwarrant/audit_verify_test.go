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
	wantContains(t, "verify", out, "record this head outside the database")
	head := m[2]
	c.ok("audit", "verify", "--expect-head", strings.ToUpper(head))
	r := c.fail(exitFailure, "audit", "verify", "--expect-head", strings.Repeat("0", 64))
	wantContains(t, "stderr", r.stderr, "audit head mismatch", head)

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

func TestAuditVerifyDetectsATamperedDatabase(t *testing.T) {
	c, _ := fixture(t)
	execSQL(t, c.db, "DROP TRIGGER audit_log_no_update", "UPDATE audit_log SET detail = 'nothing happened' WHERE seq = 2")
	r := c.fail(exitFailure, "audit", "verify")
	wantContains(t, "stderr", r.stderr, "audit log is broken at entry 2", "changed outside toolwarrant")
	wantNotContains(t, "stdout", r.stdout, "audit log ok")
}

func TestVerifyGatewayReportsLeaksAgainstAPassThroughUpstream(t *testing.T) {
	c, u := fixture(t)
	r := c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", u.url())
	wantContains(t, "stdout", r.stdout, verdictLeak+" add", verdictLeak+" echo", verdictLeak+" wipe_database")
	wantNotContains(t, "stdout", r.stdout, verdictOK)
	wantContains(t, "stderr", r.stderr, "3 tool(s) leak", "processor")

	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	r = c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", u.url())
	wantContains(t, "stdout", r.stdout, verdictLeak+" add", verdictLeak+" wipe_database")
	wantNotContains(t, "stdout", r.stdout, verdictLeak+" echo")
	wantContains(t, "stderr", r.stderr, "2 tool(s) leak")
	r = c.fail(exitFailure, "verify-gateway", "--server", "nope", "--url", u.url())
	wantContains(t, "stderr", r.stderr, "not found")
}

func TestVerifyGatewayOKAndMissing(t *testing.T) {
	c, _ := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)

	gateway := newUpstream(t, map[string]string{"echo": echoV1})
	out := c.ok("verify-gateway", "--server", "s1", "--url", gateway.url())
	wantContains(t, "stdout", out, verdictOK, "serves 1 tool(s)")
	wantNotContains(t, "stdout", out, verdictLeak, verdictMissing)

	empty := newUpstream(t, nil)
	out = c.ok("verify-gateway", "--server", "s1", "--url", empty.url())
	wantContains(t, "stdout", out, verdictMissing+" echo", verdictOK)
	wantNotContains(t, "stdout", out, verdictLeak)

	changed := newUpstream(t, map[string]string{"echo": echoV2})
	r := c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", changed.url())
	wantContains(t, "stdout", r.stdout, verdictLeak+" echo")

	closed := newUpstream(t, nil)
	closed.http.Close()
	r = c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", closed.url()+"/mcp?q="+plant("query"))
	wantContains(t, "stderr", r.stderr, "listing through the gateway failed")
	wantNotContains(t, "stderr", r.stderr, canary, "q=")
	c.fail(exitUsage, "verify-gateway", "--server", "s1", "--url", gateway.url(), "--bearer-env", "UNSET_VAR")
}
