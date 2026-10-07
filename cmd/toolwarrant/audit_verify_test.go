package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	headLine     = regexp.MustCompile(`audit log ok: (\d+) entries, head ([0-9a-f]{64})`)
	mismatchLine = regexp.MustCompile(`MISMATCH echo live [0-9a-f]{12} approved [0-9a-f]{12}`)
)

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

func TestVerifyGatewayOKMissingAndMismatch(t *testing.T) {
	c, _ := fixture(t)
	v1 := c.tool("s1", "echo").Pending
	c.approve("alice", "s1", "echo", v1)

	gateway := newUpstream(t, map[string]string{"echo": echoV1})
	out := c.ok("verify-gateway", "--server", "s1", "--url", gateway.url())
	wantContains(t, "stdout", out, verdictOK+": the gateway serves 1 tool(s), 1 approved and current")
	wantNotContains(t, "stdout", out, verdictLeak, verdictMissing, verdictMismatch)

	empty := newUpstream(t, nil)
	out = c.ok("verify-gateway", "--server", "s1", "--url", empty.url())
	wantContains(t, "stdout", out, verdictMissing+" echo "+v1[:shortDigestLen], verdictOK, "1 approved but not listed")
	wantNotContains(t, "stdout", out, verdictLeak)

	// The catalog saw the approved digest at the upstream, the gateway hands
	// out another: reported with both digests, not failed.
	changed := newUpstream(t, map[string]string{"echo": echoV2})
	r := c.run("verify-gateway", "--server", "s1", "--url", changed.url())
	if r.code != exitOK {
		t.Fatalf("a mismatch alone must not fail: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	if !mismatchLine.MatchString(r.stdout) {
		t.Errorf("no MISMATCH line with both digests:\n%s", r.stdout)
	}
	wantContains(t, "stdout", r.stdout, "approved "+v1[:shortDigestLen], "re-serialising unknown fields", verdictOK, "1 with a digest other than the approved one")
	wantNotContains(t, "stdout", r.stdout, verdictLeak)

	closed := newUpstream(t, nil)
	closed.http.Close()
	r = c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", closed.url()+"/mcp?q="+plant("query"))
	wantContains(t, "stderr", r.stderr, "listing through the gateway failed")
	wantNotContains(t, "stderr", r.stderr, canary, "q=")
	c.fail(exitUsage, "verify-gateway", "--server", "s1", "--url", gateway.url(), "--bearer-env", "UNSET_VAR")
}

func TestVerifyGatewayChecksTheEmittedConfig(t *testing.T) {
	c, _ := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	gateway := newUpstream(t, map[string]string{"echo": echoV1})
	cfg := filepath.Join(t.TempDir(), "gateway.yaml")
	c.ok("emit", "--out", cfg)
	out := c.ok("verify-gateway", "--server", "s1", "--url", gateway.url(), "--config", cfg)
	wantContains(t, "stdout", out, verdictOK)
	wantNotContains(t, "stdout", out, verdictConfigEdited)

	// The edit that fails open: the processor's failure mode.
	edited := strings.Replace(readFile(t, cfg), "failClosed", "failOpen", 1)
	if err := os.WriteFile(cfg, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	r := c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", gateway.url(), "--config", cfg)
	wantContains(t, "stdout", r.stdout, verdictConfigEdited+" "+cfg, "body sha256", "fails open")
	wantContains(t, "stderr", r.stderr, "edited after emit wrote it", "run emit again")
	wantNotContains(t, "stdout", r.stdout, verdictOK)

	r = c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", gateway.url(), "--config", filepath.Join(t.TempDir(), "none.yaml"))
	wantContains(t, "stderr", r.stderr, "read gateway config")
}

// Each scheduled check opens a fresh MCP session, which the upstream counts.
func TestVerifyGatewayEveryUsesAFreshSessionPerCheck(t *testing.T) {
	c, _ := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	gateway := newUpstream(t, map[string]string{"echo": echoV1})
	out, _, stop := c.start("verify-gateway", "--server", "s1", "--url", gateway.url(), "--every", loopEvery.String())
	waitFor(t, "two checks", func() bool { return strings.Count(out.String(), "s1: the gateway serves 1 tool(s)") >= 2 })
	if code := stop(); code != exitOK {
		t.Fatalf("verify-gateway --every: exit %d\n%s", code, out.String())
	}
	if n := gateway.sessions.Load(); n < 2 {
		t.Errorf("the gateway saw %d session(s), want one per check", n)
	}
	for _, line := range nonEmptyLines(out.String()) {
		wantContains(t, "line", line, "s1: the gateway serves 1 tool(s), 1 approved and current")
		wantNotContains(t, "line", line, verdictLeak)
	}
}

func TestVerifyGatewayEveryStopsAtTheFirstLeakUnlessKeepGoing(t *testing.T) {
	c, u := fixture(t)
	before := u.sessions.Load()
	r := c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", u.url(), "--every", loopEvery.String())
	wantContains(t, "stdout", r.stdout, verdictLeak+" echo")
	wantContains(t, "stderr", r.stderr, "3 tool(s) leak")
	if n := u.sessions.Load() - before; n != 1 {
		t.Errorf("%d checks ran, want exactly one before the first LEAK stopped the run", n)
	}

	out, errb, stop := c.start("verify-gateway", "--server", "s1", "--url", u.url(), "--every", loopEvery.String(), "--keep-going")
	waitFor(t, "two checks", func() bool { return strings.Count(out.String(), "3 leaked") >= 2 })
	if code := stop(); code != exitFailure {
		t.Fatalf("verify-gateway --keep-going with leaks: exit %d, want %d\n%s", code, exitFailure, out.String())
	}
	wantContains(t, "stderr", errb.String(), "at least one check", verdictLeak)
	wantContains(t, "stdout", out.String(), verdictLeak+" wipe_database")
}
