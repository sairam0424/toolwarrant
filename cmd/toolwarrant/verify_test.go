package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// mismatchLine is the LEAK line for the approved, enabled tool whose live
// digest differs from the approved one: both digests, then the sub-label.
var mismatchLine = regexp.MustCompile(`LEAK echo live [0-9a-f]{12} approved [0-9a-f]{12} \(MISMATCH:`)

func TestVerifyGatewayReportsLeaksAgainstAPassThroughUpstream(t *testing.T) {
	c, u := fixture(t)
	r := c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", u.url())
	wantContains(t, "stdout", r.stdout, verdictLeak+" add live ", verdictLeak+" echo live ", verdictLeak+" wipe_database live ")
	wantNotContains(t, "stdout", r.stdout, verdictOK, verdictMismatch, " approved ")
	wantContains(t, "stderr", r.stderr, "3 tool(s) leak", "processor")

	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	r = c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", u.url())
	wantContains(t, "stdout", r.stdout, verdictLeak+" add", verdictLeak+" wipe_database")
	wantNotContains(t, "stdout", r.stdout, verdictLeak+" echo")
	wantContains(t, "stderr", r.stderr, "2 tool(s) leak")
	r = c.fail(exitFailure, "verify-gateway", "--server", "nope", "--url", u.url())
	wantContains(t, "stderr", r.stderr, "not found")
}

// Decision D12: OK and MISSING exit 0; the approved tool the gateway serves
// with other bytes is a LEAK with the MISMATCH sub-label and both digests,
// exit 1 (the second review got exit 0 here three times over); once the
// catalog knows the other digest, through a crawl or a reject, the same line
// is a plain LEAK.
func TestVerifyGatewayOKMissingAndMismatch(t *testing.T) {
	c, u := fixture(t)
	v1 := c.tool("s1", "echo").Pending
	c.approve("alice", "s1", "echo", v1)

	gateway := newUpstream(t, map[string]string{"echo": echoV1})
	out := c.ok("verify-gateway", "--server", "s1", "--url", gateway.url())
	wantContains(t, "stdout", out, verdictOK+": the gateway serves 1 tool(s), 1 approved and current; live configuration not compared (no --admin); id-less tools/call rejected by the gateway")
	wantNotContains(t, "stdout", out, verdictLeak, verdictMissing, verdictMismatch)

	empty := newUpstream(t, nil)
	out = c.ok("verify-gateway", "--server", "s1", "--url", empty.url(), "--no-probe")
	wantContains(t, "stdout", out, verdictMissing+" echo "+v1[:shortDigestLen],
		verdictOK+": the gateway serves 0 tool(s), 0 approved and current, 1 approved but not listed (MISSING); live configuration not compared (no --admin); unhooked-call probe skipped (--no-probe)")
	wantNotContains(t, "stdout", out, verdictLeak)

	changed := newUpstream(t, map[string]string{"echo": echoV2})
	r := c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", changed.url())
	if !mismatchLine.MatchString(r.stdout) {
		t.Errorf("no LEAK line with the MISMATCH sub-label and both digests:\n%s", r.stdout)
	}
	wantContains(t, "stdout", r.stdout, "approved "+v1[:shortDigestLen], "the latest crawl saw the approved digest", "no processor or the gateway re-serialised")
	wantNotContains(t, "stdout", r.stdout, verdictOK, verdictMissing)
	wantContains(t, "stderr", r.stderr, "1 tool(s) leak", "processor")

	// The crawl records the drift: the catalog now knows why the definition
	// must not be served, so the sub-label goes away.
	u.set("echo", echoV2)
	c.ok("crawl", "s1")
	v2 := c.tool("s1", "echo").Pending
	r = c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", changed.url())
	wantContains(t, "stdout", r.stdout, verdictLeak+" echo live "+v2[:shortDigestLen]+" approved "+v1[:shortDigestLen])
	wantNotContains(t, "stdout", r.stdout, verdictMismatch, verdictOK)
	c.ok("--as", "alice", "reject", "s1", "echo", "--hash", v2)
	r = c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", changed.url())
	wantContains(t, "stdout", r.stdout, verdictLeak+" echo live "+v2[:shortDigestLen])
	wantNotContains(t, "stdout", r.stdout, verdictMismatch, verdictOK)

	closed := newUpstream(t, nil)
	closed.http.Close()
	r = c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", closed.url()+"/mcp?q="+plant("query"))
	wantContains(t, "stderr", r.stderr, "listing through the gateway failed")
	wantNotContains(t, "stderr", r.stderr, canary, "q=")
	c.fail(exitUsage, "verify-gateway", "--server", "s1", "--url", gateway.url(), "--bearer-env", "UNSET_VAR")
}

func TestVerifyGatewayChecksTheEmittedConfig(t *testing.T) {
	c, u := fixture(t)
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

	// A file without the header at all.
	if err := os.WriteFile(cfg, []byte("routes: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r = c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", gateway.url(), "--config", cfg)
	wantContains(t, "stdout", r.stdout, verdictConfigEdited+" "+cfg, noHash)

	// A file the canary cannot read is treated as edited, with the reason,
	// and the listing still runs, so a LEAK is reported alongside it.
	missing := filepath.Join(t.TempDir(), "none.yaml")
	r = c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", gateway.url(), "--config", missing)
	wantContains(t, "stdout", r.stdout, verdictConfigEdited+" "+missing+": the file could not be read (", "no such file", "must assume it was replaced")
	wantContains(t, "stderr", r.stderr, "could not be read, so it is treated as edited", "restore the file emit wrote")
	wantNotContains(t, "stdout", r.stdout, verdictOK, verdictLeak)
	r = c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", u.url(), "--config", missing)
	wantContains(t, "stdout", r.stdout, verdictConfigEdited+" "+missing, verdictLeak+" add live ", verdictLeak+" wipe_database live ")
	wantContains(t, "stderr", r.stderr, "2 tool(s) leak", "could not be read")
}

// Each scheduled check opens a fresh MCP session for the listing and another
// for the probe, which the upstream counts.
func TestVerifyGatewayEveryUsesAFreshSessionPerCheck(t *testing.T) {
	c, _ := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	gateway := newUpstream(t, map[string]string{"echo": echoV1})
	out, _, stop := c.start("verify-gateway", "--server", "s1", "--url", gateway.url(), "--every", loopEvery.String())
	waitFor(t, "two checks", func() bool { return strings.Count(out.String(), "s1: the gateway serves 1 tool(s)") >= 2 })
	if code := stop(); code != exitOK {
		t.Fatalf("verify-gateway --every: exit %d\n%s", code, out.String())
	}
	if n := gateway.sessions.Load(); n < 4 {
		t.Errorf("the gateway saw %d session(s), want two per check (the listing and the probe)", n)
	}
	for _, line := range nonEmptyLines(out.String()) {
		wantContains(t, "line", line, "s1: the gateway serves 1 tool(s), 1 approved and current; live configuration not compared (no --admin); id-less tools/call rejected by the gateway")
		wantNotContains(t, "line", line, verdictLeak)
	}
}

func TestVerifyGatewayEveryStopsAtTheFirstLeakUnlessKeepGoing(t *testing.T) {
	c, u := fixture(t)
	before := u.sessions.Load()
	r := c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", u.url(), "--every", loopEvery.String(), "--no-probe")
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
	wantContains(t, "stderr", errb.String(), "check(s) in this run failed", "at least one check of this run found a "+verdictLeak+" or "+verdictConfigEdited, verdictLiveConfig, verdictUnhooked)
	wantContains(t, "stdout", out.String(), verdictLeak+" wipe_database")
}
