package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// strictSentence is the stderr sentence of a --strict check that found N
// MISSING tools; docs/operations.md quotes it.
func strictSentence(n string) string {
	return n + " approved tool(s) are not listed by the gateway (" + verdictMissing + ") under --strict: the emitted allow-list predates an approval; run emit again and reload the gateway"
}

// D23 (g): the fixture of TestVerifyGatewayOKMissingAndMismatch, echo approved
// and a gateway that does not list it, prints the same MISSING line under
// --strict and exits 1 with the sentence naming the fix; the file emit wrote
// after the approval is current, so the failure is MISSING and not
// CONFIG-EDITED. Once the gateway lists the tool, as it does after a re-emit
// and a reload, the same command exits 0. A LEAK and a MISSING on one check
// each get their sentence.
func TestVerifyGatewayStrictFailsOnMissing(t *testing.T) {
	t.Parallel()
	c, u := fixture(t)
	v1 := c.tool("s1", "echo").Pending
	c.approve("alice", "s1", "echo", v1)
	cfg := filepath.Join(t.TempDir(), "gateway.yaml")
	c.ok("emit", "--out", cfg)

	stale := newUpstream(t, nil)
	r := c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", stale.url(), "--config", cfg, "--no-probe", "--strict")
	wantContains(t, "stdout", r.stdout, verdictMissing+" echo "+v1[:shortDigestLen])
	wantNotContains(t, "stdout", r.stdout, verdictOK, verdictLeak, verdictConfigEdited)
	wantContains(t, "stderr", r.stderr, strictSentence("1"))
	wantNotContains(t, "stderr", r.stderr, "leak", "edited")

	// The gateway now lists the approved tool: the check passes under the flag.
	stale.set("echo", echoV1)
	out := c.ok("verify-gateway", "--server", "s1", "--url", stale.url(), "--config", cfg, "--no-probe", "--strict")
	wantContains(t, "stdout", out, verdictOK+": the gateway serves 1 tool(s), 1 approved and current; live configuration not compared (no --admin); unhooked-call probe skipped (--no-probe)")
	wantNotContains(t, "stdout", out, verdictMissing)

	// The pass-through upstream without echo: two LEAKs and one MISSING.
	u.remove("echo")
	r = c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", u.url(), "--no-probe", "--strict")
	wantContains(t, "stdout", r.stdout, verdictLeak+" add live ", verdictLeak+" wipe_database live ", verdictMissing+" echo "+v1[:shortDigestLen])
	wantContains(t, "stderr", r.stderr, "2 tool(s) leak", "; "+strictSentence("1"))
}

// The flag adds MISSING to the failing verdicts and nothing else: a gateway
// that lists every approved tool is OK under --strict, with the probe's
// not-accepted line, with --config, and with the KNOWN-LIMIT line that
// --expect-unhooked turns a declared 202 into (D18).
func TestVerifyGatewayStrictLeavesOKAndKnownLimitAlone(t *testing.T) {
	t.Parallel()
	c, _ := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	gateway := newUpstream(t, map[string]string{"echo": echoV1})
	out := c.ok("verify-gateway", "--server", "s1", "--url", gateway.url(), "--strict")
	wantContains(t, "stdout", out, okLine+"the gateway serves 1 tool(s), 1 approved and current; live configuration not compared (no --admin); "+notAcceptedLine)
	wantNotContains(t, "stdout", out, verdictMissing, verdictLeak)

	cfg := filepath.Join(t.TempDir(), "gateway.yaml")
	c.ok("emit", "--out", cfg)
	out = c.ok("verify-gateway", "--server", "s1", "--url", gateway.url(), "--config", cfg, "--no-probe", "--strict")
	wantContains(t, "stdout", out, okLine+"the gateway serves 1 tool(s), 1 approved and current")
	wantNotContains(t, "stdout", out, verdictMissing, verdictConfigEdited)

	forwarding := newUpstream(t, map[string]string{"echo": echoV1})
	forwarding.probeMode.Store(probeModeForward)
	out = c.ok("verify-gateway", "--server", "s1", "--url", forwarding.url(), "--expect-unhooked", "--strict")
	wantContains(t, "stdout", out, knownLimitLine+"\n", okLine+"the gateway serves 1 tool(s), 1 approved and current; live configuration not compared (no --admin)"+knownLimitPart)
	wantNotContains(t, "stdout", out, verdictMissing, verdictUnhooked, verdictProbeChanged)
}

// The loop's rule under --strict mirrors the LEAK rule: without --keep-going
// the run exits 1 at the first check that printed a MISSING, after exactly one
// check; with --keep-going it keeps checking and exits 1 when stopped, and the
// outcome sentence names MISSING under --strict so a supervisor's log line
// says why.
func TestVerifyGatewayEveryStrictStopsAtAMissingUnlessKeepGoing(t *testing.T) {
	t.Parallel()
	c, _ := fixture(t)
	v1 := c.tool("s1", "echo").Pending
	c.approve("alice", "s1", "echo", v1)
	stale := newUpstream(t, nil)
	before := stale.sessions.Load()
	r := c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", stale.url(), "--every", loopEvery.String(), "--no-probe", "--strict")
	wantContains(t, "stdout", r.stdout, verdictMissing+" echo "+v1[:shortDigestLen])
	wantContains(t, "stderr", r.stderr, strictSentence("1"))
	if n := stale.sessions.Load() - before; n != 1 {
		t.Errorf("%d checks ran, want exactly one before the first MISSING stopped the strict run", n)
	}

	out, errb, stop := c.start("verify-gateway", "--server", "s1", "--url", stale.url(), "--every", loopEvery.String(), "--no-probe", "--strict", "--keep-going")
	waitFor(t, "two checks", func() bool { return strings.Count(out.String(), "1 approved but not listed ("+verdictMissing+")") >= 2 })
	if code := stop(); code != exitFailure {
		t.Fatalf("verify-gateway --strict --keep-going with a MISSING: exit %d, want %d\nstdout: %s\nstderr: %s", code, exitFailure, out.String(), errb.String())
	}
	wantContains(t, "stdout", out.String(), verdictMissing+" echo "+v1[:shortDigestLen])
	wantContains(t, "stderr", errb.String(), "check(s) in this run failed", "at least one check of this run found a "+verdictLeak+" or "+verdictConfigEdited, ", or a "+verdictMissing+" under --strict")
}

// D12 pinned: without --strict the same MISSING is a report. One check exits 0
// with the MISSING line and the OK line that counts it, a scheduled run keeps
// going past it and exits 0 when stopped, and neither prints the strict
// sentence.
func TestVerifyGatewayWithoutStrictKeepsExitZeroOnMissing(t *testing.T) {
	t.Parallel()
	c, _ := fixture(t)
	v1 := c.tool("s1", "echo").Pending
	c.approve("alice", "s1", "echo", v1)
	stale := newUpstream(t, nil)
	out := c.ok("verify-gateway", "--server", "s1", "--url", stale.url(), "--no-probe")
	wantContains(t, "stdout", out, verdictMissing+" echo "+v1[:shortDigestLen], okLine+"the gateway serves 0 tool(s), 0 approved and current, 1 approved but not listed ("+verdictMissing+")")
	wantNotContains(t, "stdout", out, verdictLeak, "--strict")

	stdout, stderr, stop := c.start("verify-gateway", "--server", "s1", "--url", stale.url(), "--every", loopEvery.String(), "--no-probe")
	waitFor(t, "two checks", func() bool {
		return strings.Count(stdout.String(), "1 approved but not listed ("+verdictMissing+")") >= 2
	})
	if code := stop(); code != exitOK {
		t.Fatalf("verify-gateway --every with a MISSING and no --strict: exit %d, want 0\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	wantNotContains(t, "stderr", stderr.String(), "check(s) in this run failed", "--strict", verdictMissing)
}
