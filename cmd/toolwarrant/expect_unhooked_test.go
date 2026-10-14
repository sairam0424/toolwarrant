package main

import (
	"strings"
	"testing"
)

// The probe's two lines under --expect-unhooked, written out rather than built
// from the constants so that this file compiles against the code before the
// flag existed and the three tests below fail there for the right reason
// (the flag unknown, exit 2).
const (
	knownLimitLine   = "KNOWN-LIMIT s1: the gateway forwarded the id-less tools/call (HTTP 202), as agentgateway v1.6.0 does (L17)"
	knownLimitPart   = "; id-less tools/call forwarded unhooked as declared with --expect-unhooked (KNOWN-LIMIT L17)"
	probeChangedLine = "PROBE-CHANGED s1: the gateway no longer answers the probe with 202"
)

// D18: against agentgateway v1.6.0 the probe's 202 fails every check, so an
// operator who had recorded the limit switched the probe off with --no-probe
// and lost the one check that would notice the gateway changing.
// --expect-unhooked keeps the probe on: the 202 is printed as KNOWN-LIMIT, the
// one-line account names it, the check exits 0, the probe still reaches the
// upstream (which is what the line records), and a scheduled run that printed
// the line on every check exits 0 when it is stopped, because KNOWN-LIMIT is a
// report, not a failing verdict line.
func TestExpectUnhookedTurnsThe202IntoAKnownLimitLine(t *testing.T) {
	c, _ := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	g := newUpstream(t, map[string]string{"echo": echoV1})
	g.probeMode.Store(probeModeForward)
	before := len(g.probeNames())
	out := c.ok("verify-gateway", "--server", "s1", "--url", g.url(), "--expect-unhooked")
	wantContains(t, "stdout", out, knownLimitLine+"\n", okLine+"the gateway serves 1 tool(s), 1 approved and current; live configuration not compared (no --admin)"+knownLimitPart)
	wantNotContains(t, "stdout", out, verdictUnhooked, "PROBE-CHANGED", verdictInconclusive, verdictLeak, "(--no-probe)")
	if n := len(g.probeNames()) - before; n != 1 {
		t.Errorf("%d probe(s) reached the upstream, want 1: --expect-unhooked must keep the probe on", n)
	}

	stdout, stderr, stop := c.start("verify-gateway", "--server", "s1", "--url", g.url(), "--expect-unhooked", "--every", loopEvery.String())
	waitFor(t, "two checks", func() bool { return strings.Count(stdout.String(), knownLimitLine) >= 2 })
	if code := stop(); code != exitOK {
		t.Fatalf("verify-gateway --expect-unhooked --every: exit %d, want 0\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	wantContains(t, "scheduled stdout", stdout.String(), "s1: the gateway serves 1 tool(s), 1 approved and current; live configuration not compared (no --admin)"+knownLimitPart)
	wantNotContains(t, "scheduled stdout", stdout.String(), verdictUnhooked, "PROBE-CHANGED")
	wantNotContains(t, "scheduled stderr", stderr.String(), "check(s) in this run failed")
}

// D18: the flag declares one answer, HTTP 202, and nothing else. When the
// gateway answers the probe with anything else the probe can classify, a bare
// 400 as a go-sdk upstream writes it and each of the shapes that are
// PROBE-INCONCLUSIVE without the flag, the declaration no longer describes the
// gateway: the pin moved or the gateway changed under it, and the check fails
// as PROBE-CHANGED, exit 1, naming the status that came back and the
// re-qualification (L7). The inconclusive shapes are PROBE-CHANGED too, not
// PROBE-INCONCLUSIVE, because none of them is the declared 202. A scheduled
// run stops at the first such check, as it does for every failing verdict.
// Without the flag the same answers keep the verdicts they had.
func TestExpectUnhookedFailsWhenTheGatewayStopsForwarding(t *testing.T) {
	c, _ := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	g := newUpstream(t, map[string]string{"echo": echoV1})
	for name, tc := range map[string]struct {
		mode   int32
		status string
	}{
		"bare 400":              {probeModeRefuse, "HTTP 400"},
		"json-rpc error on 400": {probeModeRPCError400, "HTTP 400"},
		"json-rpc error":        {probeModeRPCError, "HTTP 200"},
		"event stream error":    {probeModeSSEError, "HTTP 200"},
		"result without error":  {probeModeSilent, "HTTP 200"},
	} {
		g.probeMode.Store(tc.mode)
		r := c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", g.url(), "--expect-unhooked")
		wantContains(t, name+" stdout", r.stdout, probeChangedLine+" (the id-less tools/call came back "+tc.status+"); the pin moved or the gateway changed under it; re-qualify (L7)")
		wantNotContains(t, name+" stdout", r.stdout, okLine, "KNOWN-LIMIT", verdictUnhooked, verdictInconclusive, verdictLeak)
		wantContains(t, name+" stderr", r.stderr, "PROBE-CHANGED", "as --expect-unhooked declared", tc.status, "re-qualify it (L7)")
		wantNotContains(t, name+" stderr", r.stderr, verdictInconclusive, verdictUnhooked)
	}

	g.probeMode.Store(probeModeRefuse)
	sessions := g.sessions.Load()
	r := c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", g.url(), "--expect-unhooked", "--every", loopEvery.String())
	wantContains(t, "scheduled stdout", r.stdout, probeChangedLine)
	wantContains(t, "scheduled stderr", r.stderr, "PROBE-CHANGED")
	if n := g.sessions.Load() - sessions; n != 2 {
		t.Errorf("the scheduled run opened %d session(s), want 2 (one listing, one probe): the first PROBE-CHANGED must stop it", n)
	}

	out := c.ok("verify-gateway", "--server", "s1", "--url", g.url())
	wantContains(t, "stdout without the flag", out, okLine, notAcceptedLine)
	wantNotContains(t, "stdout without the flag", out, "PROBE-CHANGED", "KNOWN-LIMIT")
}

// D18: --expect-unhooked declares what the probe's 202 means and --no-probe
// sends no probe, so the pair cannot hold at once; it is a usage error (exit
// 2) that names both flags, decided before anything is fetched: no session is
// opened against the gateway and no probe reaches the upstream.
func TestExpectUnhookedAndNoProbeAreExclusive(t *testing.T) {
	c, _ := fixture(t)
	g := newUpstream(t, map[string]string{"echo": echoV1})
	sessions := g.sessions.Load()
	r := c.fail(exitUsage, "verify-gateway", "--server", "s1", "--url", g.url(), "--expect-unhooked", "--no-probe")
	wantContains(t, "stderr", r.stderr, "--expect-unhooked and --no-probe are exclusive", "pass one of them")
	if r.stdout != "" {
		t.Errorf("stdout = %q, want nothing from a usage error", r.stdout)
	}
	if g.sessions.Load() != sessions || len(g.probeNames()) != 0 {
		t.Errorf("a usage error must not reach the gateway: %d session(s), probes %q", g.sessions.Load()-sessions, g.probeNames())
	}
}
