//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

const (
	// probeMarker is the start of the tool name every probe carries; the
	// hostile upstream's request log shows it when the gateway forwarded the
	// id-less call to the upstream.
	probeMarker = "toolwarrant.probe."
	// What verify-gateway prints about the probe: the verdict when the gateway
	// forwarded it, the summary part when a bare HTTP 400 came back (which
	// the canary attributes to nobody, D17 h), the summary part when the
	// probe was not sent, and under --expect-unhooked the report line and
	// summary part for the declared 202 and the failing verdict for anything
	// else (D18).
	unhookedLine     = "UNHOOKED-CALLS hostile:"
	notAcceptedLine  = "the id-less tools/call was not accepted as a notification (HTTP 400, by the gateway or by the upstream)"
	skippedLine      = "unhooked-call probe skipped (--no-probe)"
	knownLimitLine   = "KNOWN-LIMIT hostile: the gateway forwarded the id-less tools/call (HTTP 202), as agentgateway v1.6.0 does (L17)"
	knownLimitPart   = "id-less tools/call forwarded unhooked as declared with --expect-unhooked (KNOWN-LIMIT L17)"
	probeChangedLine = "PROBE-CHANGED hostile: the gateway no longer answers the probe with 202"
)

// scenarioO: the unhooked-call probe. verify-gateway sends one tools/call
// without a JSON-RPC id for a name no catalog holds. agentgateway v1.6.0
// answers HTTP 202 and forwards it to the upstream without the processor or
// the allow rule (limit L17), so the check reports UNHOOKED-CALLS, exits 1,
// and the hostile upstream's request log shows the probe arriving: that is
// the fail-open shape the probe proves. A bare HTTP 400 makes the check pass
// with a sentence that attributes the refusal to nobody (D17 h), because the
// probe cannot tell the gateway's own refusal from an upstream's refusal the
// gateway relayed; the scenario then records the change and requires the
// hostile upstream's log not to show the probe, which is the one way to tell
// the two apart here. Any other answer is PROBE-INCONCLUSIVE (decision D13),
// which on the pinned gateway would be a failure of this scenario. With
// --no-probe the summary says the probe was skipped. The third run passes
// --expect-unhooked (D18) and expects the answer the first run recorded.
func scenarioO(t *testing.T, s *stack) {
	hostileLog := s.servers["hostile"].hostile.log.Name()
	before := countIn(hostileLog, probeMarker)
	r := s.tw(t, nil, s.canaryArgs("hostile", true, s.cfg)...)
	forwarded := false
	switch {
	case r.code == exitOK && strings.Contains(r.stdout, notAcceptedLine):
		s.note(t, "O: the id-less tools/call came back with a bare HTTP 400, which the canary attributes to nobody; verify-gateway with the probe printed: %s", strings.TrimSpace(r.stdout))
		if n := countIn(hostileLog, probeMarker); n != before {
			t.Errorf("the probe's answer was not HTTP 202 yet the hostile upstream received it (%d probe requests logged, %d before): the gateway forwarded the id-less call and relayed the upstream's refusal, which the canary cannot attribute (D17 h): %s", n, before, hostileLog)
		}
	case r.code == exitFailure && strings.Contains(r.stdout, unhookedLine):
		forwarded = true
		mustContain(t, "verify-gateway stderr with the probe", r.stderr, "forwards a tools/call without an id")
		mustNotContain(t, "verify-gateway with the probe", r.stdout, "LEAK", "CONFIG-EDITED", "PROBE-INCONCLUSIVE")
		n := countIn(hostileLog, probeMarker)
		if n <= before {
			t.Errorf("verify-gateway reported UNHOOKED-CALLS but the hostile upstream's request log shows no probe (%d before, %d after): %s", before, n, hostileLog)
		}
		s.note(t, "O: verify-gateway with the probe printed: %s", strings.TrimSpace(r.stdout))
		s.note(t, "O: the hostile upstream's request log gained %d tools/call request(s) named toolwarrant.probe.*: the gateway forwarded the id-less call without the processor or the allow rule (limit L17)", n-before)
	default:
		t.Fatalf("verify-gateway with the probe: exit %d, want 1 with %q or 0 with %q\nstdout: %s\nstderr: %s", r.code, unhookedLine, notAcceptedLine, r.stdout, r.stderr)
	}
	r = s.tw(t, nil, s.canaryArgs("hostile", false, s.cfg)...)
	if r.code != exitOK {
		t.Errorf("verify-gateway --no-probe: exit %d, want 0\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	mustContain(t, "verify-gateway --no-probe", r.stdout, "OK:", skippedLine)
	mustNotContain(t, "verify-gateway --no-probe", r.stdout, "UNHOOKED-CALLS")
	s.note(t, "O: verify-gateway --no-probe printed: %s", strings.TrimSpace(r.stdout))
	scenarioOExpectUnhooked(t, s, hostileLog, forwarded)
}

// scenarioOExpectUnhooked is the third run of scenario O: the same check with
// --expect-unhooked, the flag that keeps the probe on against the pinned
// gateway (D18). When the first run saw the 202, this run must print
// KNOWN-LIMIT and the summary part that names the declared limit, exit 0, and
// the hostile upstream's log must still gain the probe, because the flag
// declares the forwarding rather than switching the probe off. When the first
// run saw a bare 400 the declaration is wrong for this gateway, and the run
// must fail as PROBE-CHANGED, exit 1, which is what the flag is for after a
// move of the pin (L7).
func scenarioOExpectUnhooked(t *testing.T, s *stack, hostileLog string, forwarded bool) {
	before := countIn(hostileLog, probeMarker)
	r := s.tw(t, nil, append(s.canaryArgs("hostile", true, s.cfg), "--expect-unhooked")...)
	switch {
	case forwarded && r.code == exitOK:
		mustContain(t, "verify-gateway --expect-unhooked", r.stdout, knownLimitLine, "OK:", knownLimitPart)
		mustNotContain(t, "verify-gateway --expect-unhooked", r.stdout, "UNHOOKED-CALLS", "PROBE-CHANGED", "PROBE-INCONCLUSIVE", "LEAK", "CONFIG-EDITED", skippedLine)
		n := countIn(hostileLog, probeMarker)
		if n <= before {
			t.Errorf("verify-gateway --expect-unhooked exited 0 with KNOWN-LIMIT but the hostile upstream's request log shows no new probe (%d before, %d after): the flag must keep the probe on: %s", before, n, hostileLog)
		}
		s.note(t, "O: verify-gateway --expect-unhooked printed: %s", strings.TrimSpace(r.stdout))
		s.note(t, "O: with --expect-unhooked the hostile upstream's request log gained %d probe request(s): the probe stayed on and the declared 202 was reported as KNOWN-LIMIT with exit 0 (D18)", n-before)
	case !forwarded && r.code == exitFailure:
		mustContain(t, "verify-gateway --expect-unhooked", r.stdout, probeChangedLine)
		mustContain(t, "verify-gateway --expect-unhooked stderr", r.stderr, "PROBE-CHANGED", "re-qualify it (L7)")
		mustNotContain(t, "verify-gateway --expect-unhooked", r.stdout, "OK:", "KNOWN-LIMIT")
		s.note(t, "O: the gateway did not forward the probe, so --expect-unhooked declared the wrong answer; verify-gateway printed: %s", strings.TrimSpace(r.stdout))
	default:
		t.Fatalf("verify-gateway --expect-unhooked: exit %d after a first run that %s; want 0 with %q when the gateway forwards the probe, 1 with %q when it does not\nstdout: %s\nstderr: %s", r.code, probeAnswerWord(forwarded), knownLimitLine, probeChangedLine, r.stdout, r.stderr)
	}
}

// probeAnswerWord names what the first run of scenario O saw, for a failure
// message.
func probeAnswerWord(forwarded bool) string {
	if forwarded {
		return "saw the probe forwarded (HTTP 202)"
	}
	return "saw a bare HTTP 400"
}
