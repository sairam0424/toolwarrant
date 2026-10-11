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
	// forwarded it, the summary part when the gateway refused it, and the
	// summary part when the probe was not sent.
	unhookedLine = "UNHOOKED-CALLS hostile:"
	refusedLine  = "id-less tools/call rejected by the gateway"
	skippedLine  = "unhooked-call probe skipped (--no-probe)"
)

// scenarioO: the unhooked-call probe. verify-gateway sends one tools/call
// without a JSON-RPC id for a name no catalog holds. agentgateway v1.6.0
// answers HTTP 202 and forwards it to the upstream without the processor or
// the allow rule (limit L17), so the check reports UNHOOKED-CALLS, exits 1,
// and the hostile upstream's request log shows the probe arriving. A gateway
// that refuses the id-less call (HTTP 400) makes the check pass; the scenario
// then records that the gateway now refuses id-less calls and passes too,
// because noticing that change is what the probe is for. Any other answer is
// PROBE-INCONCLUSIVE (decision D13), which on the pinned gateway would be a
// failure of this scenario. With --no-probe the summary says the probe was
// skipped.
func scenarioO(t *testing.T, s *stack) {
	hostileLog := s.servers["hostile"].hostile.log.Name()
	before := countIn(hostileLog, probeMarker)
	r := s.tw(t, nil, s.canaryArgs("hostile", true, s.cfg)...)
	switch {
	case r.code == exitOK && strings.Contains(r.stdout, refusedLine):
		s.note(t, "O: the gateway now refuses id-less tools/call; verify-gateway with the probe printed: %s", strings.TrimSpace(r.stdout))
		if n := countIn(hostileLog, probeMarker); n != before {
			t.Errorf("the gateway refused the probe yet the hostile upstream received it (%d probe requests logged, %d before): %s", n, before, hostileLog)
		}
	case r.code == exitFailure && strings.Contains(r.stdout, unhookedLine):
		mustContain(t, "verify-gateway stderr with the probe", r.stderr, "forwards a tools/call without an id")
		mustNotContain(t, "verify-gateway with the probe", r.stdout, "LEAK", "CONFIG-EDITED", "PROBE-INCONCLUSIVE")
		n := countIn(hostileLog, probeMarker)
		if n <= before {
			t.Errorf("verify-gateway reported UNHOOKED-CALLS but the hostile upstream's request log shows no probe (%d before, %d after): %s", before, n, hostileLog)
		}
		s.note(t, "O: verify-gateway with the probe printed: %s", strings.TrimSpace(r.stdout))
		s.note(t, "O: the hostile upstream's request log gained %d tools/call request(s) named toolwarrant.probe.*: the gateway forwarded the id-less call without the processor or the allow rule (limit L17)", n-before)
	default:
		t.Fatalf("verify-gateway with the probe: exit %d, want 1 with %q or 0 with %q\nstdout: %s\nstderr: %s", r.code, unhookedLine, refusedLine, r.stdout, r.stderr)
	}
	r = s.tw(t, nil, s.canaryArgs("hostile", false, s.cfg)...)
	if r.code != exitOK {
		t.Errorf("verify-gateway --no-probe: exit %d, want 0\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	mustContain(t, "verify-gateway --no-probe", r.stdout, "OK:", skippedLine)
	mustNotContain(t, "verify-gateway --no-probe", r.stdout, "UNHOOKED-CALLS")
	s.note(t, "O: verify-gateway --no-probe printed: %s", strings.TrimSpace(r.stdout))
}
