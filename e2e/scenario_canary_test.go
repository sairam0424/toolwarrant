//go:build e2e

package e2e

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
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
	// What verify-gateway prints about the live configuration.
	liveMismatchLine = "LIVE-CONFIG-MISMATCH mock:"
	liveMatchesLine  = "live configuration matches the emitted file"
	noProcessorLine  = "processor: the live route has none"
	// emittedCopyName is the file scenario P keeps a byte-identical copy of
	// the emitted configuration in, apart from the file the gateway watches
	// and may rewrite.
	emittedCopyName = "gateway.emitted.yaml"
	// headerPrefix starts every file emit writes; whether a file the gateway
	// rewrote still starts with it is part of what scenario P records.
	headerPrefix = "# "
	// extraRouteName and extraRoutePath are the route scenario P adds next to
	// mock's: another path, no allow rule, no processor, the same upstream.
	extraRouteName = "mock-extra"
	extraRoutePath = "/mock/mcp2"
	// shadowRouteName owns mock's client path in the shadow-route step of
	// scenario P while mock's own route is parked at parkedRoutePath.
	shadowRouteName = "mock-shadow"
	parkedRoutePath = "/mock/mcp-parked"
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

// liveLab is what the replacement steps of scenario P share: the bytes emit
// wrote as the gateway watches them, a byte-identical copy of them apart from
// the watched file, the document the gateway was running before any
// replacement and how many routes that document carries.
type liveLab struct {
	original []byte
	copyPath string
	doc      []byte
	routes   int
}

// scenarioP: the live-configuration comparison. With --admin, verify-gateway
// fetches the configuration the gateway is running from the admin API and
// compares the whole document with the file named by --config (decision
// D13). The check is healthy first. Then the running configuration is
// replaced three times through the unauthenticated admin API (POST
// /api/config, limit L18), the way a local user of the gateway host could:
// with the gateway's own document minus every mcpGuardrails policy, with the
// original document plus one route on another path without a rule or a
// processor, and with mock's route parked on another path while a route under
// another name owns mock's client path with the allow rule copied and no
// processor (the shadow route of finding cli-docs-1). Against a byte-identical
// copy of the file emit wrote every replacement is LIVE-CONFIG-MISMATCH, exit
// 1, naming the missing processor or the route the file does not carry. The
// original document is posted back after each step, the emitted bytes are put
// back on disk if the gateway rewrote them, and the check is healthy again,
// so later scenarios start from the emitted state.
func scenarioP(t *testing.T, s *stack) {
	s.expectLiveHealthy(t, "with the gateway running the emitted file")
	original := s.config(t)
	emittedCopy := filepath.Join(s.h.workdir, emittedCopyName)
	if err := os.WriteFile(emittedCopy, original, 0o600); err != nil {
		t.Fatalf("write %s: %v", emittedCopy, err)
	}
	liveDoc := s.liveConfig(t)
	routes, err := routeCount(liveDoc)
	if err != nil {
		t.Fatalf("count the live routes: %v", err)
	}
	lab := liveLab{original: original, copyPath: emittedCopy, doc: liveDoc, routes: routes}
	scenarioPNoProcessor(t, s, lab)
	scenarioPExtraRoute(t, s, lab)
	scenarioPShadowRoute(t, s, lab)
	s.eventuallyServes(t, "mock", "add", "echo")
}

// scenarioPNoProcessor: the gateway's own document minus every mcpGuardrails
// policy. What the gateway did to the watched file is recorded, and so is the
// check against that file: CONFIG-EDITED when the gateway rewrote it,
// LIVE-CONFIG-MISMATCH when it left the emitted bytes alone.
func scenarioPNoProcessor(t *testing.T, s *stack, lab liveLab) {
	stripped, err := withoutGuardrails(lab.doc)
	if err != nil {
		t.Fatalf("remove the processors from the live configuration: %v", err)
	}
	s.replaceLive(t, stripped)
	s.awaitLiveProcessor(t, "mock", false)
	onDisk := s.config(t)
	s.note(t, "P: after the replacement the watched file %s", describeWatchedFile(onDisk, lab.original, stripped, stripGuardrails(lab.original)))
	s.expectLiveMismatch(t, lab.copyPath, "with every processor removed", noProcessorLine)

	r := s.verifyGateway(t, "mock", "--admin", s.adminAddr())
	if r.code != exitFailure {
		t.Errorf("verify-gateway --admin against the watched file: exit %d, want 1\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	want := liveMismatchLine
	if !bytes.Equal(onDisk, lab.original) {
		want = "CONFIG-EDITED"
	}
	mustContain(t, "verify-gateway --admin against the watched file", r.stdout, want)
	s.note(t, "P: with --config naming the watched file, verify-gateway --admin printed: %s", strings.TrimSpace(r.stdout))
	s.restoreLive(t, lab, "after the processor removal")
}

// scenarioPExtraRoute: the original document plus one route on another path
// with no allow rule and no processor (finding processor-emit-2). mock's own
// route is untouched, so a comparison of that route alone passed; the
// whole-document comparison names the route the file does not carry.
func scenarioPExtraRoute(t *testing.T, s *stack, lab liveLab) {
	doc, err := withExtraRoute(lab.doc, "mock", extraRouteName, extraRoutePath)
	if err != nil {
		t.Fatalf("add a route to the live configuration: %v", err)
	}
	s.replaceLive(t, doc)
	s.awaitLiveRouteCount(t, lab.routes+1)
	s.expectLiveMismatch(t, lab.copyPath, "with a route added on "+extraRoutePath, extraRouteName)
	s.restoreLive(t, lab, "after the added route")
}

// scenarioPShadowRoute: mock's route keeps every field but its match, which
// moves to another path, and a route under another name owns mock's client
// path with the allow rule copied and no processor (finding cli-docs-1). A new
// session on the client path still lists exactly the approved names, because
// the allow rule hides the rest, so only the live comparison can show that the
// path is served without the processor.
func scenarioPShadowRoute(t *testing.T, s *stack, lab liveLab) {
	doc, err := withShadowRoute(lab.doc, "mock", shadowRouteName, parkedRoutePath)
	if err != nil {
		t.Fatalf("build the shadow-route document: %v", err)
	}
	s.replaceLive(t, doc)
	s.awaitLiveRouteCount(t, lab.routes+1)
	cs := s.eventuallyServes(t, "mock", "add", "echo")
	s.note(t, "P: with the shadow route owning %s a new session listed the approved names and tools/call echo -> %s", s.routeURL("mock"), callTool(cs, "echo"))
	s.expectLiveMismatch(t, lab.copyPath, "with mock's route parked at "+parkedRoutePath+" and "+shadowRouteName+" owning its path", shadowRouteName)
	s.restoreLive(t, lab, "after the shadow route")
}

// expectLiveHealthy runs verify-gateway --admin against the watched file and
// requires OK with the live configuration matching the emitted file.
func (s *stack) expectLiveHealthy(t *testing.T, when string) {
	t.Helper()
	r := s.verifyGateway(t, "mock", "--admin", s.adminAddr())
	if r.code != exitOK {
		t.Fatalf("verify-gateway --admin %s: exit %d\nstdout: %s\nstderr: %s", when, r.code, r.stdout, r.stderr)
	}
	mustContain(t, "verify-gateway --admin "+when, r.stdout, "OK:", liveMatchesLine)
	s.note(t, "P: %s, verify-gateway --admin printed: %s", when, strings.TrimSpace(r.stdout))
}

// expectLiveMismatch runs verify-gateway --admin against the byte-identical
// copy of the emitted file and requires LIVE-CONFIG-MISMATCH, exit 1, with
// every substring in naming on stdout and neither CONFIG-EDITED nor LEAK: the
// file is what emit wrote and nothing drifted, so the live comparison is the
// only thing that can see the replacement.
func (s *stack) expectLiveMismatch(t *testing.T, emittedCopy, when string, naming ...string) {
	t.Helper()
	r := s.tw(t, nil, append(s.canaryArgs("mock", false, emittedCopy), "--admin", s.adminAddr())...)
	if r.code != exitFailure {
		t.Errorf("verify-gateway --admin %s: exit %d, want 1\nstdout: %s\nstderr: %s", when, r.code, r.stdout, r.stderr)
	}
	mustContain(t, "verify-gateway --admin "+when, r.stdout, append([]string{liveMismatchLine}, naming...)...)
	mustNotContain(t, "verify-gateway --admin "+when, r.stdout, "CONFIG-EDITED", "LEAK")
	mustContain(t, "verify-gateway stderr "+when, r.stderr, "differs from the emitted file")
	s.note(t, "P: %s, with --config naming a byte-identical copy of the file emit wrote, verify-gateway --admin printed: %s", when, strings.TrimSpace(r.stdout))
}

// restoreLive posts the original document back, waits until the gateway runs
// the original routes with mock's processor in place, puts the emitted bytes
// back on disk if the gateway rewrote them and proves a healthy check.
func (s *stack) restoreLive(t *testing.T, lab liveLab, when string) {
	t.Helper()
	s.replaceLive(t, lab.doc)
	s.awaitLiveRouteCount(t, lab.routes)
	s.awaitLiveProcessor(t, "mock", true)
	if !bytes.Equal(s.config(t), lab.original) {
		s.writeConfig(t, lab.original)
	}
	s.expectLiveHealthy(t, when+", with the original document posted back")
}

// replaceLive replaces the running configuration through the admin API and
// records the gateway's answer. A gateway that refuses the post fails the
// scenario with the status and the start of the answer.
func (s *stack) replaceLive(t *testing.T, doc []byte) {
	t.Helper()
	status, body := s.postLiveConfig(t, doc)
	s.note(t, "P: POST %s with %d bytes of JSON -> status %d, %d-byte answer", adminConfigPath, len(doc), status, len(body))
	if status/100 != 2 {
		t.Fatalf("POST %s: status %d: %.300s", adminConfigPath, status, body)
	}
}

// describeWatchedFile says what the gateway did to the watched file after a
// replacement through the admin API: left it alone, rewrote it with the
// posted document itself, rewrote it as the emitted YAML minus the processor
// blocks with the header lines kept (what the second review saw, threat model
// row 26), or wrote something else, and in the last case whether the emitted
// header lines survived.
func describeWatchedFile(onDisk, original, posted, strippedYAML []byte) string {
	switch {
	case bytes.Equal(onDisk, original):
		return "is unchanged (still the bytes emit wrote)"
	case bytes.Equal(onDisk, posted):
		return fmt.Sprintf("was rewritten with the posted document verbatim (%d bytes of JSON, no toolwarrant header)", len(onDisk))
	case bytes.Equal(onDisk, strippedYAML):
		return fmt.Sprintf("was rewritten as the emitted YAML minus the mcpGuardrails blocks (%d bytes), toolwarrant's header lines included, so its header hash no longer matches its body", len(onDisk))
	}
	header := "without"
	if bytes.HasPrefix(onDisk, []byte(headerPrefix)) {
		header = "still with"
	}
	return fmt.Sprintf("was rewritten with %d bytes that are neither the emitted file nor the posted document, %s the emitted header lines", len(onDisk), header)
}
