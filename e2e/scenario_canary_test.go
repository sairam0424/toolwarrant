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
)

// scenarioO: the unhooked-call probe. verify-gateway sends one tools/call
// without a JSON-RPC id for a name no catalog holds. agentgateway v1.6.0
// answers HTTP 202 and forwards it to the upstream without the processor or
// the allow rule (limit L17), so the check reports UNHOOKED-CALLS, exits 1,
// and the hostile upstream's request log shows the probe arriving. A gateway
// that refuses the id-less call (HTTP 400 or a JSON-RPC error) makes the check
// pass; the scenario then records that the gateway now refuses id-less calls
// and passes too, because noticing that change is what the probe is for. With
// --no-probe the summary says the probe was skipped.
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
		mustNotContain(t, "verify-gateway with the probe", r.stdout, "LEAK", "CONFIG-EDITED")
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

// scenarioP: the live-configuration comparison. With --admin, verify-gateway
// fetches the configuration the gateway is running from the admin API and
// compares the route with the file named by --config. The check is healthy
// first. Then the running configuration is replaced through the
// unauthenticated admin API (POST /api/config, limit L18) with the gateway's
// own document minus every mcpGuardrails policy, the way a local user of the
// gateway host could; against a byte-identical copy of the file emit wrote
// the check reports LIVE-CONFIG-MISMATCH, exit 1, naming the missing
// processor. What the gateway did to the watched file is recorded, and so is
// the check against that file. The original document is posted back, the
// emitted bytes are put back on disk if the gateway rewrote them, and the
// check is healthy again, so later scenarios start from the emitted state.
func scenarioP(t *testing.T, s *stack) {
	r := s.verifyGateway(t, "mock", "--admin", s.adminAddr())
	if r.code != exitOK {
		t.Fatalf("verify-gateway --admin before the replacement: exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	mustContain(t, "verify-gateway --admin before the replacement", r.stdout, "OK:", liveMatchesLine)
	s.note(t, "P: with the gateway running the emitted file, verify-gateway --admin printed: %s", strings.TrimSpace(r.stdout))

	original := s.config(t)
	emittedCopy := filepath.Join(s.h.workdir, emittedCopyName)
	if err := os.WriteFile(emittedCopy, original, 0o644); err != nil {
		t.Fatalf("write %s: %v", emittedCopy, err)
	}
	liveDoc := s.liveConfig(t)
	stripped, err := withoutGuardrails(liveDoc)
	if err != nil {
		t.Fatalf("remove the processors from the live configuration: %v", err)
	}
	s.replaceLive(t, stripped)
	s.awaitLiveProcessor(t, "mock", false)
	onDisk := s.config(t)
	s.note(t, "P: after the replacement the watched file %s", describeWatchedFile(onDisk, original, stripped, stripGuardrails(original)))

	r = s.tw(t, nil, append(s.canaryArgs("mock", false, emittedCopy), "--admin", s.adminAddr())...)
	if r.code != exitFailure {
		t.Errorf("verify-gateway --admin against the emitted copy: exit %d, want 1\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	mustContain(t, "verify-gateway --admin against the emitted copy", r.stdout, liveMismatchLine, noProcessorLine)
	mustNotContain(t, "verify-gateway --admin against the emitted copy", r.stdout, "CONFIG-EDITED", "LEAK")
	mustContain(t, "verify-gateway stderr against the emitted copy", r.stderr, "differs from the emitted file")
	s.note(t, "P: with --config naming a byte-identical copy of the file emit wrote, verify-gateway --admin printed: %s", strings.TrimSpace(r.stdout))

	r = s.verifyGateway(t, "mock", "--admin", s.adminAddr())
	if r.code != exitFailure {
		t.Errorf("verify-gateway --admin against the watched file: exit %d, want 1\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	want := liveMismatchLine
	if !bytes.Equal(onDisk, original) {
		want = "CONFIG-EDITED"
	}
	mustContain(t, "verify-gateway --admin against the watched file", r.stdout, want)
	s.note(t, "P: with --config naming the watched file, verify-gateway --admin printed: %s", strings.TrimSpace(r.stdout))

	s.replaceLive(t, liveDoc)
	s.awaitLiveProcessor(t, "mock", true)
	if !bytes.Equal(s.config(t), original) {
		s.writeConfig(t, original)
	}
	r = s.verifyGateway(t, "mock", "--admin", s.adminAddr())
	if r.code != exitOK {
		t.Fatalf("verify-gateway --admin after the restore: exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	mustContain(t, "verify-gateway --admin after the restore", r.stdout, "OK:", liveMatchesLine)
	s.note(t, "P: after posting the original document back, verify-gateway --admin printed: %s", strings.TrimSpace(r.stdout))
	s.eventuallyServes(t, "mock", "add", "echo")
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
