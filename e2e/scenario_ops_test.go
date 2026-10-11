//go:build e2e

package e2e

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	// sharedEnvVar names the environment variable that carries the processor's
	// shared value in scenario H, for emit and serve alike. The value itself is
	// generated per run: it must never be a literal in a source file.
	sharedEnvVar  = "TOOLWARRANT_E2E_SHARED"
	tokenBytes    = 16
	refuseTimeout = 3 * time.Second
)

// randomToken returns a fresh printable-ASCII value of 36 characters, within
// the emitter's bounds for a processor shared value.
func randomToken(t *testing.T) string {
	t.Helper()
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("random token: %v", err)
	}
	return "e2e-" + hex.EncodeToString(b)
}

// okSummary is the per-check line the canary loop prints while the route is
// healthy; the line goes on with the live-configuration and probe parts.
const okSummary = "mock: the gateway serves 2 tool(s), 2 approved and current"

// mismatchLabel is the sub-label a LEAK line carries when the latest crawl saw
// the approved digest, so the catalog has no record of drift (decision D12).
const mismatchLabel = "(MISMATCH:"

// zeroDigest is a well-formed digest no file or audit log can have, for the
// checks that hand verify-gateway and audit verify a wrong recorded value.
const zeroDigest = "0000000000000000000000000000000000000000000000000000000000000000"

// scenarioF: verify-gateway passes on the emitted file, with and without
// --expect-body-hash set to the body hash the latest emit printed; a hand edit
// that strips the processor block is reloaded by the gateway, and after a
// drift a new session sees the drifted definition. verify-gateway --config
// reports CONFIG-EDITED and a LEAK line at once, exit code 1: before the crawl
// records the drift the LEAK carries the MISMATCH sub-label (the latest crawl
// saw the approved digest), after it the plain LEAK (decision D12; before the
// third round the first check printed a non-failing MISMATCH). A canary loop
// (--every 1s --keep-going --expect-body-hash) running throughout prints the
// same verdicts as they happen and exits 1 when stopped. Restoring the file
// restores the guard, and on the restored file a recorded hash that differs
// from the body is CONFIG-EDITED on its own (decision D13, limit L19).
func scenarioF(t *testing.T, s *stack) {
	r := s.verifyGateway(t, "mock")
	if r.code != exitOK {
		t.Fatalf("verify-gateway before the edit: exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	mustContain(t, "verify-gateway", r.stdout, "OK: the gateway serves 2 tool(s)")
	s.expectBodyHash(t, "before the edit, with the hash emit printed", s.bodyHash, exitOK, "OK:")
	canaryCmd := append([]string{"--db", s.db}, s.canaryArgs("mock", false, s.cfg)...)
	canaryCmd = append(canaryCmd, "--every", "1s", "--keep-going", "--expect-body-hash", s.bodyHash)
	canary := s.spawn(t, "canary", nil, s.h.toolwarrant, canaryCmd...)
	waitForOutput(t, canary, okSummary, 1)
	original := s.config(t)
	stripped := stripGuardrails(original)
	if bytes.Equal(original, stripped) || bytes.Contains(stripped, []byte("mcpGuardrails")) {
		t.Fatalf("stripping the guardrails block changed nothing")
	}
	s.writeConfig(t, stripped)

	s.describe(t, "mock", "echo", echoV2)
	cs := s.eventuallyServes(t, "mock", "add", "echo")
	tools, err := listTools(cs)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	if tool := toolNamed(tools, "echo"); tool == nil || tool.Description != echoV2 {
		t.Errorf("without the processor a new session should see the drifted echo, got %+v", tool)
	}
	s.note(t, "F: with mcpGuardrails stripped from the file a new session saw the drifted echo definition; tools/call echo -> %s", callTool(cs, "echo"))

	r = s.verifyGateway(t, "mock")
	if r.code != exitFailure {
		t.Errorf("verify-gateway on the edited file: exit %d, want 1\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	mustContain(t, "verify-gateway before the crawl", r.stdout, "CONFIG-EDITED", "LEAK echo", mismatchLabel)
	mustContain(t, "verify-gateway stderr before the crawl", r.stderr, "leak", "edited")
	s.note(t, "F: before the crawl recorded the drift, verify-gateway printed: %s", strings.TrimSpace(r.stdout))
	s.expectBodyHash(t, "on the edited file, with the hash emit printed", s.bodyHash, exitFailure, "CONFIG-EDITED", "LEAK echo")
	mustContain(t, "crawl", s.twOK(t, "crawl", "mock"), "DRIFT")
	r = s.verifyGateway(t, "mock")
	if r.code != exitFailure {
		t.Errorf("verify-gateway after the crawl: exit %d, want 1\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	mustContain(t, "verify-gateway after the crawl", r.stdout, "CONFIG-EDITED", "LEAK echo")
	mustNotContain(t, "verify-gateway after the crawl", r.stdout, mismatchLabel)
	mustContain(t, "verify-gateway stderr", r.stderr, "leak", "edited")
	s.note(t, "F: after the crawl recorded the drift, verify-gateway printed: %s", strings.TrimSpace(r.stdout))
	waitForOutput(t, canary, "LEAK echo", 0)
	waitForOutput(t, canary, "CONFIG-EDITED", 0)
	scenarioFRestore(t, s, canary, original)
}

// scenarioFRestore puts the emitted file back, proves the guard is back (echo
// denied until the upstream reverts and a crawl records it), checks the
// recorded body hash both ways on the restored file and stops the canary,
// which must exit 1 for the verdicts it printed.
func scenarioFRestore(t *testing.T, s *stack, canary *proc, original []byte) {
	t.Helper()
	healthyBefore := countIn(canary.stdout, okSummary)
	s.writeConfig(t, original)
	cs := s.eventuallyServes(t, "mock", "add")
	s.expectDenied(t, cs, "echo")
	s.describe(t, "mock", "echo", echoV1)
	mustContain(t, "crawl after restore", s.twOK(t, "crawl", "mock"), "reverted=1")
	cs = s.eventuallyServes(t, "mock", "add", "echo")
	s.expectAllowed(t, cs, "echo", "hello")
	if r := s.verifyGateway(t, "mock"); r.code != exitOK {
		t.Errorf("verify-gateway after restoring the file: exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	s.expectBodyHash(t, "on the restored file, with the hash emit printed", s.bodyHash, exitOK, "OK:")
	r := s.expectBodyHash(t, "on the restored file, with another recorded hash", zeroDigest, exitFailure, "CONFIG-EDITED")
	mustNotContain(t, "verify-gateway --expect-body-hash with another recorded hash", r.stdout, "LEAK")
	waitForOutput(t, canary, okSummary, healthyBefore)
	if code := canary.stop(); code != exitFailure {
		t.Errorf("verify-gateway --every --keep-going exit %d after seeing a LEAK, want 1\nstdout:\n%s\nstderr:\n%s", code, canary.output(canary.stdout), canary.output(canary.stderr))
	}
	mustContain(t, "canary stderr", canary.output(canary.stderr), "check(s) in this run failed")
	s.note(t, "F: the --every 1s --keep-going canary printed %d healthy checks, %d LEAK lines (%d of them with the MISMATCH sub-label) and %d CONFIG-EDITED lines across the edit, and exited 1 on SIGTERM",
		countIn(canary.stdout, okSummary), countIn(canary.stdout, "LEAK echo"), countIn(canary.stdout, mismatchLabel), countIn(canary.stdout, "CONFIG-EDITED"))
}

// expectBodyHash runs verify-gateway --config with --expect-body-hash HASH,
// the comparison of the recorded body hash the documents describe for limit
// L19 (decision D13), and requires the exit code and the output.
func (s *stack) expectBodyHash(t *testing.T, when, hash string, wantCode int, want ...string) cliResult {
	t.Helper()
	r := s.verifyGateway(t, "mock", "--expect-body-hash", hash)
	if r.code != wantCode {
		t.Errorf("verify-gateway --expect-body-hash %s: exit %d, want %d\nstdout: %s\nstderr: %s", when, r.code, wantCode, r.stdout, r.stderr)
	}
	mustContain(t, "verify-gateway --expect-body-hash "+when, r.stdout, want...)
	s.note(t, "F: verify-gateway --expect-body-hash %s printed: %s", when, strings.TrimSpace(r.stdout))
	return r
}

// scenarioG: with the processor stopped, failClosed makes tools/list and
// tools/call fail through the gateway; after a restart on the same port they
// work again.
func scenarioG(t *testing.T, s *stack) {
	out := s.stopProcessor(t, "mock")
	mustContain(t, "processor stdout", out, "stats: lists served=")
	cs := s.connect(t, "mock")
	names, err := listNames(cs)
	if err == nil {
		t.Fatalf("tools/list succeeded with the processor down (failureMode failClosed): %v\n%s", names, s.logHints())
	}
	s.note(t, "G: processor down, tools/list -> %v", err)
	o := s.expectDenied(t, cs, "echo")
	s.note(t, "G: processor down, tools/call echo -> %s", o)

	t0 := time.Now()
	s.startProcessor(t, "mock", nil)
	cs = s.eventuallyServes(t, "mock", "add", "echo")
	s.note(t, "G: the route served again %s after the processor was restarted", since(t0))
	s.expectAllowed(t, cs, "echo", "hello")
}

// scenarioH: emit and serve share one value from the environment and
// everything works, which proves the gateway delivers metadata_context on both
// hooks (D8); a processor holding another value denies every hook and the
// gateway fails closed; the emitted file carries the metadata line and is
// 0600, as it is without a shared value too (decision D13: every emitted file
// is owner-only). The stack is returned to its unauthenticated state
// afterwards.
func scenarioH(t *testing.T, s *stack) {
	shared, other := randomToken(t), randomToken(t)
	env := []string{sharedEnvVar + "=" + shared}
	r := s.emit(t, env, "--secret-env", sharedEnvVar)
	mustContain(t, "emit --secret-env", r.stderr, "warning", "contains the processor secret", "0600")
	fi, err := os.Stat(s.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("file mode %04o, want 0600 for a file that carries the shared value", fi.Mode().Perm())
	}
	mustContain(t, "emitted config", string(s.config(t)), "metadata:", `toolwarrant_secret: "\"`+shared+`\""`)

	s.stopProcessor(t, "mock")
	s.startProcessor(t, "mock", env, "--secret-env", sharedEnvVar)
	cs := s.eventuallyServes(t, "mock", "add", "echo")
	s.expectAllowed(t, cs, "echo", "hello")
	s.note(t, "H: with the shared value in the gateway file and the processor environment, tools/list and tools/call work (metadata_context is delivered on both hooks)")

	s.stopProcessor(t, "mock")
	s.startProcessor(t, "mock", []string{sharedEnvVar + "=" + other}, "--secret-env", sharedEnvVar)
	cs = s.connect(t, "mock")
	names, err := listNames(cs)
	if err == nil && len(names) > 0 {
		t.Fatalf("tools served although the processor holds another shared value: %v\n%s", names, s.logHints())
	}
	s.note(t, "H: processor with another shared value, tools/list -> names %v, err %v", names, err)
	o := s.expectDenied(t, cs, "echo")
	mustContain(t, "denial with the wrong shared value", o.detail(), "secret")
	stats := s.stopProcessor(t, "mock")
	if n := statValue(t, stats, "unauthenticated"); n < 2 {
		t.Errorf("unauthenticated=%d, want at least 2 (one list, one call)", n)
	}

	s.startProcessor(t, "mock", nil)
	r = s.emit(t, nil)
	mustNotContain(t, "emit without a shared value", r.stderr, "secret")
	if fi, err = os.Stat(s.cfg); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("file mode %v (%v), want 0600 without a shared value too: emit writes every file owner-only (decision D13)", fi.Mode(), err)
	}
	cs = s.eventuallyServes(t, "mock", "add", "echo")
	s.expectAllowed(t, cs, "echo", "hello")
}

// scenarioI: the emitted file binds the serving port to 127.0.0.1 and the
// running gateway refuses connections on the host's non-loopback address; the
// admin, stats and readiness listeners on the ports the stack picked are not
// reachable there either.
func scenarioI(t *testing.T, s *stack) {
	mustContain(t, "emitted config", string(s.config(t)), `bindAddress: "127.0.0.1"`)
	ip := nonLoopbackIPv4()
	if ip == "" {
		t.Skip("no interface with a non-loopback IPv4 address on this host; cannot show that the gateway refuses it")
	}
	// A host firewall may drop rather than refuse, so each probe waits the
	// full refuseTimeout; the probes run together to keep that to one wait.
	ports := append([]int{s.gwPort}, s.listenerPorts()...)
	results := make([]error, len(ports))
	var wg sync.WaitGroup
	for i, port := range ports {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprint(port)), refuseTimeout)
			if err == nil {
				_ = conn.Close()
			}
			results[i] = err
		}()
	}
	wg.Wait()
	for i, port := range ports {
		addr := net.JoinHostPort(ip, fmt.Sprint(port))
		if results[i] == nil {
			t.Errorf("the gateway accepted a connection on %s; the emitted loopback bind was not honoured", addr)
			continue
		}
		s.note(t, "I: connection to %s not accepted: %v", addr, results[i])
	}
	if !portOpen(loopback(s.gwPort)) {
		t.Errorf("the gateway does not accept connections on loopback either")
	}
}

// nonLoopbackIPv4 returns an IPv4 address of this host that is not loopback
// and not link-local, preferring en0, or "" when there is none.
func nonLoopbackIPv4() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	sort.SliceStable(ifaces, func(i, j int) bool { return ifaces[i].Name == "en0" && ifaces[j].Name != "en0" })
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if ip := ipnet.IP.To4(); ip != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
				return ip.String()
			}
		}
	}
	return ""
}

// statValue reads one counter from the processor's stats line.
func statValue(t *testing.T, stats, key string) int {
	t.Helper()
	line := lastLineWith(stats, "stats:")
	_, after, ok := strings.Cut(line, key+"=")
	if !ok {
		t.Fatalf("no %s= in the stats line %q", key, line)
	}
	n := 0
	for _, c := range after {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// splitFields splits on spaces, dropping empty fields.
func splitFields(line string) []string { return strings.Fields(line) }
