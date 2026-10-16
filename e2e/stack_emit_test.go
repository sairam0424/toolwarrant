//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The emitted gateway file and the gateway's reload of it: the emit flags
// every emit of the stack shares, the reload markers the stack counts in the
// gateway's log, and the helpers that write the file, strip its guardrails,
// start the gateway on it and wait for the reload. Moved out of stack_test.go
// unchanged so that each file of the package stays under about 400 lines.

const (
	// reloadWait bounds how long the gateway may take to notice a changed
	// file; the spike measured under half a second.
	reloadWait = 20 * time.Second
	// loadedMarker and failedMarker are the gateway's log lines for a reload.
	loadedMarker = "loaded config from File"
	failedMarker = "Failed to reload config"
	// guardrailsKey is the policy block the processor lives in; the CEL-only
	// variants of scenarios F, K, L and M remove it.
	guardrailsKey    = "    mcpGuardrails:"
	guardrailsIndent = 4
	// bodyHashPrefix starts the line emit prints with the SHA-256 of the body
	// it wrote; the stack records the hash so scenario F can hand it back to
	// verify-gateway --expect-body-hash the way an operator would.
	bodyHashPrefix = "body sha256 "
	// hexDigestLen is the length of a SHA-256 digest in hex, the shape of
	// every digest the CLI prints and accepts.
	hexDigestLen = 64
)

// reloadMark is the gateway's reload counters at one moment.
type reloadMark struct{ loaded, failed int }

// emitBaseArgs are the emit flags every emit of the stack shares: the file,
// the serving port and the three listener addresses the stack picked, so the
// emitted file never pins the gateway's default listener ports.
func (s *stack) emitBaseArgs() []string {
	return []string{"emit", "--out", s.cfg, "--listen-port", strconv.Itoa(s.gwPort),
		"--admin-addr", s.adminAddr(), "--stats-addr", s.statsAddr(), "--readiness-addr", s.readinessAddr()}
}

// emit writes the gateway configuration for every registered server to the
// file the gateway watches, passing each server's processor address, and waits
// for the running gateway to report the reload. extra flags (--secret-env) are
// appended; env carries the secret for them.
func (s *stack) emit(t *testing.T, env []string, extra ...string) cliResult {
	t.Helper()
	args := s.emitBaseArgs()
	for _, name := range s.names {
		args = append(args, "--processor", name+"="+s.processorAddr(name))
	}
	return s.emitArgs(t, env, append(args, extra...))
}

// emitFromCatalog re-emits the watched file without any --processor flag, so
// every processor address must come from the catalog (decision D14 i), and
// waits for the reload.
func (s *stack) emitFromCatalog(t *testing.T) cliResult {
	t.Helper()
	return s.emitArgs(t, nil, s.emitBaseArgs())
}

// emitArgs runs one emit of the watched file with the given arguments,
// records the body hash it printed, checks that the file and the catalog pin
// every processor at the stack's address and waits for the gateway's reload.
func (s *stack) emitArgs(t *testing.T, env, args []string) cliResult {
	t.Helper()
	mark := s.mark()
	r := s.tw(t, env, args...)
	if r.code != exitOK {
		t.Fatalf("toolwarrant %v: exit %d\nstdout: %s\nstderr: %s", args, r.code, r.stdout, r.stderr)
	}
	s.bodyHash = lastField(lastLineWith(r.stdout, bodyHashPrefix))
	if len(s.bodyHash) != hexDigestLen {
		t.Fatalf("emit printed no %q line with a 64-hex digest:\n%s", bodyHashPrefix, r.stdout)
	}
	s.assertProcessorsPinned(t)
	s.awaitReload(t, mark)
	return r
}

// config reads the gateway file as it is on disk.
func (s *stack) config(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(s.cfg)
	if err != nil {
		t.Fatalf("read %s: %v", s.cfg, err)
	}
	return data
}

// writeConfig replaces the file in place, the way a hand edit would, and
// waits for the gateway to reload it.
func (s *stack) writeConfig(t *testing.T, data []byte) {
	t.Helper()
	mark := s.mark()
	if err := os.WriteFile(s.cfg, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", s.cfg, err)
	}
	s.awaitReload(t, mark)
}

// stripGuardrails removes every mcpGuardrails block from an emitted file,
// leaving the CEL allow rules alone: the variant the emitter's
// defence-in-depth claim is tested against.
func stripGuardrails(data []byte) []byte {
	var out []string
	skipping := false
	for _, line := range strings.Split(string(data), "\n") {
		if line == guardrailsKey {
			skipping = true
			continue
		}
		if skipping && strings.TrimSpace(line) != "" && len(line)-len(strings.TrimLeft(line, " ")) > guardrailsIndent {
			continue
		}
		skipping = false
		out = append(out, line)
	}
	return []byte(strings.Join(out, "\n"))
}

func (s *stack) mark() reloadMark {
	if s.gateway == nil {
		return reloadMark{}
	}
	return reloadMark{loaded: s.gatewayLogCount(loadedMarker), failed: s.gatewayLogCount(failedMarker)}
}

func (s *stack) gatewayLogCount(marker string) int {
	return countIn(s.gateway.stdout, marker) + countIn(s.gateway.stderr, marker)
}

// awaitReload waits for the gateway to log one more successful load than at
// the mark. A failed reload is reported with the gateway's own message; no
// reload at all within reloadWait is a failure too, because the operator loop
// ("run emit again and let the gateway reload the file") depends on it.
func (s *stack) awaitReload(t *testing.T, m reloadMark) {
	t.Helper()
	if s.gateway == nil || !s.gateway.running() {
		return
	}
	t0 := time.Now()
	var failed bool
	ok := pollUntil(reloadWait, func() bool {
		if s.gatewayLogCount(failedMarker) > m.failed {
			failed = true
			return true
		}
		return s.gatewayLogCount(loadedMarker) > m.loaded
	})
	switch {
	case failed:
		t.Fatalf("the gateway refused the configuration: %s", lastLineWith(s.gatewayLog(), failedMarker))
	case !ok:
		t.Fatalf("the gateway did not reload %s within %s\n%s", s.cfg, reloadWait, s.logHints())
	}
	t.Logf("gateway reloaded %s after %s", filepath.Base(s.cfg), since(t0))
}

func (s *stack) gatewayLog() string {
	return s.gateway.output(s.gateway.stdout) + s.gateway.output(s.gateway.stderr)
}

// startGateway runs the real agentgateway on the emitted file and waits for
// the serving port and the admin API. Every port is one the stack picked at
// run time, so a second gateway started from another emitted file on the same
// host cannot collide with this one.
func (s *stack) startGateway(t *testing.T) {
	t.Helper()
	p := s.spawn(t, "gateway", nil, s.h.gatewayBin, "-f", s.cfg)
	waitPort(t, p, loopback(s.gwPort))
	waitPort(t, p, s.adminAddr())
	s.gateway = p
}
