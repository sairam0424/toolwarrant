//go:build e2e

package e2e

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
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
// compares the whole document with the file named by --config (decisions D13
// and D14). The check is healthy first, and what GET /api/config renders is
// recorded: its top-level sections and whether mock's processor entry carries
// the requestHeaders filter the emitter writes. Then the running configuration
// is replaced through the unauthenticated admin API (POST /api/config, limit
// L18), the way a local user of the gateway host could: with the gateway's
// own document minus every mcpGuardrails policy, with the original document
// plus one route on another path without a rule or a processor, with mock's
// route parked on another path while a route under another name owns mock's
// client path with the allow rule copied and no processor (the shadow route
// of finding cli-docs-1 of the third review), with the requestHeaders filter
// removed from mock's processor entry (findings cli-docs-4 and
// processor-emit-7), with a top-level binds section carrying a listener on
// another port and a processor-less allow-all route to the upstream (finding
// cli-docs-1 of the fourth review), with a requestMirror policy added to
// mock's route and with a second backend next to its mcp backend (finding
// cli-docs-1 of the fifth review; what the running gateway does with each is
// recorded against a mirror target the scenario runs) and, if the gateway
// accepts it, with a top-level mcp shortcut. Against a byte-identical copy of
// the file emit wrote every replacement is LIVE-CONFIG-MISMATCH, exit 1,
// naming what the file does not carry. The original document is posted back
// after each step, the emitted bytes are put back on disk if the gateway
// rewrote them, and the check is healthy again, so later scenarios start from
// the emitted state.
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
	s.noteLiveShape(t, liveDoc)
	s.noteAdminAPIShape(t, original)
	lab := liveLab{original: original, copyPath: emittedCopy, doc: liveDoc, routes: routes}
	scenarioPNoProcessor(t, s, lab)
	scenarioPExtraRoute(t, s, lab)
	scenarioPShadowRoute(t, s, lab)
	scenarioPHeaderFilter(t, s, lab)
	scenarioPRouteExtras(t, s, lab)
	scenarioPBinds(t, s, lab)
	scenarioPMcp(t, s, lab)
	s.eventuallyServes(t, "mock", "add", "echo")
}

// noteLiveShape records what GET /api/config renders in the healthy state:
// the top-level sections and whether the request-header filter of mock's
// processor is among the fields, since cmd/toolwarrant/testdata/admin_config.json
// was recorded before the emitter wrote the filter. The note carries the
// letter of the running scenario (noteHere); P is its only caller, Q records
// the backendTLS block itself through describeLiveTLS.
func (s *stack) noteLiveShape(t *testing.T, doc []byte) {
	t.Helper()
	sections, err := liveSections(doc)
	if err != nil {
		t.Fatalf("read the live configuration: %v", err)
	}
	has, err := liveProcessorHasHeaderFilter(doc, "mock")
	if err != nil {
		t.Fatalf("read mock's processor in the live configuration: %v", err)
	}
	s.noteHere(t, "GET %s renders the top-level sections %v; mock's processor entry carries the %s filter: %v", adminConfigPath, sections, headerFilterField, has)
}

// noteAdminAPIShape records the two facts about the admin API that item 10 of
// the re-qualification checklist (scripts/requalify-gateway.sh, L7) reads
// beside the live shape: a POST whose body is not JSON is refused (agentgateway
// v1.6.0 answers 415 to the emitted YAML), and GET /config_dump answers
// without any authentication (limit L18). Only statuses and sizes are noted,
// because the dump carries every processor secret in clear.
func (s *stack) noteAdminAPIShape(t *testing.T, emitted []byte) {
	t.Helper()
	status, body := s.adminRequest(t, http.MethodPost, adminConfigPath, emitted, mediaYAML)
	s.note(t, "P: POST %s with Content-Type %s -> status %d, %d-byte answer", adminConfigPath, mediaYAML, status, len(body))
	status, body = s.adminRequest(t, http.MethodGet, adminDumpPath, nil, "")
	s.note(t, "P: GET %s -> status %d, %d-byte answer", adminDumpPath, status, len(body))
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
// with no allow rule and no processor (finding processor-emit-2 of the third
// review). mock's own route is untouched, so a comparison of that route alone
// passed; the whole-document comparison names the route the file does not
// carry.
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
// path with the allow rule copied and no processor (finding cli-docs-1 of the
// third review). A new session on the client path still lists exactly the
// approved names, because the allow rule hides the rest, so only the live
// comparison can show that the path is served without the processor.
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
	s.noteHere(t, "%s, verify-gateway --admin printed: %s", when, strings.TrimSpace(r.stdout))
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
	s.noteHere(t, "%s, with --config naming a byte-identical copy of the file emit wrote, verify-gateway --admin printed: %s", when, strings.TrimSpace(r.stdout))
}

// restoreLive posts the original document back, waits until the gateway
// reports that document again (routes, processors, filters and sections
// alike), puts the emitted bytes back on disk if the gateway rewrote them and
// proves a healthy check.
func (s *stack) restoreLive(t *testing.T, lab liveLab, when string) {
	t.Helper()
	s.replaceLive(t, lab.doc)
	s.awaitLiveDocument(t, lab.doc)
	if !bytes.Equal(s.config(t), lab.original) {
		s.writeConfig(t, lab.original)
	}
	s.awaitRouteListing(t, "mock", lab.copyPath)
	s.expectLiveHealthy(t, when+", with the original document posted back")
}

const (
	// routeRebuildWait bounds how long a restore waits for the route to serve
	// the canary's own listing again; routeRebuildPoll is the interval.
	routeRebuildWait = 15 * time.Second
	routeRebuildPoll = 250 * time.Millisecond
)

// awaitRouteListing waits until the canary's own listing through the route
// succeeds again after a configuration change: the gateway rebuilds a route a
// moment after the admin API reports the new document (sixth round, observed
// after a posted requestMirror policy was removed). A route that never serves
// again within routeRebuildWait fails the scenario with the canary's output.
func (s *stack) awaitRouteListing(t *testing.T, server, config string) {
	t.Helper()
	deadline := time.Now().Add(routeRebuildWait)
	for attempt := 1; ; attempt++ {
		r := s.tw(t, nil, s.canaryArgs(server, false, config)...)
		if r.code == exitOK {
			if attempt > 1 {
				s.noteHere(t, "the route served the canary's listing again on attempt %d", attempt)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the route never served the canary's listing again within %s after the restore: exit %d\nstdout: %s\nstderr: %s", routeRebuildWait, r.code, r.stdout, r.stderr)
		}
		time.Sleep(routeRebuildPoll)
	}
}

// replaceLive replaces the running configuration through the admin API and
// records the gateway's answer. A gateway that refuses the post fails the
// scenario with the status and the start of the answer.
func (s *stack) replaceLive(t *testing.T, doc []byte) {
	t.Helper()
	if !s.tryReplaceLive(t, doc) {
		t.Fatalf("the gateway refused the posted document; see the note above")
	}
}

// tryReplaceLive posts a document to the admin API and reports whether the
// gateway accepted it, recording the status and the size of the answer either
// way; the answer may hold the processor secret, so it is never printed.
func (s *stack) tryReplaceLive(t *testing.T, doc []byte) bool {
	t.Helper()
	status, body := s.postLiveConfig(t, doc)
	s.noteHere(t, "POST %s with %d bytes of JSON -> status %d, %d-byte answer", adminConfigPath, len(doc), status, len(body))
	return status/100 == 2
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
