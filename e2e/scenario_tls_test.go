//go:build e2e

package e2e

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sairam0424/toolwarrant/internal/testcert"
)

const (
	// grpcLogEnv turns grpc-go's own log on for the processors scenario Q
	// starts, so that the processor's side of a refused handshake ("grpc:
	// Server.Serve failed to create ServerTransport: ... ServerHandshake(...)
	// failed: ...", which grpc-go logs at its info level and discards by
	// default) is on its stderr beside the processor's own lines. The
	// variable changes what grpc-go prints, nothing the processor decides.
	grpcLogEnv = "GRPC_GO_LOG_SEVERITY_LEVEL=info"
	// alpnRefusal is what grpc-go's server says when a TLS client selected no
	// application protocol: grpc-go v1.86 requires h2 (GRPC_ENFORCE_ALPN_ENABLED
	// defaults to true), so a listing served over the link shows the gateway's
	// client offered h2 and the block needs no alpn field.
	alpnRefusal = "missing selected ALPN property"
	// tlsBlockOpener starts the block emit writes under a processor entry, at
	// the indents the canary reads (cmd/toolwarrant/liveconsts.go).
	tlsBlockOpener = "        policies:\n          backendTLS:\n"
	// tlsServePlaceholders is the tail emit prints on the serve command of a
	// server whose entry carries the block.
	tlsServePlaceholders = "--tls-cert PROCESSOR_CERT --tls-key PROCESSOR_KEY --tls-client-ca GATEWAY_CA"
	// What serve prints on its listening line with the three flags, and the
	// start of the line itself.
	listeningPrefix  = "listening on"
	tlsListeningNote = "TLS 1.3 with a client certificate required"
	tlsAuthNote      = "hooks are authenticated by the client certificate"
	// insecureField is the backendTLS field scenario Q posts through the
	// admin API: it turns the gateway's verification of the processor's
	// certificate off, and the comparison must name it (D19 e).
	insecureField  = "insecure"
	insecureNaming = tlsBlockField + " field " + insecureField
	// tlsEmittedCopyName is the byte-identical copy of the emitted file with
	// the block that the canary steps compare against; tlsGarbageCopyName is
	// the copy with the garbage root the insecure step compares against, so
	// that the posted flag is the only difference the comparison can name.
	tlsEmittedCopyName = "gateway.emitted-tls.yaml"
	tlsGarbageCopyName = "gateway.emitted-tls-garbage.yaml"
	statsPrefix        = "stats:"
	// What the processor's stderr says when a handshake is refused, one line
	// per step, so a route that is dark for another reason cannot pass as the
	// stated refusal. The strings are grpc-go's and crypto/tls's, not the
	// pinned gateway's: a plaintext client dialling the TLS listener, a client
	// certificate from an authority the listener does not trust, the client's
	// alert when its root bundle does not sign the processor's certificate,
	// and a TLS ClientHello arriving at a plaintext listener.
	plaintextClientRefusal = "first record does not look like a TLS handshake"
	unknownClientCARefusal = "x509: certificate signed by unknown authority"
	unknownRootRefusal     = "remote error: tls: unknown certificate authority"
	tlsClientRefusal       = "received bogus greeting from client"
	// refusalLogWait bounds the wait for that line: grpc-go writes it from the
	// goroutine that refused the handshake, and the gateway's answer to the
	// client can arrive first.
	refusalLogWait = 5 * time.Second
)

// logMarks is where the processor's stderr and the gateway's two streams
// stood before one step, so the step can quote what each side logged.
type logMarks struct{ proc, gwOut, gwErr int }

// scenarioQ: TLS and client certificates on the processor link (D19, limit
// L11), the first observation of the handshake between agentgateway v1.6.0
// and a processor started with --tls-cert, --tls-key and --tls-client-ca.
// Before the block is emitted, the TLS processor behind the plaintext entry
// scenario H left makes the route fail closed (the first downgrade). Then
// emit --processor-tls puts the block on mock's entry, the gateway reloads
// and a new session lists and calls through the link: both sides' logs are
// recorded, and grpc-go's h2 ALPN requirement is met, since it would refuse
// the handshake otherwise. A processor requiring client certificates from an
// authority that did not sign the gateway's refuses it (the mTLS proof); a
// root bundle of garbage, which the pinned binary's --validate-only accepts,
// fails at the handshake; a plaintext processor behind the TLS entry fails
// closed (the second downgrade). verify-gateway --admin is healthy on the TLS
// entry and what GET /api/config renders for the block is recorded; with the
// garbage root back in the block a posted insecure: true makes the route
// serve, which shows the gateway skipped the verification of the processor's
// certificate, and is LIVE-CONFIG-MISMATCH naming the field; the document is
// restored; finally the stack returns to a plaintext processor and an entry
// without the block, which the next scenarios start from.
func scenarioQ(t *testing.T, s *stack) {
	lab := newTLSLab(t, s)
	scenarioQPlaintextEntry(t, s, lab)
	scenarioQHandshake(t, s, lab)
	scenarioQWrongClientCA(t, s, lab)
	scenarioQGarbageRoot(t, s, lab)
	scenarioQPlaintextProcessor(t, s, lab)
	scenarioQCanary(t, s, lab)
	scenarioQRestorePlaintext(t, s)
}

// restartProcessor stops mock's processor and starts it again with grpc-go's
// log on and the given serve flags; it returns the stats line the stopped
// one printed and the new one's listening line.
func (s *stack) restartProcessor(t *testing.T, name string, extra ...string) (stats, listening string) {
	t.Helper()
	stats = lastLineWith(s.stopProcessor(t, name), statsPrefix)
	p := s.startProcessor(t, name, []string{grpcLogEnv}, extra...)
	waitForOutput(t, p, listeningPrefix, 0)
	return stats, lastLineWith(p.output(p.stdout), listeningPrefix)
}

// markLogs records where the logs of one server's processor and of the
// gateway stand.
func (s *stack) markLogs(name string) logMarks {
	p := s.servers[name].processor
	return logMarks{proc: lineCount(p.stderr), gwOut: lineCount(s.gateway.stdout), gwErr: lineCount(s.gateway.stderr)}
}

// logsSince says what both sides logged after the marks: the processor's
// stderr (its own JSON lines and grpc-go's), then the gateway's two streams.
func (s *stack) logsSince(name string, m logMarks) string {
	p := s.servers[name].processor
	return fmt.Sprintf("the processor logged %s; the gateway logged %s on stdout and %s on stderr",
		describeAllNewLines(p.stderr, m.proc), describeAllNewLines(s.gateway.stdout, m.gwOut), describeAllNewLines(s.gateway.stderr, m.gwErr))
}

// expectDark opens a new session through mock's route and requires the link
// to fail closed: tools/list fails, tools/call echo is denied, and the
// processor's stderr since the marks names the refusal with reason. What each
// side answered is returned for the note.
func (s *stack) expectDark(t *testing.T, m logMarks, when, reason string) string {
	t.Helper()
	cs := s.connect(t, "mock")
	names, err := listNames(cs)
	if err == nil {
		t.Fatalf("%s, tools/list served %v instead of failing closed\n%s", when, names, s.logHints())
	}
	o := s.expectDenied(t, cs, "echo")
	s.expectProcessorLogged(t, m, when, reason)
	return fmt.Sprintf("tools/list -> %v; tools/call echo -> %s", err, o)
}

// expectProcessorLogged requires mock's processor to have logged reason on
// its stderr since the marks, within refusalLogWait.
func (s *stack) expectProcessorLogged(t *testing.T, m logMarks, when, reason string) {
	t.Helper()
	stderr := s.servers["mock"].processor.stderr
	pollUntil(refusalLogWait, func() bool {
		return strings.Contains(strings.Join(newLines(stderr, m.proc), "\n"), reason)
	})
	mustContain(t, when+": processor stderr since the mark", strings.Join(newLines(stderr, m.proc), "\n"), reason)
}

// copyConfig writes a byte-identical copy of the emitted file as it is on
// disk under the work directory, apart from the file the gateway watches and
// may rewrite, and returns the path and the bytes.
func (s *stack) copyConfig(t *testing.T, name string) (path string, data []byte) {
	t.Helper()
	data = s.config(t)
	path = filepath.Join(s.h.workdir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path, data
}

// expectServing requires mock's route to list add and echo again and echo to
// answer, after a restore.
func (s *stack) expectServing(t *testing.T) {
	t.Helper()
	s.expectAllowed(t, s.eventuallyServes(t, "mock", "add", "echo"), "echo", "hello")
}

// scenarioQPlaintextEntry: the first downgrade. mock's processor is restarted
// with the three flags while the emitted file still carries the plaintext
// entry scenario H left, so the gateway dials the TLS listener in plaintext;
// the processor's handshake must refuse it and the route fail closed.
func scenarioQPlaintextEntry(t *testing.T, s *stack, lab tlsLab) {
	mustNotContain(t, "emitted file before scenario Q", string(s.config(t)), tlsBlockField)
	_, listening := s.restartProcessor(t, "mock", lab.serveFlags(lab.clientCA)...)
	mustContain(t, "listening line", listening, tlsListeningNote, tlsAuthNote)
	s.note(t, "Q: the processor started with --tls-cert, --tls-key and --tls-client-ca printed: %s", strings.TrimSpace(listening))
	m := s.markLogs("mock")
	outcome := s.expectDark(t, m, "with the plaintext entry in the file and the processor terminating TLS", plaintextClientRefusal)
	s.note(t, "Q: plaintext entry, TLS processor: %s", outcome)
	s.note(t, "Q: during that, %s", s.logsSince("mock", m))
}

// scenarioQHandshake: emit --processor-tls puts the block on mock's entry, the
// gateway reloads, and a new session lists and calls through the TLS link,
// the first handshake. grpc-go refuses a TLS client that selected no ALPN
// protocol, so a served listing shows the gateway's client offered h2.
func scenarioQHandshake(t *testing.T, s *stack, lab tlsLab) {
	m := s.markLogs("mock")
	r := s.emit(t, nil, "--processor-tls", lab.spec(lab.root))
	mustContain(t, "emit --processor-tls stdout", r.stdout, "serve --server mock --target mock --listen "+s.processorAddr("mock")+" "+tlsServePlaceholders)
	cfg := string(s.config(t))
	mustContain(t, "emitted file", cfg, tlsBlockOpener, `            cert: "`+lab.gwCert+`"`, `            key: "`+lab.gwKey+`"`,
		`            root: "`+lab.root+`"`, `            hostname: "`+testcert.ServerName+`"`)
	if n := strings.Count(cfg, tlsBlockField); n != 1 {
		t.Errorf("%s appears %d time(s) in the emitted file, want 1:\n%s", tlsBlockField, n, cfg)
	}
	t0 := time.Now()
	cs := s.eventuallyServes(t, "mock", "add", "echo")
	o := s.expectAllowed(t, cs, "echo", "hello")
	s.note(t, "Q: with the block in the file and the processor terminating TLS, a new session listed add and echo %s after the reload and tools/call echo -> %s: the first handshake between agentgateway v1.6.0 and a processor started with the three flags", since(t0), o)
	s.note(t, "Q: during that, %s", s.logsSince("mock", m))
	proc := s.servers["mock"].processor
	mustNotContain(t, "processor stderr", proc.output(proc.stderr), alpnRefusal)
	s.note(t, "Q: grpc-go v1.86 refuses a TLS client that selected no ALPN protocol (%q); the processor's stderr has no such line and the listing served, so the gateway's client offered h2 and the block needs no alpn field", alpnRefusal)
	r = s.verifyGateway(t, "mock")
	if r.code != exitOK {
		t.Errorf("verify-gateway on the TLS entry: exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	mustContain(t, "verify-gateway on the TLS entry", r.stdout, "OK: the gateway serves 2 tool(s), 2 approved and current")
}

// scenarioQWrongClientCA: the mTLS proof. The processor is restarted
// requiring client certificates from an authority that did not sign the
// gateway's, so the gateway's certificate must be refused in the handshake
// and the route fail closed; the stats of the stopped TLS processor show the
// hooks it served over the link. The right authority restores service.
func scenarioQWrongClientCA(t *testing.T, s *stack, lab tlsLab) {
	stats, _ := s.restartProcessor(t, "mock", lab.serveFlags(lab.otherCA)...)
	s.note(t, "Q: the TLS processor that served the first handshake printed on SIGTERM: %s", stats)
	if n := statValue(t, stats, "lists served"); n == 0 {
		t.Errorf("the TLS processor counted no served list although the route listed through it")
	}
	m := s.markLogs("mock")
	outcome := s.expectDark(t, m, "with the processor requiring client certificates from an authority that did not sign the gateway's", unknownClientCARefusal)
	s.note(t, "Q: client certificate from another authority: %s", outcome)
	s.note(t, "Q: during that, %s", s.logsSince("mock", m))
	s.restartProcessor(t, "mock", lab.serveFlags(lab.clientCA)...)
	s.expectServing(t)
}

// scenarioQGarbageRoot: the block names a root bundle that holds no
// certificate. The pinned binary's --validate-only accepts it (emit
// TestGatewayValidateOnlyOpensBackendTLSFiles), so emit --gateway-binary
// writes the file and the gateway reloads it; the handshake must then refuse
// the processor's certificate and the route fail closed. A re-emit with the
// real root restores service.
func scenarioQGarbageRoot(t *testing.T, s *stack, lab tlsLab) {
	m := s.markLogs("mock")
	r := s.emit(t, nil, "--processor-tls", lab.spec(lab.garbageRoot), "--gateway-binary", s.h.gatewayBin)
	mustContain(t, "emit --gateway-binary with a garbage root", r.stdout, "validated with "+s.h.gatewayBin)
	mustContain(t, "emitted file", string(s.config(t)), `root: "`+lab.garbageRoot+`"`)
	outcome := s.expectDark(t, m, "with a root bundle of garbage, which --validate-only accepted and the gateway reloaded", unknownRootRefusal)
	s.note(t, "Q: root bundle of garbage (accepted by --validate-only, reloaded by the gateway): %s", outcome)
	s.note(t, "Q: during that, %s", s.logsSince("mock", m))
	s.emit(t, nil, "--processor-tls", lab.spec(lab.root))
	s.expectServing(t)
}

// scenarioQPlaintextProcessor: the second downgrade. The processor is
// restarted without the TLS flags while the file keeps the block, so the
// gateway offers TLS to a plaintext listener; the processor must refuse the
// connection and the route fail closed. The flags restore service.
func scenarioQPlaintextProcessor(t *testing.T, s *stack, lab tlsLab) {
	_, listening := s.restartProcessor(t, "mock")
	mustNotContain(t, "plaintext listening line", listening, "TLS")
	m := s.markLogs("mock")
	outcome := s.expectDark(t, m, "with the block in the file and a plaintext processor", tlsClientRefusal)
	s.note(t, "Q: TLS entry, plaintext processor: %s", outcome)
	s.note(t, "Q: during that, %s", s.logsSince("mock", m))
	s.restartProcessor(t, "mock", lab.serveFlags(lab.clientCA)...)
	s.expectServing(t)
}

// scenarioQCanary: the canary on the TLS entry. verify-gateway --admin must be
// healthy, which says the running gateway renders the block in GET /api/config
// as the emitted-file reader expects (D19 e); what it renders is recorded
// field by field without printing a value, and the answer is searched for a
// PEM private key, since a rendering that inlined the key would widen limit
// L18. Then the insecure step posts into the block through the admin API.
func scenarioQCanary(t *testing.T, s *stack, lab tlsLab) {
	s.expectLiveHealthy(t, "with the block in the emitted file and the gateway dialling the processor under TLS")
	copyPath, original := s.copyConfig(t, tlsEmittedCopyName)
	liveDoc := s.liveConfig(t)
	routes, err := routeCount(liveDoc)
	if err != nil {
		t.Fatalf("count the live routes: %v", err)
	}
	block, err := liveProcessorTLS(liveDoc, "mock")
	if err != nil {
		t.Fatalf("read mock's %s block in the live configuration: %v", tlsBlockField, err)
	}
	keys, fields := describeLiveTLS(block, lab.emittedValues())
	inlined := "does not hold"
	if bytes.Contains(liveDoc, []byte(privateKeyMarker)) {
		inlined = "HOLDS"
	}
	s.note(t, "Q: GET %s renders mock's processor policies.%s with the keys %v (%s); the %d-byte answer %s a PEM private key", adminConfigPath, tlsBlockField, keys, fields, len(liveDoc), inlined)
	scenarioQInsecure(t, s, lab, liveLab{original: original, copyPath: copyPath, doc: liveDoc, routes: routes})
}

// scenarioQInsecure: insecure: true posted into mock's backendTLS block
// through the unauthenticated admin API (limit L18), with the block naming
// the garbage root, so that what the flag does is observable: under that root
// the route has just failed closed, and under the flag it must serve, which
// shows the gateway skipped the verification of the processor's certificate.
// Against a byte-identical copy of the garbage-root file the check must be
// LIVE-CONFIG-MISMATCH naming the field, exit 1, and the original document
// (the real root, no flag) is posted back and proven healthy. The pinned
// binary accepts the post (D19 (8)); a gateway that refuses it fails the
// scenario, since the documents state the acceptance.
func scenarioQInsecure(t *testing.T, s *stack, lab tlsLab, live liveLab) {
	m := s.markLogs("mock")
	s.emit(t, nil, "--processor-tls", lab.spec(lab.garbageRoot))
	outcome := s.expectDark(t, m, "with the garbage root back in the block, before the "+insecureField+" flag", unknownRootRefusal)
	s.note(t, "Q: garbage root again, before %s: %s", insecureField, outcome)
	garbageCopy, _ := s.copyConfig(t, tlsGarbageCopyName)
	doc, err := withTLSField(s.liveConfig(t), "mock", insecureField, true)
	if err != nil {
		t.Fatalf("set %s in the live configuration: %v", insecureField, err)
	}
	m = s.markLogs("mock")
	if !s.tryReplaceLive(t, doc) {
		t.Fatalf("the gateway refused the document with %s: true in mock's %s block; the pinned binary accepts it (D19 (8))\n%s", insecureField, tlsBlockField, s.logHints())
	}
	if !s.awaitLiveTLSField(t, "mock", insecureField, true) {
		t.Fatalf("GET %s never rendered the posted %s field; the live comparison cannot see it", adminConfigPath, insecureField)
	}
	o := s.expectAllowed(t, s.eventuallyServes(t, "mock", "add", "echo"), "echo", "hello")
	s.note(t, "Q: with %s: true posted into mock's %s block whose root is the garbage bundle, a new session listed add and echo and tools/call echo -> %s: the gateway dialled the processor without verifying its certificate", insecureField, tlsBlockField, o)
	s.note(t, "Q: during that, %s", s.logsSince("mock", m))
	s.expectLiveMismatch(t, garbageCopy, "with "+insecureField+": true posted into mock's "+tlsBlockField+" block", insecureNaming)
	s.restoreLive(t, live, "after the "+insecureField+" flag")
}

// scenarioQRestorePlaintext returns the stack to the state the next scenarios
// start from: a plaintext processor without grpc-go's log and an entry without
// the block, healthy by the canary with and without --admin.
func scenarioQRestorePlaintext(t *testing.T, s *stack) {
	stats := lastLineWith(s.stopProcessor(t, "mock"), statsPrefix)
	s.note(t, "Q: the TLS processor printed on SIGTERM: %s", stats)
	s.startProcessor(t, "mock", nil)
	r := s.emit(t, nil)
	mustNotContain(t, "re-emitted file", string(s.config(t)), tlsBlockField)
	mustNotContain(t, "emit stdout without the flag", r.stdout, tlsServePlaceholders)
	s.expectServing(t)
	s.expectLiveHealthy(t, "after the restore to a plaintext processor and an entry without the block")
}
