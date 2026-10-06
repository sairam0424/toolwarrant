package emit

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	gatewayBinaryEnv  = "TOOLWARRANT_AGENTGATEWAY"
	validateTimeout   = 60 * time.Second
	validOutputMarker = "Configuration is valid"
)

// gatewayBinary locates the real agentgateway binary, or skips the test
// loudly: a skipped validation means the YAML shape was NOT checked against
// the real parser in this run.
func gatewayBinary(t *testing.T) string {
	t.Helper()
	path := os.Getenv(gatewayBinaryEnv)
	if path == "" {
		path = filepath.Join("..", "..", ".cache", "agentgateway-darwin-arm64")
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("SKIPPED, NOT VALIDATED AGAINST THE REAL GATEWAY: agentgateway binary not found at %s (set %s): %v", path, gatewayBinaryEnv, err)
	}
	return path
}

// validateWithGateway runs `agentgateway -f file --validate-only` on a copy of
// yaml under a temp dir. It never starts the gateway as a server, so it proves
// syntax and schema only; see testdata/README.md for what it cannot prove.
func validateWithGateway(t *testing.T, binary string, yaml []byte) (string, error) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "gateway.yaml")
	if err := os.WriteFile(file, yaml, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), validateTimeout)
	defer cancel()
	var buf bytes.Buffer
	cmd := exec.CommandContext(ctx, binary, "-f", file, "--validate-only")
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	return buf.String(), err
}

// requireValid fails unless the real gateway accepts yaml.
func requireValid(t *testing.T, binary string, yaml []byte, what string) {
	t.Helper()
	if msg, err := validateWithGateway(t, binary, yaml); err != nil || !strings.Contains(msg, validOutputMarker) {
		t.Fatalf("gateway rejected %s: %v\n%.800s", what, err, msg)
	}
}

// requireRejected fails if the real gateway accepts yaml: it is how a
// validation test proves it is not vacuous.
func requireRejected(t *testing.T, binary string, yaml []byte, what string) {
	t.Helper()
	if msg, err := validateWithGateway(t, binary, yaml); err == nil || strings.Contains(msg, validOutputMarker) {
		t.Fatalf("gateway accepted %s:\n%.800s", what, msg)
	}
}

// mutate replaces old with new once and fails the test if nothing changed, so
// a probe never silently validates the unmodified file.
func mutate(t *testing.T, yaml []byte, old, replacement string) []byte {
	t.Helper()
	out := bytes.Replace(yaml, []byte(old), []byte(replacement), 1)
	if bytes.Equal(out, yaml) {
		t.Fatalf("test setup: %q not found in the output", old)
	}
	return out
}

func TestGoldenFilesValidateWithRealGateway(t *testing.T) {
	binary := gatewayBinary(t)
	files, err := filepath.Glob(filepath.Join("testdata", "*.yaml"))
	if err != nil || len(files) < len(goldenCases()) {
		t.Fatalf("want at least %d golden files, got %v (%v)", len(goldenCases()), files, err)
	}
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			requireValid(t, binary, data, file)
		})
	}
}

// TestGatewayValidationIsNotVacuous proves the check above can fail: a rule
// with broken CEL syntax must be rejected by the same binary.
func TestGatewayValidationIsNotVacuous(t *testing.T) {
	binary := gatewayBinary(t)
	out, err := AgentGateway(goldenCases()[0].input)
	if err != nil {
		t.Fatal(err)
	}
	broken := mutate(t, out.YAML, `== \"get_file\"`, `== \"get_file\" ||`)
	requireRejected(t, binary, broken, "a config with a CEL syntax error")
}

// TestGatewayParsesListenerAddresses proves the loopback config block is read,
// not ignored: the binary that accepts every golden file refuses a listener
// address it cannot parse, so a typo in the pin would fail the golden check.
func TestGatewayParsesListenerAddresses(t *testing.T) {
	binary := gatewayBinary(t)
	out, err := AgentGateway(goldenCases()[0].input)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`"nonsense"`, `"127.0.0.1:99999"`, `"http://127.0.0.1:15020"`} {
		broken := mutate(t, out.YAML, `statsAddr: "127.0.0.1:15020"`, "statsAddr: "+bad)
		requireRejected(t, binary, broken, "statsAddr "+bad)
	}
}

// allPrintable is every printable ASCII character with the space in the
// interior, so the shared rule's no-leading-or-trailing-space check passes.
func allPrintable() string {
	var all strings.Builder
	all.WriteByte('x')
	for c := byte(firstPrintable); c <= lastPrintable; c++ {
		all.WriteByte(c)
	}
	all.WriteByte('x')
	return all.String()
}

// TestHostileToolNamesAreValidCEL feeds every printable ASCII character, in
// several hostile combinations, through the emitter and the real CEL parser.
func TestHostileToolNamesAreValidCEL(t *testing.T) {
	binary := gatewayBinary(t)
	names := []string{
		allPrintable(), `\`, `"`, `\"`, `"\`, `\\"`, `A`, `\U0001F600`, `\n`, `") || true || ("`, `'`, `a\`, strings.Repeat(`\"`, 60),
	}
	out, err := AgentGateway(Input{ListenPort: testListenPort, Servers: []Server{{
		Name: "hostile", URL: testUpstreamURL, ProcessorAddr: testProcessorAddr, ApprovedTools: names,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Skipped) != 0 {
		t.Fatalf("unexpected skips: %v", out.Skipped)
	}
	requireValid(t, binary, out.YAML, "hostile-name config")
}

// TestHostileSecretsAreValidCEL runs the same hostile alphabet through the
// metadata literal, one server per secret so each is parsed on its own.
func TestHostileSecretsAreValidCEL(t *testing.T) {
	binary := gatewayBinary(t)
	secrets := []string{
		allPrintable(), strings.Repeat(`"\`, 20), strings.Repeat(`\`, MinSecretLen), strings.Repeat(`"`, MinSecretLen),
		`' || true || '-padding-0123`, `") || true || ("-padding-01`, strings.Repeat("\\u0041", 8), strings.Repeat("x", MaxSecretLen),
	}
	servers := make([]Server, len(secrets))
	for i, secret := range secrets {
		servers[i] = Server{
			Name: "s" + strconv.Itoa(i), URL: testUpstreamURL, ProcessorAddr: "127.0.0.1:" + strconv.Itoa(9000+i),
			Secret: secret, ApprovedTools: []string{"echo"},
		}
	}
	out, err := AgentGateway(Input{ListenPort: testListenPort, Servers: servers})
	if err != nil {
		t.Fatal(err)
	}
	requireValid(t, binary, out.YAML, "hostile-secret config")
}

// TestGatewayRejectsBrokenSecretLiteral proves the metadata value is parsed
// as CEL by the gateway: an unterminated string literal must be refused, so
// a quoting bug in the secret line would not pass the golden validation.
func TestGatewayRejectsBrokenSecretLiteral(t *testing.T) {
	binary := gatewayBinary(t)
	out, err := AgentGateway(goldenCases()[6].input)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(out.YAML), "\n")
	replaced := false
	for i, line := range lines {
		if strings.HasPrefix(line, secretLinePrefix) {
			lines[i] = secretLinePrefix + `"\"unterminated"`
			replaced = true
		}
	}
	if !replaced {
		t.Fatal("test setup: secret line not found")
	}
	requireRejected(t, binary, []byte(strings.Join(lines, "\n")), "an unterminated CEL literal in metadata")
}

// TestLargeToolSetValidates guards against a parser depth limit on the
// disjunction: a server can legitimately expose hundreds of tools.
func TestLargeToolSetValidates(t *testing.T) {
	binary := gatewayBinary(t)
	const toolCount = 2000
	tools := make([]string, toolCount)
	for i := range tools {
		tools[i] = "tool_" + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + strings.Repeat("y", i/26)
	}
	out, err := AgentGateway(Input{ListenPort: testListenPort, Servers: []Server{{
		Name: "big", URL: testUpstreamURL, ProcessorAddr: testProcessorAddr, ApprovedTools: tools,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	requireValid(t, binary, out.YAML, "large config")
}
