package emit

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	gatewayBinaryEnv     = "TOOLWARRANT_AGENTGATEWAY"
	validateTimeout      = 60 * time.Second
	validOutputMarker    = "Configuration is valid"
	minExpectedGoldenNum = 5
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
// yaml under a temp dir. It never starts the gateway as a server.
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

func TestGoldenFilesValidateWithRealGateway(t *testing.T) {
	binary := gatewayBinary(t)
	files, err := filepath.Glob(filepath.Join("testdata", "*.yaml"))
	if err != nil || len(files) < minExpectedGoldenNum {
		t.Fatalf("want at least %d golden files, got %v (%v)", minExpectedGoldenNum, files, err)
	}
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			out, err := validateWithGateway(t, binary, data)
			if err != nil || !strings.Contains(out, validOutputMarker) {
				t.Fatalf("gateway rejected %s: %v\n%s", file, err, out)
			}
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
	broken := bytes.Replace(out.YAML, []byte(`== \"get_file\"`), []byte(`== \"get_file\" ||`), 1)
	if bytes.Equal(broken, out.YAML) {
		t.Fatal("test setup: replacement did not apply")
	}
	if msg, err := validateWithGateway(t, binary, broken); err == nil {
		t.Fatalf("gateway accepted a config with a CEL syntax error:\n%s", msg)
	}
}

// TestHostileToolNamesAreValidCEL feeds every printable ASCII character, in
// several hostile combinations, through the emitter and the real CEL parser.
func TestHostileToolNamesAreValidCEL(t *testing.T) {
	binary := gatewayBinary(t)
	var all strings.Builder
	for c := byte(firstPrintable); c <= lastPrintable; c++ {
		all.WriteByte(c)
	}
	names := []string{
		all.String(), `\`, `"`, `\"`, `"\`, `\\"`, `A`, `\U0001F600`, `\n`, `") || true || ("`, `'`, `a\`, strings.Repeat(`\"`, 60),
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
	if msg, err := validateWithGateway(t, binary, out.YAML); err != nil || !strings.Contains(msg, validOutputMarker) {
		t.Fatalf("gateway rejected hostile-name config: %v\n%s", err, msg)
	}
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
	if msg, err := validateWithGateway(t, binary, out.YAML); err != nil || !strings.Contains(msg, validOutputMarker) {
		t.Fatalf("gateway rejected large config: %v\n%.500s", err, msg)
	}
}
