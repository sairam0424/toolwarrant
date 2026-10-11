package emit

import (
	"bytes"
	"strings"
	"testing"
)

// unsetEnvName is looked up by the gateway when it appears raw in the file.
// It is unset in any environment this suite runs in and unique enough never
// to collide, so a raw occurrence must make the gateway refuse the file.
const unsetEnvName = "TOOLWARRANT_TEST_UNSET_ZQV7"

// mutateAll replaces every occurrence of old and fails the test if nothing
// changed, so a probe never silently validates the unmodified file.
func mutateAll(t *testing.T, yaml []byte, old, replacement string) []byte {
	t.Helper()
	out := bytes.ReplaceAll(yaml, []byte(old), []byte(replacement))
	if bytes.Equal(out, yaml) {
		t.Fatalf("test setup: %q not found in the output", old)
	}
	return out
}

// requireRejectedSaying is requireRejected plus a check on the gateway's own
// explanation, so the test proves which rule the gateway applied.
func requireRejectedSaying(t *testing.T, binary string, yaml []byte, what, saying string) {
	t.Helper()
	msg, err := validateWithGateway(t, binary, yaml)
	if err == nil || strings.Contains(msg, validOutputMarker) {
		t.Fatalf("gateway accepted %s:\n%.800s", what, msg)
	}
	if !strings.Contains(msg, saying) {
		t.Errorf("gateway rejected %s but not for the expected reason %q:\n%.800s", what, saying, msg)
	}
}

// TestGatewayRefusesNamesTheEmitterRefuses ports the review's finding: the
// real binary refuses an MCP target name with '_' or a leading or trailing
// '-', and the emitter now refuses the same names first. The golden's server
// name is replaced everywhere it occurs (route, path and target).
func TestGatewayRefusesNamesTheEmitterRefuses(t *testing.T) {
	binary := gatewayBinary(t)
	out := freshOutput(t)
	for _, name := range []string{"my_server", "a-", "-a", "ab_", "a-b_c"} {
		requireInvalid(t, Input{ListenPort: testListenPort, Servers: []Server{validServer(name)}})
		requireRejectedSaying(t, binary, mutateAll(t, out.YAML, "github", name), "server name "+name, "invalid MCP target name")
	}
}

// TestEmitterNameRuleIsStricterThanTheGateway: --validate-only accepts a dot
// and a 64-byte name, so those two refusals are the emitter's own rule, kept
// so that one alphabet serves the path, the processor's target check, file
// names and audit subjects.
func TestEmitterNameRuleIsStricterThanTheGateway(t *testing.T) {
	binary := gatewayBinary(t)
	out := freshOutput(t)
	for _, name := range []string{"a.b", strings.Repeat("z", 64)} {
		requireInvalid(t, Input{ListenPort: testListenPort, Servers: []Server{validServer(name)}})
		requireValid(t, binary, mutateAll(t, out.YAML, "github", name), "server name "+name)
	}
}

// TestEveryAcceptedNameShapeValidates runs each shape the emitter accepts
// through the real parser, so the positive side of the pin cannot drift.
func TestEveryAcceptedNameShapeValidates(t *testing.T) {
	binary := gatewayBinary(t)
	for _, name := range []string{"a", "0", "a-b", "a--b", "99", "a1b2", "x-9", strings.Repeat("z", 63), "toolwarrant", "default", "mcp"} {
		out, err := AgentGateway(Input{ListenPort: testListenPort, Servers: []Server{{Name: name, URL: testUpstreamURL, ProcessorAddr: testProcessorAddr, ApprovedTools: []string{"echo"}}}})
		if err != nil {
			t.Fatalf("%q: %v", name, err)
		}
		requireValid(t, binary, out.YAML, "server name "+name)
	}
}

// TestGatewayRefusesURLCharactersTheEmitterRefuses: the gateway's URI parser
// refuses a double quote, angle brackets and a space ("invalid uri
// character"); the emitter refuses them first. The replacement is the YAML
// scalar text quote would have written, so the gateway sees the raw
// character after decoding.
func TestGatewayRefusesURLCharactersTheEmitterRefuses(t *testing.T) {
	binary := gatewayBinary(t)
	out := freshOutput(t)
	for raw, escaped := range map[string]string{`"`: `\"`, "<": "<", ">": ">", " ": " "} {
		s := validServer("a")
		s.URL = testUpstreamURL + "?x=" + raw
		requireInvalid(t, Input{ListenPort: testListenPort, Servers: []Server{s}})
		broken := mutate(t, out.YAML, `host: "`+testUpstreamURL+`"`, `host: "`+testUpstreamURL+`?x=`+escaped+`"`)
		requireRejectedSaying(t, binary, broken, "a URL with "+strings.TrimSpace(raw)+" in the query", "invalid uri character")
	}
}

// TestEmitterURLRuleIsStricterThanTheGateway: --validate-only tolerates the
// printable characters RFC 3986 leaves out, so refusing them is the emitter's
// choice of a standard over a reading of one parser version.
func TestEmitterURLRuleIsStricterThanTheGateway(t *testing.T) {
	binary := gatewayBinary(t)
	out := freshOutput(t)
	for raw, escaped := range map[string]string{"|": "|", "^": "^", "{": "{", "}": "}", "`": "`", `\`: `\\`} {
		s := validServer("a")
		s.URL = testUpstreamURL + "?x=" + raw
		requireInvalid(t, Input{ListenPort: testListenPort, Servers: []Server{s}})
		requireValid(t, binary, mutate(t, out.YAML, `host: "`+testUpstreamURL+`"`, `host: "`+testUpstreamURL+`?x=`+escaped+`"`), "a URL with "+raw)
	}
}

// TestEveryAcceptedURLShapeValidates covers each delimiter class, the
// percent-encoded form, a bracketed IPv6 host and an escaped dollar sign.
func TestEveryAcceptedURLShapeValidates(t *testing.T) {
	binary := gatewayBinary(t)
	urls := []string{
		"http://127.0.0.1:3001/mcp?x=1&y=2", "http://h.example/p;q=1,2?x=a!b'c(d)*e+f=g", "http://[::1]:3001/mcp",
		"http://h.example/mcp?t=a%24b", "http://h.example/mcp?token=$" + unsetEnvName, "https://h.example/~user/mcp@v1", "http://h.example/mcp?x=a:b[0]",
	}
	for _, raw := range urls {
		s := validServer("a")
		s.URL = raw
		out, err := AgentGateway(Input{ListenPort: testListenPort, Servers: []Server{s}})
		if err != nil {
			t.Fatalf("%q: %v", raw, err)
		}
		requireValid(t, binary, out.YAML, "url "+raw)
	}
}

// TestGatewaySubstitutesEnvironmentIntoTheRawFile proves the hazard the
// dollar escape exists for: a raw $NAME or ${NAME} anywhere in the file, a
// value or a comment, makes the gateway look the name up in its environment
// and refuse the file when it is unset (a set name would silently replace the
// value). The header's "$schema" hint survives only because the gateway
// exempts that token, not because comments are skipped. The emitter's output
// for the same names validates and holds no dollar sign below the header.
func TestGatewaySubstitutesEnvironmentIntoTheRawFile(t *testing.T) {
	binary := gatewayBinary(t)
	out := freshOutput(t)
	const saying = "environment variable not found"
	requireRejectedSaying(t, binary, mutate(t, out.YAML, `== \"get_file\"`, `== \"$`+unsetEnvName+`\"`), "a raw $NAME in a tool name", saying)
	requireRejectedSaying(t, binary, mutate(t, out.YAML, `/mcp"`, `/mcp?t=${`+unsetEnvName+`}"`), "a raw ${NAME} in the upstream URL", saying)
	requireRejectedSaying(t, binary, mutate(t, out.YAML, "$schema=", "$"+unsetEnvName+"="), "a raw $NAME in a comment line", saying)

	escaped, err := AgentGateway(Input{ListenPort: testListenPort, Servers: []Server{{
		Name: "money", URL: testUpstreamURL + "?t=$" + unsetEnvName, ProcessorAddr: testProcessorAddr,
		Secret: dollarSecret() + unsetEnvName, ApprovedTools: []string{"$" + unsetEnvName, "${" + unsetEnvName + "}", "$$", "$1"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.IndexByte(escaped.YAML[len(generatedHeader):], '$') >= 0 {
		t.Fatalf("escaped output still carries a dollar sign:\n%s", escaped.YAML)
	}
	requireValid(t, binary, escaped.YAML, "the same names written through the emitter")
}

// TestGatewayReadsListenerPinsExactly: the off switch is case-sensitive and
// unpadded, an IPv6 listener needs brackets, and an empty address is not
// "default", so the exact forms the emitter writes are the ones that work.
// The unix-socket form validates too; it is refused by the emitter on purpose
// (see the package documentation), not because the gateway lacks it.
func TestGatewayReadsListenerPinsExactly(t *testing.T) {
	binary := gatewayBinary(t)
	out := freshOutput(t)
	for _, bad := range []string{`"OFF"`, `"Off"`, `"off "`, `"::1:15000"`, `""`, `"disabled"`} {
		requireRejected(t, binary, mutate(t, out.YAML, `adminAddr: "127.0.0.1:15000"`, "adminAddr: "+bad), "adminAddr "+bad)
	}
	for _, good := range []string{`"off"`, `"[::1]:15000"`, `"unix:/tmp/toolwarrant-admin.sock"`} {
		requireValid(t, binary, mutate(t, out.YAML, `adminAddr: "127.0.0.1:15000"`, "adminAddr: "+good), "adminAddr "+good)
	}
}
