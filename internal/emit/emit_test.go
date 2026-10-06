package emit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const updateGoldenEnv = "EMIT_UPDATE_GOLDEN"

const (
	testProcessorAddr = "127.0.0.1:9001"
	testUpstreamURL   = "http://127.0.0.1:3001/mcp"
	testListenPort    = 3000
	// fixtureMetadataValue is the shared-secret fixture: a throwaway test value
	// (not a credential) that holds both characters the two quoting layers must
	// escape. It is assembled from parts so secret scanners do not mistake it
	// for a real key.
	fixtureMetadataValue = "tw-0123456789abcdef" + `-"quoted"-back\slash`
	// headerLines is the number of comment lines before the body: the constant
	// header plus the hash line.
	headerLines = 4
	// secretLinePrefix is the indented metadata line the emitter writes.
	secretLinePrefix = "              " + SecretMetadataKey + ": "
)

// goldenCase is one named input with its expected skipped tools.
type goldenCase struct {
	name    string
	input   Input
	skipped []Skipped
}

// invalidReason builds the Reason the emitter reports for a name the shared
// rule refuses with the given explanation.
func invalidReason(detail string) string { return ReasonInvalidName + ": " + detail }

func goldenCases() []goldenCase {
	longName := strings.Repeat("a", MaxToolNameLen+1)
	midName := strings.Repeat("m", 200) // over the emitter's former cap of 128, within the shared rule
	return []goldenCase{
		{
			name: "one_server",
			input: Input{ListenPort: testListenPort, Servers: []Server{{
				Name: "github", URL: testUpstreamURL, ProcessorAddr: testProcessorAddr,
				ApprovedTools: []string{"search_repos", "create_issue", "get_file"},
			}}},
		},
		{
			name: "two_servers",
			input: Input{ListenPort: 8080, Servers: []Server{
				{
					Name: "weather", URL: "https://weather.example.com/mcp", ProcessorAddr: "127.0.0.1:9002",
					ApprovedTools: []string{"forecast", "alerts", "forecast"},
				},
				{
					Name: "github", URL: testUpstreamURL, ProcessorAddr: testProcessorAddr,
					ApprovedTools: []string{"get_file"},
				},
			}},
		},
		{
			name: "zero_approved",
			input: Input{ListenPort: testListenPort, Servers: []Server{
				{Name: "alpha", URL: testUpstreamURL, ProcessorAddr: testProcessorAddr},
				{Name: "beta", URL: "http://127.0.0.1:3002/mcp", ProcessorAddr: "127.0.0.1:9002", ApprovedTools: []string{}},
			}},
		},
		{
			name: "hostile_names",
			input: Input{ListenPort: testListenPort, Servers: []Server{{
				Name: "quotes", URL: testUpstreamURL, ProcessorAddr: testProcessorAddr,
				ApprovedTools: []string{
					`say "hi"`, `back\slash`, `\"`, `a\\"b`, `A`, `x || true`, `") || true || ("`, `it's`,
				},
			}}},
		},
		{
			name: "non_ascii",
			input: Input{ListenPort: testListenPort, Servers: []Server{{
				Name: "unicode", URL: testUpstreamURL, ProcessorAddr: testProcessorAddr,
				ApprovedTools: []string{
					"café", "emoji\U0001F600", "ctrl\x01", "ok_tool", "", "tab\there", longName,
				},
			}}},
			skipped: []Skipped{
				{Server: "unicode", Tool: "", Reason: ReasonEmptyName},
				{Server: "unicode", Tool: longName, Reason: ReasonNameTooLong},
				{Server: "unicode", Tool: "café", Reason: ReasonNotPrintableASCII},
				{Server: "unicode", Tool: "ctrl\x01", Reason: invalidReason("contains a control, invisible or non-printing character (U+0001)")},
				{Server: "unicode", Tool: "emoji\U0001F600", Reason: ReasonNotPrintableASCII},
				{Server: "unicode", Tool: "tab\there", Reason: invalidReason("contains a control, invisible or non-printing character (U+0009)")},
			},
		},
		{
			name: "shared_rule",
			input: Input{ListenPort: testListenPort, Servers: []Server{{
				Name: "rule", URL: testUpstreamURL, ProcessorAddr: testProcessorAddr,
				ApprovedTools: []string{
					"Tool Name", midName, "u\u0308ber", " lead", "trail ", "two  spaces", "zero\u200bwidth", "ok",
				},
			}}},
			skipped: []Skipped{
				{Server: "rule", Tool: " lead", Reason: invalidReason("leading or trailing space")},
				{Server: "rule", Tool: "trail ", Reason: invalidReason("leading or trailing space")},
				{Server: "rule", Tool: "two  spaces", Reason: invalidReason("consecutive spaces")},
				{Server: "rule", Tool: "u\u0308ber", Reason: invalidReason("not in Unicode normalization form C")},
				{Server: "rule", Tool: "zero\u200bwidth", Reason: invalidReason("contains a control, invisible or non-printing character (U+200B)")},
			},
		},
		{
			name: "with_secret",
			input: Input{ListenPort: testListenPort, Servers: []Server{{
				Name: "vault", URL: testUpstreamURL, ProcessorAddr: testProcessorAddr,
				Secret: fixtureMetadataValue, ApprovedTools: []string{"read_secret"},
			}}},
		},
	}
}

func TestGolden(t *testing.T) {
	for _, tc := range goldenCases() {
		t.Run(tc.name, func(t *testing.T) {
			out, err := AgentGateway(tc.input)
			if err != nil {
				t.Fatalf("AgentGateway: %v", err)
			}
			if !reflect.DeepEqual(out.Skipped, tc.skipped) {
				t.Errorf("Skipped mismatch\n got: %#v\nwant: %#v", out.Skipped, tc.skipped)
			}
			if got, ok := Verify(out.YAML); !ok || got != out.BodyHash {
				t.Errorf("fresh output does not verify: ok=%v hash=%q BodyHash=%q", ok, got, out.BodyHash)
			}
			path := filepath.Join("testdata", tc.name+".yaml")
			if os.Getenv(updateGoldenEnv) != "" {
				if err := os.WriteFile(path, out.YAML, 0o644); err != nil {
					t.Fatalf("update golden: %v", err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden (set %s=1 to create): %v", updateGoldenEnv, err)
			}
			if !bytes.Equal(out.YAML, want) {
				t.Errorf("output differs from %s\n--- got ---\n%s\n--- want ---\n%s", path, out.YAML, want)
			}
		})
	}
}

// TestZeroApprovedNeverEmptyRuleList pins the allow-rule invariant: with
// nothing approved the file holds an explicit, never-matching allow rule.
func TestZeroApprovedNeverEmptyRuleList(t *testing.T) {
	out, err := AgentGateway(goldenCases()[2].input)
	if err != nil {
		t.Fatal(err)
	}
	yaml := string(out.YAML)
	if got := strings.Count(yaml, "- allow: \"false\"\n"); got != 2 {
		t.Errorf("want 2 never-matching allow rules, got %d\n%s", got, yaml)
	}
	if strings.Contains(yaml, "rules: []") || strings.Contains(yaml, "deny:") || strings.Contains(yaml, "mcp.tool.name") {
		t.Errorf("unexpected rule shape in zero-approval output:\n%s", yaml)
	}
}

func TestHeaderSaysGeneratedAndRecordsHash(t *testing.T) {
	out, err := AgentGateway(goldenCases()[0].input)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitN(string(out.YAML), "\n", headerLines+1)
	if !strings.HasPrefix(lines[0], "# ") || !strings.Contains(lines[0], "Do not edit by hand") {
		t.Errorf("first line is not the generated-file warning: %q", lines[0])
	}
	if want := hashLinePrefix + out.BodyHash; lines[headerLines-1] != want {
		t.Errorf("line %d = %q, want %q", headerLines, lines[headerLines-1], want)
	}
	for _, l := range lines[:headerLines] {
		if !strings.HasPrefix(l, "# ") {
			t.Errorf("header line is not a comment: %q", l)
		}
	}
}

// TestConfigPinsAdminListenersToLoopback: left unset, the gateway binds stats
// and readiness on every interface.
func TestConfigPinsAdminListenersToLoopback(t *testing.T) {
	out, err := AgentGateway(goldenCases()[0].input)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.SplitN(string(out.YAML), "\n", headerLines+1)[headerLines]
	want := "config:\n" +
		"  adminAddr: \"127.0.0.1:15000\"\n" +
		"  statsAddr: \"127.0.0.1:15020\"\n" +
		"  readinessAddr: \"127.0.0.1:15021\"\n" +
		"binds:\n"
	if !strings.HasPrefix(body, want) {
		t.Errorf("body does not start with the loopback config block:\n%s", body)
	}
	if strings.Count(string(out.YAML), "Addr: ") != 3 {
		t.Errorf("want exactly three listener addresses:\n%s", out.YAML)
	}
}

// TestSecretWrittenAsCELStringLiteral checks the two quoting layers: a YAML
// double-quoted scalar whose value is a CEL string literal of the secret.
func TestSecretWrittenAsCELStringLiteral(t *testing.T) {
	out, err := AgentGateway(goldenCases()[6].input)
	if err != nil {
		t.Fatal(err)
	}
	wantLine := secretLinePrefix + `"\"tw-0123456789abcdef-\\\"quoted\\\"-back\\\\slash\""`
	var found []string
	for _, line := range strings.Split(string(out.YAML), "\n") {
		if strings.HasPrefix(line, secretLinePrefix) {
			found = append(found, line)
		}
	}
	if len(found) != 1 || found[0] != wantLine {
		t.Fatalf("secret lines = %q, want exactly %q", found, wantLine)
	}
	var cel string
	if err := json.Unmarshal([]byte(strings.TrimPrefix(found[0], secretLinePrefix)), &cel); err != nil {
		t.Fatalf("YAML scalar does not decode: %v", err)
	}
	secret, rest, err := readCELString(strings.TrimPrefix(cel, `"`))
	if err != nil || rest != "" || secret != fixtureMetadataValue {
		t.Errorf("CEL literal decodes to %q (rest %q, err %v), want %q", secret, rest, err, fixtureMetadataValue)
	}
	if !strings.Contains(string(out.YAML), "            metadata:\n"+wantLine+"\n            methods:\n") {
		t.Errorf("metadata block is not under the processor entry:\n%s", out.YAML)
	}
}

func TestNoSecretMeansNoMetadata(t *testing.T) {
	out, err := AgentGateway(goldenCases()[0].input)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out.YAML), "metadata") || strings.Contains(string(out.YAML), SecretMetadataKey) {
		t.Errorf("output without a secret mentions metadata:\n%s", out.YAML)
	}
}

// TestRaisedNameCapIsEmitted: a 200-byte name used to be skipped silently.
func TestRaisedNameCapIsEmitted(t *testing.T) {
	out, err := AgentGateway(goldenCases()[5].input)
	if err != nil {
		t.Fatal(err)
	}
	mid := strings.Repeat("m", 200)
	if !strings.Contains(string(out.YAML), `mcp.tool.name == \"`+mid+`\"`) {
		t.Errorf("200-byte name missing from the allow rule:\n%s", out.YAML)
	}
	if !strings.Contains(string(out.YAML), `mcp.tool.name == \"Tool Name\"`) {
		t.Errorf("name with an interior space missing from the allow rule:\n%s", out.YAML)
	}
}

func TestDeterministic(t *testing.T) {
	for _, tc := range goldenCases() {
		a, errA := AgentGateway(tc.input)
		b, errB := AgentGateway(tc.input)
		if errA != nil || errB != nil {
			t.Fatalf("%s: errors %v %v", tc.name, errA, errB)
		}
		if !bytes.Equal(a.YAML, b.YAML) || a.BodyHash != b.BodyHash || !reflect.DeepEqual(a.Skipped, b.Skipped) {
			t.Errorf("%s: two calls differ", tc.name)
		}
	}
}

func TestInputOrderDoesNotMatter(t *testing.T) {
	base := Input{ListenPort: testListenPort, Servers: []Server{
		{Name: "b", URL: testUpstreamURL, ProcessorAddr: testProcessorAddr, ApprovedTools: []string{"z", "a", "m", "a"}},
		{Name: "a", URL: "http://x.example/mcp", ProcessorAddr: "h.example:1", Secret: fixtureMetadataValue, ApprovedTools: []string{"q", "café", "p"}},
		{Name: "c", URL: testUpstreamURL, ProcessorAddr: "127.0.0.1:9003"},
	}}
	want, err := AgentGateway(base)
	if err != nil {
		t.Fatal(err)
	}
	shuffled := Input{ListenPort: base.ListenPort, Servers: []Server{
		{Name: "c", URL: testUpstreamURL, ProcessorAddr: "127.0.0.1:9003"},
		{Name: "a", URL: "http://x.example/mcp", ProcessorAddr: "h.example:1", Secret: fixtureMetadataValue, ApprovedTools: []string{"p", "café", "q"}},
		{Name: "b", URL: testUpstreamURL, ProcessorAddr: testProcessorAddr, ApprovedTools: []string{"m", "a", "z", "a"}},
	}}
	got, err := AgentGateway(shuffled)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.YAML, want.YAML) || got.BodyHash != want.BodyHash || !reflect.DeepEqual(got.Skipped, want.Skipped) {
		t.Errorf("reordered input changed the output\n--- got ---\n%s\n--- want ---\n%s", got.YAML, want.YAML)
	}
}

func TestInputNotMutated(t *testing.T) {
	in := Input{ListenPort: testListenPort, Servers: []Server{
		{Name: "b", URL: testUpstreamURL, ProcessorAddr: testProcessorAddr, Secret: fixtureMetadataValue, ApprovedTools: []string{"z", "a", "a"}},
		{Name: "a", URL: testUpstreamURL, ProcessorAddr: "127.0.0.1:9002", ApprovedTools: []string{"y", "x"}},
	}}
	before := Input{ListenPort: in.ListenPort, Servers: []Server{
		{Name: "b", URL: testUpstreamURL, ProcessorAddr: testProcessorAddr, Secret: fixtureMetadataValue, ApprovedTools: []string{"z", "a", "a"}},
		{Name: "a", URL: testUpstreamURL, ProcessorAddr: "127.0.0.1:9002", ApprovedTools: []string{"y", "x"}},
	}}
	if _, err := AgentGateway(in); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, before) {
		t.Errorf("AgentGateway modified its input: %#v", in)
	}
}

func TestToolsSortedAndDeduplicated(t *testing.T) {
	out, err := AgentGateway(Input{ListenPort: testListenPort, Servers: []Server{{
		Name: "s", URL: testUpstreamURL, ProcessorAddr: testProcessorAddr,
		ApprovedTools: []string{"b", "a", "b", "a"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	want := `- allow: "mcp.tool.name == \"a\" || mcp.tool.name == \"b\""` + "\n"
	if !strings.Contains(string(out.YAML), want) {
		t.Errorf("allow rule not sorted/deduplicated:\n%s", out.YAML)
	}
}
