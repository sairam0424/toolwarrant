package emit

import (
	"bytes"
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
)

// goldenCase is one named input with its expected skipped tools.
type goldenCase struct {
	name    string
	input   Input
	skipped []Skipped
}

func goldenCases() []goldenCase {
	longName := strings.Repeat("a", MaxToolNameLen+1)
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
				{Server: "unicode", Tool: "ctrl\x01", Reason: ReasonNotPrintableASCII},
				{Server: "unicode", Tool: "emoji\U0001F600", Reason: ReasonNotPrintableASCII},
				{Server: "unicode", Tool: "tab\there", Reason: ReasonNotPrintableASCII},
			},
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

// TestZeroApprovedNeverEmptyRuleList pins the central safety property: with
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

func TestHeaderSaysGenerated(t *testing.T) {
	out, err := AgentGateway(goldenCases()[0].input)
	if err != nil {
		t.Fatal(err)
	}
	first := strings.SplitN(string(out.YAML), "\n", 2)[0]
	if !strings.HasPrefix(first, "# ") || !strings.Contains(first, "Do not edit by hand") {
		t.Errorf("first line is not the generated-file warning: %q", first)
	}
}

func TestDeterministic(t *testing.T) {
	for _, tc := range goldenCases() {
		a, errA := AgentGateway(tc.input)
		b, errB := AgentGateway(tc.input)
		if errA != nil || errB != nil {
			t.Fatalf("%s: errors %v %v", tc.name, errA, errB)
		}
		if !bytes.Equal(a.YAML, b.YAML) || !reflect.DeepEqual(a.Skipped, b.Skipped) {
			t.Errorf("%s: two calls differ", tc.name)
		}
	}
}

func TestInputOrderDoesNotMatter(t *testing.T) {
	base := Input{ListenPort: testListenPort, Servers: []Server{
		{Name: "b", URL: testUpstreamURL, ProcessorAddr: testProcessorAddr, ApprovedTools: []string{"z", "a", "m", "a"}},
		{Name: "a", URL: "http://x.example/mcp", ProcessorAddr: "h.example:1", ApprovedTools: []string{"q", "café", "p"}},
		{Name: "c", URL: testUpstreamURL, ProcessorAddr: testProcessorAddr},
	}}
	want, err := AgentGateway(base)
	if err != nil {
		t.Fatal(err)
	}
	shuffled := Input{ListenPort: base.ListenPort, Servers: []Server{
		{Name: "c", URL: testUpstreamURL, ProcessorAddr: testProcessorAddr},
		{Name: "a", URL: "http://x.example/mcp", ProcessorAddr: "h.example:1", ApprovedTools: []string{"p", "café", "q"}},
		{Name: "b", URL: testUpstreamURL, ProcessorAddr: testProcessorAddr, ApprovedTools: []string{"m", "a", "z", "a"}},
	}}
	got, err := AgentGateway(shuffled)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.YAML, want.YAML) || !reflect.DeepEqual(got.Skipped, want.Skipped) {
		t.Errorf("reordered input changed the output\n--- got ---\n%s\n--- want ---\n%s", got.YAML, want.YAML)
	}
}

func TestInputNotMutated(t *testing.T) {
	in := Input{ListenPort: testListenPort, Servers: []Server{
		{Name: "b", URL: testUpstreamURL, ProcessorAddr: testProcessorAddr, ApprovedTools: []string{"z", "a", "a"}},
		{Name: "a", URL: testUpstreamURL, ProcessorAddr: testProcessorAddr, ApprovedTools: []string{"y", "x"}},
	}}
	before := Input{ListenPort: in.ListenPort, Servers: []Server{
		{Name: "b", URL: testUpstreamURL, ProcessorAddr: testProcessorAddr, ApprovedTools: []string{"z", "a", "a"}},
		{Name: "a", URL: testUpstreamURL, ProcessorAddr: testProcessorAddr, ApprovedTools: []string{"y", "x"}},
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
