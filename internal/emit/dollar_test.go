package emit

import (
	"bytes"
	"slices"
	"strings"
	"testing"
)

// dollarFixture is the tail of the fixture secret: a name the gateway would
// look up in its environment. The secret is assembled at run time from a pad
// and this tail so that secret scanners do not mistake it for a credential.
const dollarFixture = "$NOT_AN_ENV_VAR"

// dollarSecret is the fixture secret: MinSecretLen pad bytes and the tail.
func dollarSecret() string { return strings.Repeat("0", MinSecretLen) + dollarFixture }

// dollarGoldenCases pins how every value class that can carry a dollar sign
// is written: a URL query, tool names and a secret.
func dollarGoldenCases() []goldenCase {
	return []goldenCase{{
		name: "dollar_sign",
		input: Input{ListenPort: testListenPort, Servers: []Server{{
			Name: "money", URL: testUpstreamURL + "?token=$UPSTREAM_TOKEN", ProcessorAddr: testProcessorAddr,
			Secret: dollarSecret(), ApprovedTools: []string{"$HOME", "price$", "${PATH}", "$$", "plain"},
		}}},
	}}
}

// TestDollarEscapeIsPinned: the escape is the one both YAML and CEL decode
// to the dollar sign and the gateway's substitution does not recognise.
func TestDollarEscapeIsPinned(t *testing.T) {
	if dollarEscape != `\u0024` {
		t.Fatalf("dollarEscape = %q", dollarEscape)
	}
	if got := quote("$"); got != `"\u0024"` {
		t.Errorf("quote($) = %s", got)
	}
}

// TestDollarSignNeverReachesTheFile: no raw dollar sign anywhere below the
// header, and every escaped value decodes back to what the input said, so
// the gateway's environment substitution has nothing to act on while the
// gateway still compares the real names and secret.
func TestDollarSignNeverReachesTheFile(t *testing.T) {
	tc := dollarGoldenCases()[0]
	out, err := AgentGateway(tc.input)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.IndexByte(out.YAML[len(generatedHeader):], '$') >= 0 {
		t.Errorf("output carries a raw dollar sign below the header:\n%s", out.YAML)
	}
	if len(out.Skipped) != 0 {
		t.Errorf("dollar names were skipped instead of escaped: %v", out.Skipped)
	}
	routes := splitRoutes(string(out.YAML))
	if len(routes) != 1 {
		t.Fatalf("want 1 route, got %d", len(routes))
	}
	want := slices.Clone(tc.input.Servers[0].ApprovedTools)
	slices.Sort(want)
	if got := decodeAllow(t, routes[0]); !slices.Equal(got, want) {
		t.Errorf("allow rule decodes to %q, want %q", got, want)
	}
	if got := decodeSecret(t, routes[0]); got != dollarSecret() {
		t.Errorf("secret decodes to %q, want %q", got, dollarSecret())
	}
	hostLine := `          host: "http://127.0.0.1:3001/mcp?token=\u0024UPSTREAM_TOKEN"` + "\n"
	if !strings.Contains(string(out.YAML), hostLine) {
		t.Errorf("upstream URL line not escaped as expected:\n%s", out.YAML)
	}
	allowLine := `      - allow: "mcp.tool.name == \"\\u0024\\u0024\" || mcp.tool.name == \"\\u0024HOME\" || mcp.tool.name == \"\\u0024{PATH}\" || mcp.tool.name == \"plain\" || mcp.tool.name == \"price\\u0024\""` + "\n"
	if !strings.Contains(string(out.YAML), allowLine) {
		t.Errorf("allow rule not escaped as expected:\n%s", out.YAML)
	}
}
