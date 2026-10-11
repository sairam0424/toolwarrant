package emit

import (
	"slices"
	"strings"
	"testing"
)

// requestHeadersBlock is the filter the emitter writes under every processor
// entry, assembled from the same constants: the test states the shape (two
// block sequences at the key's indentation) and the constants state the
// names.
func requestHeadersBlock() string {
	lines := []string{"        requestHeaders:", "          allowed:", "          - " + quote(forwardedPseudoHeader), "          disallowed:"}
	for _, name := range deniedHeaders() {
		lines = append(lines, "          - "+quote(name))
	}
	return strings.Join(lines, "\n") + "\n"
}

// TestHeaderFilterNamesArePinned: the one forwarded pseudo-header and the
// three denied credential headers, lowercase, in this order, and the exact
// text they produce. A change here is a change to what every processor
// receives.
func TestHeaderFilterNamesArePinned(t *testing.T) {
	if forwardedPseudoHeader != ":method" {
		t.Errorf("forwardedPseudoHeader = %q", forwardedPseudoHeader)
	}
	if got := deniedHeaders(); !slices.Equal(got, []string{"authorization", "cookie", "proxy-authorization"}) {
		t.Errorf("deniedHeaders() = %q", got)
	}
	want := "        requestHeaders:\n          allowed:\n          - \":method\"\n          disallowed:\n          - \"authorization\"\n          - \"cookie\"\n          - \"proxy-authorization\"\n"
	if got := requestHeadersBlock(); got != want {
		t.Errorf("block =\n%s\nwant\n%s", got, want)
	}
}

// TestEveryProcessorEntryFiltersClientHeaders ports the third review's
// finding processor-emit-6: every processor entry carries the gateway's
// request-header filter, directly after failureMode and before the metadata
// or methods block, once per server and nowhere else, whatever the tools,
// secrets and addresses of the input. Before this the entry had no filter and
// agentgateway forwarded every client header, Authorization and Cookie
// included, with each hook.
func TestEveryProcessorEntryFiltersClientHeaders(t *testing.T) {
	block := "        failureMode: " + quote("failClosed") + "\n" + requestHeadersBlock()
	for _, tc := range goldenCases() {
		out, err := AgentGateway(tc.input)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		yaml := string(out.YAML)
		servers := len(tc.input.Servers)
		if got := strings.Count(yaml, block); got != servers {
			t.Errorf("%s: %d filter blocks after failureMode, want %d:\n%s", tc.name, got, servers, yaml)
		}
		if got := strings.Count(yaml, "requestHeaders:"); got != servers {
			t.Errorf("%s: requestHeaders appears %d times, want %d", tc.name, got, servers)
		}
		followed := strings.Count(yaml, block+"        metadata:\n") + strings.Count(yaml, block+"        methods:\n")
		if followed != servers {
			t.Errorf("%s: %d filter blocks are followed by metadata or methods, want %d:\n%s", tc.name, followed, servers, yaml)
		}
	}
}

// TestGatewayParsesTheRequestHeaderFilter proves the block is read by the
// real binary, not ignored: the emitted file validates (as every golden does
// in TestGoldenFilesValidateWithRealGateway), and the same binary refuses a
// scalar where the allow list belongs, an unknown key, an invalid header name
// and an unknown pseudo-header, each for the reason the gateway states. Which
// headers the gateway then puts on the wire is a runtime question for the
// end-to-end test; the module source says the listed names and nothing else.
func TestGatewayParsesTheRequestHeaderFilter(t *testing.T) {
	binary := gatewayBinary(t)
	out := freshOutput(t)
	requireValid(t, binary, out.YAML, "the emitted request-header filter")
	allowLine := "          - " + quote(forwardedPseudoHeader) + "\n"
	cases := []struct{ what, old, replacement, saying string }{
		{"a scalar where the allow list belongs", "          allowed:\n" + allowLine, "          allowed: " + quote(forwardedPseudoHeader) + "\n", "expected a sequence"},
		{"an unknown key in the filter", "          allowed:\n", "          allow:\n", "unknown field `allow`"},
		{"an invalid header name", allowLine, "          - " + quote("bad header!") + "\n", "invalid HTTP header name"},
		{"an unknown pseudo-header", allowLine, "          - " + quote(":nosuch") + "\n", "invalid HTTP header name"},
	}
	for _, tc := range cases {
		requireRejectedSaying(t, binary, mutate(t, out.YAML, tc.old, tc.replacement), tc.what, tc.saying)
	}
}

// TestGatewayAcceptsEachHalfOfTheFilterAlone ports the review's probe: the
// binary loads a deny-only and an allow-only filter too, so the two lists are
// independent and writing both is the emitter's choice, not a parser
// requirement.
func TestGatewayAcceptsEachHalfOfTheFilterAlone(t *testing.T) {
	binary := gatewayBinary(t)
	out := freshOutput(t)
	allowed := "          allowed:\n          - " + quote(forwardedPseudoHeader) + "\n"
	denied := "          disallowed:\n"
	for _, name := range deniedHeaders() {
		denied += "          - " + quote(name) + "\n"
	}
	requireValid(t, binary, mutate(t, out.YAML, denied, ""), "an allow-only filter")
	requireValid(t, binary, mutate(t, out.YAML, allowed, ""), "a deny-only filter")
}
