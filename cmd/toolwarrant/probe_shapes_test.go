package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// The probe shapes of D17 (h): what a relayed answer may look like and how
// the probe refuses to attribute it (seventh review canary-1 and canary-2).

// Seventh review (canary-1, D17 h): a 400 with an empty or non-JSON body was
// called "rejected by the gateway", although the forwarding stand-in in front
// of a plain go-sdk upstream relays the upstream's own text/plain 400 and the
// probe's name is in the upstream's log: the call crossed the gateway
// unhooked and the canary attributed the refusal to the gateway. The pass
// sentence now names the status and says the gateway or the upstream did not
// accept the call as a notification, which is all the probe can tell, and
// the documents say the probe proves the fail-open shape of v1.6.0 and
// cannot prove the hook. Not the pinned gateway's shape (v1.6.0 answers 202);
// it matters on every move of the pin (L7).
func TestProbeDoesNotAttributeARelayedPlainTextRefusalToTheGateway(t *testing.T) {
	c, _ := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	up := newUpstream(t, map[string]string{"echo": echoV1})
	up.probeMode.Store(probeModeRefuse)
	gw := forwardingGateway(t, up.url(), nil)
	before := len(up.probeNames())
	out := c.ok("verify-gateway", "--server", "s1", "--url", gw.URL)
	names := up.probeNames()
	if len(names) != before+1 || !strings.HasPrefix(names[len(names)-1], probeToolPrefix) {
		t.Fatalf("the probe did not reach the upstream through the forwarding stand-in: %q", names)
	}
	wantContains(t, "stdout", out, okLine, notAcceptedLine)
	wantNotContains(t, "stdout", out, "rejected by the gateway", "healthy", verdictInconclusive)
	if got := (probeReport{outcome: probeNotAccepted, status: http.StatusBadRequest}).summary(); got != "; "+notAcceptedLine {
		t.Errorf("summary = %q", got)
	}
	if got := (probeReport{outcome: probeNotAccepted, status: http.StatusTeapot}).summary(); !strings.Contains(got, "(HTTP 418, by the gateway or by the upstream)") {
		t.Errorf("summary names another status: %q", got)
	}
}

// Seventh review (canary-2, D17 h): carriesJSONAnswer validated each SSE data
// line on its own and the body as one value, so three answers an upstream can
// put on a 400 were not read as JSON and passed: a JSON-RPC error split over
// two data lines of one event (the SSE specification joins them with a
// newline), a JSON body behind a UTF-8 byte-order mark, and a body longer
// than probeMaxBody, which the reader cuts into invalid JSON. Each is now
// PROBE-INCONCLUSIVE, at the unit level and through the forwarding stand-in.
func TestProbeReadsTheJSONShapesAnUpstreamCanRelayOnA400(t *testing.T) {
	rpcErr := `{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"id required"}}`
	split := "event: message\ndata: {\"jsonrpc\":\"2.0\",\ndata: \"id\":null,\"error\":{\"code\":-32600,\"message\":\"id required\"}}\n\n"
	long := `{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"` + strings.Repeat("x", probeMaxBody) + `"}}`
	cases := map[string]rawResponse{
		"sse data split over two lines": {status: http.StatusBadRequest, contentType: mediaSSE, body: []byte(split)},
		"utf-8 bom before the object":   {status: http.StatusBadRequest, contentType: mediaJSON, body: []byte("\ufeff" + rpcErr)},
		"object cut at probeMaxBody":    {status: http.StatusBadRequest, contentType: mediaJSON, body: []byte(long)[:probeMaxBody]},
	}
	for name, resp := range cases {
		if got, err := classifyProbe(resp); got != probeInconclusive || err != nil {
			t.Errorf("%s: classifyProbe = %d, %v; want PROBE-INCONCLUSIVE", name, got, err)
		}
	}
	joined := (rawResponse{contentType: mediaSSE, body: []byte(split)}).messages()
	if len(joined) != 1 || !json.Valid(joined[0]) {
		t.Errorf("the split event was read as %q, want one valid JSON message", joined)
	}
	if !(rawResponse{contentType: mediaJSON, body: []byte("\ufeff" + rpcErr)}).carriesJSONAnswer() {
		t.Error("a byte-order mark hid the JSON answer")
	}
	if !(rawResponse{body: []byte(long)[:probeMaxBody]}).truncated() || (rawResponse{body: []byte(rpcErr)}).truncated() {
		t.Error("truncated misjudges the read cap")
	}

	c, _ := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	up := newUpstream(t, map[string]string{"echo": echoV1})
	for name, answer := range map[string]struct {
		contentType, body string
	}{
		"split event":  {mediaSSE, split},
		"over the cap": {mediaJSON, long},
	} {
		gw := forwardingGateway(t, up.url(), func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", answer.contentType)
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, answer.body)
		})
		r := c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", gw.URL)
		wantContains(t, name+" stdout", r.stdout, verdictInconclusive+" s1: ", "HTTP 400 and a JSON body")
		wantNotContains(t, name+" stdout", r.stdout, okLine, "rejected by the gateway")
		wantContains(t, name+" stderr", r.stderr, verdictInconclusive)
	}
}
