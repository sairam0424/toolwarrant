package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/fetch"
)

// okLine is the start of the one line that says a check passed; the word OK
// alone also occurs inside UNHOOKED-CALLS. notAcceptedLine is the probe's
// pass sentence for a bare HTTP 400 (D17 h), which attributes the refusal to
// nobody; docs/operations.md and e2e scenario O quote it.
const (
	okLine          = verdictOK + ": "
	notAcceptedLine = "the id-less tools/call was not accepted as a notification (HTTP 400, by the gateway or by the upstream)"
)

// Decision D12, D13 (h) and D17 (h): every check sends one tools/call without
// an id for a name no catalog can hold. A bare HTTP 400 passes the check as
// "not accepted as a notification" by the gateway or by the upstream, which
// is all the probe can say; a gateway that accepts the call (202) forwarded
// it to the upstream unhooked and fails the check; any other 2xx answer that
// carries a body (a JSON-RPC error in JSON or in an event stream, or a
// result) is PROBE-INCONCLUSIVE and fails the check too, because the gateway
// or the upstream may have written it; any other answer is an error, never
// OK; --no-probe sends nothing. The test upstream's five modes cover the
// three outcomes.
func TestVerifyGatewayProbesForUnhookedCalls(t *testing.T) {
	c, _ := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	g := newUpstream(t, map[string]string{"echo": echoV1})
	sessions, deletes := g.sessions.Load(), g.deletes.Load()
	out := c.ok("verify-gateway", "--server", "s1", "--url", g.url())
	wantContains(t, "stdout", out, okLine, notAcceptedLine)
	wantNotContains(t, "stdout", out, "rejected by the gateway")
	names := g.probeNames()
	if len(names) != 1 || !strings.HasPrefix(names[0], probeToolPrefix) || len(names[0]) != len(probeToolPrefix)+2*probeSuffixBytes {
		t.Fatalf("probe names = %q, want exactly one %s<8 hex digits>", names, probeToolPrefix)
	}
	if n := g.sessions.Load() - sessions; n != 2 {
		t.Errorf("%d sessions for one check, want 2: the listing and the probe each open their own", n)
	}
	if g.deletes.Load() == deletes {
		t.Error("the probe's session was not ended with a DELETE")
	}

	for name, mode := range map[string]int32{"json-rpc error": probeModeRPCError, "event stream error": probeModeSSEError, "result without error": probeModeSilent} {
		g.probeMode.Store(mode)
		r := c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", g.url())
		wantContains(t, name+" stdout", r.stdout, verdictInconclusive+" s1: the answer to a tools/call without an id was a 2xx status with a body, or HTTP 400 and a JSON body", "not a bare HTTP 400", "the gateway or the upstream may have written that answer")
		wantNotContains(t, name+" stdout", r.stdout, okLine, verdictUnhooked, verdictLeak)
		wantContains(t, name+" stderr", r.stderr, verdictInconclusive, "treat the gateway as unhooked until the answer is a bare HTTP 400", "only HTTP 202 proves anything")
	}
	g.probeMode.Store(probeModeForward)
	r := c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", g.url())
	wantContains(t, "stdout", r.stdout, verdictUnhooked+" s1: the gateway accepted a tools/call without an id (HTTP 202) and forwarded it to the upstream", "known limit L17")
	wantNotContains(t, "stdout", r.stdout, okLine, verdictLeak, verdictInconclusive)
	wantContains(t, "stderr", r.stderr, "forwards a tools/call without an id to the upstream unhooked", verdictUnhooked, "L17", "bypasses the approval")

	seen := len(g.probeNames())
	out = c.ok("verify-gateway", "--server", "s1", "--url", g.url(), "--no-probe")
	wantContains(t, "stdout", out, okLine, "unhooked-call probe skipped (--no-probe)")
	if len(g.probeNames()) != seen {
		t.Error("--no-probe still sent a probe")
	}
	names = g.probeNames()
	if len(names) != 5 || names[0] == names[1] {
		t.Errorf("probe names = %q, want five distinct random names", names)
	}
}

// Third review (cli-docs-9): a 2xx answer carrying a JSON-RPC error was taken
// as the gateway's refusal whoever produced it. A stand-in gateway that
// forwards every request to the upstream, in front of an upstream that
// answers the id-less tools/call with HTTP 200 and an error object, relayed
// the upstream's answer and the canary called the probe healthy although the
// probe had reached the upstream (its name is in the upstream's log). Now that
// answer is PROBE-INCONCLUSIVE, exit 1. Not the pinned gateway's behaviour
// (v1.6.0 answers 202 itself); the rule matters on every move of the pin (L7).
func TestProbeReportsARelayedUpstreamAnswerAsInconclusive(t *testing.T) {
	c, _ := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	up := newUpstream(t, map[string]string{"echo": echoV1})
	up.probeMode.Store(probeModeRPCError)
	target, err := url.Parse(up.url())
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.FlushInterval = -1
	gw := httptest.NewServer(proxy)
	t.Cleanup(gw.Close)

	before := len(up.probeNames())
	r := c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", gw.URL)
	names := up.probeNames()
	if len(names) != before+1 || !strings.HasPrefix(names[len(names)-1], probeToolPrefix) {
		t.Fatalf("the probe did not reach the upstream through the forwarding stand-in: %q", names)
	}
	wantContains(t, "stdout", r.stdout, verdictInconclusive+" s1:")
	wantNotContains(t, "stdout", r.stdout, okLine, "rejected by the gateway")
	wantContains(t, "stderr", r.stderr, verdictInconclusive)
}

// scripted is a gateway that answers each JSON-RPC method with a fixed
// response, for the probe's own error paths; the listing never runs here.
type scripted struct {
	initialize  func(w http.ResponseWriter)
	initialized int
	call        func(w http.ResponseWriter)
}

// initResult is a JSON initialize result the probe accepts.
const initResult = `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"g","version":"1"}}}`

// answerJSON writes body as JSON with the given status and session id.
func answerJSON(code int, session, body string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", mediaJSON)
		w.Header().Set(mcpSessionHeader, session)
		w.WriteHeader(code)
		_, _ = io.WriteString(w, body)
	}
}

// answerStatus writes an empty answer with the given status.
func answerStatus(code int) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) { w.WriteHeader(code) }
}

func (s scripted) serve(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var msg struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &msg)
		switch {
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		case msg.Method == methodInitialize:
			s.initialize(w)
		case msg.Method == methodInitialized:
			w.WriteHeader(s.initialized)
		case msg.Method == methodToolsCall && s.call != nil:
			s.call(w)
		default:
			http.Error(w, "unexpected", http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestProbeFailsClosedOnAGatewayItCannotRead(t *testing.T) {
	client, err := fetch.NewClient(fetch.Policy{AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	healthy := answerJSON(http.StatusOK, "session-1", initResult)
	cases := map[string]struct {
		gateway scripted
		want    probeOutcome
		err     string
	}{
		"bare 400":           {scripted{healthy, http.StatusAccepted, answerStatus(http.StatusBadRequest)}, probeNotAccepted, ""},
		"forwarded 202":      {scripted{healthy, http.StatusOK, answerStatus(http.StatusAccepted)}, probeUnhooked, ""},
		"call 200 with body": {scripted{healthy, http.StatusAccepted, answerJSON(http.StatusOK, "session-1", `{"jsonrpc":"2.0","id":null,"result":{}}`)}, probeInconclusive, ""},
		"call 200 empty":     {scripted{healthy, http.StatusAccepted, answerStatus(http.StatusOK)}, probeSkipped, "http status 200 without a body"},
		"call 204":           {scripted{healthy, http.StatusAccepted, answerStatus(http.StatusNoContent)}, probeSkipped, "http status 204 without a body"},
		"call 500":           {scripted{healthy, http.StatusAccepted, answerStatus(http.StatusInternalServerError)}, probeSkipped, "http status 500 without a body"},
		"initialize 500":     {scripted{answerStatus(http.StatusInternalServerError), http.StatusAccepted, nil}, probeSkipped, "http status 500 on initialize"},
		"no result":          {scripted{answerJSON(http.StatusOK, "s", `{"jsonrpc":"2.0","id":1,"error":{"code":1,"message":"no"}}`), http.StatusAccepted, nil}, probeSkipped, "no initialize result"},
		"other id":           {scripted{answerJSON(http.StatusOK, "s", `{"jsonrpc":"2.0","id":2,"result":{"protocolVersion":"2025-06-18"}}`), http.StatusAccepted, nil}, probeSkipped, "no initialize result"},
		"no protocol":        {scripted{answerJSON(http.StatusOK, "s", `{"jsonrpc":"2.0","id":1,"result":{}}`), http.StatusAccepted, nil}, probeSkipped, "no usable protocol version"},
		"hostile protocol":   {scripted{answerJSON(http.StatusOK, "s", `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025\r\nX: y"}}`), http.StatusAccepted, nil}, probeSkipped, "no usable protocol version"},
		"hostile session":    {scripted{answerJSON(http.StatusOK, strings.Repeat("s", maxHeaderValueLen+1), initResult), http.StatusAccepted, nil}, probeSkipped, "unusable session id"},
		"initialized 500":    {scripted{healthy, http.StatusInternalServerError, nil}, probeSkipped, "http status 500 on notifications/initialized"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := probeUnhookedCalls(context.Background(), client, tc.gateway.serve(t), nil)
			if got.outcome != tc.want {
				t.Errorf("outcome %d, want %d (err %v)", got.outcome, tc.want, err)
			}
			if tc.err == "" && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err) || !strings.HasPrefix(err.Error(), "unhooked-call probe: ")) {
				t.Errorf("error %v, want one mentioning %q", err, tc.err)
			}
		})
	}
	// A gateway that is not there at all: the class of the error, never the
	// URL with its query.
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	if _, err := probeUnhookedCalls(context.Background(), client, closed.URL+"/mcp?q="+plant("query"), nil); err == nil || !strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), canary) {
		t.Errorf("closed gateway: %v", err)
	}
}

func TestProbeHelpers(t *testing.T) {
	name, err := probeToolName()
	if err != nil || !strings.HasPrefix(name, probeToolPrefix) || len(name) != len(probeToolPrefix)+2*probeSuffixBytes {
		t.Errorf("probeToolName = %q, %v", name, err)
	}
	if other, _ := probeToolName(); other == name {
		t.Error("two probe names are equal")
	}
	for v, want := range map[string]bool{"": true, "abc": true, "a b": true, "a\nb": false, "a" + string(rune(0x7f)): false, strings.Repeat("x", maxHeaderValueLen+1): false} {
		if got := headerValueOK(v); got != want {
			t.Errorf("headerValueOK(%q) = %v", v, got)
		}
	}
	sse := rawResponse{contentType: "text/event-stream; charset=utf-8", body: []byte("event: message\r\ndata: {\"id\":1,\"result\":{\"a\":1}}\r\n\r\n: comment\ndata:{\"id\":2,\"error\":{\"code\":1}}\n\n")}
	msgs := sse.messages()
	if len(msgs) != 2 || string(msgs[0]) != `{"id":1,"result":{"a":1}}` || string(msgs[1]) != `{"id":2,"error":{"code":1}}` {
		t.Errorf("sse messages = %q", msgs)
	}
	plain := rawResponse{contentType: mediaJSON, body: []byte(`{"id":1,"result":{}}`)}
	if msgs := plain.messages(); len(msgs) != 1 || string(msgs[0]) != `{"id":1,"result":{}}` {
		t.Errorf("json messages = %q", msgs)
	}
	if msgs := (rawResponse{contentType: "nonsense/;;", body: []byte("x")}).messages(); len(msgs) != 1 || string(msgs[0]) != "x" {
		t.Errorf("unparseable content type: %q", msgs)
	}
	if res, ok := findResult(sse.messages(), 1); !ok || string(res) != `{"a":1}` {
		t.Errorf("findResult = %s, %v", res, ok)
	}
	if _, ok := findResult(sse.messages(), 3); ok {
		t.Error("findResult found an absent id")
	}
	if _, ok := findResult([][]byte{[]byte("not json")}, 1); ok {
		t.Error("findResult read garbage")
	}
	cases := []struct {
		resp rawResponse
		want probeOutcome
		err  bool
	}{
		{rawResponse{status: http.StatusAccepted}, probeUnhooked, false},
		{rawResponse{status: http.StatusAccepted, body: []byte("{}")}, probeUnhooked, false},
		{rawResponse{status: http.StatusBadRequest}, probeNotAccepted, false},
		{rawResponse{status: http.StatusBadRequest, body: []byte("Bad Request: id required")}, probeNotAccepted, false},
		{rawResponse{status: http.StatusBadRequest, contentType: mediaJSON, body: []byte("Bad Request: id required")}, probeNotAccepted, false},
		{rawResponse{status: http.StatusBadRequest, contentType: mediaSSE, body: []byte("event: message\n\n")}, probeNotAccepted, false},
		// D17 (h): the three shapes the seventh review found the heuristic
		// missing (canary-2): an event whose JSON is split over two data
		// lines, a byte-order mark before the object, a body cut at the cap.
		{rawResponse{status: http.StatusBadRequest, contentType: mediaSSE, body: []byte("event: message\ndata: {\"jsonrpc\":\"2.0\",\ndata: \"id\":null,\"error\":{\"code\":-32600}}\n\n")}, probeInconclusive, false},
		{rawResponse{status: http.StatusBadRequest, contentType: mediaJSON, body: []byte("\ufeff" + `{"error":{"code":1}}`)}, probeInconclusive, false},
		{rawResponse{status: http.StatusBadRequest, contentType: mediaJSON, body: []byte(`{"error":{"code":1,"message":"` + strings.Repeat("x", probeMaxBody) + `"}}`)[:probeMaxBody]}, probeInconclusive, false},
		{rawResponse{status: http.StatusBadRequest, body: []byte(strings.Repeat("x", probeMaxBody))}, probeInconclusive, false},
		// D14 (i), D15 (k): a 400 whose body is JSON may be an upstream's
		// refusal relayed by a forwarding gateway (fourth review cli-docs-7),
		// a batch of JSON-RPC errors included (fifth review cli-docs-4), so
		// every JSON body on a 400 is inconclusive, an error member or not.
		{rawResponse{status: http.StatusBadRequest, body: []byte(`{"error":{"code":1}}`)}, probeInconclusive, false},
		{rawResponse{status: http.StatusBadRequest, contentType: mediaSSE, body: []byte("data: {\"error\":{\"code\":1}}\n\n")}, probeInconclusive, false},
		{rawResponse{status: http.StatusBadRequest, contentType: mediaJSON, body: []byte(`[{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"id required"}}]`)}, probeInconclusive, false},
		{rawResponse{status: http.StatusBadRequest, contentType: mediaSSE, body: []byte("data: [{\"error\":{\"code\":1}}]\n\n")}, probeInconclusive, false},
		{rawResponse{status: http.StatusBadRequest, body: []byte(`{"error":null}`)}, probeInconclusive, false},
		{rawResponse{status: http.StatusBadRequest, body: []byte(`{"result":{}}`)}, probeInconclusive, false},
		{rawResponse{status: http.StatusBadRequest, body: []byte(` "id required" `)}, probeInconclusive, false},
		{rawResponse{status: http.StatusBadRequest, body: []byte(`[]`)}, probeInconclusive, false},
		{rawResponse{status: http.StatusBadRequest, body: []byte(`{"error":`)}, probeNotAccepted, false},
		{rawResponse{status: http.StatusOK, contentType: mediaJSON, body: []byte(`{"error":{"code":1}}`)}, probeInconclusive, false},
		{rawResponse{status: http.StatusOK, contentType: mediaJSON, body: []byte(`{"result":{}}`)}, probeInconclusive, false},
		{rawResponse{status: http.StatusOK, contentType: mediaSSE, body: []byte("data: {\"error\":{\"code\":1}}\n\n")}, probeInconclusive, false},
		{rawResponse{status: http.StatusOK}, probeSkipped, true},
		{rawResponse{status: http.StatusNoContent}, probeSkipped, true},
		{rawResponse{status: http.StatusInternalServerError}, probeSkipped, true},
		{rawResponse{status: http.StatusUnauthorized, body: []byte(`{"error":{"code":1}}`)}, probeSkipped, true},
	}
	for _, tc := range cases {
		got, err := classifyProbe(tc.resp)
		if got != tc.want || (err != nil) != tc.err {
			t.Errorf("classifyProbe(%d, %d bytes) = %d, %v", tc.resp.status, len(tc.resp.body), got, err)
		}
	}
}

// Fourth review (cli-docs-7, D14 i): the probe called every HTTP 400 healthy,
// whoever produced it, so a forwarding stand-in in front of an upstream that
// refuses the id-less tools/call with 400 and a JSON-RPC error relayed that
// answer, the probe name reached the upstream, and the canary printed "rejected
// by the gateway" with exit 0. A 400 whose body is JSON is now
// PROBE-INCONCLUSIVE (D15 k widened it from a JSON-RPC error object to any
// JSON body); a 400 with a plain-text body or none stays healthy, which is
// what the go-sdk upstream answers and what the pinned gateway's own refusal
// would look like.
func TestProbeReportsARelayed400WithAJSONRPCErrorAsInconclusive(t *testing.T) {
	c, _ := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	up := newUpstream(t, map[string]string{"echo": echoV1})
	up.probeMode.Store(probeModeRPCError400)
	gw := forwardingGateway(t, up.url(), nil)
	before := len(up.probeNames())
	r := c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", gw.URL)
	names := up.probeNames()
	if len(names) != before+1 || !strings.HasPrefix(names[len(names)-1], probeToolPrefix) {
		t.Fatalf("the probe did not reach the upstream through the forwarding stand-in: %q", names)
	}
	wantContains(t, "stdout", r.stdout, verdictInconclusive+" s1: ", "HTTP 400 and a JSON body")
	wantNotContains(t, "stdout", r.stdout, verdictOK, "rejected by the gateway")
	wantContains(t, "stderr", r.stderr, "HTTP 400 and a JSON body", "treat the gateway as unhooked until the answer is a bare HTTP 400")

	// The go-sdk's own refusal, a 400 with a plain-text body, relayed by the
	// same stand-in, passes: the rule is about JSON bodies, and since D17 (h)
	// the pass sentence attributes the refusal to nobody.
	up.probeMode.Store(probeModeRefuse)
	out := c.ok("verify-gateway", "--server", "s1", "--url", gw.URL)
	wantContains(t, "stdout", out, verdictOK, notAcceptedLine)
}

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

// Fifth review (cli-docs-4, D15 k): the probe read each message as one JSON
// object, so a JSON-RPC batch answer, an array of error objects, relayed on a
// 400 by a forwarding stand-in was not recognised and the canary printed
// "rejected by the gateway" with exit 0 for the same relayed-upstream shape
// D14 (i) made inconclusive. Any JSON body on a 400 is now PROBE-INCONCLUSIVE.
func TestProbeReportsA400WithABatchOfJSONRPCErrorsAsInconclusive(t *testing.T) {
	c, _ := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	up := newUpstream(t, map[string]string{"echo": echoV1})
	const batch = `[{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"id required"}}]`
	gw := forwardingGateway(t, up.url(), func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", mediaJSON)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, batch)
	})
	r := c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", gw.URL)
	wantContains(t, "stdout", r.stdout, verdictInconclusive+" s1: ", "HTTP 400 and a JSON body")
	wantNotContains(t, "stdout", r.stdout, verdictOK, "rejected by the gateway")
	wantContains(t, "stderr", r.stderr, verdictInconclusive)
	resp := rawResponse{status: http.StatusBadRequest, contentType: mediaJSON, body: []byte(batch)}
	if !resp.carriesJSONAnswer() {
		t.Error("a batch of JSON-RPC errors is not recognised as a JSON answer")
	}
	if got, err := classifyProbe(resp); got != probeInconclusive || err != nil {
		t.Errorf("classifyProbe(400, batch) = %d, %v; want PROBE-INCONCLUSIVE", got, err)
	}
}

// The error for a status the probe cannot classify says whether the answer
// carried a body (fourth review cli-docs-7: it said "without a body" for a 500
// that had one).
func TestProbeErrorSaysWhetherTheAnswerHadABody(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"boom"}}`)
	_, err := classifyProbe(rawResponse{status: http.StatusInternalServerError, contentType: mediaJSON, body: body})
	if err == nil || !strings.Contains(err.Error(), "http status 500 with a body of "+strconv.Itoa(len(body))+" bytes") || strings.Contains(err.Error(), "boom") {
		t.Errorf("500 with a body: %v", err)
	}
	_, err = classifyProbe(rawResponse{status: http.StatusInternalServerError})
	if err == nil || !strings.Contains(err.Error(), "http status 500 without a body") {
		t.Errorf("500 without a body: %v", err)
	}
	if (rawResponse{status: http.StatusBadRequest, body: []byte("not json")}).carriesJSONAnswer() {
		t.Error("plain text counted as a JSON answer")
	}
}

// An event stream that opens with a byte-order mark still carries its first
// data line: the SSE parser strips the mark from the stream before reading
// lines, so a relayed JSON-RPC refusal behind it stays inconclusive instead
// of passing as a bare 400 (eighth review).
func TestProbeReadsAnEventStreamBehindALeadingByteOrderMark(t *testing.T) {
	body := "\ufeffdata: {\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32600,\"message\":\"no id\"}}\n\n"
	resp := rawResponse{status: 400, contentType: mediaSSE, body: []byte(body)}
	if !resp.carriesJSONAnswer() {
		t.Fatalf("an SSE body behind a byte-order mark was not read as JSON: %q", body)
	}
	outcome, err := classifyProbe(resp)
	if err != nil || outcome != probeInconclusive {
		t.Fatalf("classifyProbe = %v, %v; want PROBE-INCONCLUSIVE", outcome, err)
	}
}
