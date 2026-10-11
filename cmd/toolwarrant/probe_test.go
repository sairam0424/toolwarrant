package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/fetch"
)

// okLine is the start of the one line that says a check passed; the word OK
// alone also occurs inside UNHOOKED-CALLS.
const okLine = verdictOK + ": "

// Decision D12: every check sends one tools/call without an id for a name no
// catalog can hold. A gateway that refuses it (400, or a JSON-RPC error in
// JSON or in an event stream) is healthy; one that accepts it (202) forwarded
// it to the upstream unhooked and fails the check; any other answer is an
// error, never OK; --no-probe sends nothing.
func TestVerifyGatewayProbesForUnhookedCalls(t *testing.T) {
	c, _ := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	g := newUpstream(t, map[string]string{"echo": echoV1})
	sessions, deletes := g.sessions.Load(), g.deletes.Load()
	out := c.ok("verify-gateway", "--server", "s1", "--url", g.url())
	wantContains(t, "stdout", out, okLine, "id-less tools/call rejected by the gateway")
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

	for name, mode := range map[string]int32{"json-rpc error": probeModeRPCError, "event stream error": probeModeSSEError} {
		g.probeMode.Store(mode)
		wantContains(t, name, c.ok("verify-gateway", "--server", "s1", "--url", g.url()), okLine, "rejected by the gateway")
	}
	g.probeMode.Store(probeModeForward)
	r := c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", g.url())
	wantContains(t, "stdout", r.stdout, verdictUnhooked+" s1: the gateway accepted a tools/call without an id (HTTP 202) and forwarded it to the upstream", "known limit L17")
	wantNotContains(t, "stdout", r.stdout, okLine, verdictLeak)
	wantContains(t, "stderr", r.stderr, "forwards a tools/call without an id to the upstream unhooked", verdictUnhooked, "L17", "bypasses the approval")
	g.probeMode.Store(probeModeSilent)
	r = c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", g.url())
	wantContains(t, "stderr", r.stderr, "unhooked-call probe", "http status 200 without a json-rpc error", "unknown")
	wantNotContains(t, "stdout", r.stdout, okLine, verdictUnhooked)

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
		"healthy 400":      {scripted{healthy, http.StatusAccepted, answerStatus(http.StatusBadRequest)}, probeHealthy, ""},
		"forwarded 202":    {scripted{healthy, http.StatusOK, answerStatus(http.StatusAccepted)}, probeUnhooked, ""},
		"call 500":         {scripted{healthy, http.StatusAccepted, answerStatus(http.StatusInternalServerError)}, probeSkipped, "http status 500 without a json-rpc error"},
		"call 200 silent":  {scripted{healthy, http.StatusAccepted, answerJSON(http.StatusOK, "session-1", `{"jsonrpc":"2.0","id":null,"result":{}}`)}, probeSkipped, "http status 200 without a json-rpc error"},
		"initialize 500":   {scripted{answerStatus(http.StatusInternalServerError), http.StatusAccepted, nil}, probeSkipped, "http status 500 on initialize"},
		"no result":        {scripted{answerJSON(http.StatusOK, "s", `{"jsonrpc":"2.0","id":1,"error":{"code":1,"message":"no"}}`), http.StatusAccepted, nil}, probeSkipped, "no initialize result"},
		"other id":         {scripted{answerJSON(http.StatusOK, "s", `{"jsonrpc":"2.0","id":2,"result":{"protocolVersion":"2025-06-18"}}`), http.StatusAccepted, nil}, probeSkipped, "no initialize result"},
		"no protocol":      {scripted{answerJSON(http.StatusOK, "s", `{"jsonrpc":"2.0","id":1,"result":{}}`), http.StatusAccepted, nil}, probeSkipped, "no usable protocol version"},
		"hostile protocol": {scripted{answerJSON(http.StatusOK, "s", `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025\r\nX: y"}}`), http.StatusAccepted, nil}, probeSkipped, "no usable protocol version"},
		"hostile session":  {scripted{answerJSON(http.StatusOK, strings.Repeat("s", maxHeaderValueLen+1), initResult), http.StatusAccepted, nil}, probeSkipped, "unusable session id"},
		"initialized 500":  {scripted{healthy, http.StatusInternalServerError, nil}, probeSkipped, "http status 500 on notifications/initialized"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := probeUnhookedCalls(context.Background(), client, tc.gateway.serve(t), nil)
			if got != tc.want {
				t.Errorf("outcome %d, want %d (err %v)", got, tc.want, err)
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
	if !hasRPCError(sse.messages()) || hasRPCError(plain.messages()) || hasRPCError([][]byte{[]byte(`{"error":null}`), []byte("garbage")}) {
		t.Error("hasRPCError wrong")
	}
	cases := []struct {
		resp rawResponse
		want probeOutcome
		err  bool
	}{
		{rawResponse{status: http.StatusAccepted}, probeUnhooked, false},
		{rawResponse{status: http.StatusBadRequest}, probeHealthy, false},
		{rawResponse{status: http.StatusOK, contentType: mediaJSON, body: []byte(`{"error":{"code":1}}`)}, probeHealthy, false},
		{rawResponse{status: http.StatusOK, contentType: mediaJSON, body: []byte(`{"result":{}}`)}, probeSkipped, true},
		{rawResponse{status: http.StatusNoContent}, probeSkipped, true},
		{rawResponse{status: http.StatusInternalServerError}, probeSkipped, true},
		{rawResponse{status: http.StatusUnauthorized, body: []byte(`{"error":{"code":1}}`)}, probeSkipped, true},
	}
	for _, tc := range cases {
		got, err := classifyProbe(tc.resp)
		if got != tc.want || (err != nil) != tc.err {
			t.Errorf("classifyProbe(%d) = %d, %v", tc.resp.status, got, err)
		}
	}
}
