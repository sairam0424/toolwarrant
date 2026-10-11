package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// forwardingGateway stands in for a gateway that relays every message to the
// upstream; answer, when set, takes the canary's tools/call without an id
// instead of relaying it.
func forwardingGateway(t *testing.T, upstreamURL string, answer http.HandlerFunc) *httptest.Server {
	t.Helper()
	target, err := url.Parse(upstreamURL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.FlushInterval = -1
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if answer != nil && r.Method == http.MethodPost {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "read", http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			var msg struct {
				ID     json.RawMessage `json:"id"`
				Method string          `json:"method"`
			}
			if json.Unmarshal(body, &msg) == nil && msg.Method == methodToolsCall && (len(msg.ID) == 0 || string(msg.ID) == "null") {
				answer(w, r)
				return
			}
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// answerRPCError answers with the given status and a JSON-RPC error body.
func answerRPCError(status int) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", mediaJSON)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"internal error"}}`)
	}
}

// expectOneVerdictThenExit watches a run started without --keep-going: it must
// end by itself with exit 1 after printing the verdict once; a second verdict
// line means the run went on past the failed check (fourth review cli-docs-5).
func expectOneVerdictThenExit(t *testing.T, run *running, verdict string) {
	t.Helper()
	deadline := time.Now().Add(testTimeout)
	for {
		out := run.stdout.String()
		if strings.Count(out, verdict) >= 2 {
			code := run.stop()
			t.Fatalf("without --keep-going the run printed %s on two checks instead of exiting at the first failed check (exit %d at stop):\n%s%s", verdict, code, out, run.stderr.String())
		}
		select {
		case code := <-run.done:
			if code != exitFailure {
				t.Errorf("exit %d, want %d", code, exitFailure)
			}
			wantContains(t, "stdout", run.stdout.String(), verdict, "check failed: ")
			return
		case <-time.After(pollEvery):
		}
		if time.Now().After(deadline) {
			run.stop()
			t.Fatal("timed out waiting for the run to stop or to repeat")
		}
	}
}

// Fourth review (cli-docs-5): in loop() the error branch came before the
// failing-verdict branch, so a check whose listing found a LEAK and whose probe
// then errored (a 5xx from the gateway) was printed as "check failed" and an
// un-flagged run went on, printing the LEAK on every tick. A failing verdict
// now ends an un-flagged run whatever error followed it, with the "check
// failed" line printed as well.
func TestEveryWithoutKeepGoingStopsAtALeakWhenTheProbeErrors(t *testing.T) {
	c, _ := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	up := newUpstream(t, map[string]string{"echo": echoV2}) // drifted bytes behind a route without its processor: LEAK (MISMATCH)
	gw := forwardingGateway(t, up.url(), answerRPCError(http.StatusInternalServerError))
	run := c.launch("verify-gateway", "--server", "s1", "--url", gw.URL+routePath, "--every", loopEvery.String())
	expectOneVerdictThenExit(t, run, verdictLeak+" echo")
	wantContains(t, "stdout", run.stdout.String(), "http status 500 with a body of")
	wantContains(t, "stderr", run.stderr.String(), "1 tool(s) leak")
}

// The same branch with CONFIG-EDITED plus a listing failure: an edited file
// while the gateway is down ends an un-flagged run at the first check.
func TestEveryWithoutKeepGoingStopsAtAnEditedConfigWhenTheListingFails(t *testing.T) {
	c, _ := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	cfg := filepath.Join(t.TempDir(), "gateway.yaml")
	c.ok("emit", "--out", cfg)
	edited := strings.Replace(readFile(t, cfg), "failClosed", "failOpen", 1)
	if err := os.WriteFile(cfg, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	closed := newUpstream(t, nil)
	closed.http.Close()
	run := c.launch("verify-gateway", "--server", "s1", "--url", closed.url(), "--config", cfg, "--every", loopEvery.String(), "--no-probe")
	expectOneVerdictThenExit(t, run, verdictConfigEdited)
	wantContains(t, "stderr", run.stderr.String(), "edited after emit wrote it")
	// With --keep-going the same run goes on, as the flag promises.
	run = c.launch("verify-gateway", "--server", "s1", "--url", closed.url(), "--config", cfg, "--every", loopEvery.String(), "--no-probe", "--keep-going")
	waitFor(t, "two checks", func() bool { return strings.Count(run.stdout.String(), verdictConfigEdited) >= 2 })
	if code := run.stop(); code != exitFailure {
		t.Errorf("exit %d at stop, want %d", code, exitFailure)
	}
}
