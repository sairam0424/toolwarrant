package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	testTimeout = 30 * time.Second
	pollEvery   = 10 * time.Millisecond
	// sessionHeader is the Streamable HTTP session header; a POST without it
	// opens a new MCP session (it is the initialize request).
	sessionHeader = "Mcp-Session-Id"
	// loopEvery is the smallest interval --every accepts, used by every
	// scheduled-command test.
	loopEvery = minEvery
)

// How the test upstream, which stands in for the gateway, answers the
// canary's tools/call without an id. The go-sdk server refuses one with 400
// by itself, which is the healthy answer; the other modes imitate agentgateway
// v1.6.0 (202, the call forwarded) and the other shapes the probe classifies.
const (
	probeModeRefuse   int32 = iota // let the go-sdk answer: 400
	probeModeForward               // 202 Accepted: the unhooked gateway
	probeModeRPCError              // 200 with a JSON-RPC error object
	probeModeSSEError              // 200 text/event-stream carrying a JSON-RPC error
	probeModeSilent                // 200 with a result and no error: unknown
)

var hexDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

// cli drives run in-process against a temporary database with an injected
// environment, so no test touches the real environment or file system.
type cli struct {
	t   *testing.T
	db  string
	env map[string]string
}

// result is what one invocation produced.
type result struct {
	code   int
	stdout string
	stderr string
}

// auditRow is the subset of an audit entry the tests look at.
type auditRow struct {
	Seq       int64  `json:"seq"`
	Actor     string `json:"actor"`
	ActorType string `json:"actor_type"`
	Event     string `json:"event"`
	Subject   string `json:"subject"`
	Detail    string `json:"detail"`
}

func newCLI(t *testing.T) *cli {
	t.Helper()
	c := &cli{t: t, db: filepath.Join(t.TempDir(), "tw.db"), env: map[string]string{}}
	c.ok("init")
	return c
}

// sub returns a copy bound to a subtest, so failures are reported there.
func (c *cli) sub(t *testing.T) *cli { return &cli{t: t, db: c.db, env: c.env} }

func (c *cli) getenv(k string) string { return c.env[k] }

func (c *cli) run(args ...string) result {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	return c.runCtx(ctx, args...)
}

func (c *cli) runCtx(ctx context.Context, args ...string) result {
	var out, errb bytes.Buffer
	full := append([]string{"--db", c.db}, args...)
	code := runCtx(ctx, full, strings.NewReader(""), &out, &errb, c.getenv)
	return result{code: code, stdout: out.String(), stderr: errb.String()}
}

func (c *cli) ok(args ...string) string {
	c.t.Helper()
	r := c.run(args...)
	if r.code != exitOK {
		c.t.Fatalf("%v: exit %d\nstdout: %s\nstderr: %s", args, r.code, r.stdout, r.stderr)
	}
	return r.stdout
}

func (c *cli) fail(want int, args ...string) result {
	c.t.Helper()
	r := c.run(args...)
	if r.code != want {
		c.t.Fatalf("%v: exit %d, want %d\nstdout: %s\nstderr: %s", args, r.code, want, r.stdout, r.stderr)
	}
	return r
}

func (c *cli) jsonInto(v any, args ...string) {
	c.t.Helper()
	out := c.ok(args...)
	if err := json.Unmarshal([]byte(out), v); err != nil {
		c.t.Fatalf("%v: output is not json (%v):\n%s", args, err, out)
	}
}

func (c *cli) auditEntries() []auditRow {
	c.t.Helper()
	var rows []auditRow
	c.jsonInto(&rows, "audit", "list", "--json")
	return rows
}

// running is a long-lived command started in the background: its streams,
// and the two ways it ends, by itself (wait) or on cancellation (stop).
type running struct {
	t              *testing.T
	args           []string
	stdout, stderr *syncBuffer
	done           chan int
	cancel         context.CancelFunc
}

// launch runs a long-lived command in the background.
func (c *cli) launch(args ...string) *running {
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{t: c.t, args: args, stdout: &syncBuffer{}, stderr: &syncBuffer{}, done: make(chan int, 1), cancel: cancel}
	full := append([]string{"--db", c.db}, args...)
	go func() { r.done <- runCtx(ctx, full, strings.NewReader(""), r.stdout, r.stderr, c.getenv) }()
	return r
}

// wait returns the exit code of a command that is expected to end by itself.
func (r *running) wait() int {
	r.t.Helper()
	select {
	case code := <-r.done:
		return code
	case <-time.After(testTimeout):
		r.t.Fatalf("%v did not exit by itself", r.args)
		return -1
	}
}

// stop cancels the command (what SIGTERM does) and returns its exit code.
func (r *running) stop() int {
	r.t.Helper()
	r.cancel()
	select {
	case code := <-r.done:
		return code
	case <-time.After(testTimeout):
		r.t.Fatalf("%v did not stop after cancellation", r.args)
		return -1
	}
}

// start runs a long-lived command in the background. The returned stop cancels
// it and returns its exit code.
func (c *cli) start(args ...string) (stdout, stderr *syncBuffer, stop func() int) {
	r := c.launch(args...)
	return r.stdout, r.stderr, r.stop
}

// syncBuffer is a bytes.Buffer that a background command and the test may
// share.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// brokenPipe fails every write, like a pipe whose reader went away.
type brokenPipe struct{ writes int }

func (b *brokenPipe) Write([]byte) (int, error) {
	b.writes++
	return 0, errors.New("broken pipe")
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(testTimeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(pollEvery)
	}
}

// nonEmptyLines splits output into its lines.
func nonEmptyLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}

func wantContains(t *testing.T, where, s string, subs ...string) {
	t.Helper()
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			t.Errorf("%s lacks %q:\n%s", where, sub, s)
		}
	}
}

func wantNotContains(t *testing.T, where, s string, subs ...string) {
	t.Helper()
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			t.Errorf("%s must not contain %q:\n%s", where, sub, s)
		}
	}
}

// upstream is a real go-sdk MCP server over Streamable HTTP whose tools a
// test can change at will, which is how drift is simulated. It counts the MCP
// sessions opened against it, so a test can show that a scheduled check
// really starts a fresh one every time, and it stands in for the gateway in
// front of the canary's probe: every tools/call without an id is recorded and
// answered the way probeMode says.
type upstream struct {
	server    *mcp.Server
	http      *httptest.Server
	sessions  atomic.Int64
	deletes   atomic.Int64
	probeMode atomic.Int32
	mu        sync.Mutex
	probes    []string // tool names of the id-less tools/call messages seen
}

func newUpstream(t *testing.T, tools map[string]string) *upstream {
	t.Helper()
	srv := mcp.NewServer(&mcp.Implementation{Name: "test-upstream", Version: "0.0.1"}, nil)
	u := &upstream{server: srv}
	for name, desc := range tools {
		u.set(name, desc)
	}
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)
	u.http = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.Header.Get(sessionHeader) == "" {
			u.sessions.Add(1)
		}
		if r.Method == http.MethodDelete {
			u.deletes.Add(1)
		}
		if u.answerProbe(w, r) {
			return
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(u.http.Close)
	return u
}

func (u *upstream) url() string { return u.http.URL }

// set adds a tool or replaces the one with that name.
func (u *upstream) set(name, desc string) {
	u.server.AddTool(&mcp.Tool{Name: name, Description: desc, InputSchema: json.RawMessage(`{"type":"object"}`)},
		func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}, nil
		})
}

func (u *upstream) remove(name string) { u.server.RemoveTools(name) }

// probeNames returns the tool names of the id-less tools/call messages seen.
func (u *upstream) probeNames() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.probes...)
}

// answerProbe recognises a tools/call without an id, records it and answers
// it the way probeMode says; in the default mode it leaves the answer to the
// go-sdk server, which refuses the shape with 400.
func (u *upstream) answerProbe(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return false
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	var msg struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	if json.Unmarshal(body, &msg) != nil || msg.Method != methodToolsCall || (len(msg.ID) > 0 && string(msg.ID) != "null") {
		return false
	}
	u.mu.Lock()
	u.probes = append(u.probes, msg.Params.Name)
	u.mu.Unlock()
	const rpcError = `{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"id required"}}`
	switch u.probeMode.Load() {
	case probeModeForward:
		w.WriteHeader(http.StatusAccepted)
	case probeModeRPCError:
		w.Header().Set("Content-Type", mediaJSON)
		_, _ = io.WriteString(w, rpcError)
	case probeModeSSEError:
		w.Header().Set("Content-Type", mediaSSE)
		_, _ = io.WriteString(w, "event: message\r\ndata: "+rpcError+"\r\n\r\n")
	case probeModeSilent:
		w.Header().Set("Content-Type", mediaJSON)
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":null,"result":{}}`)
	default:
		return false
	}
	return true
}
