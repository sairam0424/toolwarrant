package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
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

// start runs a long-lived command in the background. The returned stop cancels
// it and returns its exit code.
func (c *cli) start(args ...string) (stdout, stderr *syncBuffer, stop func() int) {
	ctx, cancel := context.WithCancel(context.Background())
	stdout, stderr = &syncBuffer{}, &syncBuffer{}
	done := make(chan int, 1)
	full := append([]string{"--db", c.db}, args...)
	go func() { done <- runCtx(ctx, full, strings.NewReader(""), stdout, stderr, c.getenv) }()
	stop = func() int {
		cancel()
		select {
		case code := <-done:
			return code
		case <-time.After(testTimeout):
			c.t.Fatalf("%v did not stop after cancellation", args)
			return -1
		}
	}
	return stdout, stderr, stop
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
// really starts a fresh one every time.
type upstream struct {
	server   *mcp.Server
	http     *httptest.Server
	sessions atomic.Int64
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

func TestHelpAndVersion(t *testing.T) {
	c := newCLI(t)
	out := c.ok("help")
	wantContains(t, "help", out, "approve SERVER TOOL --hash HASH", "server add NAME URL", "server pause NAME", "server resume NAME",
		"crawl SERVER [--every DURATION] [--bearer-env VAR] [--strict] [--json]",
		"serve --server NAME --listen ADDR [--target NAME] [--secret-env VAR] [--allow-non-loopback [--insecure-no-secret]] [--max-evidence-age DURATION]",
		"emit --out FILE [--listen-port N] [--bind-address ADDR [--allow-all-interfaces]] [--processor-base-port N] [--processor NAME=HOST:PORT ...] [--secret-env VAR]",
		"verify-gateway --server NAME --url URL [--bearer-env VAR] [--config FILE] [--every DURATION] [--keep-going]",
		"audit verify", "exit codes", "-allow-self-approval")
	out = c.ok("version")
	wantContains(t, "version", out, programName+" dev", gatewayVersion)
	r := c.run("-h")
	if r.code != exitOK {
		t.Fatalf("-h exit %d: %s", r.code, r.stderr)
	}
	wantContains(t, "-h", r.stdout, "global flags")
	out = c.ok("approve", "-h")
	wantContains(t, "approve -h", out, "usage: toolwarrant [global flags] approve", "-hash", "-accept-suspicious")
	wantContains(t, "help serve", c.ok("help", "serve"), "-target", "-secret-env", "-max-evidence-age", "-allow-non-loopback", "-insecure-no-secret", "anyone who reaches the port")
	wantContains(t, "help verify-gateway", c.ok("help", "verify-gateway"), "-config", "-every", "-keep-going")
	wantContains(t, "help crawl", c.ok("help", "crawl"), "-strict", "-every")
	wantContains(t, "help emit", c.ok("help", "emit"), "-secret-env", "-bind-address", `(default "127.0.0.1")`, "-allow-all-interfaces", "a permission, not a request")
	out = c.ok("help", "server")
	wantContains(t, "help server", out, "server add", "server list", "server pause", "server resume")
	out = c.ok("help", "server", "add")
	wantContains(t, "help server add", out, "-allow-private", "-owner")
	out = c.ok("server", "-h")
	wantContains(t, "server -h", out, "subcommands")
	r = c.fail(exitUsage, "help", "nope")
	wantContains(t, "stderr", r.stderr, "unknown command")
}

func TestUsageErrors(t *testing.T) {
	c := newCLI(t)
	c.env["SHORT_SECRET"] = "short"
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no command", nil, "a command is required"},
		{"unknown command", []string{"frobnicate"}, "unknown command"},
		{"unknown global flag", []string{"--bogus", "list"}, "bogus"},
		{"approve without hash", []string{"approve", "s1", "echo"}, "--hash is required"},
		{"approve missing tool", []string{"approve", "s1", "--hash", "deadbeefdead"}, "expected 2 argument(s)"},
		{"server alone", []string{"server"}, "needs a subcommand"},
		{"server unknown", []string{"server", "frob"}, "unknown server subcommand"},
		{"server pause without name", []string{"server", "pause"}, "expected 1 argument(s)"},
		{"server resume as the system actor", []string{"--as", "crawler", "server", "resume", "s1"}, "system actor"},
		{"init extra", []string{"init", "extra"}, "expected 0 argument(s)"},
		{"list two", []string{"list", "a", "b"}, "at most one argument"},
		{"crawl negative every", []string{"crawl", "s1", "--every", "-1s"}, "--every must be at least"},
		{"crawl every below the minimum", []string{"crawl", "s1", "--every", "10ms"}, "--every must be at least 1s"},
		{"verify every below the minimum", []string{"verify-gateway", "--server", "s1", "--url", "http://127.0.0.1:1/mcp", "--every", "1ms"}, "--every must be at least 1s"},
		{"audit negative limit", []string{"audit", "list", "--limit", "-1"}, "must not be negative"},
		{"rollback without to", []string{"rollback", "s1", "echo"}, "--to is required"},
		{"reject without hash", []string{"reject", "s1", "echo"}, "--hash is required"},
		{"serve without flags", []string{"serve"}, "--server is required"},
		{"serve without listen", []string{"serve", "--server", "s1"}, "--listen is required"},
		{"serve negative evidence age", []string{"serve", "--server", "s1", "--listen", "127.0.0.1:0", "--max-evidence-age", "-1s"}, "must not be negative"},
		{"serve secret unset", []string{"serve", "--server", "s1", "--listen", "127.0.0.1:0", "--secret-env", "UNSET_SECRET"}, "UNSET_SECRET is unset"},
		{"serve non-loopback without a secret", []string{"serve", "--server", "s1", "--listen", "0.0.0.0:0", "--allow-non-loopback"}, "without a shared secret"},
		{"emit without out", []string{"emit"}, "--out is required"},
		{"emit secret too short", []string{"emit", "--out", "x", "--secret-env", "SHORT_SECRET"}, "16 to 256 printable ASCII"},
		{"emit wildcard bind without permission", []string{"emit", "--out", "x", "--bind-address", "0.0.0.0"}, "--allow-all-interfaces"},
		{"export without dir", []string{"export"}, "--dir is required"},
		{"verify without url", []string{"verify-gateway", "--server", "s1"}, "--url is required"},
		{"unknown subcommand flag", []string{"list", "--nope"}, "nope"},
		{"bad processor override", []string{"emit", "--out", "x", "--processor", "nonsense"}, "NAME=HOST:PORT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := c.sub(t).fail(exitUsage, tc.args...)
			wantContains(t, "stderr", r.stderr, tc.want, programName+":")
		})
	}
}

func TestInitIsIdempotentAndPrivate(t *testing.T) {
	c := newCLI(t)
	first := c.ok("init")
	second := c.ok("init")
	abs, err := filepath.Abs(c.db)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(first) != abs || first != second {
		t.Errorf("init printed %q then %q, want %q twice", first, second, abs)
	}
	fi, err := os.Stat(c.db)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != dbFileMode {
		t.Errorf("database mode %o, want %o", fi.Mode().Perm(), dbFileMode)
	}
}

func TestCommandsNeedAnExistingDatabase(t *testing.T) {
	c := &cli{t: t, db: filepath.Join(t.TempDir(), "missing.db"), env: map[string]string{}}
	for _, args := range [][]string{{"list"}, {"audit", "verify"}, {"serve", "--server", "s1", "--listen", "127.0.0.1:0"}} {
		r := c.fail(exitFailure, args...)
		wantContains(t, "stderr", r.stderr, "does not exist", programName+" init")
	}
	if _, err := os.Stat(c.db); !os.IsNotExist(err) {
		t.Error("a failed command must not create the database")
	}
}

func TestDatabasePathComesFromTheEnvironment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "env.db")
	var out, errb bytes.Buffer
	getenv := func(k string) string {
		if k == envDB {
			return path
		}
		return ""
	}
	if code := runCtx(context.Background(), []string{"init"}, strings.NewReader(""), &out, &errb, getenv); code != exitOK {
		t.Fatalf("init: exit %d: %s", code, errb.String())
	}
	if strings.TrimSpace(out.String()) != path {
		t.Errorf("init printed %q, want %q", out.String(), path)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("database not created: %v", err)
	}
}

func TestRunUsesASignalContext(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"version"}, strings.NewReader(""), &out, &errb, func(string) string { return "" })
	if code != exitOK || !strings.Contains(out.String(), programName+" dev") {
		t.Fatalf("run version: exit %d, out %q, err %q", code, out.String(), errb.String())
	}
}

func TestBrokenStreamsExitOne(t *testing.T) {
	ctx := context.Background()
	none := func(string) string { return "" }
	var errb bytes.Buffer
	code := runCtx(ctx, []string{"version"}, strings.NewReader(""), &brokenPipe{}, &errb, none)
	if code != exitFailure {
		t.Fatalf("version with a broken stdout: exit %d, want %d", code, exitFailure)
	}
	wantContains(t, "stderr", errb.String(), "writing to stdout failed", "broken pipe")

	// A broken stderr can only be reported through the exit code; the work
	// itself was done.
	c := newCLI(t)
	u := newUpstream(t, nil)
	var out bytes.Buffer
	code = runCtx(ctx, []string{"--db", c.db, "server", "add", "s1", u.url(), "--allow-private"}, strings.NewReader(""), &out, &brokenPipe{}, c.getenv)
	if code != exitFailure {
		t.Fatalf("server add with a broken stderr: exit %d, want %d", code, exitFailure)
	}
	wantContains(t, "stdout", out.String(), "added server s1")

	// A command that already failed keeps its more specific code.
	if code = runCtx(ctx, []string{"nope"}, strings.NewReader(""), &out, &brokenPipe{}, none); code != exitUsage {
		t.Errorf("unknown command with a broken stderr: exit %d, want %d", code, exitUsage)
	}
}

func TestActorNamesAreValidatedAndLowerCased(t *testing.T) {
	c := newCLI(t)
	u := newUpstream(t, nil)
	r := c.fail(exitUsage, "--as", "ali ce", "server", "add", "s1", u.url())
	wantContains(t, "stderr", r.stderr, "must match")
	r = c.fail(exitUsage, "--as", "ali"+zeroWidth+"ce", "server", "add", "s1", u.url())
	wantContains(t, "stderr", r.stderr, `\u{200B}`)
	wantNotContains(t, "stderr", r.stderr, zeroWidth)
	c.ok("--as", "Alice", "server", "add", "s1", u.url())
	c.env[envActor] = "BOB"
	c.ok("server", "add", "s2", u.url())
	entries := c.auditEntries()
	if len(entries) != 2 || entries[0].Actor != "alice" || entries[1].Actor != "bob" {
		t.Fatalf("audit actors = %+v, want alice then bob", entries)
	}
	if entries[0].ActorType != "human" || entries[0].Event != "server.added" {
		t.Errorf("entry = %+v", entries[0])
	}
}

func TestDefaultActorIsTheOSUser(t *testing.T) {
	who, err := user.Current()
	if err != nil || !actorNamePattern.MatchString(who.Username) {
		t.Skipf("os user %q is not usable as an actor name: %v", who, err)
	}
	c := newCLI(t)
	u := newUpstream(t, nil)
	c.ok("server", "add", "s1", u.url())
	entries := c.auditEntries()
	if len(entries) != 1 || entries[0].Actor != strings.ToLower(who.Username) {
		t.Fatalf("audit actors = %+v, want %q", entries, strings.ToLower(who.Username))
	}
}
