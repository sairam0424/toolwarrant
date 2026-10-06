package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/sairam0424/toolwarrant/internal/crawl"
	api "github.com/sairam0424/toolwarrant/internal/extmcpv1"
	"github.com/sairam0424/toolwarrant/internal/fetch"
)

const (
	// maxUnixPath is the shortest sun_path limit among the supported systems.
	maxUnixPath  = 100
	loopInterval = 30 * time.Millisecond
	loopRun      = 400 * time.Millisecond
)

var listeningLine = regexp.MustCompile(`listening on ([^,]+), guarding`)

// rawTools lists the upstream exactly as a gateway would see it, so the gRPC
// test can replay the real bytes through the processor.
func rawTools(t *testing.T, url string) []json.RawMessage {
	t.Helper()
	client, err := fetch.NewClient(fetch.Policy{AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	res, err := crawl.ListTools(context.Background(), url, crawl.Options{Client: client})
	if err != nil {
		t.Fatal(err)
	}
	out := make([]json.RawMessage, 0, len(res.Tools))
	for _, tool := range res.Tools {
		out = append(out, tool.Raw)
	}
	return out
}

func listBody(tools []json.RawMessage) []byte {
	parts := make([]string, len(tools))
	for i, tl := range tools {
		parts[i] = string(tl)
	}
	return []byte(`{"tools":[` + strings.Join(parts, ",") + `]}`)
}

func servedNames(t *testing.T, mutated []byte) []string {
	t.Helper()
	var r struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(mutated, &r); err != nil {
		t.Fatalf("mutated list is not json: %v: %s", err, mutated)
	}
	names := make([]string, 0, len(r.Tools))
	for _, tl := range r.Tools {
		names = append(names, tl.Name)
	}
	return names
}

func waitListening(t *testing.T, out *syncBuffer) string {
	t.Helper()
	var addr string
	waitFor(t, "the listening line", func() bool {
		m := listeningLine.FindStringSubmatch(out.String())
		if m == nil {
			return false
		}
		addr = m[1]
		return true
	})
	return addr
}

func TestServeRefusesNonLoopbackAndBadAddresses(t *testing.T) {
	c, _ := fixture(t)
	r := c.fail(exitUsage, "serve", "--server", "s1", "--listen", "0.0.0.0:0")
	wantContains(t, "stderr", r.stderr, "not a loopback address", "--allow-non-loopback")
	c.fail(exitUsage, "serve", "--server", "s1", "--listen", ":0")
	c.fail(exitUsage, "serve", "--server", "s1", "--listen", "192.168.1.10:9001")
	c.fail(exitUsage, "serve", "--server", "s1", "--listen", "nonsense")
	c.fail(exitUsage, "serve", "--server", "s1", "--listen", "unix:")
	c.fail(exitUsage, "serve", "--server", "s1", "--listen", "127.0.0.1:0", "extra")
	r = c.fail(exitFailure, "serve", "--server", "nope", "--listen", "127.0.0.1:0")
	wantContains(t, "stderr", r.stderr, "not found")
	r = c.fail(exitFailure, "serve", "--server", "s1", "--listen", "unix:"+filepath.Join(t.TempDir(), "missing", "dir", "p.sock"))
	wantContains(t, "stderr", r.stderr, "unix socket")
}

func TestServeEnforcesApprovalsOverGRPC(t *testing.T) {
	c, u := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	out, _, stop := c.start("serve", "--server", "s1", "--listen", "127.0.0.1:0")
	addr := waitListening(t, out)
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Fatalf("listening on %q, want a loopback address", addr)
	}

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := api.NewExtMcpClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	res, err := client.CheckResponse(ctx, &api.McpResponse{Method: "tools/list", McpResponse: listBody(rawTools(t, u.url()))})
	if err != nil {
		t.Fatal(err)
	}
	if res.GetMutated() == nil {
		t.Fatalf("tools/list was not filtered: %v", res)
	}
	if names := servedNames(t, res.GetMutated()); len(names) != 1 || names[0] != "echo" {
		t.Fatalf("served %v, want only echo", names)
	}
	denied, err := client.CheckRequest(ctx, &api.McpRequest{Method: "tools/call", McpRequest: []byte(`{"name":"wipe_database","arguments":{}}`)})
	if err != nil || denied.GetError() == nil {
		t.Fatalf("wipe_database call = %v, %v; want a denial", denied, err)
	}
	allowed, err := client.CheckRequest(ctx, &api.McpRequest{Method: "tools/call", McpRequest: []byte(`{"name":"echo","arguments":{}}`)})
	if err != nil || allowed.GetPass() == nil {
		t.Fatalf("echo call = %v, %v; want pass", allowed, err)
	}

	if code := stop(); code != exitOK {
		t.Fatalf("serve exit %d:\n%s", code, out.String())
	}
	wantContains(t, "stdout", out.String(), "stats:", "tools hidden=2", "calls allowed=1 denied=1", "guarding server s1")
}

func TestServeOnAUnixSocketIsOwnerOnly(t *testing.T) {
	dir, err := os.MkdirTemp("", "tw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "p.sock")
	if len(path) > maxUnixPath {
		t.Skipf("temp path too long for a unix socket: %s", path)
	}
	c, _ := fixture(t)
	out, _, stop := c.start("serve", "--server", "s1", "--listen", unixPrefix+path)
	if addr := waitListening(t, out); addr != path {
		t.Fatalf("listening on %q, want %q", addr, path)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != socketMode {
		t.Errorf("socket mode %v, want a socket with %o", fi.Mode(), socketMode)
	}
	if code := stop(); code != exitOK {
		t.Fatalf("serve exit %d:\n%s", code, out.String())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("socket file still present after shutdown: %v", err)
	}
}

func TestCrawlEveryRepeatsAndSurvivesFailures(t *testing.T) {
	c := newCLI(t)
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer broken.Close()
	c.ok("server", "add", "down", broken.URL, "--allow-private")
	u := newUpstream(t, map[string]string{"echo": echoV1})
	c.ok("server", "add", "up", u.url(), "--allow-private")

	ctx, cancel := context.WithTimeout(context.Background(), loopRun)
	defer cancel()
	r := c.runCtx(ctx, "crawl", "down", "--every", loopInterval.String())
	if r.code != exitOK {
		t.Fatalf("crawl --every against a broken upstream: exit %d: %s", r.code, r.stderr)
	}
	lines := strings.Split(strings.TrimSpace(r.stdout), "\n")
	if len(lines) < 2 {
		t.Fatalf("want at least two crawl lines, got:\n%s", r.stdout)
	}
	for _, line := range lines {
		wantContains(t, "line", line, "down:", "http status 500")
		wantNotContains(t, "line", line, broken.URL)
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), loopRun)
	defer cancel2()
	r = c.runCtx(ctx2, "crawl", "up", "--every", loopInterval.String(), "--json")
	if r.code != exitOK {
		t.Fatalf("crawl --every --json: exit %d: %s", r.code, r.stderr)
	}
	lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
	if len(lines) < 2 {
		t.Fatalf("want at least two json lines, got:\n%s", r.stdout)
	}
	for i, line := range lines {
		var rep crawlJSON
		if err := json.Unmarshal([]byte(line), &rep); err != nil || !rep.Complete || rep.Server != "up" {
			t.Fatalf("line %d = %s (%v)", i, line, err)
		}
	}
	// the crawls table has one row per iteration, every one of the broken ones incomplete
	var incomplete, complete int
	queryRow(t, c.db, "SELECT COUNT(*) FROM crawls WHERE complete = 0", &incomplete)
	queryRow(t, c.db, "SELECT COUNT(*) FROM crawls WHERE complete = 1", &complete)
	if incomplete < 2 || complete < 2 {
		t.Errorf("crawls recorded: %d incomplete, %d complete", incomplete, complete)
	}
}
