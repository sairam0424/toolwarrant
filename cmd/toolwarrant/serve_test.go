package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	"github.com/sairam0424/toolwarrant/internal/crawl"
	api "github.com/sairam0424/toolwarrant/internal/extmcpv1"
	"github.com/sairam0424/toolwarrant/internal/fetch"
	"github.com/sairam0424/toolwarrant/internal/processor"
)

const (
	// maxUnixPath is the shortest sun_path limit among the supported systems.
	maxUnixPath = 100
	secretVar   = "TW_SECRET"
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

// listHook is a tools/list response hook as the gateway sends it for the
// backend named target, carrying md as its metadata context (nil for none).
func listHook(target string, body []byte, md *structpb.Struct) *api.McpResponse {
	return &api.McpResponse{Method: "tools/list", ServiceNames: []string{target}, MetadataContext: md, McpResponse: body}
}

// callHook is a tools/call request hook for one tool of the backend target.
func callHook(target, tool string, md *structpb.Struct) *api.McpRequest {
	return &api.McpRequest{Method: "tools/call", ServiceNames: []string{target}, MetadataContext: md, McpRequest: []byte(`{"name":"` + tool + `","arguments":{}}`)}
}

// secretMetadata is the metadata context the gateway builds from the emitted
// processor entry.
func secretMetadata(t *testing.T, shared string) *structpb.Struct {
	t.Helper()
	md, err := structpb.NewStruct(map[string]any{processor.SecretMetadataKey: shared})
	if err != nil {
		t.Fatal(err)
	}
	return md
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

// dial connects a gRPC client to a running processor.
func dial(t *testing.T, addr string) (api.ExtMcpClient, context.Context) {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	t.Cleanup(cancel)
	return api.NewExtMcpClient(conn), ctx
}

func TestServeRefusesNonLoopbackAndBadAddresses(t *testing.T) {
	c, _ := fixture(t)
	r := c.fail(exitUsage, "serve", "--server", "s1", "--listen", "0.0.0.0:0")
	wantContains(t, "stderr", r.stderr, "not a loopback address", "--allow-non-loopback", "--secret-env")
	c.fail(exitUsage, "serve", "--server", "s1", "--listen", ":0")
	c.fail(exitUsage, "serve", "--server", "s1", "--listen", "192.168.1.10:9001")
	// The permission alone is refused: without a shared secret anyone who
	// reaches the port decides what the gateway serves, so the operator must
	// name the secret or say in so many words that there is none.
	r = c.fail(exitUsage, "serve", "--server", "s1", "--listen", "192.168.1.10:9001", "--allow-non-loopback")
	wantContains(t, "stderr", r.stderr, "refusing to listen on 192.168.1.10:9001 without a shared secret", "--secret-env", "--insecure-no-secret")
	r = c.fail(exitUsage, "serve", "--server", "s1", "--listen", "0.0.0.0:0", "--allow-non-loopback", "--secret-env", "UNSET_SECRET")
	wantContains(t, "stderr", r.stderr, "UNSET_SECRET is unset")
	c.fail(exitUsage, "serve", "--server", "s1", "--listen", "nonsense")
	c.fail(exitUsage, "serve", "--server", "s1", "--listen", "unix:")
	c.fail(exitUsage, "serve", "--server", "s1", "--listen", "127.0.0.1:0", "extra")
	r = c.fail(exitFailure, "serve", "--server", "nope", "--listen", "127.0.0.1:0")
	wantContains(t, "stderr", r.stderr, "not found")
	r = c.fail(exitFailure, "serve", "--server", "s1", "--listen", "unix:"+filepath.Join(t.TempDir(), "missing", "dir", "p.sock"))
	wantContains(t, "stderr", r.stderr, "unix socket")
}

// The listen policy without a socket. The flags are permissions, not
// requests: a unix socket or a loopback address passes whatever they say, and
// an address other hosts can reach is refused unless --allow-non-loopback is
// given and either the hooks will carry the secret or --insecure-no-secret
// asks for an unauthenticated processor in so many words.
func TestCheckListenAddrPolicy(t *testing.T) {
	c := &command{name: "serve"}
	allow := listenPolicy{allowNonLoopback: true}
	withSecret := listenPolicy{allowNonLoopback: true, hasSecret: true}
	insecure := listenPolicy{allowNonLoopback: true, insecureNoSecret: true}
	noPermission := listenPolicy{hasSecret: true, insecureNoSecret: true}
	// O-2: a client certificate authority authenticates the hooks as the
	// secret does, so it satisfies the rule in its place; it is no permission.
	withClientCA := listenPolicy{allowNonLoopback: true, hasClientCA: true}
	cases := []struct {
		addr   string
		policy listenPolicy
		want   string // part of the refusal; "" when the address is accepted
	}{
		{"unix:/tmp/p.sock", listenPolicy{}, ""},
		{"unix:/tmp/p.sock", insecure, ""},
		{"unix:/tmp/p.sock", withClientCA, ""},
		{"unix:", withSecret, "needs a socket path"},
		{"127.0.0.1:9001", listenPolicy{}, ""},
		{"[::1]:9001", insecure, ""},
		{"localhost:9001", withSecret, ""},
		{"10.0.0.7:9001", listenPolicy{}, "not a loopback address"},
		{"10.0.0.7:9001", listenPolicy{}, "--tls-client-ca"},
		{"10.0.0.7:9001", noPermission, "not a loopback address"},
		{"10.0.0.7:9001", listenPolicy{hasClientCA: true}, "not a loopback address"},
		{"10.0.0.7:9001", allow, "without a shared secret"},
		{"10.0.0.7:9001", allow, "--tls-client-ca"},
		{"[2001:db8::7]:9001", allow, "without a shared secret"},
		{"0.0.0.0:9001", allow, "without a shared secret"},
		{"10.0.0.7:9001", withSecret, ""},
		{"10.0.0.7:9001", withClientCA, ""},
		{"0.0.0.0:9001", withClientCA, ""},
		{"10.0.0.7:9001", insecure, ""},
		{":9001", withSecret, ""},
		{"nonsense", insecure, "neither host:port nor unix:/path"},
	}
	for _, tc := range cases {
		err := checkListenAddr(c, tc.addr, tc.policy)
		if tc.want == "" {
			if err != nil {
				t.Errorf("%s with %+v: refused: %v", tc.addr, tc.policy, err)
			}
			continue
		}
		var usage *usageError
		if err == nil || !errors.As(err, &usage) || usage.cmd != c || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s with %+v: %v, want a serve usage error mentioning %q", tc.addr, tc.policy, err, tc.want)
		}
	}
}

// On a loopback address the two permissions change nothing, so both flags
// parse, the processor starts, and the listening line still says whether
// hooks are authenticated.
func TestServeAcceptsTheExposureFlagsOnLoopback(t *testing.T) {
	c, _ := fixture(t)
	out, _, stop := c.start("serve", "--server", "s1", "--listen", "127.0.0.1:0", "--allow-non-loopback", "--insecure-no-secret")
	if addr := waitListening(t, out); !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Fatalf("listening on %q, want a loopback address", addr)
	}
	if code := stop(); code != exitOK {
		t.Fatalf("serve exit %d:\n%s", code, out.String())
	}
	wantContains(t, "stdout", out.String(), "hooks are not authenticated")

	c.env[secretVar] = plant("shared")
	out, errb, stop := c.start("serve", "--server", "s1", "--listen", "127.0.0.1:0", "--allow-non-loopback", "--secret-env", secretVar)
	waitListening(t, out)
	if code := stop(); code != exitOK {
		t.Fatalf("serve exit %d:\n%s", code, out.String())
	}
	wantContains(t, "stdout", out.String(), "hooks must carry the shared secret")
	wantNotContains(t, "output", out.String()+errb.String(), canary)
}

func TestServeEnforcesApprovalsOverGRPC(t *testing.T) {
	c, u := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	out, _, stop := c.start("serve", "--server", "s1", "--listen", "127.0.0.1:0")
	addr := waitListening(t, out)
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Fatalf("listening on %q, want a loopback address", addr)
	}
	client, ctx := dial(t, addr)
	body := listBody(rawTools(t, u.url()))

	res, err := client.CheckResponse(ctx, listHook("s1", body, nil))
	if err != nil {
		t.Fatal(err)
	}
	if res.GetMutated() == nil {
		t.Fatalf("tools/list was not filtered: %v", res)
	}
	if names := servedNames(t, res.GetMutated()); len(names) != 1 || names[0] != "echo" {
		t.Fatalf("served %v, want only echo", names)
	}
	// D2: a hook about another backend is denied, never judged with s1's
	// approvals.
	other, err := client.CheckResponse(ctx, listHook("other", body, nil))
	if err != nil || other.GetError() == nil || !strings.Contains(other.GetError().GetReason(), "wrong backend") {
		t.Fatalf("hook for another backend = %v, %v; want a wrong-backend denial", other, err)
	}
	denied, err := client.CheckRequest(ctx, callHook("s1", "wipe_database", nil))
	if err != nil || denied.GetError() == nil {
		t.Fatalf("wipe_database call = %v, %v; want a denial", denied, err)
	}
	allowed, err := client.CheckRequest(ctx, callHook("s1", "echo", nil))
	if err != nil || allowed.GetPass() == nil {
		t.Fatalf("echo call = %v, %v; want pass", allowed, err)
	}

	if code := stop(); code != exitOK {
		t.Fatalf("serve exit %d:\n%s", code, out.String())
	}
	// docs/operations.md quotes this line; the unverified category was added
	// in the third round, the evidence dropped counter in the fourth and the
	// stale counter with --max-crawl-age (D21).
	wantContains(t, "stdout", out.String(), "guarding server s1, target s1", "hooks are not authenticated",
		"stats: lists served=1 denied=1, tools hidden=2 (mismatched=0 unapproved=2 oversized=0 unverified=0), calls allowed=1 denied=1 (stale=0), wrong backend=1, unauthenticated=0, throttled=0, source errors=0, evidence dropped=0\n")
}

// The stats line is quoted by docs/operations.md and read by operators, so
// every counter is pinned here in order, with values that cannot be confused
// with one another.
func TestWriteStatsPinsTheLine(t *testing.T) {
	var sb strings.Builder
	writeStats(&stream{w: &sb}, processor.Stats{ListsServed: 1, ListsDenied: 2, ToolsHidden: 3, ToolsMismatched: 4, ToolsUnapproved: 5, ToolsOversized: 6, ToolsUnverified: 7,
		CallsAllowed: 8, CallsDenied: 9, CallsStale: 10, WrongBackend: 11, Unauthenticated: 12, Throttled: 13, SourceErrors: 14, EvidenceDropped: 15})
	want := "stats: lists served=1 denied=2, tools hidden=3 (mismatched=4 unapproved=5 oversized=6 unverified=7), calls allowed=8 denied=9 (stale=10), wrong backend=11, unauthenticated=12, throttled=13, source errors=14, evidence dropped=15\n"
	if got := sb.String(); got != want {
		t.Errorf("stats line\n got %q\nwant %q", got, want)
	}
}

func TestServeRequiresTheSharedSecretWhenConfigured(t *testing.T) {
	c, u := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	c.env[secretVar] = plant("shared")
	out, errb, stop := c.start("serve", "--server", "s1", "--listen", "127.0.0.1:0", "--secret-env", secretVar, "--target", "s1", "--max-evidence-age", "1h")
	addr := waitListening(t, out)
	client, ctx := dial(t, addr)
	body := listBody(rawTools(t, u.url()))

	denied, err := client.CheckResponse(ctx, listHook("s1", body, nil))
	if err != nil || denied.GetError() == nil || !strings.Contains(denied.GetError().GetReason(), "secret") {
		t.Fatalf("hook without the secret = %v, %v; want a denial naming the secret", denied, err)
	}
	wrong, err := client.CheckRequest(ctx, callHook("s1", "echo", secretMetadata(t, plant("other"))))
	if err != nil || wrong.GetError() == nil {
		t.Fatalf("call with the wrong secret = %v, %v; want a denial", wrong, err)
	}
	res, err := client.CheckResponse(ctx, listHook("s1", body, secretMetadata(t, plant("shared"))))
	if err != nil || res.GetMutated() == nil {
		t.Fatalf("hook with the secret = %v, %v; want a filtered list", res, err)
	}
	if names := servedNames(t, res.GetMutated()); len(names) != 1 || names[0] != "echo" {
		t.Fatalf("served %v, want only echo", names)
	}
	if code := stop(); code != exitOK {
		t.Fatalf("serve exit %d:\n%s", code, out.String())
	}
	wantContains(t, "stdout", out.String(), "hooks must carry the shared secret", "unauthenticated=2")
	wantNotContains(t, "output", out.String()+errb.String(), canary)
}

func TestServeHidesEverythingOfAPausedServer(t *testing.T) {
	c, u := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	c.ok("--as", "alice", "server", "pause", "s1")
	out, _, stop := c.start("serve", "--server", "s1", "--listen", "127.0.0.1:0")
	client, ctx := dial(t, waitListening(t, out))

	res, err := client.CheckResponse(ctx, listHook("s1", listBody(rawTools(t, u.url())), nil))
	if err != nil {
		t.Fatal(err)
	}
	if res.GetPass() != nil {
		t.Fatal("the list of a paused server was passed through")
	}
	if m := res.GetMutated(); m != nil {
		if names := servedNames(t, m); len(names) != 0 {
			t.Fatalf("served %v from a paused server, want nothing", names)
		}
	}
	denied, err := client.CheckRequest(ctx, callHook("s1", "echo", nil))
	if err != nil || denied.GetError() == nil {
		t.Fatalf("call on a paused server = %v, %v; want a denial", denied, err)
	}
	if code := stop(); code != exitOK {
		t.Fatalf("serve exit %d:\n%s", code, out.String())
	}
}

func TestServeOpensTheCatalogReadOnly(t *testing.T) {
	c, _ := fixture(t)
	a := &app{ctx: context.Background(), stdout: &stream{w: io.Discard}, stderr: &stream{w: io.Discard}, getenv: c.getenv, globals: globals{db: c.db}}
	alice := catalog.Actor{Name: "alice", Type: catalog.ActorHuman}
	for _, mode := range []openMode{openReadOnly, openForensic} {
		store, err := a.openStore(mode)
		if err != nil {
			t.Fatalf("mode %d: %v", mode, err)
		}
		if !store.ReadOnly() {
			t.Errorf("mode %d opened the catalog writable", mode)
		}
		_, err = store.AddServer(a.ctx, catalog.ServerSpec{Name: "x", URL: "https://x.example.com/mcp"}, alice)
		if !errors.Is(err, catalog.ErrReadOnly) {
			t.Errorf("mode %d: write = %v, want ErrReadOnly", mode, err)
		}
		if msg := describe(err); !strings.Contains(msg, adviceReadOnly) {
			t.Errorf("describe = %q", msg)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	}
	missing := &app{ctx: context.Background(), getenv: c.getenv, globals: globals{db: filepath.Join(t.TempDir(), "none.db")}}
	for _, mode := range []openMode{openWrite, openReadOnly, openForensic} {
		if _, err := missing.openStore(mode); err == nil || !strings.Contains(err.Error(), "does not exist") {
			t.Errorf("mode %d on a missing file: %v", mode, err)
		}
	}
	if _, err := os.Stat(missing.globals.db); !os.IsNotExist(err) {
		t.Error("a non-create open made the file")
	}
}

func TestServeOnAUnixSocketIsOwnerOnlyAndWarnsAboutALooseDirectory(t *testing.T) {
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
	out, errb, stop := c.start("serve", "--server", "s1", "--listen", unixPrefix+path)
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
	wantNotContains(t, "stderr for a 0700 directory", errb.String(), "warning")

	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	out, errb, stop = c.start("serve", "--server", "s1", "--listen", unixPrefix+path)
	waitListening(t, out)
	if code := stop(); code != exitOK {
		t.Fatalf("serve exit %d:\n%s", code, out.String())
	}
	wantContains(t, "stderr for a 0755 directory", errb.String(), "warning: socket directory", "0755", "not 0700")
}
