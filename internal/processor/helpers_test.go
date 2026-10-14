package processor

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/structpb"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	api "github.com/sairam0424/toolwarrant/internal/extmcpv1"
	"github.com/sairam0424/toolwarrant/internal/gate"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

const testServer = "mock"

// fakeSource is a controllable catalog Source that counts its calls.
type fakeSource struct {
	mu        sync.Mutex
	gen       int64
	snap      catalog.Snapshot
	crawledAt time.Time // the latest complete crawl every snapshot reports; zero means none
	genErr    error
	snapErr   error
	genCalls  int
	snapCalls int
}

func newFakeSource(tools map[string]catalog.ToolPolicy) *fakeSource {
	return &fakeSource{gen: 1, snap: snapshotOf(tools)}
}

func (f *fakeSource) Generation(context.Context) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.genCalls++
	if f.genErr != nil {
		return 0, f.genErr
	}
	return f.gen, nil
}

func (f *fakeSource) Snapshot(_ context.Context, server string) (catalog.Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snapCalls++
	if f.snapErr != nil {
		return catalog.Snapshot{}, f.snapErr
	}
	s := f.snap
	s.Server = server
	s.CrawledAt = f.crawledAt
	return s, nil
}

// crawled records when the latest complete crawl of the server ran and bumps
// the generation, as a crawl's committed write does; the contents are kept.
func (f *fakeSource) crawled(at time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gen++
	f.crawledAt = at
}

// publish replaces the catalog contents and bumps the generation, like a
// committed write would.
func (f *fakeSource) publish(tools map[string]catalog.ToolPolicy) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gen++
	f.snap = catalog.Snapshot{Server: testServer, Generation: f.gen, Tools: tools}
}

func (f *fakeSource) failGeneration(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.genErr = err
}

func (f *fakeSource) failSnapshot(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snapErr = err
}

func (f *fakeSource) calls() (gen, snap int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.genCalls, f.snapCalls
}

// syncBuffer is a goroutine-safe log sink.
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

func newTestServer(src Source, mutate ...func(*Config)) (*Server, *syncBuffer) {
	logs := &syncBuffer{}
	cfg := Config{
		Server: testServer,
		Logger: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	for _, m := range mutate {
		m(&cfg)
	}
	return New(src, cfg), logs
}

// q returns s as a JSON string literal.
func q(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}

// tool builds a compact tool definition.
func tool(name, desc string) []byte {
	return []byte(`{"name":` + q(name) + `,"description":` + q(desc) +
		`,"inputSchema":{"type":"object","properties":{"m":{"type":"string"}}}}`)
}

func mustDigest(t *testing.T, raw []byte) string {
	t.Helper()
	d, err := gate.Digest(raw)
	if err != nil {
		t.Fatalf("gate.Digest(%s): %v", raw, err)
	}
	return d
}

func policy(state lifecycle.State, approved, lastSeen string) catalog.ToolPolicy {
	return catalog.ToolPolicy{State: state, Approved: approved, LastSeen: lastSeen}
}

// servedPolicy is an enabled tool whose approved digest is also what the
// latest crawl saw: the healthy steady state.
func servedPolicy(digest string) catalog.ToolPolicy {
	return policy(lifecycle.Enabled, digest, digest)
}

func snapshotOf(tools map[string]catalog.ToolPolicy) catalog.Snapshot {
	return catalog.Snapshot{Server: testServer, Tools: tools}
}

// listBody builds a tools/list result page.
func listBody(cursor string, tools ...[]byte) []byte {
	parts := make([]string, len(tools))
	for i, tl := range tools {
		parts[i] = string(tl)
	}
	body := `{"tools":[` + strings.Join(parts, ",") + `]`
	if cursor != "" {
		body += `,"nextCursor":` + q(cursor)
	}
	return []byte(body + `}`)
}

// listMsg is a tools/list response hook as the gateway sends it for the
// guarded route: exactly one service name, the server's.
func listMsg(body []byte) *api.McpResponse {
	return &api.McpResponse{Method: "tools/list", ServiceNames: []string{testServer}, McpResponse: body}
}

func list(t *testing.T, s *Server, body []byte) *api.McpResponseResult {
	t.Helper()
	return listVia(t, s, listMsg(body))
}

func listVia(t *testing.T, s *Server, resp *api.McpResponse) *api.McpResponseResult {
	t.Helper()
	res, err := s.CheckResponse(context.Background(), resp)
	if err != nil {
		t.Fatalf("CheckResponse returned a transport error: %v", err)
	}
	if res == nil {
		t.Fatal("CheckResponse returned a nil result")
	}
	return res
}

func call(t *testing.T, s *Server, req *api.McpRequest) *api.McpRequestResult {
	t.Helper()
	res, err := s.CheckRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("CheckRequest returned a transport error: %v", err)
	}
	if res == nil {
		t.Fatal("CheckRequest returned a nil result")
	}
	return res
}

// callReq is a tools/call request hook for the guarded route.
func callReq(name string) *api.McpRequest {
	return rawCallReq(`{"name":` + q(name) + `,"arguments":{"m":"hi"}}`)
}

func rawCallReq(params string) *api.McpRequest {
	return &api.McpRequest{Method: "tools/call", ServiceNames: []string{testServer}, McpRequest: []byte(params)}
}

// secretMeta builds the metadata_context the gateway sends when the processor
// entry in its configuration carries a toolwarrant_secret value.
func secretMeta(t *testing.T, value any) *structpb.Struct {
	t.Helper()
	md, err := structpb.NewStruct(map[string]any{SecretMetadataKey: value})
	if err != nil {
		t.Fatalf("structpb.NewStruct: %v", err)
	}
	return md
}

// namesIn returns the tool names in a tools/list result, in order.
func namesIn(t *testing.T, out []byte) []string {
	t.Helper()
	var r struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("result is not valid JSON: %v\n%s", err, out)
	}
	names := make([]string, 0, len(r.Tools))
	for _, tl := range r.Tools {
		names = append(names, tl.Name)
	}
	return names
}

// servedNames asserts the result is a filtered list and returns its tool names.
func servedNames(t *testing.T, res *api.McpResponseResult) []string {
	t.Helper()
	if res.GetPass() != nil {
		t.Fatal("tools/list was passed through unfiltered")
	}
	if e := res.GetError(); e != nil {
		t.Fatalf("tools/list was denied: %s", e.GetReason())
	}
	if res.GetMutated() == nil {
		t.Fatal("result carries neither a list nor an error")
	}
	return namesIn(t, res.GetMutated())
}

// requireListDenied asserts the list was refused with the given code and that
// no list bytes leaked into the result.
func requireListDenied(t *testing.T, res *api.McpResponseResult, code api.AuthorizationError_Code) *api.AuthorizationError {
	t.Helper()
	if res.GetPass() != nil || res.GetMutated() != nil {
		t.Fatalf("a denied list must not carry list bytes: %v", res)
	}
	e := res.GetError()
	if e == nil {
		t.Fatal("expected an AuthorizationError")
	}
	if e.GetCode() != code {
		t.Fatalf("code = %v, want %v (reason %q)", e.GetCode(), code, e.GetReason())
	}
	return e
}

func requireAllowed(t *testing.T, res *api.McpRequestResult) {
	t.Helper()
	if res.GetPass() == nil {
		t.Fatalf("call was not allowed: %v", res)
	}
}

// requireCallDenied asserts a PERMISSION_DENIED whose reason names the quoted
// tool and the cause class.
func requireCallDenied(t *testing.T, res *api.McpRequestResult, name string, want cause) {
	t.Helper()
	e := res.GetError()
	if e == nil {
		t.Fatalf("call was not denied: %v", res)
	}
	if e.GetCode() != api.AuthorizationError_PERMISSION_DENIED {
		t.Fatalf("code = %v, want PERMISSION_DENIED", e.GetCode())
	}
	if !strings.Contains(e.GetReason(), quoteName(name)) {
		t.Errorf("reason %q does not name the quoted tool %s", e.GetReason(), quoteName(name))
	}
	if !strings.Contains(e.GetReason(), string(want)) {
		t.Errorf("reason %q does not carry the cause %q", e.GetReason(), want)
	}
}

// requireRefused asserts a tools/call denial decided before the tool name was
// read: the given code and a reason that carries only the cause class.
func requireRefused(t *testing.T, res *api.McpRequestResult, code api.AuthorizationError_Code, want cause) {
	t.Helper()
	e := res.GetError()
	if e == nil {
		t.Fatalf("call was not denied: %v", res)
	}
	if e.GetCode() != code {
		t.Fatalf("code = %v, want %v (reason %q)", e.GetCode(), code, e.GetReason())
	}
	if !strings.Contains(e.GetReason(), string(want)) {
		t.Errorf("reason %q does not carry the cause %q", e.GetReason(), want)
	}
}

// replace swaps the catalog contents without moving the generation, the way a
// fresh file at the same path can happen to carry the number the processor
// cached its snapshot under.
func (f *fakeSource) replace(tools map[string]catalog.ToolPolicy) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snap = catalog.Snapshot{Server: testServer, Generation: f.gen, Tools: tools}
}
