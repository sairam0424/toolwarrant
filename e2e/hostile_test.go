//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The hostile upstream is a raw MCP Streamable HTTP server that answers
// tools/list with whatever bytes the test put on its page. The go-sdk server
// cannot list one name twice or carry a top-level key it does not know, and
// those two pages are exactly what scenarios J and L need: everything an
// upstream sends is hostile, so the test must be able to send anything.
const (
	hostileSessionID = "hostile-session-1"
	hostileMaxBody   = 1 << 20
	hostileShutdown  = 5 * time.Second
	// defaultProtocol is answered when a client sends no protocolVersion.
	defaultProtocol = "2025-06-18"
)

// rpcMessage is the part of a JSON-RPC message the server reads. The id is
// kept raw so that a number or a string is echoed exactly.
type rpcMessage struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

// hostileServer serves /mcp with a page the test controls and logs every
// request it receives, so a failure can show what the gateway asked.
type hostileServer struct {
	srv   *http.Server
	url   string
	log   *os.File
	logMu sync.Mutex
	mu    sync.Mutex
	page  []json.RawMessage
	calls atomic.Int64
}

// startHostile listens on a free loopback port and serves until the root test
// ends.
func startHostile(t *testing.T, s *stack, name string) *hostileServer {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for the hostile upstream: %v", err)
	}
	logf, err := os.Create(filepath.Join(s.h.logDir, name+".requests.log"))
	if err != nil {
		t.Fatalf("create the hostile upstream log: %v", err)
	}
	hs := &hostileServer{url: fmt.Sprintf("http://%s/mcp", lis.Addr().String()), log: logf}
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", hs.handle)
	hs.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = hs.srv.Serve(lis) }()
	s.root.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), hostileShutdown)
		defer cancel()
		_ = hs.srv.Shutdown(ctx)
		_ = logf.Close()
	})
	return hs
}

// setPage replaces the tools/list page.
func (hs *hostileServer) setPage(tools ...json.RawMessage) {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	hs.page = append([]json.RawMessage(nil), tools...)
}

func (hs *hostileServer) note(format string, args ...any) {
	hs.logMu.Lock()
	defer hs.logMu.Unlock()
	_, _ = fmt.Fprintf(hs.log, time.Now().UTC().Format(time.RFC3339Nano)+" "+format+"\n", args...)
}

// handle speaks just enough Streamable HTTP for the crawler and the gateway:
// POST carries JSON-RPC, GET (the optional SSE stream) is refused, DELETE ends
// the session.
func (hs *hostileServer) handle(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		hs.note("GET refused")
		http.Error(w, "no standalone stream", http.StatusMethodNotAllowed)
	case http.MethodDelete:
		hs.note("DELETE session")
		w.WriteHeader(http.StatusOK)
	case http.MethodPost:
		hs.handlePost(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (hs *hostileServer) handlePost(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, hostileMaxBody))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var msg rpcMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		http.Error(w, "not json-rpc", http.StatusBadRequest)
		return
	}
	hs.note("POST %s session=%q protocol=%q body=%s", msg.Method, r.Header.Get("Mcp-Session-Id"), r.Header.Get("MCP-Protocol-Version"), body)
	if len(msg.ID) == 0 || bytes.Equal(msg.ID, []byte("null")) {
		w.WriteHeader(http.StatusAccepted) // a notification
		return
	}
	switch msg.Method {
	case "initialize":
		w.Header().Set("Mcp-Session-Id", hostileSessionID)
		hs.reply(w, msg.ID, hs.initResult(msg.Params))
	case "ping":
		hs.reply(w, msg.ID, json.RawMessage(`{}`))
	case "tools/list":
		hs.reply(w, msg.ID, hs.listResult())
	case "tools/call":
		hs.calls.Add(1)
		hs.reply(w, msg.ID, json.RawMessage(`{"content":[{"type":"text","text":"`+hostileReply+`"}],"isError":false}`))
	default:
		hs.replyError(w, msg.ID, -32601, "method not found")
	}
}

// initResult negotiates whatever protocol version the client asked for and
// advertises the tools capability, which is what makes the gateway list.
func (hs *hostileServer) initResult(params json.RawMessage) json.RawMessage {
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(params, &p)
	if p.ProtocolVersion == "" {
		p.ProtocolVersion = defaultProtocol
	}
	version, _ := json.Marshal(p.ProtocolVersion)
	return json.RawMessage(`{"protocolVersion":` + string(version) + `,"capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"hostile","version":"0.0.1"}}`)
}

// listResult is the page, byte for byte, as a tools array.
func (hs *hostileServer) listResult() json.RawMessage {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	parts := make([]string, len(hs.page))
	for i, tool := range hs.page {
		parts[i] = string(tool)
	}
	return json.RawMessage(`{"tools":[` + strings.Join(parts, ",") + `]}`)
}

func (hs *hostileServer) reply(w http.ResponseWriter, id, result json.RawMessage) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":%s}`, id, result)
}

func (hs *hostileServer) replyError(w http.ResponseWriter, id json.RawMessage, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	text, _ := json.Marshal(message)
	_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":%d,"message":%s}}`, id, code, text)
}

// hostileEcho is an echo definition with the given description, so the
// hostile page can carry an approved copy and a changed one at once.
func hostileEcho(description string) json.RawMessage {
	desc, _ := json.Marshal(description)
	return json.RawMessage(`{"name":"echo","description":` + string(desc) + `,"inputSchema":{"type":"object","properties":{"message":{"type":"string"}},"required":["message"]}}`)
}

// padTool is a harmless-looking definition whose description is size bytes
// long, so a page can be made larger than the processor's payload cap while
// the tool next to it is the one that changed (scenario J).
func padTool(size int) json.RawMessage {
	return json.RawMessage(`{"name":"pad","description":"` + strings.Repeat("x", size) + `","inputSchema":{"type":"object"}}`)
}

// vendorTool is the definition scenario L lists through the gateway to record
// which key paths agentgateway v1.6.0 drops, keeps and adds before the hook
// (limit L2, the golden e2e/testdata/gateway_tool_keys.json). It carries the
// top-level members the MCP revision 2025-11-25 names (title, outputSchema,
// icons, execution), a _meta member of three shapes (a vendor-prefixed string,
// the ui object of MCP Apps, the openai/outputTemplate string), a vendor key
// inside inputSchema, an unknown annotations member x-risk and the unknown
// top-level key x-vendor whose dropping the scenario asserts by name, so that
// the tool keeps mismatching and MISSING vendor_tool keeps meaning something.
func vendorTool() json.RawMessage {
	return json.RawMessage(`{"name":"vendor_tool","title":"Vendor Tool","description":"Vendor tool with extension keys.","inputSchema":{"type":"object","properties":{"q":{"type":"string"}},"x-vendor":{"schema":"gold"}},"outputSchema":{"type":"object","properties":{"answer":{"type":"string"}}},"icons":[{"src":"https://example.invalid/icon.png","mimeType":"image/png","sizes":["48x48"]}],"execution":{"taskSupport":"optional"},"annotations":{"title":"Vendor","readOnlyHint":true,"x-risk":"low"},"_meta":{"vendor/ui":"https://example.invalid/ui","ui":{"resourceUri":"ui://vendor/panel"},"openai/outputTemplate":"ui://vendor/widget"},"x-vendor":{"tier":"gold"}}`)
}
