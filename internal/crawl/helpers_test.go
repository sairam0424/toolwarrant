package crawl

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// testTimeout keeps a hung test from stalling the suite.
const testTimeout = 10 * time.Second

// replyMode selects how the fake server encodes a JSON-RPC response.
type replyMode int

const (
	modeJSON      replyMode = iota // application/json
	modeSSE                        // text/event-stream, one clean event
	modeSSENoisy                   // SSE with comments, notifications, other ids, CRLF, multi-line data
	modeSSELoneCR                  // SSE whose lines all end in a bare CR
)

var allModes = map[string]replyMode{
	"json":      modeJSON,
	"sse":       modeSSE,
	"sse-noisy": modeSSENoisy,
	"sse-cr":    modeSSELoneCR,
}

// rpcIn is what the fake server decodes from a client POST.
type rpcIn struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

// seenReq records one request the fake server received.
type seenReq struct {
	HTTPMethod string
	RPCMethod  string
	Header     http.Header
	Body       string
}

// fake is a hand-written MCP server whose behaviour each test bends.
type fake struct {
	t    *testing.T
	mode replyMode
	// page returns the raw JSON result of the call-th tools/list request.
	page func(call int, cursor string) string
	// override may fully handle a request; it returns true when it did.
	override func(w http.ResponseWriter, r *http.Request, in rpcIn) bool
	// noSession makes initialize omit Mcp-Session-Id.
	noSession bool
	// initResult replaces the default initialize result when non-empty.
	initResult string

	mu    sync.Mutex
	seen  []seenReq
	calls int
	srv   *httptest.Server
}

const defaultInitResult = `{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"fake-server","version":"9.9"}}`

func newFake(t *testing.T, mode replyMode, page func(call int, cursor string) string) *fake {
	t.Helper()
	f := &fake{t: t, mode: mode, page: page}
	f.srv = httptest.NewServer(f)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fake) url() string { return f.srv.URL + "/mcp" }

func (f *fake) requests() []seenReq {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]seenReq(nil), f.seen...)
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var in rpcIn
	if r.Method == http.MethodPost {
		_ = json.Unmarshal(body, &in)
	}
	f.mu.Lock()
	f.seen = append(f.seen, seenReq{HTTPMethod: r.Method, RPCMethod: in.Method, Header: r.Header.Clone(), Body: string(body)})
	if in.Method == methodToolsList {
		f.calls++
	}
	call := f.calls
	f.mu.Unlock()

	if f.override != nil && f.override(w, r, in) {
		return
	}
	switch {
	case r.Method == http.MethodDelete:
		w.WriteHeader(http.StatusOK)
	case in.Method == methodInitialize:
		if !f.noSession {
			w.Header().Set(headerSessionID, "sess-123")
		}
		result := f.initResult
		if result == "" {
			result = defaultInitResult
		}
		f.reply(w, in.ID, result)
	case in.Method == methodInitialized:
		w.WriteHeader(http.StatusAccepted)
	case in.Method == methodToolsList:
		var p struct {
			Cursor string `json:"cursor"`
		}
		_ = json.Unmarshal(in.Params, &p)
		f.reply(w, in.ID, f.page(call, p.Cursor))
	default:
		http.Error(w, "unexpected", http.StatusBadRequest)
	}
}

// reply writes a JSON-RPC success response in the fake's mode.
func (f *fake) reply(w http.ResponseWriter, id json.RawMessage, result string) {
	msg := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":%s}`, id, result)
	writeMessage(w, f.mode, id, msg, result)
}

// writeMessage sends msg (a full JSON-RPC message with the given id and
// result) using mode's framing.
func writeMessage(w http.ResponseWriter, mode replyMode, id json.RawMessage, msg, result string) {
	if mode == modeJSON {
		w.Header().Set("Content-Type", mediaJSON)
		_, _ = io.WriteString(w, msg)
		return
	}
	w.Header().Set("Content-Type", mediaSSE)
	// An SSE data field cannot contain a line break, so a payload that has
	// one is sent as several data lines, which the client joins with LF.
	msg = strings.ReplaceAll(msg, "\n", "\ndata: ")
	result = strings.ReplaceAll(result, "\n", "\ndata: ")
	var out string
	switch mode {
	case modeSSE:
		out = "event: message\ndata: " + msg + "\n\n"
	case modeSSENoisy:
		out = ": keepalive\r\n\r\n" +
			"event: message\r\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{\"level\":\"info\"}}\r\n\r\n" +
			"data: {\"jsonrpc\":\"2.0\",\"id\":9999,\"result\":{\"tools\":[]}}\n\n" +
			"id: 7\nretry: 100\nevent: ping\ndata: not json at all\n\n" +
			"data:\n\n" +
			"id: 8\r\nevent: message\r\n" +
			"data: {\"jsonrpc\":\"2.0\",\r\n" +
			"data: \"id\":" + string(id) + ",\r\n" +
			"data: \"result\":" + result + "}\r\n\r\n" +
			"data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/after\"}\n\n"
	case modeSSELoneCR:
		out = ": c\r\revent: message\rdata: " + msg + "\r\r"
	}
	_, _ = io.WriteString(w, out)
}

// toolJSON is a plain tool definition named tool<i>.
func toolJSON(i int) string {
	return fmt.Sprintf(`{"name":"tool%d","description":"tool number %d","inputSchema":{"type":"object","properties":{"x":{"type":"string"}}}}`, i, i)
}

// pagesOf serves tools in pages of perPage with cursors "c1", "c2", ...
func pagesOf(perPage int, tools []string) func(call int, cursor string) string {
	return func(_ int, cursor string) string {
		start := 0
		if cursor != "" {
			var n int
			_, _ = fmt.Sscanf(cursor, "c%d", &n)
			start = n * perPage
		}
		end := min(start+perPage, len(tools))
		page := fmt.Sprintf(`{"tools":[%s]`, strings.Join(tools[start:end], ","))
		if end < len(tools) {
			page += fmt.Sprintf(`,"nextCursor":"c%d"`, end/perPage)
		}
		return page + "}"
	}
}

func nTools(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = toolJSON(i)
	}
	return out
}

// jsonEscape is the JSON \uXXXX escape of r (one half of a surrogate pair when
// r is a surrogate). The backslash is written as \x5c so that this source holds
// no \u sequence: tooling that normalises such sequences into the character
// they denote would quietly turn an escaped-spelling test into a plain one.
func jsonEscape(r rune) string {
	return fmt.Sprintf("\x5cu%04x", r)
}

func testOptions() Options {
	return Options{Client: &http.Client{Timeout: testTimeout}}
}
