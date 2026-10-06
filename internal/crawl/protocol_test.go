package crawl

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestListToolsAllResponseModes(t *testing.T) {
	for name, mode := range allModes {
		t.Run(name, func(t *testing.T) {
			f := newFake(t, mode, pagesOf(3, nTools(7)))
			res, err := ListTools(context.Background(), f.url(), testOptions())
			if err != nil {
				t.Fatalf("ListTools: %v", err)
			}
			if len(res.Tools) != 7 || res.Pages != 3 {
				t.Fatalf("tools=%d pages=%d, want 7 and 3", len(res.Tools), res.Pages)
			}
			for i, tool := range res.Tools {
				if tool.Name != "tool"+string(rune('0'+i)) || string(tool.Raw) != toolJSON(i) {
					t.Errorf("tool %d = %q %s", i, tool.Name, tool.Raw)
				}
			}
			if res.ServerName != "fake-server" || res.ServerVersion != "9.9" || res.ProtocolVersion != "2025-06-18" {
				t.Errorf("info = %q %q %q", res.ServerName, res.ServerVersion, res.ProtocolVersion)
			}
		})
	}
}

func TestListToolsRequestSequence(t *testing.T) {
	f := newFake(t, modeJSON, pagesOf(3, nTools(7)))
	opt := testOptions()
	opt.ClientName, opt.ClientVersion = "my-crawler", "4.5.6"
	if _, err := ListTools(context.Background(), f.url(), opt); err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	reqs := f.requests()
	wantSeq := []string{"POST initialize", "POST notifications/initialized", "POST tools/list", "POST tools/list", "POST tools/list", "DELETE "}
	if len(reqs) != len(wantSeq) {
		t.Fatalf("%d requests, want %d", len(reqs), len(wantSeq))
	}
	for i, r := range reqs {
		if got := r.HTTPMethod + " " + r.RPCMethod; got != wantSeq[i] {
			t.Errorf("request %d = %q, want %q", i, got, wantSeq[i])
		}
	}
	assertInitializeBody(t, reqs[0].Body)
	assertNotificationBody(t, reqs[1].Body)
	assertCursors(t, reqs)
	assertSessionHeaders(t, reqs)
}

func assertInitializeBody(t *testing.T, body string) {
	t.Helper()
	var msg struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Params  struct {
			ProtocolVersion string         `json:"protocolVersion"`
			Capabilities    map[string]any `json:"capabilities"`
			ClientInfo      struct {
				Name, Version string
			} `json:"clientInfo"`
		} `json:"params"`
	}
	if err := json.Unmarshal([]byte(body), &msg); err != nil {
		t.Fatalf("initialize body: %v", err)
	}
	p := msg.Params
	if msg.JSONRPC != "2.0" || msg.ID == 0 || p.ProtocolVersion != "2025-06-18" ||
		p.Capabilities == nil || len(p.Capabilities) != 0 ||
		p.ClientInfo.Name != "my-crawler" || p.ClientInfo.Version != "4.5.6" {
		t.Errorf("initialize body = %s", body)
	}
}

func assertNotificationBody(t *testing.T, body string) {
	t.Helper()
	var msg map[string]any
	if err := json.Unmarshal([]byte(body), &msg); err != nil {
		t.Fatalf("notification body: %v", err)
	}
	if _, hasID := msg["id"]; hasID || msg["method"] != methodInitialized {
		t.Errorf("notification must have no id: %s", body)
	}
}

func assertCursors(t *testing.T, reqs []seenReq) {
	t.Helper()
	want := []string{`{}`, `{"cursor":"c1"}`, `{"cursor":"c2"}`}
	var got []string
	for _, r := range reqs {
		if r.RPCMethod != methodToolsList {
			continue
		}
		var msg struct {
			Params json.RawMessage `json:"params"`
		}
		_ = json.Unmarshal([]byte(r.Body), &msg)
		got = append(got, string(msg.Params))
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("tools/list params = %v, want %v", got, want)
	}
}

func assertSessionHeaders(t *testing.T, reqs []seenReq) {
	t.Helper()
	if reqs[0].Header.Get("Mcp-Session-Id") != "" || reqs[0].Header.Get("MCP-Protocol-Version") != "" {
		t.Error("initialize must not carry session or protocol headers")
	}
	for i, r := range reqs {
		if r.HTTPMethod == http.MethodPost {
			if ct := r.Header.Get("Content-Type"); ct != "application/json" {
				t.Errorf("request %d Content-Type %q", i, ct)
			}
			if a := r.Header.Get("Accept"); a != "application/json, text/event-stream" {
				t.Errorf("request %d Accept %q", i, a)
			}
		}
		if i == 0 {
			continue
		}
		if r.Header.Get("Mcp-Session-Id") != "sess-123" || r.Header.Get("MCP-Protocol-Version") != "2025-06-18" {
			t.Errorf("request %d missing session or protocol header: %v", i, r.Header)
		}
	}
}

func TestListToolsWithoutSessionSkipsDelete(t *testing.T) {
	f := newFake(t, modeSSE, pagesOf(10, nTools(2)))
	f.noSession = true
	if _, err := ListTools(context.Background(), f.url(), testOptions()); err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	for _, r := range f.requests() {
		if r.HTTPMethod == http.MethodDelete || r.Header.Get("Mcp-Session-Id") != "" {
			t.Errorf("stateless server saw %s with session header %q", r.HTTPMethod, r.Header.Get("Mcp-Session-Id"))
		}
		if r.RPCMethod == methodToolsList && r.Header.Get("MCP-Protocol-Version") == "" {
			t.Error("protocol header must be sent even without a session")
		}
	}
}

func TestListToolsIgnoresFailedDelete(t *testing.T) {
	for _, status := range []int{http.StatusMethodNotAllowed, http.StatusInternalServerError} {
		f := newFake(t, modeJSON, pagesOf(10, nTools(2)))
		f.override = func(w http.ResponseWriter, r *http.Request, _ rpcIn) bool {
			if r.Method == http.MethodDelete {
				w.WriteHeader(status)
				return true
			}
			return false
		}
		res, err := ListTools(context.Background(), f.url(), testOptions())
		if err != nil || len(res.Tools) != 2 {
			t.Errorf("DELETE %d must not fail the crawl: tools=%d err=%v", status, len(res.Tools), err)
		}
	}
}

func TestListToolsEndsSessionAfterFailure(t *testing.T) {
	f := newFake(t, modeJSON, func(int, string) string { return `{"tools":"nope"}` })
	if _, err := ListTools(context.Background(), f.url(), testOptions()); err == nil {
		t.Fatal("want an error")
	}
	reqs := f.requests()
	if last := reqs[len(reqs)-1]; last.HTTPMethod != http.MethodDelete {
		t.Errorf("last request = %s, want DELETE even after a failed crawl", last.HTTPMethod)
	}
}

func TestListToolsStopsAtResponseOnOpenStream(t *testing.T) {
	f := newFake(t, modeSSE, pagesOf(10, nTools(2)))
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	f.override = func(w http.ResponseWriter, r *http.Request, in rpcIn) bool {
		if in.Method != methodToolsList {
			return false
		}
		f.reply(w, in.ID, f.page(1, ""))
		w.(http.Flusher).Flush()
		select { // a server that keeps the stream open after answering
		case <-release:
		case <-r.Context().Done():
		}
		return true
	}
	done := make(chan error, 1)
	go func() {
		_, err := ListTools(context.Background(), f.url(), testOptions())
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ListTools: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ListTools waited for the end of an open event stream")
	}
}

func TestListToolsDefaultsAndCustomLimits(t *testing.T) {
	cfg, err := newConfig("http://127.0.0.1:1/mcp", testOptions())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.maxPages != 100 || cfg.maxTools != 10000 || cfg.maxMessage != 8<<20 ||
		cfg.maxToolBytes != 256<<10 || cfg.maxTotal != 32<<20 || cfg.timeout != 5*time.Minute {
		t.Errorf("default limits = %+v", cfg)
	}
	if cfg.clientName != defaultClientName || cfg.clientVersion != defaultClientVersion || cfg.clientName == "" || cfg.clientVersion == "" {
		t.Errorf("default clientInfo = %q %q", cfg.clientName, cfg.clientVersion)
	}
	opt := testOptions()
	opt.MaxPages, opt.MaxTools, opt.MaxMessageBytes, opt.MaxToolBytes, opt.MaxTotalBytes = 1, 2, 3, 4, 5
	opt.Timeout, opt.ClientName, opt.ClientVersion = 6*time.Second, "n", "v"
	cfg, err = newConfig("http://127.0.0.1:1/mcp", opt)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.maxPages != 1 || cfg.maxTools != 2 || cfg.maxMessage != 3 || cfg.maxToolBytes != 4 || cfg.maxTotal != 5 ||
		cfg.timeout != 6*time.Second || cfg.clientName != "n" || cfg.clientVersion != "v" {
		t.Errorf("explicit values not honoured: %+v", cfg)
	}
}

// TestDefaultClientInfoIsNeutral: the crawler must not announce itself. An
// upstream that recognises toolwarrant can show it the approved definition and
// show the gateway another one, so the default clientInfo removes the easiest
// tell; the package comment lists the tells that remain.
func TestDefaultClientInfoIsNeutral(t *testing.T) {
	f := newFake(t, modeJSON, pagesOf(5, nTools(1)))
	if _, err := ListTools(context.Background(), f.url(), testOptions()); err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	var msg struct {
		Params struct {
			ClientInfo struct{ Name, Version string } `json:"clientInfo"`
		} `json:"params"`
	}
	if err := json.Unmarshal([]byte(f.requests()[0].Body), &msg); err != nil {
		t.Fatalf("initialize body: %v", err)
	}
	info := msg.Params.ClientInfo
	if info.Name != defaultClientName || info.Version != defaultClientVersion {
		t.Errorf("clientInfo on the wire = %+v, want the defaults", info)
	}
	if lower := strings.ToLower(info.Name + info.Version); strings.Contains(lower, "warrant") || strings.Contains(lower, "crawl") {
		t.Errorf("default clientInfo %+v announces the crawler", info)
	}
}

func TestContentTypeParametersAreAccepted(t *testing.T) {
	for _, tc := range []struct{ contentType, framing string }{
		{"application/json; charset=utf-8", "json"},
		{"Application/JSON", "json"},
		{"Text/Event-Stream;charset=UTF-8", "sse"},
	} {
		f := newFake(t, modeJSON, pagesOf(5, nTools(1)))
		f.override = func(w http.ResponseWriter, _ *http.Request, in rpcIn) bool {
			if in.Method != methodToolsList {
				return false
			}
			msg := `{"jsonrpc":"2.0","id":` + string(in.ID) + `,"result":` + f.page(1, "") + `}`
			w.Header().Set("Content-Type", tc.contentType)
			if tc.framing == "sse" {
				msg = "data: " + msg + "\n\n"
			}
			_, _ = io.WriteString(w, msg)
			return true
		}
		res, err := ListTools(context.Background(), f.url(), testOptions())
		if err != nil || len(res.Tools) != 1 {
			t.Errorf("Content-Type %q: tools=%d err=%v", tc.contentType, len(res.Tools), err)
		}
	}
}
