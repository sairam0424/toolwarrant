package crawl

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sairam0424/toolwarrant/internal/gate"
)

type noArgs struct{}

// sdkServer runs the real go-sdk Streamable HTTP server with pageSize and n
// tools and records every request it serves.
func sdkServer(t *testing.T, pageSize, n int, jsonResponse bool) (url string, reqs func() []seenReq) {
	t.Helper()
	server := mcp.NewServer(&mcp.Implementation{Name: "sdk-under-test", Version: "1.2.3"}, &mcp.ServerOptions{PageSize: pageSize})
	for i := 0; i < n; i++ {
		mcp.AddTool(server, &mcp.Tool{
			Name:        fmt.Sprintf("tool%d", i),
			Description: fmt.Sprintf("tool number %d", i),
		}, func(context.Context, *mcp.CallToolRequest, noArgs) (*mcp.CallToolResult, struct{}, error) {
			return &mcp.CallToolResult{}, struct{}{}, nil
		})
	}
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{JSONResponse: jsonResponse})

	var (
		mu   sync.Mutex
		seen []seenReq
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, seenReq{HTTPMethod: r.Method, Header: r.Header.Clone()})
		mu.Unlock()
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, func() []seenReq {
		mu.Lock()
		defer mu.Unlock()
		return append([]seenReq(nil), seen...)
	}
}

func TestListToolsAgainstGoSDKServer(t *testing.T) {
	for _, jsonResponse := range []bool{false, true} {
		t.Run(fmt.Sprintf("jsonResponse=%v", jsonResponse), func(t *testing.T) {
			url, reqs := sdkServer(t, 2, 7, jsonResponse)
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()

			res, err := ListTools(ctx, url, testOptions())
			if err != nil {
				t.Fatalf("ListTools: %v", err)
			}
			if len(res.Tools) != 7 {
				t.Fatalf("got %d tools, want 7", len(res.Tools))
			}
			if res.Pages != 4 {
				t.Errorf("Pages = %d, want 4 (7 tools, page size 2)", res.Pages)
			}
			if res.ServerName != "sdk-under-test" || res.ServerVersion != "1.2.3" {
				t.Errorf("server info = %q %q", res.ServerName, res.ServerVersion)
			}
			if res.ProtocolVersion == "" {
				t.Error("ProtocolVersion empty")
			}
			assertSDKTools(t, res)
			assertSDKProtocol(t, reqs(), res.ProtocolVersion)
		})
	}
}

func assertSDKTools(t *testing.T, res Result) {
	t.Helper()
	seen := map[string]bool{}
	for _, tool := range res.Tools {
		if seen[tool.Name] {
			t.Errorf("duplicate tool %q in result", tool.Name)
		}
		seen[tool.Name] = true
		var decoded struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		}
		if err := json.Unmarshal(tool.Raw, &decoded); err != nil {
			t.Fatalf("tool %q raw is not JSON: %v", tool.Name, err)
		}
		if decoded.Name != tool.Name {
			t.Errorf("Name %q does not match raw name %q", tool.Name, decoded.Name)
		}
		if _, err := gate.Digest(tool.Raw); err != nil {
			t.Errorf("gate.Digest(%q): %v", tool.Name, err)
		}
	}
	for i := 0; i < 7; i++ {
		if !seen[fmt.Sprintf("tool%d", i)] {
			t.Errorf("tool%d missing from result", i)
		}
	}
}

// assertSDKProtocol checks the session is used and closed the way the MCP
// spec says: a session id and protocol version on every request after
// initialize, and a DELETE at the end.
func assertSDKProtocol(t *testing.T, reqs []seenReq, protocol string) {
	t.Helper()
	if len(reqs) < 3 {
		t.Fatalf("only %d requests seen", len(reqs))
	}
	first := reqs[0]
	if first.HTTPMethod != http.MethodPost || first.Header.Get("Mcp-Session-Id") != "" {
		t.Errorf("first request should be initialize without a session, got %s", first.HTTPMethod)
	}
	for _, accept := range []string{"application/json", "text/event-stream"} {
		if got := first.Header.Get("Accept"); !strings.Contains(got, accept) {
			t.Errorf("Accept %q lacks %q", got, accept)
		}
	}
	var sessionID string
	for _, r := range reqs[1:] {
		if sessionID == "" {
			sessionID = r.Header.Get("Mcp-Session-Id")
		}
		if sessionID != "" && r.Header.Get("Mcp-Session-Id") != sessionID {
			t.Errorf("%s request carried session %q, want %q", r.HTTPMethod, r.Header.Get("Mcp-Session-Id"), sessionID)
		}
		if got := r.Header.Get("MCP-Protocol-Version"); got != protocol {
			t.Errorf("%s request protocol header %q, want %q", r.HTTPMethod, got, protocol)
		}
	}
	if last := reqs[len(reqs)-1]; last.HTTPMethod != http.MethodDelete {
		t.Errorf("last request is %s, want DELETE to end the session", last.HTTPMethod)
	}
}

func TestListToolsSinglePageAgainstGoSDKServer(t *testing.T) {
	url, _ := sdkServer(t, 100, 3, false)
	res, err := ListTools(context.Background(), url, testOptions())
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(res.Tools) != 3 || res.Pages != 1 {
		t.Errorf("tools=%d pages=%d, want 3 and 1", len(res.Tools), res.Pages)
	}
}

func TestListToolsEmptyServer(t *testing.T) {
	url, _ := sdkServer(t, 2, 0, true)
	res, err := ListTools(context.Background(), url, testOptions())
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if res.Tools == nil || len(res.Tools) != 0 || res.Pages != 1 {
		t.Errorf("tools=%v pages=%d, want empty non-nil and 1 page", res.Tools, res.Pages)
	}
}
