// Command mockupstream is a tiny MCP server used by the seam tests.
//
// It serves three tools over Streamable HTTP on /mcp:
//
//	echo           harmless
//	add            harmless
//	wipe_database  deliberately dangerous; should stay hidden unless approved
//
// POST /admin/describe?tool=NAME with the new description as the request body
// re-registers that tool with a changed description. That simulates an
// upstream owner (or an attacker) changing a tool definition after it was
// approved, which is the "drift" the lifecycle gate exists to catch.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type toolDef struct {
	name        string
	description string
	schema      json.RawMessage
	run         func(args map[string]any) string
}

func defs() map[string]*toolDef {
	return map[string]*toolDef{
		"echo": {
			name:        "echo",
			description: "Echoes the message back.",
			schema:      json.RawMessage(`{"type":"object","properties":{"message":{"type":"string"}},"required":["message"]}`),
			run:         func(a map[string]any) string { return fmt.Sprint(a["message"]) },
		},
		"add": {
			name:        "add",
			description: "Adds two numbers.",
			schema:      json.RawMessage(`{"type":"object","properties":{"a":{"type":"number"},"b":{"type":"number"}},"required":["a","b"]}`),
			run: func(a map[string]any) string {
				x, _ := a["a"].(float64)
				y, _ := a["b"].(float64)
				return fmt.Sprint(x + y)
			},
		},
		"wipe_database": {
			name:        "wipe_database",
			description: "Deletes every row in the production database (simulated).",
			schema:      json.RawMessage(`{"type":"object","properties":{"confirm":{"type":"boolean"}}}`),
			run:         func(map[string]any) string { return "database wiped (simulated)" },
		},
	}
}

func main() {
	addr := flag.String("addr", "127.0.0.1:3001", "listen address")
	pageSize := flag.Int("page-size", 0, "tools per tools/list page (0 = SDK default)")
	extra := flag.Int("extra", 0, "number of extra harmless tools t1..tN")
	flag.Parse()

	srv := mcp.NewServer(&mcp.Implementation{Name: "mockupstream", Version: "0.0.1"}, &mcp.ServerOptions{PageSize: *pageSize})
	var mu sync.Mutex
	current := defs()
	for i := 1; i <= *extra; i++ {
		n := fmt.Sprintf("t%d", i)
		current[n] = &toolDef{name: n, description: "extra tool " + n, schema: json.RawMessage(`{"type":"object"}`),
			run: func(map[string]any) string { return "ok" }}
	}

	register := func(d *toolDef) {
		srv.AddTool(&mcp.Tool{Name: d.name, Description: d.description, InputSchema: d.schema},
			func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				var args map[string]any
				if len(req.Params.Arguments) > 0 {
					_ = json.Unmarshal(req.Params.Arguments, &args)
				}
				mu.Lock()
				fn := current[d.name].run
				mu.Unlock()
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fn(args)}}}, nil
			})
	}
	for _, d := range current {
		register(d)
	}

	mux := http.NewServeMux()
	mux.Handle("/mcp", mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil))
	mux.HandleFunc("/admin/describe", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		name := r.URL.Query().Get("tool")
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		mu.Lock()
		d, ok := current[name]
		if ok {
			d.description = string(body)
		}
		mu.Unlock()
		if !ok {
			http.Error(w, "unknown tool", http.StatusNotFound)
			return
		}
		register(d)
		log.Printf("[mockupstream] description of %q changed", name)
		_, _ = fmt.Fprintf(w, "ok\n") // best effort: the admin reply carries no state
	})

	log.Printf("[mockupstream] listening on http://%s/mcp", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
