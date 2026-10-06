// Command seamclient drives the gateway like an MCP client would: it lists
// the tools the gateway offers, then tries to call each named tool.
//
//	seamclient -url http://127.0.0.1:3000/mcp -call echo,wipe_database
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	url := flag.String("url", "http://127.0.0.1:3000/mcp", "gateway MCP endpoint")
	call := flag.String("call", "", "comma-separated tools to try calling")
	nolist := flag.Bool("nolist", false, "skip tools/list and call directly (tests call-time checks against a stale snapshot)")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "seamclient", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: *url, MaxRetries: -1}, nil)
	if err != nil {
		fmt.Println("CONNECT ERROR:", err)
		os.Exit(2)
	}
	defer session.Close()

	if !*nolist {
		tools, err := session.ListTools(ctx, nil)
		if err != nil {
			fmt.Println("LIST ERROR:", err)
		} else {
			names := make([]string, 0, len(tools.Tools))
			for _, t := range tools.Tools {
				names = append(names, fmt.Sprintf("%s(%q)", t.Name, t.Description))
			}
			fmt.Printf("LIST OK  tools=%d  %s\n", len(tools.Tools), strings.Join(names, " | "))
		}

	}

	for _, name := range strings.Split(*call, ",") {
		if name = strings.TrimSpace(name); name == "" {
			continue
		}
		args := map[string]any{"message": "hello", "a": 2, "b": 3, "confirm": true}
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		switch {
		case err != nil:
			fmt.Printf("CALL %-14s -> PROTOCOL ERROR: %v\n", name, err)
		case res.IsError:
			fmt.Printf("CALL %-14s -> TOOL ERROR: %s\n", name, text(res))
		default:
			fmt.Printf("CALL %-14s -> OK: %s\n", name, text(res))
		}
	}
}

func text(r *mcp.CallToolResult) string {
	var parts []string
	for _, c := range r.Content {
		if t, ok := c.(*mcp.TextContent); ok {
			parts = append(parts, t.Text)
		}
	}
	return strings.Join(parts, " ")
}
