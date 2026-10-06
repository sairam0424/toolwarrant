// Command seamgate is the hash-bound version of seamprocessor: approvals bind
// to a digest of the whole tool definition, not to a name.
//
//	tools/list  (response) shows a tool only if its digest equals the approved digest
//	tools/call  (request)  denies a tool unless its approval is current, judged by the
//	                       digest seen in the most recent tools/list ("last-seen snapshot")
//
// Approvals live in a JSON file (tool name -> digest) that is re-read on every
// request, so disable and rollback take effect on the very next list or call.
// -learn records "approve what is served right now" for the named tools; it is
// a spike convenience, not the approval workflow.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"

	"google.golang.org/grpc"

	api "github.com/sairam0424/toolwarrant/internal/extmcpv1"
	"github.com/sairam0424/toolwarrant/internal/gate"
	"github.com/sairam0424/toolwarrant/internal/mcpwire"
)

type gateServer struct {
	api.UnimplementedExtMcpServer
	approvedPath string
	learn        map[string]bool

	mu       sync.Mutex
	observed map[string]string // tool name -> digest from the most recent tools/list
	learned  map[string]bool   // tools already auto-approved once by -learn
}

func (g *gateServer) loadApproved() map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile(g.approvedPath)
	if err != nil {
		return out // no file means nothing approved
	}
	_ = json.Unmarshal(b, &out)
	return out
}

func (g *gateServer) saveApproved(m map[string]string) {
	b, _ := json.MarshalIndent(m, "", "  ")
	tmp := g.approvedPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err == nil {
		_ = os.Rename(tmp, g.approvedPath)
	}
}

func (g *gateServer) CheckResponse(_ context.Context, resp *api.McpResponse) (*api.McpResponseResult, error) {
	if resp.GetMethod() != "tools/list" {
		return &api.McpResponseResult{Result: &api.McpResponseResult_Pass{Pass: &api.Pass{}}}, nil
	}
	approved := g.loadApproved()
	var hidden []string
	out, _, err := mcpwire.FilterToolsListRaw(resp.GetMcpResponse(), func(name string, tool []byte) bool {
		d, derr := gate.Digest(tool)
		if derr != nil {
			hidden = append(hidden, name+"(unreadable)")
			return false
		}
		g.mu.Lock()
		g.observed[name] = d
		first := g.learn[name] && !g.learned[name]
		if first {
			g.learned[name] = true
		}
		g.mu.Unlock()
		if first && approved[name] == "" {
			approved[name] = d
			g.saveApproved(approved)
			log.Printf("[learn   ] approved %q as %s", name, d[:12])
		}
		switch {
		case approved[name] == "":
			hidden = append(hidden, name+"(unapproved)")
			return false
		case approved[name] != d:
			hidden = append(hidden, name+"(changed)")
			return false
		}
		return true
	})
	if err != nil {
		log.Printf("[response] cannot filter tools/list, denying: %v", err)
		return &api.McpResponseResult{Result: &api.McpResponseResult_Error{Error: &api.AuthorizationError{
			Code: api.AuthorizationError_INVALID, Reason: "cannot filter tools/list: " + err.Error()}}}, nil
	}
	sort.Strings(hidden)
	log.Printf("[response] tools/list filtered, hidden=%v", hidden)
	return &api.McpResponseResult{Result: &api.McpResponseResult_Mutated{Mutated: out}}, nil
}

func (g *gateServer) CheckRequest(_ context.Context, req *api.McpRequest) (*api.McpRequestResult, error) {
	if req.GetMethod() != "tools/call" {
		return pass(), nil
	}
	name, err := mcpwire.ToolCallName(req.GetMcpRequest())
	if err != nil {
		return deny(api.AuthorizationError_INVALID, "cannot read tool name"), nil
	}
	approved := g.loadApproved()
	want, ok := approved[name]
	if !ok {
		log.Printf("[request ] DENY %q: not approved", name)
		return deny(api.AuthorizationError_PERMISSION_DENIED, fmt.Sprintf("tool %s is not approved", name)), nil
	}
	g.mu.Lock()
	seen, observed := g.observed[name]
	g.mu.Unlock()
	switch {
	case !observed:
		log.Printf("[request ] DENY %q: definition not yet observed", name)
		return deny(api.AuthorizationError_PERMISSION_DENIED, fmt.Sprintf("tool %s has not been checked yet; list tools first", name)), nil
	case seen != want:
		log.Printf("[request ] DENY %q: definition changed since approval", name)
		return deny(api.AuthorizationError_PERMISSION_DENIED, fmt.Sprintf("tool %s changed since it was approved", name)), nil
	}
	return pass(), nil
}

func pass() *api.McpRequestResult {
	return &api.McpRequestResult{Result: &api.McpRequestResult_Pass{Pass: &api.Pass{}}}
}

func deny(code api.AuthorizationError_Code, reason string) *api.McpRequestResult {
	return &api.McpRequestResult{Result: &api.McpRequestResult_Error{Error: &api.AuthorizationError{Code: code, Reason: reason}}}
}

func main() {
	listen := flag.String("listen", "127.0.0.1:9001", "gRPC listen address")
	approved := flag.String("approved", ".cache/approved.json", "approvals file (tool name -> digest)")
	learn := flag.String("learn", "", "comma-separated tool names to approve as currently served (spike only)")
	flag.Parse()

	g := &gateServer{approvedPath: *approved, learn: map[string]bool{}, observed: map[string]string{}, learned: map[string]bool{}}
	for _, n := range strings.Split(*learn, ",") {
		if n = strings.TrimSpace(n); n != "" {
			g.learn[n] = true
		}
	}
	lis, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	s := grpc.NewServer()
	api.RegisterExtMcpServer(s, g)
	log.Printf("[seamgate] listening on %s approvals=%s learn=%v", *listen, *approved, *learn)
	log.Fatal(s.Serve(lis))
}
