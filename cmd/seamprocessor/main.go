// Command seamprocessor is the smallest useful ExtMCP processor: a static
// allowlist of tool names. It exists to answer one question for the spike
// before anything else is built: can an external processor hide a tool from
// tools/list and deny a tools/call on agentgateway?
//
//	tools/list  (response phase) drops every tool not on the allowlist
//	tools/call  (request phase)  denies every tool not on the allowlist
//
// Failure handling is deliberately closed: anything it cannot parse is denied.
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"strings"

	"google.golang.org/grpc"

	api "github.com/sairam0424/toolwarrant/internal/extmcpv1"
	"github.com/sairam0424/toolwarrant/internal/mcpwire"
)

type processor struct {
	api.UnimplementedExtMcpServer
	allow map[string]bool
}

func (p *processor) CheckRequest(_ context.Context, req *api.McpRequest) (*api.McpRequestResult, error) {
	log.Printf("[request ] method=%q services=%q params=%s", req.GetMethod(), req.GetServiceNames(), trunc(req.GetMcpRequest()))
	if req.GetMethod() != "tools/call" {
		return pass(), nil
	}
	name, err := mcpwire.ToolCallName(req.GetMcpRequest())
	if err != nil {
		return deny(api.AuthorizationError_INVALID, "cannot read tool name: "+err.Error()), nil
	}
	if !p.allow[name] {
		log.Printf("[request ] DENY tools/call %q", name)
		return deny(api.AuthorizationError_PERMISSION_DENIED, "tool "+name+" is not approved"), nil
	}
	return pass(), nil
}

func (p *processor) CheckResponse(_ context.Context, resp *api.McpResponse) (*api.McpResponseResult, error) {
	log.Printf("[response] method=%q services=%q result=%s", resp.GetMethod(), resp.GetServiceNames(), trunc(resp.GetMcpResponse()))
	if resp.GetMethod() != "tools/list" {
		return &api.McpResponseResult{Result: &api.McpResponseResult_Pass{Pass: &api.Pass{}}}, nil
	}
	out, dropped, err := mcpwire.FilterToolsList(resp.GetMcpResponse(), func(n string) bool { return p.allow[n] })
	if err != nil {
		log.Printf("[response] cannot filter tools/list, denying: %v", err)
		return &api.McpResponseResult{Result: &api.McpResponseResult_Error{Error: &api.AuthorizationError{
			Code: api.AuthorizationError_INVALID, Reason: "cannot filter tools/list: " + err.Error()}}}, nil
	}
	log.Printf("[response] tools/list filtered, hidden=%v", dropped)
	return &api.McpResponseResult{Result: &api.McpResponseResult_Mutated{Mutated: out}}, nil
}

func pass() *api.McpRequestResult {
	return &api.McpRequestResult{Result: &api.McpRequestResult_Pass{Pass: &api.Pass{}}}
}

func deny(code api.AuthorizationError_Code, reason string) *api.McpRequestResult {
	return &api.McpRequestResult{Result: &api.McpRequestResult_Error{Error: &api.AuthorizationError{Code: code, Reason: reason}}}
}

func trunc(b []byte) string {
	if len(b) > 160 {
		return string(b[:160]) + "..."
	}
	return string(b)
}

func main() {
	listen := flag.String("listen", "127.0.0.1:9001", "gRPC listen address")
	allowFlag := flag.String("allow", "echo,add", "comma-separated tool names to allow")
	flag.Parse()

	allow := map[string]bool{}
	for _, n := range strings.Split(*allowFlag, ",") {
		if n = strings.TrimSpace(n); n != "" {
			allow[n] = true
		}
	}
	lis, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	s := grpc.NewServer()
	api.RegisterExtMcpServer(s, &processor{allow: allow})
	log.Printf("[seamprocessor] listening on %s, allow=%v", *listen, *allowFlag)
	log.Fatal(s.Serve(lis))
}
