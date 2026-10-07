//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	// opTimeout bounds one MCP operation through the gateway.
	opTimeout = 30 * time.Second
	// servesWait bounds how long a route may take to show an expected list
	// after a reload, a restart or a decision.
	servesWait = 20 * time.Second
	// hostileReply is what the hostile upstream answers to every tools/call;
	// seeing it proves a call reached that upstream.
	hostileReply = "hostile-ok"
)

// toolArgs are arguments the mock upstream's tools accept.
var toolArgs = map[string]map[string]any{
	"echo":          {"message": "hello"},
	"add":           {"a": 2, "b": 3},
	"wipe_database": {"confirm": true},
	"vendor_tool":   {"q": "x"},
}

// toolSuccess is the text each mock tool returns when a call reaches it, so
// a denial can be checked for not having let the call through.
var toolSuccess = map[string]string{
	"echo":          "hello",
	"add":           "5",
	"wipe_database": "database wiped",
}

// callOutcome is what one tools/call produced, in whichever of the three
// shapes the gateway uses: a result, a result flagged isError (how the
// processor's denial arrives), or a JSON-RPC or transport error (how a CEL
// denial and a dead processor arrive).
type callOutcome struct {
	allowed bool
	isError bool
	text    string
	err     error
}

// detail is the text a person would read: the content or the error.
func (o callOutcome) detail() string {
	if o.err != nil {
		return o.err.Error()
	}
	return o.text
}

func (o callOutcome) String() string {
	switch {
	case o.allowed:
		return "allowed: " + o.text
	case o.isError:
		return "denied (result isError): " + o.text
	default:
		return "denied (error): " + o.detail()
	}
}

// routeURL is the gateway endpoint of one server, /<server>/mcp.
func (s *stack) routeURL(server string) string {
	return fmt.Sprintf("http://127.0.0.1:%d/%s/mcp", s.gwPort, server)
}

// openSession opens a new MCP session at url with the go-sdk client. The
// standalone SSE stream is not opened: the test only needs request-response
// traffic, and one connection per session keeps the gateway's session
// handling easy to reason about.
func openSession(url string) (*mcp.ClientSession, error) {
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "toolwarrant-e2e", Version: "0.0.1"}, nil)
	return client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: url, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
}

// connect opens a new session through the route of server. Every check opens
// a new session because the gateway binds its processor chain per session
// (limit L3): a check that reused a session could not see a reload.
func (s *stack) connect(t *testing.T, server string) *mcp.ClientSession {
	t.Helper()
	cs, err := openSession(s.routeURL(server))
	if err != nil {
		t.Fatalf("connect to %s: %v\n%s", s.routeURL(server), err, s.logHints())
	}
	s.root.Cleanup(func() { _ = cs.Close() })
	return cs
}

// listTools runs tools/list on a session.
func listTools(cs *mcp.ClientSession) ([]*mcp.Tool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		return nil, err
	}
	return res.Tools, nil
}

// listNames runs tools/list and returns the sorted names.
func listNames(cs *mcp.ClientSession) ([]string, error) {
	tools, err := listTools(cs)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		names = append(names, tool.Name)
	}
	slices.Sort(names)
	return names, nil
}

// mustListNames fails the test when tools/list fails.
func (s *stack) mustListNames(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	names, err := listNames(cs)
	if err != nil {
		t.Fatalf("tools/list: %v\n%s", err, s.logHints())
	}
	return names
}

// toolNamed finds a tool in a listing.
func toolNamed(tools []*mcp.Tool, name string) *mcp.Tool {
	for _, tool := range tools {
		if tool.Name == name {
			return tool
		}
	}
	return nil
}

// callTool runs tools/call and classifies the outcome.
func callTool(cs *mcp.ClientSession, name string) callOutcome {
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: toolArgs[name]})
	if err != nil {
		return callOutcome{err: err}
	}
	var parts []string
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			parts = append(parts, tc.Text)
		}
	}
	return callOutcome{allowed: !res.IsError, isError: res.IsError, text: strings.Join(parts, " ")}
}

// expectAllowed asserts that a call reaches the upstream and returns its text.
func (s *stack) expectAllowed(t *testing.T, cs *mcp.ClientSession, name, wantText string) callOutcome {
	t.Helper()
	o := callTool(cs, name)
	if !o.allowed {
		t.Fatalf("tools/call %s should be allowed, got %s\n%s", name, o, s.logHints())
	}
	if !strings.Contains(o.text, wantText) {
		t.Errorf("tools/call %s returned %q, want it to contain %q", name, o.text, wantText)
	}
	return o
}

// expectDenied asserts that a call does not reach the upstream: the outcome is
// an error of some shape and the upstream's success text is absent.
func (s *stack) expectDenied(t *testing.T, cs *mcp.ClientSession, name string) callOutcome {
	t.Helper()
	o := callTool(cs, name)
	if o.allowed {
		t.Fatalf("tools/call %s should be denied, but the upstream answered: %s\n%s", name, o, s.logHints())
	}
	if success := toolSuccess[name]; success != "" && strings.Contains(o.text, success) {
		t.Errorf("tools/call %s was flagged as an error but carries the upstream's answer: %s", name, o)
	}
	return o
}

// eventuallyServes opens new sessions until the route of server lists exactly
// the given names (sorted) or servesWait passes, and returns the session that
// saw the list, so the caller can make calls on a session that has listed. A
// bounded poll is used instead of a sleep because reloads, processor restarts
// and catalog changes take effect asynchronously.
func (s *stack) eventuallyServes(t *testing.T, server string, want ...string) *mcp.ClientSession {
	t.Helper()
	slices.Sort(want)
	if want == nil {
		want = []string{}
	}
	var last string
	var found *mcp.ClientSession
	ok := pollUntil(servesWait, func() bool {
		cs, err := openSession(s.routeURL(server))
		if err != nil {
			last = "connect: " + err.Error()
			return false
		}
		names, err := listNames(cs)
		switch {
		case err != nil:
			last = "tools/list: " + err.Error()
		case slices.Equal(names, want):
			found = cs
			return true
		default:
			last = fmt.Sprintf("tools/list: %v", names)
		}
		_ = cs.Close()
		return false
	})
	if !ok {
		t.Fatalf("route %s did not serve exactly %v within %s; last observation: %s\n%s", server, want, servesWait, last, s.logHints())
	}
	s.root.Cleanup(func() { _ = found.Close() })
	return found
}
