//go:build e2e

package e2e

import (
	"slices"
	"strconv"
	"testing"
	"time"
)

// scenarioA: a fresh catalog is crawled, nothing is approved, the emitted
// file pins the gateway's listeners to the ports the stack picked, the file is
// loaded by the real gateway and the processor guards the route. Through the
// gateway tools/list is empty and every tools/call is denied.
func scenarioA(t *testing.T, s *stack) {
	s.addMock(t, "mock")
	out := s.twOK(t, "crawl", "mock")
	mustContain(t, "first crawl", out, "crawl 1 of mock complete: 3 tools, new=3")
	for _, row := range s.tools(t, "mock") {
		if row.State != "pending_review" || row.Approved != "" {
			t.Fatalf("after the first crawl %s is %q with approved %q; a crawl must approve nothing", row.Tool, row.State, row.Approved)
		}
	}
	s.emit(t, nil)
	cfg := string(s.config(t))
	mustContain(t, "emitted config", cfg, `allow: "false"`, `failureMode: "failClosed"`, `bindAddress: "127.0.0.1"`,
		"port: "+strconv.Itoa(s.gwPort), `host: "`+s.processorAddr("mock")+`"`, `gateways: "toolwarrant"`,
		`adminAddr: "`+s.adminAddr()+`"`, `statsAddr: "`+s.statsAddr()+`"`, `readinessAddr: "`+s.readinessAddr()+`"`)
	// The listeners are the stack's ports, never the emitter's defaults, so a
	// second gateway on this host cannot collide with this one.
	mustNotContain(t, "emitted config", cfg, ":15000", ":15020", ":15021")
	s.startProcessor(t, "mock", nil)
	s.startGateway(t)

	cs := s.eventuallyServes(t, "mock")
	for _, name := range []string{"echo", "add", "wipe_database"} {
		o := s.expectDenied(t, cs, name)
		mustContain(t, "denial of "+name, o.detail(), "not approved")
		t.Logf("A: tools/call %s -> %s", name, o)
	}
	r := s.verifyGateway(t, "mock")
	if r.code != exitOK {
		t.Errorf("verify-gateway on a fresh deployment: exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	mustContain(t, "verify-gateway", r.stdout, "OK: the gateway serves 0 tool(s)")
}

// scenarioB: a named person approves echo and add by digest, the file is
// re-emitted (the allow rule changed) and the gateway reloads it; a new
// session sees exactly echo and add, wipe_database stays denied and echo
// answers. The processor is not restarted: approvals reach it through the
// catalog's generation.
func scenarioB(t *testing.T, s *stack) {
	echo, add := s.tool(t, "mock", "echo"), s.tool(t, "mock", "add")
	s.approve(t, "mock", "echo", echo.Pending)
	s.approve(t, "mock", "add", add.Pending)
	if row := s.tool(t, "mock", "echo"); row.State != "enabled" || row.Approved != echo.Pending {
		t.Fatalf("after approve: state %q approved %q, want enabled at %s", row.State, row.Approved, echo.Pending)
	}
	processor := s.servers["mock"].processor
	r := s.emit(t, nil)
	mustContain(t, "emit", r.stdout, "/mock/mcp", s.processorAddr("mock"), "run one processor per server", "serve --server mock --target mock --listen "+s.processorAddr("mock"))
	cfg := string(s.config(t))
	mustContain(t, "allow rule", cfg, `allow: "mcp.tool.name == \"add\" || mcp.tool.name == \"echo\""`)
	mustNotContain(t, "allow rule", cfg, "wipe_database")

	cs := s.eventuallyServes(t, "mock", "add", "echo")
	tools, err := listTools(cs)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	if tool := toolNamed(tools, "echo"); tool == nil || tool.Description != echoV1 {
		t.Errorf("echo served as %+v, want description %q", tool, echoV1)
	}
	s.expectDenied(t, cs, "wipe_database")
	s.expectAllowed(t, cs, "echo", "hello")
	s.expectAllowed(t, cs, "add", "5")
	if !processor.running() || s.servers["mock"].processor != processor {
		t.Errorf("the processor was restarted; approvals must take effect through the catalog generation without a restart")
	}
	s.existing = cs
	r = s.verifyGateway(t, "mock")
	if r.code != exitOK {
		t.Errorf("verify-gateway: exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	// docs/operations.md quotes this line as "every one approved and current";
	// the CLI prints the count. The count is asserted, the wording is a doc nit.
	mustContain(t, "verify-gateway", r.stdout, "OK: the gateway serves 2 tool(s), 2 approved and current")
}

// scenarioC: the upstream changes echo's description behind the gateway. A
// new session no longer sees echo and its call is denied. A session that
// never re-lists (limit L1) is measured on both paths the docs describe: it
// is denied as soon as any session has listed the drifted definition through
// the gateway, and otherwise as soon as a crawl records the new LastSeen. The
// crawl flags the drift and diff shows the changed text.
func scenarioC(t *testing.T, s *stack) {
	cs0 := s.existing
	if cs0 == nil {
		t.Fatalf("scenario B left no open session to measure with")
	}
	s.describe(t, "mock", "echo", echoV2)
	t0 := time.Now()
	first := callTool(cs0, "echo")
	s.note(t, "C: %s after the drift, a session that never re-listed got: %s (limit L1: the call hook carries no definition)", since(t0), first)

	cs1 := s.connect(t, "mock")
	if names := s.mustListNames(t, cs1); slices.Contains(names, "echo") {
		t.Fatalf("a new session still lists the drifted echo: %v", names)
	}
	o := s.expectDenied(t, cs1, "echo")
	mustContain(t, "denial after drift", o.detail(), "changed since approval")
	tListed := time.Now()
	o = s.expectDenied(t, cs0, "echo")
	s.note(t, "C: the never-re-listing session was denied %s after the drift, %s after another session listed the drifted definition through the gateway: %s", since(t0), since(tListed), o)

	out := s.twOK(t, "crawl", "mock")
	mustContain(t, "crawl after drift", out, "CHANGED", "DRIFT", "changed_pending_reapproval", "changed=1")
	row := s.tool(t, "mock", "echo")
	if !row.Drifted || row.State != "changed_pending_reapproval" || row.Pending == "" || row.Pending == row.Approved || row.Live != row.Pending {
		t.Fatalf("after the drift crawl: %+v", row)
	}
	mustContain(t, "list", s.twOK(t, "list", "mock"), "DRIFT", "changed_pending_reapproval")
	diff := s.twOK(t, "diff", "mock", "echo")
	mustContain(t, "diff", diff, "from: "+row.Approved, "to:   "+row.Pending, echoV1, echoV2, "Changed text")

	// Second path: the upstream reverts, the catalog records it, then drifts
	// again while no gateway session lists; the crawl alone must catch it.
	s.describe(t, "mock", "echo", echoV1)
	s.eventuallyServes(t, "mock", "add", "echo")
	mustContain(t, "crawl after revert", s.twOK(t, "crawl", "mock"), "reverted=1")
	s.expectAllowed(t, cs0, "echo", "hello")
	s.describe(t, "mock", "echo", echoV2)
	t1 := time.Now()
	s.note(t, "C: %s after the second drift (no session listed it), the never-re-listing session got: %s", since(t1), callTool(cs0, "echo"))
	mustContain(t, "crawl after second drift", s.twOK(t, "crawl", "mock"), "DRIFT", "changed=1")
	o = s.expectDenied(t, cs0, "echo")
	s.note(t, "C: the never-re-listing session was denied %s after the second drift, right after the crawl recorded LastSeen: %s", since(t1), o)
}

// scenarioD: approving the new digest serves the new definition; rollback to
// the old digest hides echo while the upstream still serves the new one
// (strict mode); when the upstream restores the old definition echo is listed
// again, calls are allowed once the crawl records the revert, and the audit
// chain verifies.
func scenarioD(t *testing.T, s *stack) {
	row := s.tool(t, "mock", "echo")
	v1, v2 := row.Approved, row.Pending
	if v2 == "" || v2 == v1 {
		t.Fatalf("no pending drifted digest to approve: %+v", row)
	}
	s.approve(t, "mock", "echo", v2)
	cs := s.eventuallyServes(t, "mock", "add", "echo")
	tools, err := listTools(cs)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	if tool := toolNamed(tools, "echo"); tool == nil || tool.Description != echoV2 {
		t.Errorf("echo served as %+v, want the newly approved description %q", tool, echoV2)
	}
	s.expectAllowed(t, cs, "echo", "hello")

	out := s.twOK(t, "--as", reviewer, "rollback", "mock", "echo", "--to", v1)
	mustContain(t, "rollback", out, "rolled back mock/echo to "+v1)
	cs = s.eventuallyServes(t, "mock", "add")
	o := s.expectDenied(t, cs, "echo")
	s.note(t, "D: after rollback, with the upstream still serving the newer definition: %s", o)

	s.describe(t, "mock", "echo", echoV1)
	cs = s.eventuallyServes(t, "mock", "add", "echo")
	o = s.expectDenied(t, cs, "echo")
	s.note(t, "D: listed again after the upstream restored the approved definition, but until a crawl records the revert the call rule (D9) still denies: %s", o)
	mustContain(t, "crawl after restore", s.twOK(t, "crawl", "mock"), "reverted=1")
	s.expectAllowed(t, cs, "echo", "hello")

	out = s.twOK(t, "audit", "verify")
	mustContain(t, "audit verify", out, "audit log ok:", "head", "record this head outside the database")
	head := lastField(lastLineWith(out, "audit log ok:"))
	s.twOK(t, "audit", "verify", "--expect-head", head)
	r := s.twFail(t, exitFailure, "audit", "verify", "--expect-head", zeroDigest)
	mustContain(t, "wrong head", r.stderr, "audit head mismatch")
}

// scenarioE: disable hides and denies; enable brings the tool back for review
// and nothing is served until a person approves again; pausing the server
// empties its route and refuses crawls; resume restores service. None of this
// restarts the processor or re-emits the file.
func scenarioE(t *testing.T, s *stack) {
	v1 := s.tool(t, "mock", "echo").Approved
	mustContain(t, "disable", s.twOK(t, "--as", reviewer, "disable", "mock", "echo"), "disabled mock/echo")
	cs := s.eventuallyServes(t, "mock", "add")
	s.expectDenied(t, cs, "echo")

	mustContain(t, "enable", s.twOK(t, "--as", reviewer, "enable", "mock", "echo"), "state is now pending_review")
	cs = s.eventuallyServes(t, "mock", "add")
	s.expectDenied(t, cs, "echo")
	row := s.tool(t, "mock", "echo")
	if row.Pending != v1 {
		t.Fatalf("after enable the pending digest is %q, want the previously approved %s", row.Pending, v1)
	}
	s.approve(t, "mock", "echo", row.Pending)
	cs = s.eventuallyServes(t, "mock", "add", "echo")
	s.expectAllowed(t, cs, "echo", "hello")

	mustContain(t, "pause", s.twOK(t, "--as", reviewer, "server", "pause", "mock"), "paused server mock")
	if !s.server(t, "mock").Paused {
		t.Errorf("server list does not show mock as paused")
	}
	cs = s.eventuallyServes(t, "mock")
	s.expectDenied(t, cs, "echo")
	s.expectDenied(t, cs, "add")
	r := s.twFail(t, exitFailure, "crawl", "mock")
	mustContain(t, "crawl of a paused server", r.stderr, "server is paused", `run "toolwarrant server resume NAME" before crawling it again`)

	mustContain(t, "resume", s.twOK(t, "--as", reviewer, "server", "resume", "mock"), "resumed server mock")
	cs = s.eventuallyServes(t, "mock", "add", "echo")
	s.expectAllowed(t, cs, "echo", "hello")
	s.twOK(t, "crawl", "mock")
}

// lastField returns the last space-separated word of a line.
func lastField(line string) string {
	fields := splitFields(line)
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}
