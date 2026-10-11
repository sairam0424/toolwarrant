//go:build e2e

package e2e

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// scenarioJ: two upstreams, two servers, two processors. echo is approved on
// mock only, so the byte-identical echo of mockb is hidden and denied on
// mockb's route. emit refuses one processor address for two servers; a file
// edited to do it anyway still has mockb's echo denied, by the processor's
// service_names check (D2). A hostile upstream whose page lists echo twice has
// the page denied as a whole and the following call denied until a clean
// page is listed (D3).
func scenarioJ(t *testing.T, s *stack) {
	s.addMock(t, "mockb")
	mustContain(t, "crawl mockb", s.twOK(t, "crawl", "mockb"), "new=3")
	s.startProcessor(t, "mockb", nil)
	s.emit(t, nil)
	if a, b := s.tool(t, "mock", "echo"), s.tool(t, "mockb", "echo"); b.Live != a.Approved {
		t.Fatalf("mockb's echo digest %s differs from mock's approved %s; the two mocks should serve byte-identical definitions", b.Live, a.Approved)
	}
	cs := s.eventuallyServes(t, "mockb")
	o := s.expectDenied(t, cs, "echo")
	mustContain(t, "denial on mockb", o.detail(), "not approved")
	s.expectAllowed(t, s.eventuallyServes(t, "mock", "add", "echo"), "echo", "hello")

	r := s.tw(t, nil, append(s.emitBaseArgs(), "--processor", "mock="+s.processorAddr("mock"), "--processor", "mockb="+s.processorAddr("mock"))...)
	if r.code != exitFailure {
		t.Fatalf("emit with one processor address for two servers: exit %d, want 1\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	mustContain(t, "emit refusal", r.stderr, "duplicate processor address")
	cfg := string(s.config(t))
	edited := strings.Replace(cfg, `host: "`+s.processorAddr("mockb")+`"`, `host: "`+s.processorAddr("mock")+`"`, 1)
	if edited == cfg {
		t.Fatalf("mockb's processor host not found in the emitted file")
	}
	s.writeConfig(t, []byte(edited))
	cs = s.connect(t, "mockb")
	names, err := listNames(cs)
	if err == nil && slices.Contains(names, "echo") {
		t.Fatalf("mockb's echo rode on mock's approval through a shared processor: %v", names)
	}
	s.note(t, "J: both routes pointed at mock's processor; on mockb tools/list -> names %v, err %v", names, err)
	o = s.expectDenied(t, cs, "echo")
	s.note(t, "J: on mockb tools/call echo -> %s", o)
	s.expectAllowed(t, s.eventuallyServes(t, "mock", "add", "echo"), "echo", "hello")
	s.emit(t, nil)

	hostile := s.addHostile(t, "hostile")
	hostile.hostile.setPage(hostileEcho(echoV1))
	mustContain(t, "crawl hostile", s.twOK(t, "crawl", "hostile"), "new=1")
	s.approve(t, "hostile", "echo", s.tool(t, "hostile", "echo").Pending)
	s.startProcessor(t, "hostile", nil)
	s.emit(t, nil)
	cs = s.eventuallyServes(t, "hostile", "echo")
	s.expectAllowed(t, cs, "echo", hostileReply)

	hostile.hostile.setPage(hostileEcho(echoV1), hostileEcho(echoV2))
	cs = s.connect(t, "hostile")
	names, err = listNames(cs)
	if err == nil {
		t.Fatalf("a page listing echo twice (approved copy first) was served instead of denied as a whole: %v\n%s", names, s.logHints())
	}
	s.note(t, "J: duplicate page, tools/list -> %v", err)
	o = s.expectDenied(t, cs, "echo")
	mustContain(t, "call after a duplicate page", o.detail(), "changed since approval")
	hostile.hostile.setPage(hostileEcho(echoV1))
	cs = s.eventuallyServes(t, "hostile", "echo")
	s.expectAllowed(t, cs, "echo", hostileReply)
}

// scenarioK: the emitted allow rule alone, with every processor block
// removed. A server with zero approvals gets allow: "false": tools/list is
// empty and every tools/call is refused by the gateway itself. With echo
// approved the rule serves exactly echo. This is the emitter's
// defence-in-depth claim at runtime; without the processor the rule is also
// all that stands, so the drift checks of the other scenarios do not apply.
func scenarioK(t *testing.T, s *stack) {
	original := s.config(t)
	mustContain(t, "emitted config", string(original), `allow: "false"`)
	s.writeConfig(t, stripGuardrails(original))
	cs := s.eventuallyServes(t, "mockb")
	for _, name := range []string{"echo", "add", "wipe_database"} {
		o := s.expectDenied(t, cs, name)
		if name == "echo" {
			s.note(t, "K: allow \"false\" alone, tools/call %s -> %s", name, o)
		}
	}
	csA := s.eventuallyServes(t, "mock", "add", "echo")
	s.expectAllowed(t, csA, "echo", "hello")
	o := s.expectDenied(t, csA, "wipe_database")
	s.note(t, "K: rule naming add and echo alone, tools/call wipe_database -> %s", o)

	s.approve(t, "mockb", "echo", s.tool(t, "mockb", "echo").Pending)
	s.emit(t, nil)
	with := s.config(t)
	mustContain(t, "emitted config", string(with), `allow: "mcp.tool.name == \"echo\""`)
	s.writeConfig(t, stripGuardrails(with))
	cs = s.eventuallyServes(t, "mockb", "echo")
	s.expectAllowed(t, cs, "echo", "hello")
	s.expectDenied(t, cs, "add")
	s.expectDenied(t, cs, "wipe_database")
	s.emit(t, nil)
	s.eventuallyServes(t, "mockb", "echo")
}

// scenarioL: a tool carrying keys the gateway does not know is crawled
// directly and approved. The gateway re-serialises it before the hook, so the
// processor sees another digest and hides it (counted as a mismatch, D10,
// limit L2), and verify-gateway reports the hidden tool as MISSING with exit
// 0. Which keys the gateway dropped is recorded by listing the CEL-only
// variant with a raw client; there the gateway serves the re-serialised bytes
// and verify-gateway reports a LEAK with the MISMATCH sub-label, exit 1,
// with or without --config (decision D12; before the third round the check
// without --config printed a non-failing MISMATCH verdict).
func scenarioL(t *testing.T, s *stack) {
	hostile := s.servers["hostile"].hostile
	vendor := vendorTool()
	hostile.setPage(hostileEcho(echoV1), vendor)
	mustContain(t, "crawl hostile", s.twOK(t, "crawl", "hostile"), "new=1")
	s.approve(t, "hostile", "vendor_tool", s.tool(t, "hostile", "vendor_tool").Pending)
	s.emit(t, nil)
	mustContain(t, "emitted config", string(s.config(t)), `mcp.tool.name == \"vendor_tool\"`)

	cs := s.eventuallyServes(t, "hostile", "echo")
	o := s.expectDenied(t, cs, "vendor_tool")
	s.note(t, "L: with the processor, vendor_tool is hidden and tools/call -> %s", o)
	proc := s.servers["hostile"].processor
	mustContain(t, "processor log", proc.output(proc.stderr), `"msg":"digest mismatch"`, "vendor_tool")
	r := s.verifyGateway(t, "hostile")
	if r.code != exitOK {
		t.Errorf("verify-gateway with the processor hiding vendor_tool: exit %d, want 0 (MISSING never fails)\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	mustContain(t, "verify-gateway with the processor", r.stdout, "MISSING vendor_tool", "OK: the gateway serves 1 tool(s), 1 approved and current, 1 approved but not listed (MISSING)")
	mustNotContain(t, "verify-gateway with the processor", r.stdout, "LEAK", "MISMATCH")
	s.note(t, "L: with the processor in place verify-gateway printed: %s", strings.TrimSpace(r.stdout))

	original := s.config(t)
	s.writeConfig(t, stripGuardrails(original))
	served := servedTool(t, openRaw(t, s.routeURL("hostile")).listRaw(t), "vendor_tool")
	dropped, added, err := keyDiff(vendor, served)
	if err != nil {
		t.Fatalf("compare definitions: %v", err)
	}
	s.note(t, "L: keys the gateway dropped before the hook: %v; keys it added: %v", dropped, added)
	s.note(t, "L: upstream served %s", vendor)
	s.note(t, "L: gateway served  %s", served)
	if !slices.Contains(dropped, "x-vendor") {
		t.Errorf("the gateway kept the unknown top-level key x-vendor, so the processor's mismatch has another cause; dropped %v", dropped)
	}
	// The re-serialised bytes reach a client only without the processor. With
	// --config the hand edit is CONFIG-EDITED as well; without it the LEAK
	// alone fails the check, because the catalog has no record of drift and
	// the MISMATCH sub-label says so.
	r = s.verifyGateway(t, "hostile")
	if r.code != exitFailure {
		t.Errorf("verify-gateway --config on the edited CEL-only file: exit %d, want 1\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	mustContain(t, "verify-gateway --config without the processor", r.stdout, "CONFIG-EDITED", "LEAK vendor_tool", mismatchLabel)
	r = s.tw(t, nil, s.canaryArgs("hostile", false, "")...)
	if r.code != exitFailure {
		t.Errorf("verify-gateway without --config on the CEL-only variant: exit %d, want 1 (a LEAK fails whatever its sub-label)\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	mustContain(t, "verify-gateway without the processor", r.stdout, "LEAK vendor_tool", mismatchLabel)
	mustContain(t, "verify-gateway stderr without the processor", r.stderr, "1 tool(s) leak")
	s.note(t, "L: without the processor and without --config verify-gateway printed: %s", strings.TrimSpace(r.stdout))
	s.emit(t, nil)
	s.eventuallyServes(t, "hostile", "echo")
}

// servedTool finds one tool's raw bytes in a raw listing.
func servedTool(t *testing.T, tools []json.RawMessage, name string) json.RawMessage {
	t.Helper()
	for _, raw := range tools {
		var tool struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(raw, &tool) == nil && tool.Name == name {
			return raw
		}
	}
	t.Fatalf("%s is not in the raw listing: %s", name, tools)
	return nil
}
