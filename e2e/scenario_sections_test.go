//go:build e2e

package e2e

import (
	"fmt"
	"testing"
)

// The sections of the fourth review's finding cli-docs-1. agentgateway v1.6.0
// loads fourteen top-level sections (its --validate-only error lists them:
// config, binds, frontendPolicies, policies, workloads, services, backends,
// routeGroups, gateways, routes, tcpRoutes, llm, mcp, ui); the emitter writes
// config, gateways and routes, and before the fifth round the live comparison
// decoded those alone, so a binds listener or an mcp shortcut posted next to
// the emitted gateway through the admin API was invisible to it.
const (
	bindsSection = "binds"
	mcpSection   = "mcp"
	// openListenerName, openRouteName and openRoutePath name the listener and
	// the processor-less allow-all route the binds section carries.
	openListenerName = "open"
	openRouteName    = "mock-open"
	openRoutePath    = "/open/mcp"
	// mcpShortcutPath is where an mcp shortcut listener is tried; the
	// shortcut names a port and targets and no path, so the path is a guess
	// the scenario records the outcome of.
	mcpShortcutPath = "/mcp"
	// headerFilterField is the processor field the emitter writes so that a
	// client's credentials do not ride each hook (limit L11).
	headerFilterField = "requestHeaders"
)

// scenarioPHeaderFilter: the original document with requestHeaders removed
// from mock's processor entry (findings cli-docs-4 and processor-emit-7 of the
// fourth review). The gateway then forwards every client header, bearer tokens
// and cookies included, to the processor again, while host, kind,
// failureMode and methods still compare equal. The check must report
// LIVE-CONFIG-MISMATCH naming the processor and the filter, exit 1. The step
// needs the filter in the live document, which noteLiveShape recorded.
func scenarioPHeaderFilter(t *testing.T, s *stack, lab liveLab) {
	has, err := liveProcessorHasHeaderFilter(lab.doc, "mock")
	if err != nil {
		t.Fatalf("read mock's processor in the live configuration: %v", err)
	}
	if !has {
		t.Fatalf("the live configuration renders no %s filter for mock's processor although the emitted file carries one, so a removed filter cannot be compared", headerFilterField)
	}
	doc, err := withoutHeaderFilter(lab.doc, "mock")
	if err != nil {
		t.Fatalf("remove the filter from the live configuration: %v", err)
	}
	s.replaceLive(t, doc)
	s.awaitLiveHeaderFilter(t, "mock", false)
	// The server's own route keeps its lines unprefixed, so the line names the
	// processor entry and the filter: "processor requestHeaders allowed:
	// emitted :method, live (none)", and one more for the disallowed list.
	s.expectLiveMismatch(t, lab.copyPath, "with the "+headerFilterField+" filter removed from mock's processor", "processor "+headerFilterField+" allowed", "processor "+headerFilterField+" disallowed")
	s.restoreLive(t, lab, "after the filter removal")
}

// scenarioPBinds: the original document plus a top-level binds section with a
// listener on another port carrying a route named openRouteName to mock's
// upstream with an allow-all rule and no processor (the document the fourth
// review loaded with --validate-only). Whether the extra port serves is
// recorded by listing and calling through it; the check must report
// LIVE-CONFIG-MISMATCH naming the section, exit 1.
func scenarioPBinds(t *testing.T, s *stack, lab liveLab) {
	port := s.freeProcPort(t)
	doc, err := withSection(lab.doc, bindsSection, bindsValue(port, s.servers["mock"].url))
	if err != nil {
		t.Fatalf("add a binds section to the live configuration: %v", err)
	}
	s.replaceLive(t, doc)
	if !s.awaitLiveSection(t, bindsSection, true) {
		t.Fatalf("GET %s never rendered the posted %s section; the live comparison cannot see it", adminConfigPath, bindsSection)
	}
	s.noteExtraListener(t, bindsSection, port, openRoutePath)
	s.expectLiveMismatch(t, lab.copyPath, fmt.Sprintf("with a %s section carrying a listener on port %d", bindsSection, port), sectionNaming(bindsSection))
	s.restoreLive(t, lab, "after the "+bindsSection+" section")
}

// scenarioPMcp: the original document plus a top-level mcp shortcut (a port
// and targets) to mock's upstream. The pinned binary loads such a file with
// --validate-only; whether its admin API accepts and renders the section is
// recorded here. When it does, the check must report LIVE-CONFIG-MISMATCH
// naming the section, exit 1; when the gateway refuses the post the step
// records the refusal and ends.
func scenarioPMcp(t *testing.T, s *stack, lab liveLab) {
	port := s.freeProcPort(t)
	doc, err := withSection(lab.doc, mcpSection, mcpValue(port, s.servers["mock"].url))
	if err != nil {
		t.Fatalf("add an mcp section to the live configuration: %v", err)
	}
	if !s.tryReplaceLive(t, doc) {
		s.note(t, "P: the gateway refused the document with a top-level %s section, so the section cannot reach the running configuration through the admin API", mcpSection)
		s.restoreLive(t, lab, "after the refused "+mcpSection+" section")
		return
	}
	if !s.awaitLiveSection(t, mcpSection, true) {
		t.Fatalf("GET %s never rendered the posted %s section; the live comparison cannot see it", adminConfigPath, mcpSection)
	}
	s.noteExtraListener(t, mcpSection, port, mcpShortcutPath)
	s.expectLiveMismatch(t, lab.copyPath, fmt.Sprintf("with an %s section naming port %d", mcpSection, port), sectionNaming(mcpSection))
	s.restoreLive(t, lab, "after the "+mcpSection+" section")
}

// sectionNaming is the substring a LIVE-CONFIG-MISMATCH line about an extra
// top-level section must carry: one line per section, naming it (the CLI
// prints "section NAME: not in the emitted file; it may bind ports and routes
// the comparison cannot see").
func sectionNaming(section string) string {
	return "section " + section + ":"
}

// noteExtraListener records what the listener of an extra section does:
// whether the port accepts connections within the reload wait, what a new
// session lists through it and what tools/call echo answers, so the documents
// can say what the gateway does with such a section posted next to the
// emitted gateway. Nothing is asserted: the finding is about the comparison.
func (s *stack) noteExtraListener(t *testing.T, section string, port int, path string) {
	t.Helper()
	addr := loopback(port)
	if !pollUntil(reloadWait, func() bool { return portOpen(addr) }) {
		s.note(t, "P: the %s listener on %s accepted no connection within %s", section, addr, reloadWait)
		return
	}
	cs, err := openSession("http://" + addr + path)
	if err != nil {
		s.note(t, "P: the %s listener on %s accepts connections; an MCP session at %s failed: %v", section, addr, path, err)
		return
	}
	defer func() { _ = cs.Close() }()
	names, err := listNames(cs)
	s.note(t, "P: through the %s listener on %s%s a new session listed %v (err %v) and tools/call echo -> %s", section, addr, path, names, err, callTool(cs, "echo"))
}
