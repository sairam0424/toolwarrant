package emit

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

// gatewaySocketPorts is every socket the default input binds for the gateway
// itself, by the name the error must carry, with the port as text so that a
// processor address can be assembled from it.
func gatewaySocketPorts() map[string]string {
	return map[string]string{
		servingName:   strconv.Itoa(testListenPort),
		adminName:     "15000",
		statsName:     "15020",
		readinessName: "15021",
	}
}

// thisHostSpellings are the processor hosts that mean the gateway's own host:
// IPv4 loopback in two spellings, localhost in two cases, both wildcards and
// the IPv6 loopback in brackets (which the host-shape rule refuses on its
// own; the socket rule must still be the one that names it).
func thisHostSpellings() []string {
	return []string{"127.0.0.1", "127.0.0.2", "localhost", "LOCALHOST", "0.0.0.0", "[::]", "[::1]"}
}

// requireRefusedSocket checks that in is refused with ErrInvalidInput whose
// message names the server, the processor address, the socket and its port.
func requireRefusedSocket(t *testing.T, in Input, server, addr, socket, port string) {
	t.Helper()
	requireInvalid(t, in)
	_, err := AgentGateway(in)
	for _, want := range []string{"server " + server + ":", shown(addr), "gateway's own " + socket + " socket", "(port " + port + ")"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to say %q", err, want)
		}
	}
}

// TestProcessorOnAGatewaySocketIsRefused ports the third review's
// reproduction (processor-emit-4, the second review's E7, decision D13 g):
// every spelling of this host with the serving, admin, stats or readiness
// port is refused, and the error names the socket. Before the rule the
// emitter accepted all of them and --validate-only loads the file
// (TestGatewayAcceptsAProcessorOnItsOwnSocket), so the gateway dialled its
// own HTTP listener for every hook.
func TestProcessorOnAGatewaySocketIsRefused(t *testing.T) {
	for socket, port := range gatewaySocketPorts() {
		for _, host := range thisHostSpellings() {
			addr := host + ":" + port
			t.Run(addr, func(t *testing.T) {
				s := validServer("a")
				s.ProcessorAddr = addr
				requireRefusedSocket(t, Input{ListenPort: testListenPort, Servers: []Server{s}}, "a", addr, socket, port)
			})
		}
	}
}

// TestProcessorSocketRuleFollowsTheListenerInputs: the rule reads the ports
// the input actually binds, not the defaults. Moved listeners reserve their
// new ports and free the default ones, the serving port moves with
// ListenPort, and an admin API turned off frees its port.
func TestProcessorSocketRuleFollowsTheListenerInputs(t *testing.T) {
	moved := func(addr string) Input {
		s := validServer("a")
		s.ProcessorAddr = addr
		return Input{ListenPort: 8080, AdminAddr: "[::1]:16000", StatsAddr: "127.0.0.2:16020", ReadinessAddr: "127.0.0.1:16021", Servers: []Server{s}}
	}
	refused := []struct{ addr, socket, port string }{
		{"127.0.0.1:8080", servingName, "8080"}, {"localhost:16000", adminName, "16000"},
		{"[::1]:16020", statsName, "16020"}, {"0.0.0.0:16021", readinessName, "16021"},
	}
	for _, tc := range refused {
		requireRefusedSocket(t, moved(tc.addr), "a", tc.addr, tc.socket, tc.port)
	}
	for _, addr := range []string{"127.0.0.1:" + strconv.Itoa(testListenPort), DefaultAdminAddr, "localhost:15020", DefaultReadinessAddr} {
		if _, err := AgentGateway(moved(addr)); err != nil {
			t.Errorf("processor %q on a port the moved gateway does not bind rejected: %v", addr, err)
		}
	}
	s := validServer("a")
	s.ProcessorAddr = DefaultAdminAddr
	if _, err := AgentGateway(Input{ListenPort: testListenPort, DisableAdmin: true, Servers: []Server{s}}); err != nil {
		t.Errorf("admin API off, processor on its default port rejected: %v", err)
	}
}

// TestProcessorOnAnotherHostMayShareAGatewayPort: the rule is about this
// host. A processor on a specific address or a name may use any port, with
// the usual off-loopback warning; the emitter cannot know whether a specific
// address is this host, so it does not pretend to.
func TestProcessorOnAnotherHostMayShareAGatewayPort(t *testing.T) {
	for _, addr := range []string{"10.0.0.5:15000", "h.example:" + strconv.Itoa(testListenPort), "192.168.1.20:15020", "processor.svc:15021"} {
		s := validServer("a")
		s.ProcessorAddr = addr
		out, err := AgentGateway(Input{ListenPort: testListenPort, Servers: []Server{s}})
		if err != nil {
			t.Errorf("processor %q rejected: %v", addr, err)
			continue
		}
		if want := "processor for server a at " + addr + processorRisk; out.Warning != want {
			t.Errorf("processor %q: Warning = %q, want %q", addr, out.Warning, want)
		}
	}
}

// TestProcessorSocketRuleAppliesToEveryServer: the second server is checked
// like the first and the error names it.
func TestProcessorSocketRuleAppliesToEveryServer(t *testing.T) {
	in := Input{ListenPort: testListenPort, Servers: []Server{
		{Name: "a", URL: testUpstreamURL, ProcessorAddr: testProcessorAddr},
		{Name: "b", URL: testUpstreamURL, ProcessorAddr: "localhost:15021"},
	}}
	requireRefusedSocket(t, in, "b", "localhost:15021", readinessName, "15021")
}

// TestProcessorSocketRuleLeavesOtherRefusalsAlone: an address the port or
// host-shape rule refuses is still refused by that rule, including a host
// that means this host with a port outside the range or on a free port.
func TestProcessorSocketRuleLeavesOtherRefusalsAlone(t *testing.T) {
	for addr, want := range map[string]string{
		"127.0.0.1:0":     "processor port must be",
		"localhost:70000": "processor port must be",
		"[::1]:9001":      "processor host must be a DNS name or IPv4 address",
		"[::]:9001":       "processor host must be a DNS name or IPv4 address",
	} {
		s := validServer("a")
		s.ProcessorAddr = addr
		_, err := AgentGateway(Input{ListenPort: testListenPort, Servers: []Server{s}})
		if err == nil || !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), want) {
			t.Errorf("processor %q: err = %v, want ErrInvalidInput saying %q", addr, err, want)
		}
	}
}

// TestIsThisHost pins the predicate: loopback and localhost as isLoopbackHost
// has them, plus both wildcards in any spelling; names, specific addresses,
// a bracketed host and malformed hosts are not this host.
func TestIsThisHost(t *testing.T) {
	for host, want := range map[string]bool{
		"127.0.0.1": true, "127.0.0.2": true, "::1": true, "0:0:0:0:0:0:0:1": true, "localhost": true, "LocalHost": true,
		"0.0.0.0": true, "::": true, "0:0:0:0:0:0:0:0": true,
		"10.0.0.5": false, "h.example": false, "localhost.": false, "": false, "127.1": false, "0.0.0.0.0": false, "[::1]": false,
	} {
		if got := isThisHost(host); got != want {
			t.Errorf("isThisHost(%q) = %v, want %v", host, got, want)
		}
	}
}

// TestGatewayAcceptsAProcessorOnItsOwnSocket pins why the emitter's rule
// exists: the real binary in --validate-only mode loads a file whose
// processor host is the admin, stats, readiness or serving socket, so nothing
// between emit and the reload would name the collision. If a gateway version
// starts refusing it, this test says so and the documents can drop the caveat.
func TestGatewayAcceptsAProcessorOnItsOwnSocket(t *testing.T) {
	binary := gatewayBinary(t)
	out := freshOutput(t)
	hostLine := "      - host: " + quote(testProcessorAddr) + "\n"
	for _, addr := range []string{DefaultAdminAddr, DefaultStatsAddr, DefaultReadinessAddr, "127.0.0.1:" + strconv.Itoa(testListenPort)} {
		s := validServer("a")
		s.ProcessorAddr = addr
		requireInvalid(t, Input{ListenPort: testListenPort, Servers: []Server{s}})
		requireValid(t, binary, mutate(t, out.YAML, hostLine, "      - host: "+quote(addr)+"\n"), "a processor on the gateway's own socket "+addr)
	}
}
