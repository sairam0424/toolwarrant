package emit

import (
	"strconv"
	"strings"
	"testing"
)

// loopbackAliases are the names beside localhost that common resolvers map
// to loopback from /etc/hosts without any DNS query (loopbackNames), as the
// files spell them plus one upper-case spelling, because DNS names are
// compared without regard to case.
func loopbackAliases() []string {
	return []string{
		"localhost.localdomain", "localhost4", "localhost4.localdomain4", "localhost6",
		"localhost6.localdomain6", "ip6-localhost", "ip6-loopback", "LOCALHOST.LOCALDOMAIN",
	}
}

// otherNames are processor hosts that are neither IP literals nor loopback
// names: names of other hosts, localhost with a trailing dot or under a
// domain, a near miss, a name with an underscore and an empty host (which
// dials this host). The first four pass the host-shape rule; the rest fail it,
// and the socket rule must still be the one that refuses them on a gateway
// port because it runs first.
func otherNames() []string {
	return []string{"h.example", "processor.svc", "my_svc.ns.svc", "localhost5", "localhost.example", "localhost.", ""}
}

// refusalOf checks the parts every socket refusal shares
// (requireRefusedSocket) and returns the message, so a test can pin the
// wording that tells the two refusals apart.
func refusalOf(t *testing.T, in Input, server, addr, socket, port string) string {
	t.Helper()
	requireRefusedSocket(t, in, server, addr, socket, port)
	_, err := AgentGateway(in)
	return err.Error()
}

// requireWording fails unless msg carries every phrase.
func requireWording(t *testing.T, msg string, phrases ...string) {
	t.Helper()
	for _, want := range phrases {
		if !strings.Contains(msg, want) {
			t.Errorf("err = %q, want it to say %q", msg, want)
		}
	}
}

// TestLoopbackAliasOnAGatewaySocketIsRefused ports the fifth review's
// reproduction (processor-emit-2, decision D15 h): a processor at a resolver
// alias of localhost with the serving port or the admin port is the gateway's
// own socket, exactly like 127.0.0.1 with that port, and the error says so.
// Before this round the socket rule knew the one name localhost, so every
// alias was accepted, Output.Warning said the processor was off loopback and
// the gateway loaded the file (TestGatewayAcceptsAProcessorNamedForItsOwnSocket).
func TestLoopbackAliasOnAGatewaySocketIsRefused(t *testing.T) {
	for _, host := range loopbackAliases() {
		for socket, port := range map[string]string{servingName: strconv.Itoa(testListenPort), adminName: "15000"} {
			addr := host + ":" + port
			t.Run(addr, func(t *testing.T) {
				s := validServer("a")
				s.ProcessorAddr = addr
				msg := refusalOf(t, Input{ListenPort: testListenPort, Servers: []Server{s}}, "a", addr, socket, port)
				requireWording(t, msg, " is the gateway's own ")
			})
		}
	}
}

// TestProcessorNameOnAGatewayPortIsRefused: a host that is not an IP literal
// is refused with every port the gateway binds, because a name may resolve to
// this host and the emitter has no safe way to tell (D15 h). The error says
// that the address may be the gateway's own socket, not that it is, and asks
// for an IP address or another port. Before this round every one of these was
// accepted with the off-loopback warning.
func TestProcessorNameOnAGatewayPortIsRefused(t *testing.T) {
	for _, host := range otherNames() {
		for socket, port := range gatewaySocketPorts() {
			addr := host + ":" + port
			t.Run(addr, func(t *testing.T) {
				s := validServer("a")
				s.ProcessorAddr = addr
				msg := refusalOf(t, Input{ListenPort: testListenPort, Servers: []Server{s}}, "a", addr, socket, port)
				requireWording(t, msg, "not an IP literal", "may resolve to this host", "may be the gateway's own", "write the processor's IP address")
			})
		}
	}
}

// TestProcessorNameRuleFollowsTheListenerInputs: the name rule reads the
// ports the input binds, like the rest of the socket rule. A name or an alias
// on a moved listener's new port or the moved serving port is refused; on the
// port the listener left, a name is accepted with the usual warning and an
// alias quietly.
func TestProcessorNameRuleFollowsTheListenerInputs(t *testing.T) {
	moved := func(addr string) Input {
		s := validServer("a")
		s.ProcessorAddr = addr
		return Input{ListenPort: 8080, AdminAddr: "127.0.0.1:16000", Servers: []Server{s}}
	}
	refusalOf(t, moved("h.example:8080"), "a", "h.example:8080", servingName, "8080")
	refusalOf(t, moved("localhost4:16000"), "a", "localhost4:16000", adminName, "16000")
	accepted := map[string]string{
		"h.example:15000": "processor for server a at h.example:15000" + processorRisk,
		"localhost4:" + strconv.Itoa(testListenPort): "",
	}
	for addr, want := range accepted {
		out, err := AgentGateway(moved(addr))
		if err != nil {
			t.Errorf("processor %q on a port the moved gateway does not bind rejected: %v", addr, err)
			continue
		}
		if out.Warning != want {
			t.Errorf("processor %q: Warning = %q, want %q", addr, out.Warning, want)
		}
	}
}

// TestLoopbackAliasOnAFreePortIsQuiet: on a port the gateway does not bind an
// alias is accepted like localhost, with no off-loopback line, so the printed
// serve command does not demand --allow-non-loopback and a secret for a
// loopback socket (the wrong warning the fifth review found); another name on
// a free port is accepted with the line, as before.
func TestLoopbackAliasOnAFreePortIsQuiet(t *testing.T) {
	for _, host := range loopbackAliases() {
		s := validServer("a")
		s.ProcessorAddr = host + ":9001"
		out, err := AgentGateway(Input{ListenPort: testListenPort, Servers: []Server{s}})
		if err != nil {
			t.Errorf("processor %q rejected: %v", s.ProcessorAddr, err)
			continue
		}
		if out.Warning != "" {
			t.Errorf("processor %q: Warning = %q, want none", s.ProcessorAddr, out.Warning)
		}
	}
	for _, host := range []string{"h.example", "my_svc.ns.svc", "localhost5", "localhost.example"} {
		s := validServer("a")
		s.ProcessorAddr = host + ":9001"
		out, err := AgentGateway(Input{ListenPort: testListenPort, Servers: []Server{s}})
		if err != nil {
			t.Errorf("processor %q rejected: %v", s.ProcessorAddr, err)
			continue
		}
		if want := "processor for server a at " + s.ProcessorAddr + processorRisk; out.Warning != want {
			t.Errorf("processor %q: Warning = %q, want %q", s.ProcessorAddr, out.Warning, want)
		}
	}
}

// TestIsLoopbackName pins the exported predicate the serve command shares
// with the emitter: localhost and every alias in lower, upper and mixed case,
// and nothing else, not a trailing dot, a domain under localhost, a near
// miss, an alias with the wrong suffix, an IP literal or an empty host.
func TestIsLoopbackName(t *testing.T) {
	for _, name := range loopbackNames() {
		for _, host := range []string{name, strings.ToUpper(name), strings.ToUpper(name[:1]) + name[1:]} {
			if !IsLoopbackName(host) {
				t.Errorf("IsLoopbackName(%q) = false, want true", host)
			}
		}
	}
	for _, host := range []string{"localhost.", "localhost.example", "localhost5", "ip6-localhost.", "localhost4.localdomain", "localhost.localdomain4", "127.0.0.1", "::1", "", "local host"} {
		if IsLoopbackName(host) {
			t.Errorf("IsLoopbackName(%q) = true, want false", host)
		}
	}
}

// TestGatewayAcceptsAProcessorNamedForItsOwnSocket pins why the name half of
// the socket rule exists: the real binary in --validate-only mode loads a file
// whose processor host is a resolver alias of localhost or another name with
// the serving or admin port, so nothing between emit and the reload would name
// the collision. If a gateway version starts refusing it, this test says so
// and the documents can drop the caveat.
func TestGatewayAcceptsAProcessorNamedForItsOwnSocket(t *testing.T) {
	binary := gatewayBinary(t)
	out := freshOutput(t)
	hostLine := "      - host: " + quote(testProcessorAddr) + "\n"
	for _, addr := range []string{"localhost.localdomain:" + strconv.Itoa(testListenPort), "ip6-localhost:15000", "h.example:" + strconv.Itoa(testListenPort)} {
		s := validServer("a")
		s.ProcessorAddr = addr
		requireInvalid(t, Input{ListenPort: testListenPort, Servers: []Server{s}})
		requireValid(t, binary, mutate(t, out.YAML, hostLine, "      - host: "+quote(addr)+"\n"), "a processor named for the gateway's own socket "+addr)
	}
}
