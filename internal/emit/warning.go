package emit

import (
	"net"
	"net/netip"
	"strings"
)

// Exposure phrases shared by every warning line, so the same situation is
// always described in the same words.
const (
	reachEveryInterface = "every interface of this host"
	reachOtherHosts     = "an address other hosts can reach"
)

// localhostName is the one host name the processor rules treat as loopback,
// mirroring the serve command: any other name is not resolved, because a
// name is not a safe way to say "loopback".
const localhostName = "localhost"

// processorRisk is what a processor reachable from other hosts means.
const processorRisk = " is not on loopback: the hooks that decide what the gateway serves cross the network, and serve refuses such a listener unless it is explicitly allowed and carries a shared secret"

// reach says who can connect to a socket bound to addr, which is known not to
// be loopback.
func reach(addr netip.Addr) string {
	if addr.IsUnspecified() {
		return reachEveryInterface
	}
	return reachOtherHosts
}

// buildWarning assembles Output.Warning from the validated input: the serving
// socket, then each listener, then each processor that is not on loopback,
// servers in name order, one line each, joined by newlines. Every piece of
// text comes from a validated address or name, so each line is printable
// ASCII and never carries upstream text.
func buildWarning(v validated, port int) string {
	var lines []string
	if line := bindWarning(v.bind, port); line != "" {
		lines = append(lines, line)
	}
	for _, l := range v.listeners {
		if !l.off && !l.addr.IsLoopback() {
			lines = append(lines, l.name+" listens on "+l.text()+", "+reach(l.addr)+": "+l.risk)
		}
	}
	for _, s := range v.servers {
		if !isLoopbackHost(processorHost(s.ProcessorAddr)) {
			lines = append(lines, "processor for server "+s.Name+" at "+s.ProcessorAddr+processorRisk)
		}
	}
	return strings.Join(lines, "\n")
}

// processorHost is the host part of a processor address that validation has
// already proved to be host:port.
func processorHost(addr string) string {
	host, _, _ := net.SplitHostPort(addr)
	return host
}

// isLoopbackHost reports whether a processor host is "localhost" in any case
// or a loopback IP literal. Anything else, a specific address or a name, is
// taken to be reachable from other hosts.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, localhostName) {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}
