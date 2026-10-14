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

// localhostName is the one host name every resolver maps to loopback;
// loopbackNames adds the aliases common /etc/hosts files carry beside it.
const localhostName = "localhost"

// processorRisk is what a processor reachable from other hosts means when
// the gateway dials it in plaintext; processorTLSRisk when its entry carries
// the backendTLS block (D19): the hooks still cross the network, but under
// TLS with the gateway's client certificate, which serve --tls-client-ca
// verifies in place of the shared secret (owner decision O-2). The line
// states the protection so that the exposure and its guard are read together.
const (
	processorRisk    = " is not on loopback: the hooks that decide what the gateway serves cross the network, and serve refuses such a listener unless it is explicitly allowed and carries a shared secret"
	processorTLSRisk = " is not on loopback: the hooks that decide what the gateway serves cross the network under TLS (backendTLS: the gateway presents its client certificate and verifies the processor's certificate under hostname "
	processorTLSEnd  = "), and serve must require that certificate with --tls-client-ca, or carry the shared secret, to accept such a listener"
)

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
			lines = append(lines, "processor for server "+s.Name+" at "+s.ProcessorAddr+processorExposure(s.TLS))
		}
	}
	return strings.Join(lines, "\n")
}

// processorExposure is the tail of the warning line for a processor off
// loopback: the plaintext risk, or the TLS protection with the validated
// hostname (printable ASCII by validateTLSHostname, so the line stays one).
func processorExposure(t *ProcessorTLS) string {
	if t == nil {
		return processorRisk
	}
	return processorTLSRisk + t.Hostname + processorTLSEnd
}

// processorHost is the host part of a processor address that validation has
// already proved to be host:port.
func processorHost(addr string) string {
	host, _, _ := net.SplitHostPort(addr)
	return host
}

// loopbackNames are the host names the resolvers of common gateway hosts map
// to 127.0.0.1 or ::1 from /etc/hosts without any DNS query: localhost, the
// aliases the RHEL and Fedora family ship ("127.0.0.1 localhost
// localhost.localdomain localhost4 localhost4.localdomain4" and "::1
// localhost localhost.localdomain localhost6 localhost6.localdomain6") and
// the ones Debian and Ubuntu ship ("::1 ip6-localhost ip6-loopback"). A
// function rather than a package-level slice so that the list cannot be
// modified at run time.
func loopbackNames() []string {
	return []string{
		localhostName, "localhost.localdomain", "localhost4", "localhost4.localdomain4",
		"localhost6", "localhost6.localdomain6", "ip6-localhost", "ip6-loopback",
	}
}

// IsLoopbackName reports whether host is a name common resolvers map to a
// loopback address without any DNS query (loopbackNames), compared without
// regard to case as DNS names are. It is exported so that the serve command's
// listen rule and the emitter's processor rules read one list (D15 h): the
// fifth review found the emitter warning that a processor at
// localhost.localdomain was off loopback, so the printed serve command
// demanded --allow-non-loopback and a secret for a loopback socket, while the
// socket rule let the alias reach the gateway's own port. Any other name is
// not resolved, because a name is not a safe way to say "loopback"; the
// socket rule treats it as a host that may resolve to this one
// (refuseGatewaySocket).
func IsLoopbackName(host string) bool {
	for _, name := range loopbackNames() {
		if strings.EqualFold(host, name) {
			return true
		}
	}
	return false
}

// isLoopbackHost reports whether a processor host is a loopback name
// (IsLoopbackName) or a loopback IP literal. Anything else, a specific
// address or another name, is taken to be reachable from other hosts.
func isLoopbackHost(host string) bool {
	if IsLoopbackName(host) {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}
