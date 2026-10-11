package emit

import (
	"fmt"
	"net/netip"
	"strings"
)

// gatewaySocket is one socket the gateway binds for itself, the serving
// socket or a listener that is not off: the name errors call it by and the
// canonical address it binds. The address is kept, not only the port, so that
// the processor rule can recognise the very socket the input names and not
// only the loopback class (D14 h).
type gatewaySocket struct {
	name string
	addr netip.Addr
}

// refuseAmbiguousHost is the numeric-spelling rule (D14 h): a processor host
// the resolver would read as a number must be the canonical dotted quad that
// netip.ParseAddr accepts. getaddrinfo reads "127.1", "127.000.000.001",
// "0x7f.0.0.1", "2130706433" and "0" as 127.0.0.1 or 0.0.0.0 without any DNS
// lookup, and a leading zero is octal to glibc and decimal to macOS, so such
// a spelling names a loopback or wildcard socket the socket rule cannot see,
// is warned about as off-loopback, and may mean different addresses on the
// host that emits and the host that runs the gateway. The fourth review
// reached the D13(g) collision this way; the gateway's --validate-only loads
// every one of these spellings (TestGatewayAcceptsAmbiguousProcessorSpellings).
func refuseAmbiguousHost(host string) error {
	if !isNumericHost(host) {
		return nil
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil
	}
	return fmt.Errorf("processor host %s is an ambiguous numeric spelling: the resolver reads a host whose labels are all digits or start with 0x as an IPv4 address in its own notation (127.1 and 0x7f.0.0.1 both mean 127.0.0.1 to it, and a leading zero is octal to some resolvers); write the canonical dotted quad", shown(host))
}

// isNumericHost reports whether the resolver would read host as a number
// instead of looking it up: every dot-separated label is a part of inet_aton's
// IPv4 notation (all digits, or hexadecimal with a 0x prefix), or the host
// starts with 0x. A name with a numeric label among others ("1.example",
// "0.pool.example") is a DNS name and is not numeric.
func isNumericHost(host string) bool {
	labels := strings.Split(host, ".")
	if hasHexPrefix(labels[0]) {
		return true
	}
	for _, label := range labels {
		if !isDigits(label) && !hasHexPrefix(label) {
			return false
		}
	}
	return true
}

// hasHexPrefix reports whether label begins with 0x or 0X, inet_aton's marker
// for a hexadecimal part.
func hasHexPrefix(label string) bool {
	return len(label) >= 2 && label[0] == '0' && (label[1] == 'x' || label[1] == 'X')
}

// isDigits reports whether s is one or more ASCII digits; an empty label is
// not a number.
func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// refuseGatewaySocket is the rule that keeps a processor off the gateway's
// own listeners. With a port the gateway binds for itself (reserved), a
// processor host that is this host (isThisHost) or the very address the
// socket binds (isGatewayHost) is the socket the gateway binds itself, and a
// host that is not an IP literal is refused as well (D15 h): a name may
// resolve to this host, through /etc/hosts or DNS, and the emitter has no
// safe way to tell, so the only hosts that may share a gateway port are IP
// literals the emitter can see are not this host. The fifth review reached
// the gateway's own socket with the resolver aliases of localhost
// (localhost.localdomain, ip6-localhost and their kin, now loopbackNames);
// with this rule no name at all reaches it. A port the port rule will refuse
// is left to it. The class comparison stays deliberately coarse, like the
// listeners' distinct-port rule: "127.0.0.2" with the admin port is refused
// although the admin API binds 127.0.0.1, because two loopback spellings are
// not worth telling apart here. A specific address of this host that the
// input does not bind cannot be recognised and is not refused, and a wildcard
// listener is not expanded to every specific address, because a processor on
// another host may legitimately use that port.
func refuseGatewaySocket(addr, host, portText string, reserved map[int]gatewaySocket) error {
	port, ok := parsePort(portText)
	if !ok {
		return nil
	}
	socket, taken := reserved[port]
	if !taken {
		return nil
	}
	if isGatewayHost(host, socket.addr) {
		return fmt.Errorf("processor address %s is the gateway's own %s socket (port %d): the gateway would dial its own listener for every hook; use a port the gateway does not bind", shown(addr), socket.name, port)
	}
	if !isIPLiteral(host) {
		return fmt.Errorf("processor address %s has a host that is not an IP literal and may resolve to this host, so it may be the gateway's own %s socket (port %d): the gateway would dial its own listener for every hook; write the processor's IP address or use a port the gateway does not bind", shown(addr), socket.name, port)
	}
	return nil
}

// isIPLiteral reports whether host is an address netip.ParseAddr accepts. Only
// canonical spellings reach the socket rule, so a numeric host that is not a
// literal has already been refused by refuseAmbiguousHost; what is left when
// this is false is a name, an empty host or a shape the host rule refuses.
func isIPLiteral(host string) bool {
	_, err := netip.ParseAddr(host)
	return err == nil
}

// isGatewayHost reports whether a processor host collides with the socket
// bound at bound: it is this host as a class (isThisHost), or it is bound
// itself, so that BindAddress 10.0.0.5 with a processor on 10.0.0.5 and the
// serving port is refused although 10.0.0.5 is not loopback (D14 h). An
// IPv4-mapped spelling is unmapped first so that it is reported as the
// collision it is rather than as a host-shape error.
func isGatewayHost(host string, bound netip.Addr) bool {
	if isThisHost(host) {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.Unmap() == bound
}

// isThisHost reports whether a processor host names the gateway's own host
// for the socket rule: a loopback name in any case (IsLoopbackName: localhost
// and the aliases common resolvers map to loopback without DNS) or a loopback
// literal (see isLoopbackHost), or a wildcard address, which connects to
// loopback when it is dialled. Only canonical spellings reach it:
// refuseAmbiguousHost has already refused the resolver's shorthand forms.
func isThisHost(host string) bool {
	if isLoopbackHost(host) {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsUnspecified()
}
