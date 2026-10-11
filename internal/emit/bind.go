package emit

import (
	"net"
	"net/netip"
	"strconv"
)

// DefaultBindAddress is the address the serving gateway binds ListenPort on
// when Input.BindAddress is empty. It is loopback because seam finding F2
// showed that any reach to an unguarded route or bind is a complete bypass of
// the control plane and that a gateway bind listens on every interface unless
// told otherwise; a socket other hosts cannot reach needs no firewall to be
// safe. An operator who needs the gateway on the network asks for it with
// Input.BindAddress and, for a wildcard address, Input.AllowAllInterfaces.
const DefaultBindAddress = "127.0.0.1"

// gatewayName is the key of the single entry in the emitted gateways map and
// the value of every route's gateways field. It is deliberately not "default":
// agentgateway attaches a route that has no gateways field to the gateway
// named default, so with this name a route added to the file by hand without
// naming the gateway is refused at load ("routes.<name> must set gateways")
// instead of being served on the port.
const gatewayName = "toolwarrant"

// bindWhat names the serving address in error messages.
const bindWhat = "bind address"

// warningTail is the second half of the bind warning: what the exposure
// means and what to do about it.
const warningTail = ": the routes are reachable from the network and the toolwarrant processor is their only guard (seam finding F2); firewall the port or bind a loopback address"

// parseListenIP parses one IP literal the gateway must be able to bind, for
// the serving socket and for the admin, stats and readiness listeners alike.
// agentgateway's own parser refuses host names, host:port forms, brackets and
// zones, which binary_test.go confirms; the rules below are stricter, because
// the gateway accepts at load time addresses it cannot bind at start-up:
//
//   - an IPv4-mapped IPv6 address ("::ffff:127.0.0.1") is refused because what
//     it binds is implementation-defined (Go's own predicates treat it as the
//     IPv4 address it wraps); the IPv4 address itself says the same thing
//     without ambiguity;
//   - an IPv6 link-local address needs a zone to be bound and the gateway's
//     address fields cannot carry one, so it is refused rather than written;
//   - multicast and broadcast addresses cannot be listened on.
//
// A wildcard passes here; whether the caller may use one is its own rule.
func parseListenIP(what, raw string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Addr{}, invalid("%s %s is not an IPv4 or IPv6 literal", what, shown(raw))
	}
	switch {
	case addr.Zone() != "":
		return netip.Addr{}, invalid("%s %s carries a zone, which the gateway's address fields cannot", what, shown(raw))
	case addr.Is4In6():
		return netip.Addr{}, invalid("%s %s is an IPv4-mapped IPv6 address; write the IPv4 address itself", what, shown(raw))
	case addr.Is6() && addr.IsLinkLocalUnicast():
		return netip.Addr{}, invalid("%s %s is IPv6 link-local and needs a zone, which the gateway's address fields cannot carry", what, shown(raw))
	case !addr.IsUnspecified() && !addr.IsLoopback() && !addr.IsGlobalUnicast() && !addr.IsLinkLocalUnicast():
		return netip.Addr{}, invalid("%s %s is not a unicast, loopback or wildcard address", what, shown(raw))
	}
	return addr, nil
}

// validateBindAddress parses in.BindAddress (DefaultBindAddress when empty)
// and returns the address the gateway block will carry. A wildcard ("0.0.0.0"
// or "::") needs in.AllowAllInterfaces, since it exposes every route to the
// network (F2); a specific address other hosts can reach is accepted without
// it and reported through Output.Warning.
func validateBindAddress(in Input) (netip.Addr, error) {
	raw := in.BindAddress
	if raw == "" {
		raw = DefaultBindAddress
	}
	addr, err := parseListenIP(bindWhat, raw)
	if err != nil {
		return netip.Addr{}, err
	}
	if addr.IsUnspecified() && !in.AllowAllInterfaces {
		return netip.Addr{}, invalid("%s %s would listen on every interface; refused unless AllowAllInterfaces is set", bindWhat, shown(raw))
	}
	return addr, nil
}

// bindWarning is the line Output.Warning carries when the serving socket is
// reachable from other hosts, or "" for a loopback address. It is advice, not
// an error: the operator asked for the address and the input is valid.
func bindWarning(addr netip.Addr, port int) string {
	if addr.IsLoopback() {
		return ""
	}
	socket := net.JoinHostPort(addr.String(), strconv.Itoa(port))
	return "gateway listens on " + socket + ", " + reach(addr) + warningTail
}
