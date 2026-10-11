package emit

import (
	"net"
	"net/netip"
	"strconv"
)

// Default addresses of the gateway's own process-level listeners. Left unset
// in the file, agentgateway v1.6.0 binds stats to [::]:15020 and readiness to
// [::]:15021, which exposes metrics and health on every interface of the
// host, so the emitter always writes all three. The ports are the gateway's
// own defaults, so an operator who knows the gateway finds them where
// expected; they are inputs rather than constants so that two gateways can
// run from emitted files on one host and so that the admin API can be moved
// or turned off.
const (
	DefaultAdminAddr     = "127.0.0.1:15000"
	DefaultStatsAddr     = "127.0.0.1:15020"
	DefaultReadinessAddr = "127.0.0.1:15021"
)

// listenerOff is the exact value agentgateway v1.6.0 takes for a disabled
// listener. binary_test.go proves that "OFF", "Off" and "off " are refused by
// its parser, so this must stay lowercase and unpadded.
const listenerOff = "off"

// YAML keys of the three listeners under config, in the order they are
// written.
const (
	adminKey     = "adminAddr"
	statsKey     = "statsAddr"
	readinessKey = "readinessAddr"
)

// How the listeners and the serving port are called in errors and warnings.
const (
	adminName     = "admin API"
	statsName     = "stats endpoint"
	readinessName = "readiness probe"
	servingName   = "serving port"
)

// What exposing each listener means, for Output.Warning. The admin notice
// says what the API can do, because that is what makes exposing it a decision
// (see the package documentation).
const (
	adminRisk     = "it has no authentication, POST /api/config replaces the running configuration and /config_dump returns it with every processor secret in clear; firewall the port, bind a loopback address or set DisableAdmin"
	statsRisk     = "it exposes the gateway's metrics; firewall the port or bind a loopback address"
	readinessRisk = "it exposes the gateway's health probe; firewall the port or bind a loopback address"
)

// listener is one process-level listener after validation: either off, or an
// IP literal and a port.
type listener struct {
	key  string
	name string
	risk string
	off  bool
	addr netip.Addr
	port int
}

// text is the value the config block carries for the listener: the gateway's
// off switch, or the canonical host:port ("[::1]:15000" for IPv6).
func (l listener) text() string {
	if l.off {
		return listenerOff
	}
	return net.JoinHostPort(l.addr.String(), strconv.Itoa(l.port))
}

// listenerInput pairs one listener's fixed identity with what the input said
// about it.
type listenerInput struct {
	key, name, risk string
	raw, fallback   string
	off             bool
}

// listenerInputs is the three listeners in file order with their input
// values. Only the admin API has a switch.
func listenerInputs(in Input) []listenerInput {
	return []listenerInput{
		{key: adminKey, name: adminName, risk: adminRisk, raw: in.AdminAddr, fallback: DefaultAdminAddr, off: in.DisableAdmin},
		{key: statsKey, name: statsName, risk: statsRisk, raw: in.StatsAddr, fallback: DefaultStatsAddr},
		{key: readinessKey, name: readinessName, risk: readinessRisk, raw: in.ReadinessAddr, fallback: DefaultReadinessAddr},
	}
}

// validateListeners checks the admin, stats and readiness addresses. Each is
// an IP literal and a port under the bind-address rules, and loopback unless
// in.AllowAllInterfaces permits otherwise: any address other hosts can reach,
// not only a wildcard, because the admin API is unauthenticated and the other
// two have no business being public. The serving port and the listeners must
// use distinct ports (compared as ports, whatever the hosts): the gateway's
// --validate-only accepts a collision and the gateway then fails at start-up.
// The returned map is every socket the gateway binds for itself, the serving
// socket (bind is its validated address) and each listener that is not off,
// keyed by port and carrying the socket's name and canonical address; validate
// uses it to keep every processor off those sockets, by loopback class and by
// the very address (D14 h).
func validateListeners(in Input, bind netip.Addr) ([]listener, map[int]gatewaySocket, error) {
	if in.DisableAdmin && in.AdminAddr != "" {
		return nil, nil, invalid("AdminAddr %s and DisableAdmin contradict each other; set one of them", shown(in.AdminAddr))
	}
	ports := map[int]gatewaySocket{in.ListenPort: {name: servingName, addr: bind}}
	inputs := listenerInputs(in)
	out := make([]listener, 0, len(inputs))
	for _, li := range inputs {
		l := listener{key: li.key, name: li.name, risk: li.risk, off: li.off}
		if !li.off {
			addr, port, err := validateListenerAddr(li.name, li.raw, li.fallback, in.AllowAllInterfaces)
			if err != nil {
				return nil, nil, err
			}
			if other, dup := ports[port]; dup {
				return nil, nil, invalid("the %s and the %s both use port %d; the gateway's listeners need distinct ports", li.name, other.name, port)
			}
			ports[port] = gatewaySocket{name: li.name, addr: addr}
			l.addr, l.port = addr, port
		}
		out = append(out, l)
	}
	return out, ports, nil
}

// validateListenerAddr parses one listener address (fallback when raw is
// empty) and returns its IP and port. The off switch is refused as an address
// so that there is exactly one way to turn the admin API off and no way to
// turn the others off.
func validateListenerAddr(name, raw, fallback string, allowAll bool) (netip.Addr, int, error) {
	if raw == "" {
		raw = fallback
	}
	if raw == listenerOff {
		return netip.Addr{}, 0, invalid("%s address %s is the gateway's off switch; the emitter turns the admin API off with DisableAdmin and keeps the stats and readiness listeners", name, shown(raw))
	}
	host, portText, err := net.SplitHostPort(raw)
	if err != nil {
		return netip.Addr{}, 0, invalid("%s address %s must be host:port with an IP literal", name, shown(raw))
	}
	addr, err := parseListenIP(name+" address", host)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	if !addr.IsLoopback() && !allowAll {
		return netip.Addr{}, 0, invalid("%s address %s is not loopback and would be reachable from other hosts; refused unless AllowAllInterfaces is set", name, shown(raw))
	}
	port, ok := parsePort(portText)
	if !ok {
		return netip.Addr{}, 0, invalid("%s address %s has a port outside %d-%d", name, shown(raw), minPort, maxPort)
	}
	return addr, port, nil
}
