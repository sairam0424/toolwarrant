package fetch

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
)

// addrClass is the verdict of the classifier before the AllowPrivate switch is
// applied.
type addrClass int

const (
	// classPublic is a globally routable unicast address.
	classPublic addrClass = iota
	// classPrivate is loopback, RFC 1918 or unique-local: forbidden unless
	// Policy.AllowPrivate is set.
	classPrivate
	// classBlocked is never allowed, whatever the policy says.
	classBlocked
)

// classRules holds the prefix tables. They are built once and never changed.
type classRules struct {
	// metadata lists cloud instance-metadata endpoints. It is checked before
	// everything else so that no AllowPrivate setting, and no edit to the
	// private table, can expose credentials served there.
	metadata []netip.Prefix
	// private is what AllowPrivate relaxes: loopback, RFC 1918, unique-local.
	private []netip.Prefix
	// blocked is special-purpose space that is never a legitimate crawl target.
	blocked []netip.Prefix
	// nat64 and sixToFour embed an IPv4 destination that is judged instead of
	// the IPv6 wrapper.
	nat64     netip.Prefix
	sixToFour netip.Prefix
	// global is the only IPv6 range IANA hands out for public unicast use.
	global netip.Prefix
}

var loadRules = sync.OnceValue(buildRules)

func buildRules() classRules {
	return classRules{
		metadata:  metadataPrefixes(),
		private:   privatePrefixes(),
		blocked:   blockedPrefixes(),
		nat64:     netip.MustParsePrefix("64:ff9b::/96"),
		sixToFour: netip.MustParsePrefix("2002::/16"),
		global:    netip.MustParsePrefix("2000::/3"),
	}
}

func metadataPrefixes() []netip.Prefix {
	return parsePrefixes(
		"169.254.169.254/32", // AWS, GCP, Azure, OpenStack and others
		"169.254.170.2/32",   // AWS ECS task credentials
		"100.100.100.200/32", // Alibaba Cloud
		"192.0.0.192/32",     // Oracle Cloud
		"168.63.129.16/32",   // Azure WireServer (looks public)
		"fd00:ec2::/32",      // AWS IMDS over IPv6, fd00:ec2::254
		"fd20:ce::/32",       // Google Compute Engine IPv6 metadata
	)
}

func privatePrefixes() []netip.Prefix {
	return parsePrefixes(
		"127.0.0.0/8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"::1/128",
		"fc00::/7",
	)
}

func blockedPrefixes() []netip.Prefix {
	return parsePrefixes(
		"0.0.0.0/8",       // "this network", includes 0.0.0.0
		"100.64.0.0/10",   // carrier-grade NAT
		"169.254.0.0/16",  // link-local, includes the metadata address
		"192.0.0.0/24",    // IETF protocol assignments
		"192.0.2.0/24",    // TEST-NET-1
		"192.88.99.0/24",  // deprecated 6to4 relay anycast
		"198.18.0.0/15",   // benchmarking
		"198.51.100.0/24", // TEST-NET-2
		"203.0.113.0/24",  // TEST-NET-3
		"224.0.0.0/4",     // multicast
		"240.0.0.0/4",     // reserved, includes 255.255.255.255 broadcast
		"::/96",           // unspecified and deprecated IPv4-compatible
		"::ffff:0:0:0/96", // deprecated IPv4-translated
		"64:ff9b:1::/48",  // local-use NAT64: the embedding depends on the operator's prefix length
		"100::/64",        // discard-only
		"2001::/32",       // Teredo tunnelling
		"2001:2::/48",     // benchmarking
		"2001:db8::/32",   // documentation
		"3fff::/20",       // documentation
		"5f00::/16",       // SRv6 segment identifiers
		"fe80::/10",       // link-local
		"fec0::/10",       // deprecated site-local
		"ff00::/8",        // multicast
	)
}

// parsePrefixes parses compile-time constant CIDR strings. A typo is a
// programming error, caught by TestRulesParse, never a runtime input problem.
func parsePrefixes(cidrs ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(cidrs))
	for i, cidr := range cidrs {
		out[i] = netip.MustParsePrefix(cidr)
	}
	return out
}

// IsForbiddenIP reports whether a connection to ip must be refused. It is the
// single classifier behind the dialer and is exported so other code (for
// example a validator that wants to reject a URL early) applies the same rules.
//
// Loopback, RFC 1918 and unique-local addresses are forbidden unless
// allowPrivate is true. Link-local (which contains the cloud metadata address),
// cloud-metadata endpoints, multicast, broadcast, reserved, unspecified,
// carrier-grade NAT, documentation and benchmarking ranges are forbidden
// whatever allowPrivate says. IPv4-mapped IPv6 addresses are judged as the IPv4
// address they contain. NAT64 (64:ff9b::/96) and 6to4 (2002::/16) addresses are
// judged by the IPv4 address they embed, strictly: a private destination behind
// a translator is not a local-development convenience. An invalid address is
// forbidden.
func IsForbiddenIP(ip net.IP, allowPrivate bool) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	return forbiddenAddr(addr, allowPrivate)
}

// forbiddenAddr is IsForbiddenIP for a netip.Addr. A zone is forbidden: a
// scoped address only makes sense on a local link.
func forbiddenAddr(addr netip.Addr, allowPrivate bool) bool {
	if !addr.IsValid() || addr.Zone() != "" {
		return true
	}
	switch classifyAddr(addr) {
	case classPublic:
		return false
	case classPrivate:
		return !allowPrivate
	default:
		return true
	}
}

// checkAddr is the one function both the pre-dial vetting and the socket-level
// Control hook call, so the two can never disagree.
func checkAddr(addr netip.Addr, allowPrivate bool) error {
	if forbiddenAddr(addr, allowPrivate) {
		return fmt.Errorf("%w: %s", ErrBlockedAddress, addr)
	}
	return nil
}

func classifyAddr(addr netip.Addr) addrClass {
	addr = addr.Unmap()
	rules := loadRules()
	if containsAny(rules.metadata, addr) {
		return classBlocked
	}
	if embedded, ok := embeddedIPv4(rules, addr); ok {
		if classifyAddr(embedded) != classPublic {
			return classBlocked
		}
		return classPublic
	}
	if containsAny(rules.private, addr) {
		return classPrivate
	}
	if containsAny(rules.blocked, addr) {
		return classBlocked
	}
	if addr.Is6() && !rules.global.Contains(addr) {
		return classBlocked
	}
	return classPublic
}

// embeddedIPv4 extracts the IPv4 destination from the translation prefixes
// whose embedding is fixed by their RFC.
func embeddedIPv4(rules classRules, addr netip.Addr) (netip.Addr, bool) {
	if !addr.Is6() {
		return netip.Addr{}, false
	}
	raw := addr.As16()
	switch {
	case rules.nat64.Contains(addr):
		return netip.AddrFrom4([4]byte(raw[12:16])), true
	case rules.sixToFour.Contains(addr):
		return netip.AddrFrom4([4]byte(raw[2:6])), true
	}
	return netip.Addr{}, false
}

func containsAny(list []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range list {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
