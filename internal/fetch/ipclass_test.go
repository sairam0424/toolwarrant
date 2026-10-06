package fetch

import (
	"errors"
	"net"
	"net/netip"
	"testing"
)

func TestIsForbiddenIP(t *testing.T) {
	cases := []struct {
		ip      string
		strict  bool // forbidden with allowPrivate=false
		lenient bool // forbidden with allowPrivate=true
	}{
		// loopback: relaxable
		{"127.0.0.1", true, false},
		{"127.255.255.255", true, false},
		{"::1", true, false},
		{"::ffff:127.0.0.1", true, false},
		{"::ffff:7f00:1", true, false},
		// unspecified and "this network": never
		{"0.0.0.0", true, true},
		{"0.1.2.3", true, true},
		{"::", true, true},
		// link-local and metadata: never
		{"169.254.169.254", true, true},
		{"169.254.0.1", true, true},
		{"169.254.170.2", true, true},
		{"::ffff:169.254.169.254", true, true},
		{"fd00:ec2::254", true, true},
		{"fd20:ce::254", true, true},
		{"fe80::1", true, true},
		{"fe80::a:b", true, true},
		{"100.100.100.200", true, true},
		{"168.63.129.16", true, true},
		{"192.0.0.192", true, true},
		// RFC 1918 and unique-local: relaxable
		{"10.0.0.1", true, false},
		{"10.255.255.255", true, false},
		{"172.16.0.1", true, false},
		{"172.31.255.255", true, false},
		{"192.168.1.1", true, false},
		{"fc00::1", true, false},
		{"fd12:3456:789a::1", true, false},
		// just outside the private ranges: public
		{"172.15.255.255", false, false},
		{"172.32.0.1", false, false},
		{"192.167.255.255", false, false},
		{"192.169.0.1", false, false},
		{"11.0.0.1", false, false},
		// special-purpose IPv4: never
		{"100.64.0.1", true, true},
		{"100.127.255.255", true, true},
		{"100.63.255.255", false, false},
		{"100.128.0.1", false, false},
		{"192.0.0.1", true, true},
		{"192.0.2.1", true, true},
		{"198.51.100.1", true, true},
		{"203.0.113.1", true, true},
		{"198.18.0.1", true, true},
		{"198.19.255.255", true, true},
		{"198.20.0.1", false, false},
		{"192.88.99.1", true, true},
		// multicast, broadcast, reserved: never
		{"224.0.0.1", true, true},
		{"239.255.255.255", true, true},
		{"ff02::1", true, true},
		{"ff0e::1", true, true},
		{"255.255.255.255", true, true},
		{"240.0.0.1", true, true},
		// translation prefixes are judged by the embedded IPv4, strictly
		{"64:ff9b::7f00:1", true, true},
		{"64:ff9b::a00:1", true, true},
		{"64:ff9b::a9fe:a9fe", true, true},
		{"64:ff9b::808:808", false, false},
		{"64:ff9b:1::1", true, true},
		{"2002:7f00:1::", true, true},
		{"2002:a00:1::", true, true},
		{"2002:a9fe:a9fe::", true, true},
		{"2002:808:808::", false, false},
		// deprecated or special IPv6: never
		{"2001::1", true, true},
		{"2001:db8::1", true, true},
		{"2001:2::1", true, true},
		{"3fff::1", true, true},
		{"100::1", true, true},
		{"5f00::1", true, true},
		{"fec0::1", true, true},
		{"::7f00:1", true, true},
		{"::ffff:0:7f00:1", true, true},
		{"4000::1", true, true},
		// public
		{"8.8.8.8", false, false},
		{"1.1.1.1", false, false},
		{"93.184.216.34", false, false},
		{"2001:4860:4860::8888", false, false},
		{"2606:4700:4700::1111", false, false},
		{"::ffff:8.8.8.8", false, false},
	}
	for _, tc := range cases {
		addr, err := netip.ParseAddr(tc.ip)
		if err != nil {
			t.Fatalf("bad test address %q: %v", tc.ip, err)
		}
		ip := net.IP(addr.AsSlice())
		if got := IsForbiddenIP(ip, false); got != tc.strict {
			t.Errorf("IsForbiddenIP(%s, false) = %v, want %v", tc.ip, got, tc.strict)
		}
		if got := IsForbiddenIP(ip, true); got != tc.lenient {
			t.Errorf("IsForbiddenIP(%s, true) = %v, want %v", tc.ip, got, tc.lenient)
		}
	}
}

func TestIsForbiddenIPInvalid(t *testing.T) {
	for _, ip := range []net.IP{nil, {}, {1}, {1, 2, 3}, {1, 2, 3, 4, 5}, make(net.IP, 15), make(net.IP, 17)} {
		if !IsForbiddenIP(ip, true) || !IsForbiddenIP(ip, false) {
			t.Errorf("IsForbiddenIP(%v) must fail closed", []byte(ip))
		}
	}
}

func TestForbiddenAddrRejectsZoneAndZeroValue(t *testing.T) {
	zoned := netip.MustParseAddr("fe80::1%eth0")
	if !forbiddenAddr(zoned, true) {
		t.Error("a zoned address must be forbidden")
	}
	public := netip.MustParseAddr("2606:4700:4700::1111").WithZone("eth0")
	if !forbiddenAddr(public, true) {
		t.Error("a zoned public address must be forbidden too")
	}
	if !forbiddenAddr(netip.Addr{}, true) {
		t.Error("the zero Addr must be forbidden")
	}
}

func TestCheckAddrWrapsSentinel(t *testing.T) {
	if err := checkAddr(netip.MustParseAddr("8.8.8.8"), false); err != nil {
		t.Fatalf("public address rejected: %v", err)
	}
	err := checkAddr(netip.MustParseAddr("10.0.0.1"), false)
	if !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("got %v, want ErrBlockedAddress", err)
	}
	if err := checkAddr(netip.MustParseAddr("10.0.0.1"), true); err != nil {
		t.Fatalf("private address rejected under AllowPrivate: %v", err)
	}
}

// TestRulesParse makes sure every prefix literal in the tables is valid, since
// a typo there would panic on first use.
func TestRulesParse(t *testing.T) {
	rules := loadRules()
	if len(rules.metadata) == 0 || len(rules.private) == 0 || len(rules.blocked) == 0 {
		t.Fatal("a rule table is empty")
	}
	if !rules.nat64.IsValid() || !rules.sixToFour.IsValid() || !rules.global.IsValid() {
		t.Fatal("a single-prefix rule is invalid")
	}
}

// FuzzIsForbiddenIP checks the classifier against the standard library's own
// predicates, which act as an independent oracle, and against the structural
// invariants the dialer relies on.
func FuzzIsForbiddenIP(f *testing.F) {
	seeds := [][]byte{
		{127, 0, 0, 1}, {10, 0, 0, 1}, {169, 254, 169, 254}, {8, 8, 8, 8},
		{0, 0, 0, 0}, {255, 255, 255, 255}, {224, 0, 0, 1}, {100, 64, 0, 1},
		net.ParseIP("::1"), net.ParseIP("::"), net.ParseIP("fe80::1"),
		net.ParseIP("fd00:ec2::254"), net.ParseIP("::ffff:127.0.0.1"),
		net.ParseIP("64:ff9b::7f00:1"), net.ParseIP("2002:7f00:1::"),
		net.ParseIP("2001::1"), net.ParseIP("2606:4700:4700::1111"),
		{}, {1, 2, 3}, make([]byte, 15), make([]byte, 17),
	}
	for _, seed := range seeds {
		f.Add([]byte(seed), true)
		f.Add([]byte(seed), false)
	}
	f.Fuzz(func(t *testing.T, raw []byte, allowPrivate bool) {
		ip := net.IP(raw)
		got := IsForbiddenIP(ip, allowPrivate)
		if len(raw) != net.IPv4len && len(raw) != net.IPv6len {
			if !got {
				t.Fatalf("invalid length %d accepted", len(raw))
			}
			return
		}
		if IsForbiddenIP(ip, true) && !IsForbiddenIP(ip, false) {
			t.Fatalf("%v: allowPrivate=true is stricter than false", ip)
		}
		if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			if !IsForbiddenIP(ip, true) {
				t.Fatalf("%v is never-allowed space but was accepted with AllowPrivate", ip)
			}
		}
		if (ip.IsLoopback() || ip.IsPrivate()) && !IsForbiddenIP(ip, false) {
			t.Fatalf("%v is loopback or private but was accepted without AllowPrivate", ip)
		}
		if v4 := ip.To4(); v4 != nil && len(raw) == net.IPv6len {
			if IsForbiddenIP(v4, allowPrivate) != got {
				t.Fatalf("%v: IPv4-mapped form disagrees with its IPv4 form", ip)
			}
		}
	})
}
