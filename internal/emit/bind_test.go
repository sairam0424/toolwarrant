package emit

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// bindInput is a valid single-server input with the given bind settings.
func bindInput(addr string, allowAll bool) Input {
	return Input{ListenPort: testListenPort, BindAddress: addr, AllowAllInterfaces: allowAll, Servers: []Server{validServer("a")}}
}

// gatewayBlock is the gateways block the emitter writes for port 3000 and the
// given canonical address, up to and including the routes key.
func gatewayBlock(addr string) string {
	return "gateways:\n  toolwarrant:\n    port: 3000\n    bindAddress: " + quote(addr) + "\nroutes:\n"
}

// TestDefaultBindIsLoopback pins the F2 default: no BindAddress means
// 127.0.0.1 and no warning, and the deprecated binds form is gone.
func TestDefaultBindIsLoopback(t *testing.T) {
	if DefaultBindAddress != "127.0.0.1" {
		t.Fatalf("DefaultBindAddress = %q", DefaultBindAddress)
	}
	out, err := AgentGateway(bindInput("", false))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out.YAML), gatewayBlock("127.0.0.1")) {
		t.Errorf("gateway block missing or not loopback:\n%s", out.YAML)
	}
	if out.Warning != "" {
		t.Errorf("loopback bind produced a warning: %q", out.Warning)
	}
	if strings.Contains(string(out.YAML), "binds:") || strings.Contains(string(out.YAML), "listeners:") {
		t.Errorf("output still uses the binds form:\n%s", out.YAML)
	}
}

// TestBindAddressAcceptedAndCanonical: every accepted spelling is written in
// canonical form, so two spellings of one address give one file.
func TestBindAddressAcceptedAndCanonical(t *testing.T) {
	cases := map[string]string{
		"127.0.0.1": "127.0.0.1", "127.0.0.2": "127.0.0.2", "::1": "::1", "0:0:0:0:0:0:0:1": "::1",
		"10.0.0.5": "10.0.0.5", "192.168.1.20": "192.168.1.20", "169.254.1.1": "169.254.1.1",
		"fc00::1": "fc00::1", "2001:DB8::1": "2001:db8::1", "2001:db8:0:0:0:0:0:1": "2001:db8::1",
	}
	for raw, want := range cases {
		out, err := AgentGateway(bindInput(raw, false))
		if err != nil {
			t.Errorf("bind address %q rejected: %v", raw, err)
			continue
		}
		if !strings.Contains(string(out.YAML), gatewayBlock(want)) {
			t.Errorf("bind address %q: gateway block does not carry %q:\n%s", raw, want, out.YAML)
		}
	}
}

// TestWildcardNeedsAllowAllInterfaces: a wildcard is refused by default in
// every spelling, and written canonically once the flag confirms it.
func TestWildcardNeedsAllowAllInterfaces(t *testing.T) {
	for raw, want := range map[string]string{"0.0.0.0": "0.0.0.0", "::": "::", "0000::": "::", "0:0:0:0:0:0:0:0": "::"} {
		_, err := AgentGateway(bindInput(raw, false))
		if err == nil || !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "AllowAllInterfaces") {
			t.Errorf("wildcard %q without the flag: err = %v, want ErrInvalidInput naming AllowAllInterfaces", raw, err)
		}
		out, err := AgentGateway(bindInput(raw, true))
		if err != nil {
			t.Errorf("wildcard %q with the flag rejected: %v", raw, err)
			continue
		}
		if !strings.Contains(string(out.YAML), gatewayBlock(want)) {
			t.Errorf("wildcard %q written as something other than %q:\n%s", raw, want, out.YAML)
		}
		if out.Warning == "" {
			t.Errorf("wildcard %q produced no warning", raw)
		}
	}
}

// TestBindAddressRefused lists what is not an acceptable bind address, with
// and without the wildcard permission: the flag unlocks the wildcard only.
func TestBindAddressRefused(t *testing.T) {
	bad := []string{
		"localhost", "example.com", "127.0.0.1:3000", "[::1]", "[::1]:3000", "::1%lo0", "fe80::1%en0", "fe80::1", "FE80::1",
		"::ffff:127.0.0.1", "::ffff:0.0.0.0", "::ffff:10.0.0.5", "224.0.0.1", "239.255.255.250", "ff02::1", "255.255.255.255",
		" 127.0.0.1", "127.0.0.1 ", "127.0.0.1\n", "010.0.0.1", "1.2.3", "1.2.3.4.5", "caf\u00e9", "0x7f000001", "2130706433", "http://127.0.0.1",
	}
	for _, raw := range bad {
		for _, allowAll := range []bool{false, true} {
			t.Run(fmt.Sprintf("%q/%v", raw, allowAll), func(t *testing.T) { requireInvalid(t, bindInput(raw, allowAll)) })
		}
	}
}

// TestBindAddressErrorsExplain: each refusal names the address and its
// reason, so an operator can fix the input rather than guess.
func TestBindAddressErrorsExplain(t *testing.T) {
	cases := map[string]string{
		"localhost":        "not an IPv4 or IPv6 literal",
		"fe80::1%en0":      "zone",
		"::ffff:127.0.0.1": "IPv4-mapped",
		"fe80::1":          "link-local",
		"224.0.0.1":        "not a unicast, loopback or wildcard",
		"0.0.0.0":          "every interface",
	}
	for raw, reason := range cases {
		_, err := AgentGateway(bindInput(raw, false))
		if err == nil || !strings.Contains(err.Error(), shown(raw)) || !strings.Contains(err.Error(), reason) {
			t.Errorf("bind address %q: err = %v, want it to name %s and say %q", raw, err, shown(raw), reason)
		}
	}
}

// TestAllowAllInterfacesIsOnlyAPermission: with a non-wildcard address the
// flag changes neither the file nor the warning.
func TestAllowAllInterfacesIsOnlyAPermission(t *testing.T) {
	for _, raw := range []string{"", "::1", "10.0.0.5"} {
		a, errA := AgentGateway(bindInput(raw, false))
		b, errB := AgentGateway(bindInput(raw, true))
		if errA != nil || errB != nil {
			t.Fatalf("%q: errors %v %v", raw, errA, errB)
		}
		if !bytes.Equal(a.YAML, b.YAML) || a.BodyHash != b.BodyHash || a.Warning != b.Warning {
			t.Errorf("%q: AllowAllInterfaces changed the output", raw)
		}
	}
}

// TestWarningTextIsPinned: the exact text for a specific address and for both
// wildcards, so a wording change is deliberate; loopback never warns.
func TestWarningTextIsPinned(t *testing.T) {
	const tail = ": the routes are reachable from the network and the toolwarrant processor is their only guard (seam finding F2); firewall the port or bind a loopback address"
	cases := []struct {
		addr     string
		allowAll bool
		want     string
	}{
		{"", false, ""},
		{"127.0.0.1", false, ""},
		{"127.0.0.2", false, ""},
		{"::1", false, ""},
		{"10.0.0.5", false, "gateway listens on 10.0.0.5:3000, an address other hosts can reach" + tail},
		{"2001:db8::1", false, "gateway listens on [2001:db8::1]:3000, an address other hosts can reach" + tail},
		{"0.0.0.0", true, "gateway listens on 0.0.0.0:3000, every interface of this host" + tail},
		{"::", true, "gateway listens on [::]:3000, every interface of this host" + tail},
	}
	for _, tc := range cases {
		out, err := AgentGateway(bindInput(tc.addr, tc.allowAll))
		if err != nil {
			t.Fatalf("%q: %v", tc.addr, err)
		}
		if out.Warning != tc.want {
			t.Errorf("%q: Warning = %q, want %q", tc.addr, out.Warning, tc.want)
		}
		if !isPrintableASCII(out.Warning) {
			t.Errorf("%q: warning is not single-line printable ASCII: %q", tc.addr, out.Warning)
		}
	}
}

// TestWarningNamesTheListenPort: the socket in the warning is the one the
// gateway block declares.
func TestWarningNamesTheListenPort(t *testing.T) {
	in := bindInput("0.0.0.0", true)
	in.ListenPort = 8080
	out, err := AgentGateway(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.Warning, "0.0.0.0:8080") || !strings.Contains(string(out.YAML), "    port: 8080\n") {
		t.Errorf("warning %q or file do not carry port 8080:\n%s", out.Warning, out.YAML)
	}
}

// TestInvalidBindProducesNoOutput: a refused bind address, like every other
// invalid input, yields a zero Output and in particular no warning.
func TestInvalidBindProducesNoOutput(t *testing.T) {
	out, err := AgentGateway(bindInput("0.0.0.0", false))
	if err == nil || out.YAML != nil || out.BodyHash != "" || out.Skipped != nil || out.Warning != "" {
		t.Errorf("want error and zero Output, got %v %#v", err, out)
	}
}
