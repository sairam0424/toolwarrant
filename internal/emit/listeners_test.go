package emit

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// Exact warning lines for the exposed_listeners golden case: an operator
// reads these, so a wording change must be deliberate.
const (
	exposedAdminWarning     = "admin API listens on 0.0.0.0:15000, every interface of this host: it has no authentication, POST /api/config replaces the running configuration and /config_dump returns it with every processor secret in clear; firewall the port, bind a loopback address or set DisableAdmin"
	exposedStatsWarning     = "stats endpoint listens on [::]:15020, every interface of this host: it exposes the gateway's metrics; firewall the port or bind a loopback address"
	exposedReadinessWarning = "readiness probe listens on 10.0.0.5:15021, an address other hosts can reach: it exposes the gateway's health probe; firewall the port or bind a loopback address"
	remoteProcessorWarning  = "processor for server a at h.example:9001 is not on loopback: the hooks that decide what the gateway serves cross the network, and serve refuses such a listener unless it is explicitly allowed and carries a shared secret"
	// freeListenerPort collides with no default listener and not with
	// testListenPort, so a refusal in the tables below is about the address.
	freeListenerPort = "16000"
)

// goldenCases is every golden input: the original nine, the listener cases,
// the dollar-sign case and the TLS case. New cases are appended so the
// positional references in older tests keep pointing at the same inputs.
func goldenCases() []goldenCase {
	return slices.Concat(baseGoldenCases(), listenerGoldenCases(), dollarGoldenCases(), tlsGoldenCases())
}

func listenerGoldenCases() []goldenCase {
	server := Server{Name: "github", URL: testUpstreamURL, ProcessorAddr: testProcessorAddr, ApprovedTools: []string{"get_file"}}
	return []goldenCase{
		{
			name:  "admin_off",
			input: Input{ListenPort: testListenPort, DisableAdmin: true, Servers: []Server{server}},
		},
		{
			name:  "custom_listeners",
			input: Input{ListenPort: testListenPort, AdminAddr: "[::1]:16000", StatsAddr: "127.0.0.2:16020", ReadinessAddr: "127.0.0.1:16021", Servers: []Server{server}},
		},
		{
			name: "exposed_listeners",
			input: Input{
				ListenPort: testListenPort, BindAddress: "0.0.0.0", AllowAllInterfaces: true,
				AdminAddr: "0.0.0.0:15000", StatsAddr: "[::]:15020", ReadinessAddr: "10.0.0.5:15021", Servers: []Server{server},
			},
			warning: strings.Join([]string{wildcardWarning, exposedAdminWarning, exposedStatsWarning, exposedReadinessWarning}, "\n"),
		},
	}
}

// withListener is a valid single-server input with one listener field set.
func withListener(key, addr string, allowAll bool) Input {
	in := bindInput("", allowAll)
	switch key {
	case adminKey:
		in.AdminAddr = addr
	case statsKey:
		in.StatsAddr = addr
	default:
		in.ReadinessAddr = addr
	}
	return in
}

// listenerKeys is the three listener fields in file order.
func listenerKeys() []string { return []string{adminKey, statsKey, readinessKey} }

// TestDefaultListenersAreTheOldPins: the defaults are the addresses the
// emitter used to hard-code, so a file emitted from an input that says
// nothing about listeners is byte for byte the old file.
func TestDefaultListenersAreTheOldPins(t *testing.T) {
	if DefaultAdminAddr != "127.0.0.1:15000" || DefaultStatsAddr != "127.0.0.1:15020" || DefaultReadinessAddr != "127.0.0.1:15021" {
		t.Fatalf("defaults moved: %q %q %q", DefaultAdminAddr, DefaultStatsAddr, DefaultReadinessAddr)
	}
	implicit, err := AgentGateway(bindInput("", false))
	if err != nil {
		t.Fatal(err)
	}
	explicitIn := bindInput("", false)
	explicitIn.AdminAddr, explicitIn.StatsAddr, explicitIn.ReadinessAddr = DefaultAdminAddr, DefaultStatsAddr, DefaultReadinessAddr
	explicit, err := AgentGateway(explicitIn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(implicit.YAML, explicit.YAML) || implicit.Warning != "" || explicit.Warning != "" {
		t.Errorf("explicit defaults differ from implicit ones:\n%s\n%s", implicit.YAML, explicit.YAML)
	}
}

// TestDisableAdminWritesOff: the gateway's own switch, the other two
// listeners untouched, and no warning, since nothing is exposed.
func TestDisableAdminWritesOff(t *testing.T) {
	in := bindInput("", false)
	in.DisableAdmin = true
	out, err := AgentGateway(in)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.SplitN(string(out.YAML), "\n", headerLines+1)[headerLines]
	want := "config:\n  adminAddr: \"off\"\n  statsAddr: \"127.0.0.1:15020\"\n  readinessAddr: \"127.0.0.1:15021\"\ngateways:\n"
	if !strings.HasPrefix(body, want) {
		t.Errorf("body does not start with the admin-off config block:\n%s", body)
	}
	if out.Warning != "" || strings.Count(string(out.YAML), "Addr: ") != 3 {
		t.Errorf("warning %q or listener count wrong:\n%s", out.Warning, out.YAML)
	}
}

// TestDisableAdminContradictsAdminAddr: the switch and an address together
// are refused, and the switch spelled as an address is refused with a pointer
// to the field, for every listener.
func TestDisableAdminContradictsAdminAddr(t *testing.T) {
	in := bindInput("", false)
	in.DisableAdmin, in.AdminAddr = true, DefaultAdminAddr
	requireInvalid(t, in)
	if _, err := AgentGateway(in); err == nil || !strings.Contains(err.Error(), "contradict") {
		t.Errorf("want an error naming the contradiction, got %v", err)
	}
	for _, key := range listenerKeys() {
		_, err := AgentGateway(withListener(key, listenerOff, false))
		if err == nil || !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "DisableAdmin") {
			t.Errorf("%s = %q: err = %v, want ErrInvalidInput pointing at DisableAdmin", key, listenerOff, err)
		}
	}
}

// TestListenerAddressesRefused lists what is never a listener address, for
// each of the three fields, with and without the permission: the permission
// unlocks exposure only, never a name, a bare port or a bad class.
func TestListenerAddressesRefused(t *testing.T) {
	bad := []string{
		"localhost:" + freeListenerPort, "LOCALHOST:" + freeListenerPort, "example.com:" + freeListenerPort, "127.0.0.1", ":" + freeListenerPort, "127.0.0.1:",
		"127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:+80", "127.0.0.1: 80", "127.0.0.1:" + freeListenerPort + "/x", "http://127.0.0.1:" + freeListenerPort,
		"::1:" + freeListenerPort, "[::1]", "[::1]:", "unix:/tmp/tw.sock", "unix:///tmp/tw.sock", "OFF", "Off", "off ",
		" 127.0.0.1:" + freeListenerPort, "127.0.0.1:" + freeListenerPort + " ", "127.0.0.1:" + freeListenerPort + "\n",
		"[fe80::1]:" + freeListenerPort, "[fe80::1%en0]:" + freeListenerPort, "[::ffff:127.0.0.1]:" + freeListenerPort,
		"224.0.0.1:" + freeListenerPort, "255.255.255.255:" + freeListenerPort, "caf\u00e9:" + freeListenerPort,
	}
	for _, key := range listenerKeys() {
		for _, raw := range bad {
			for _, allowAll := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%q/%v", key, raw, allowAll), func(t *testing.T) { requireInvalid(t, withListener(key, raw, allowAll)) })
			}
		}
	}
}

// TestExposedListenerNeedsPermission: any address other hosts can reach, a
// wildcard or a specific one, is refused without AllowAllInterfaces and
// accepted with it, with a warning line that names the listener.
func TestExposedListenerNeedsPermission(t *testing.T) {
	exposed := []string{"0.0.0.0:" + freeListenerPort, "[::]:" + freeListenerPort, "10.0.0.5:" + freeListenerPort, "[2001:db8::1]:" + freeListenerPort, "169.254.1.1:" + freeListenerPort}
	names := map[string]string{adminKey: adminName, statsKey: statsName, readinessKey: readinessName}
	for _, key := range listenerKeys() {
		for _, raw := range exposed {
			_, err := AgentGateway(withListener(key, raw, false))
			if err == nil || !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "AllowAllInterfaces") {
				t.Errorf("%s = %q without the permission: err = %v, want ErrInvalidInput naming AllowAllInterfaces", key, raw, err)
			}
			out, err := AgentGateway(withListener(key, raw, true))
			if err != nil {
				t.Errorf("%s = %q with the permission rejected: %v", key, raw, err)
				continue
			}
			if !strings.HasPrefix(out.Warning, names[key]+" listens on ") || strings.Contains(out.Warning, "\n") {
				t.Errorf("%s = %q: Warning = %q, want exactly one line about the %s", key, raw, out.Warning, names[key])
			}
		}
	}
}

// TestListenerErrorsExplain: each refusal names the listener and the reason.
func TestListenerErrorsExplain(t *testing.T) {
	cases := []struct{ key, addr, want string }{
		{adminKey, "localhost:" + freeListenerPort, "admin API address \"localhost\" is not an IPv4 or IPv6 literal"},
		{statsKey, listenerOff, "stats endpoint address \"off\" is the gateway's off switch"},
		{readinessKey, "10.0.0.5:" + freeListenerPort, "readiness probe address \"10.0.0.5:16000\" is not loopback"},
		{adminKey, "127.0.0.1:70000", "admin API address \"127.0.0.1:70000\" has a port outside 1-65535"},
		{adminKey, "127.0.0.1", "admin API address \"127.0.0.1\" must be host:port"},
		{statsKey, "[fe80::1]:" + freeListenerPort, "stats endpoint address \"fe80::1\" is IPv6 link-local"},
		{readinessKey, "[::ffff:127.0.0.1]:" + freeListenerPort, "readiness probe address \"::ffff:127.0.0.1\" is an IPv4-mapped"},
	}
	for _, tc := range cases {
		_, err := AgentGateway(withListener(tc.key, tc.addr, false))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s = %q: err = %v, want it to say %q", tc.key, tc.addr, err, tc.want)
		}
	}
}

// TestListenerPortsMustBeDistinct: --validate-only accepts two listeners on
// one port and the gateway then fails to start, so the emitter refuses it,
// comparing ports whatever the hosts. Turning the admin API off frees its
// port.
func TestListenerPortsMustBeDistinct(t *testing.T) {
	servingOnAdmin := bindInput("", false)
	servingOnAdmin.ListenPort = 15000
	requireInvalid(t, servingOnAdmin)
	if _, err := AgentGateway(servingOnAdmin); err == nil || !strings.Contains(err.Error(), servingName) || !strings.Contains(err.Error(), adminName) || !strings.Contains(err.Error(), "15000") {
		t.Errorf("serving port on the admin port: err = %v, want both names and the port", err)
	}
	statsOnReadiness := withListener(statsKey, "127.0.0.1:15021", false)
	requireInvalid(t, statsOnReadiness)
	if _, err := AgentGateway(statsOnReadiness); err == nil || !strings.Contains(err.Error(), statsName) || !strings.Contains(err.Error(), readinessName) {
		t.Errorf("stats on the readiness port: err = %v, want both names", err)
	}
	requireInvalid(t, withListener(adminKey, "127.0.0.2:15020", false))
	servingOnAdmin.DisableAdmin = true
	if _, err := AgentGateway(servingOnAdmin); err != nil {
		t.Errorf("serving port 15000 with the admin API off rejected: %v", err)
	}
}

// TestListenerAddressesAcceptedAndCanonical: IPv6 in brackets, canonical
// spelling, and the wildcard forms once permitted.
func TestListenerAddressesAcceptedAndCanonical(t *testing.T) {
	cases := []struct {
		raw, want string
		allowAll  bool
	}{
		{"[0:0:0:0:0:0:0:1]:16000", "[::1]:16000", false}, {"[::1]:16000", "[::1]:16000", false}, {"127.0.0.2:16000", "127.0.0.2:16000", false},
		{"0.0.0.0:16000", "0.0.0.0:16000", true}, {"[::]:16000", "[::]:16000", true}, {"[0000::]:16000", "[::]:16000", true}, {"[2001:DB8::1]:16000", "[2001:db8::1]:16000", true},
	}
	for _, key := range listenerKeys() {
		for _, tc := range cases {
			out, err := AgentGateway(withListener(key, tc.raw, tc.allowAll))
			if err != nil {
				t.Errorf("%s = %q rejected: %v", key, tc.raw, err)
				continue
			}
			if want := "\n  " + key + ": " + quote(tc.want) + "\n"; !strings.Contains(string(out.YAML), want) {
				t.Errorf("%s = %q: file lacks %q:\n%s", key, tc.raw, want, out.YAML)
			}
		}
	}
}

// TestExposedListenersWarnOnePerLine pins the three listener lines and the
// format: newline-separated, printable ASCII, no trailing newline, and no
// line for a loopback serving socket.
func TestExposedListenersWarnOnePerLine(t *testing.T) {
	in := bindInput("", true)
	in.AdminAddr, in.StatsAddr, in.ReadinessAddr = "0.0.0.0:15000", "[::]:15020", "10.0.0.5:15021"
	out, err := AgentGateway(in)
	if err != nil {
		t.Fatal(err)
	}
	want := exposedAdminWarning + "\n" + exposedStatsWarning + "\n" + exposedReadinessWarning
	if out.Warning != want {
		t.Errorf("Warning =\n%q\nwant\n%q", out.Warning, want)
	}
	for _, line := range strings.Split(out.Warning, "\n") {
		if line == "" || !isPrintableASCII(line) {
			t.Errorf("warning line is empty or not printable ASCII: %q", line)
		}
	}
}

// TestProcessorOffLoopbackWarns mirrors the serve command's rule: localhost
// in any case and loopback literals are quiet; a name or another address
// gets a line, with or without a secret, servers in name order.
func TestProcessorOffLoopbackWarns(t *testing.T) {
	out, err := AgentGateway(Input{ListenPort: testListenPort, Servers: []Server{
		{Name: "e", URL: testUpstreamURL, ProcessorAddr: "10.0.0.5:9005", Secret: fixtureMetadataValue},
		{Name: "a", URL: testUpstreamURL, ProcessorAddr: "h.example:9001"},
		{Name: "b", URL: testUpstreamURL, ProcessorAddr: "localhost:9002"},
		{Name: "c", URL: testUpstreamURL, ProcessorAddr: "LocalHost:9003"},
		{Name: "d", URL: testUpstreamURL, ProcessorAddr: "127.0.0.2:9004"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := remoteProcessorWarning + "\n" + "processor for server e at 10.0.0.5:9005" + processorRisk
	if out.Warning != want {
		t.Errorf("Warning =\n%q\nwant\n%q", out.Warning, want)
	}
}

// TestWarningLinesAreOrdered: serving socket, admin, stats, readiness, then
// processors by server name.
func TestWarningLinesAreOrdered(t *testing.T) {
	out, err := AgentGateway(Input{
		ListenPort: testListenPort, BindAddress: "0.0.0.0", AllowAllInterfaces: true,
		AdminAddr: "0.0.0.0:15000", StatsAddr: "[::]:15020", ReadinessAddr: "10.0.0.5:15021",
		Servers: []Server{
			{Name: "b", URL: testUpstreamURL, ProcessorAddr: "10.0.0.5:9002"},
			{Name: "a", URL: testUpstreamURL, ProcessorAddr: "h.example:9001"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(out.Warning, "\n")
	prefixes := []string{"gateway listens on 0.0.0.0:3000", "admin API listens on", "stats endpoint listens on", "readiness probe listens on", "processor for server a at", "processor for server b at"}
	if len(lines) != len(prefixes) {
		t.Fatalf("got %d warning lines, want %d:\n%s", len(lines), len(prefixes), out.Warning)
	}
	for i, prefix := range prefixes {
		if !strings.HasPrefix(lines[i], prefix) {
			t.Errorf("line %d = %q, want prefix %q", i, lines[i], prefix)
		}
	}
}

// TestAllowAllInterfacesIsOnlyAPermissionForListeners: with loopback
// listeners the flag changes neither the file nor the warning.
func TestAllowAllInterfacesIsOnlyAPermissionForListeners(t *testing.T) {
	for _, raw := range []string{"", "[::1]:16000", "127.0.0.2:16000"} {
		for _, key := range listenerKeys() {
			a, errA := AgentGateway(withListener(key, raw, false))
			b, errB := AgentGateway(withListener(key, raw, true))
			if errA != nil || errB != nil {
				t.Fatalf("%s = %q: errors %v %v", key, raw, errA, errB)
			}
			if !bytes.Equal(a.YAML, b.YAML) || a.Warning != "" || b.Warning != "" {
				t.Errorf("%s = %q: AllowAllInterfaces changed the output or produced a warning", key, raw)
			}
		}
	}
}

// TestIsLoopbackHost pins the processor-host predicate on its own: loopback
// names in any case (localhost and its resolver aliases, IsLoopbackName) and
// loopback literals; nothing else.
func TestIsLoopbackHost(t *testing.T) {
	for host, want := range map[string]bool{
		"localhost": true, "LOCALHOST": true, "localhost4": true, "Ip6-Localhost": true, "localhost6.localdomain6": true,
		"127.0.0.1": true, "127.255.255.254": true, "::1": true,
		"localhost.": false, "localhost.example": false, "localhost5": false, "h.example": false, "10.0.0.5": false, "0.0.0.0": false, "": false, "127.1": false,
	} {
		if got := isLoopbackHost(host); got != want {
			t.Errorf("isLoopbackHost(%q) = %v, want %v", host, got, want)
		}
	}
}
