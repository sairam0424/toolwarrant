package emit

import (
	"strconv"
	"strings"
	"testing"
)

// ambiguousHostSpellings are the processor hosts the fourth review found
// escaping the socket rule (processor-emit-4, decision D14 h): spellings
// getaddrinfo reads as 127.0.0.1 or 0.0.0.0 with no DNS lookup, in inet_aton's
// notation (the review's lab/spellings.txt), plus the leading-zero form that
// is octal to glibc and decimal to macOS, a hexadecimal part in the middle, a
// bare 0x, an upper-case 0X and a five-part number, which inet_aton refuses
// and the resolver then fails on.
func ambiguousHostSpellings() []string {
	return []string{
		"127.1", "127.000.000.001", "0x7f.0.0.1", "0X7F.0.0.1", "2130706433", "0", "127.0.1",
		"0177.0.0.1", "010.0.0.1", "0x7f000001", "127.0x1.0.1", "1.2.3.4.5", "0x",
	}
}

// TestAmbiguousProcessorHostSpellingsAreRefused ports the fourth review's
// reproduction: every spelling is refused with the serving port, the admin
// port and a free port alike, because the rule is about the spelling and not
// about the socket, and the error names the rule and the canonical form.
// Before the rule the emitter accepted all of them with the off-loopback
// warning, so the printed serve command demanded --allow-non-loopback for a
// loopback socket and the D13(g) collision was reachable by spelling.
func TestAmbiguousProcessorHostSpellingsAreRefused(t *testing.T) {
	for _, host := range ambiguousHostSpellings() {
		for _, port := range []string{strconv.Itoa(testListenPort), "15000", "9001"} {
			addr := host + ":" + port
			t.Run(addr, func(t *testing.T) {
				s := validServer("a")
				s.ProcessorAddr = addr
				in := Input{ListenPort: testListenPort, Servers: []Server{s}}
				requireInvalid(t, in)
				_, err := AgentGateway(in)
				for _, want := range []string{"server a:", shown(host), "ambiguous numeric spelling", "canonical dotted quad"} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("err = %v, want it to say %q", err, want)
					}
				}
			})
		}
	}
}

// TestNumericHostRuleLeavesNamesAndCanonicalAddressesAlone: the rule reads
// only hosts the resolver would read as numbers. A canonical dotted quad
// passes it (and meets the socket rule as before), and a DNS name with a
// numeric label among others is a name, as "0.pool.ntp.org" is.
func TestNumericHostRuleLeavesNamesAndCanonicalAddressesAlone(t *testing.T) {
	for _, addr := range []string{
		"127.0.0.1:9001", "10.0.0.5:9001", "1.example:9001", "0.pool.example:9001", "example.1:9001",
		"x0.example:9001", "a-1.b-2:9001", "127.0.0.1.example:9001", "127-0-0-1:9001",
	} {
		s := validServer("a")
		s.ProcessorAddr = addr
		if _, err := AgentGateway(Input{ListenPort: testListenPort, Servers: []Server{s}}); err != nil {
			t.Errorf("processor %q rejected: %v", addr, err)
		}
	}
}

// TestIsNumericHost pins the predicate: every label a part of inet_aton's
// notation (digits, or 0x and hexadecimal digits), or a leading 0x label, is
// numeric; a letter label other than a hexadecimal part, an empty label or an
// empty host is not.
func TestIsNumericHost(t *testing.T) {
	for host, want := range map[string]bool{
		"127.0.0.1": true, "127.1": true, "0": true, "2130706433": true, "0x7f.0.0.1": true, "0X7F.0.0.1": true,
		"127.0x1.0.1": true, "0x7f000001": true, "0xdead.example": true, "0x7f.0.0.1.example": true, "0177.0.0.1": true,
		"1.2.3.4.5": true, "0x": true,
		"": false, ".": false, "h.example": false, "1.example": false, "example.1": false, "127.0.0.1.example": false,
		"a..b": false, "x0.example": false, "127-0-0-1": false, "localhost": false, "::1": false, "0x7f:1": true,
	} {
		if got := isNumericHost(host); got != want {
			t.Errorf("isNumericHost(%q) = %v, want %v", host, got, want)
		}
	}
}

// TestGatewayAcceptsAmbiguousProcessorSpellings pins why the spelling rule
// lives in the emitter: the pinned binary's --validate-only loads a file
// whose processor host is any of the spellings, so nothing between emit and
// the reload would question them. Whether the running gateway dials them as
// loopback or fails to resolve them is not observed here (no server run);
// either way the route is dark or the gateway dials itself.
func TestGatewayAcceptsAmbiguousProcessorSpellings(t *testing.T) {
	binary := gatewayBinary(t)
	out := freshOutput(t)
	hostLine := "      - host: " + quote(testProcessorAddr) + "\n"
	for _, host := range ambiguousHostSpellings() {
		addr := host + ":15000"
		s := validServer("a")
		s.ProcessorAddr = addr
		requireInvalid(t, Input{ListenPort: testListenPort, Servers: []Server{s}})
		requireValid(t, binary, mutate(t, out.YAML, hostLine, "      - host: "+quote(addr)+"\n"), "a processor at the ambiguous spelling "+addr)
	}
}
