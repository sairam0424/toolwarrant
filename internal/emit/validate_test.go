package emit

import (
	"errors"
	"strings"
	"testing"
)

func validServer(name string) Server {
	return Server{Name: name, URL: testUpstreamURL, ProcessorAddr: testProcessorAddr}
}

func TestRejectsInvalidInput(t *testing.T) {
	second := validServer("b")
	second.ProcessorAddr = "127.0.0.1:9002"
	cases := []struct {
		name string
		in   Input
	}{
		{"no servers", Input{ListenPort: testListenPort}},
		{"port zero", Input{ListenPort: 0, Servers: []Server{validServer("a")}}},
		{"port negative", Input{ListenPort: -1, Servers: []Server{validServer("a")}}},
		{"port too big", Input{ListenPort: 65536, Servers: []Server{validServer("a")}}},
		{"duplicate names", Input{ListenPort: testListenPort, Servers: []Server{validServer("a"), {Name: "a", URL: testUpstreamURL, ProcessorAddr: "127.0.0.1:9002"}}}},
		{"duplicate processor address", Input{ListenPort: testListenPort, Servers: []Server{validServer("a"), validServer("b")}}},
		{"duplicate processor address, third server", Input{ListenPort: testListenPort, Servers: []Server{validServer("a"), second, validServer("c")}}},
		{"name empty", Input{ListenPort: testListenPort, Servers: []Server{validServer("")}}},
		{"name uppercase", Input{ListenPort: testListenPort, Servers: []Server{validServer("Github")}}},
		{"name leading dash", Input{ListenPort: testListenPort, Servers: []Server{validServer("-a")}}},
		{"name trailing dash", Input{ListenPort: testListenPort, Servers: []Server{validServer("a-")}}},
		{"name leading underscore", Input{ListenPort: testListenPort, Servers: []Server{validServer("_a")}}},
		{"name interior underscore", Input{ListenPort: testListenPort, Servers: []Server{validServer("my_server")}}},
		{"name trailing underscore", Input{ListenPort: testListenPort, Servers: []Server{validServer("ab_")}}},
		{"name dot", Input{ListenPort: testListenPort, Servers: []Server{validServer("a.b")}}},
		{"name dot dash", Input{ListenPort: testListenPort, Servers: []Server{validServer("a.-")}}},
		{"name space", Input{ListenPort: testListenPort, Servers: []Server{validServer("a b")}}},
		{"name colon", Input{ListenPort: testListenPort, Servers: []Server{validServer("a:b")}}},
		{"name hash", Input{ListenPort: testListenPort, Servers: []Server{validServer("a#b")}}},
		{"name dollar", Input{ListenPort: testListenPort, Servers: []Server{validServer("a$b")}}},
		{"name trailing newline", Input{ListenPort: testListenPort, Servers: []Server{validServer("a\n")}}},
		{"name slash", Input{ListenPort: testListenPort, Servers: []Server{validServer("a/b")}}},
		{"name quote", Input{ListenPort: testListenPort, Servers: []Server{validServer(`a"b`)}}},
		{"name unicode", Input{ListenPort: testListenPort, Servers: []Server{validServer("café")}}},
		{"name 64 chars", Input{ListenPort: testListenPort, Servers: []Server{validServer(strings.Repeat("a", 64))}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { requireInvalid(t, tc.in) })
	}
}

// TestDuplicateProcessorAddrNamesBothServers: one processor serves exactly one
// target, so the second server on an address would have every call denied
// with nothing in the config to say why. The error names both servers.
func TestDuplicateProcessorAddrNamesBothServers(t *testing.T) {
	_, err := AgentGateway(Input{ListenPort: testListenPort, Servers: []Server{
		{Name: "alpha", URL: testUpstreamURL, ProcessorAddr: testProcessorAddr, ApprovedTools: []string{"echo"}},
		{Name: "beta", URL: "http://10.0.0.5:3001/mcp", ProcessorAddr: testProcessorAddr, ApprovedTools: []string{"echo"}},
	}})
	if err == nil || !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("shared processor address accepted: %v", err)
	}
	msg := err.Error()
	for _, want := range []string{"duplicate processor address", testProcessorAddr, "alpha", "beta"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q lacks %q", msg, want)
		}
	}
}

func TestDistinctProcessorAddrsAccepted(t *testing.T) {
	_, err := AgentGateway(Input{ListenPort: testListenPort, Servers: []Server{
		{Name: "alpha", URL: testUpstreamURL, ProcessorAddr: "127.0.0.1:9001"},
		{Name: "beta", URL: testUpstreamURL, ProcessorAddr: "127.0.0.1:9002"},
		{Name: "gamma", URL: testUpstreamURL, ProcessorAddr: "localhost:9001"},
	}})
	if err != nil {
		t.Fatalf("distinct addresses rejected: %v", err)
	}
}

// TestServerNameShapesAccepted lists every shape the gateway's target rule
// admits and the emitter keeps: single characters, digits, interior hyphens
// (also doubled), the 63-byte boundary, and names that are also YAML keys or
// the gateway name, which live in other namespaces. "a_b-c" was accepted
// before this round; the gateway refuses the underscore.
func TestServerNameShapesAccepted(t *testing.T) {
	for _, name := range []string{"a", "0", "a-b-c", "a--b", "99", "a1", "x-9", strings.Repeat("a", 63), "toolwarrant", "default", "routes", "config", "gateways", "mcp"} {
		if _, err := AgentGateway(Input{ListenPort: testListenPort, Servers: []Server{validServer(name)}}); err != nil {
			t.Errorf("name %q rejected: %v", name, err)
		}
	}
}

// TestServerNameRuleIsTheGatewaysTargetRule ports the review's probe: every
// name here is one agentgateway v1.6.0 refuses as an MCP target name, or one
// the emitter refuses on purpose ('.' and the 63-byte cap). The errors say
// which rule bit, so an operator can rename rather than guess.
func TestServerNameRuleIsTheGatewaysTargetRule(t *testing.T) {
	refused := []string{"A", "a b", "a/b", "a:b", "-a", "_a", "a\n", "", strings.Repeat("z", 64), "a#b", "a.b", "my_server", "a-", "a-b_c"}
	for _, name := range refused {
		requireInvalid(t, Input{ListenPort: testListenPort, Servers: []Server{validServer(name)}})
	}
	explain := map[string]string{
		"my_server":             "reserves '_'",
		"a-":                    "trailing '-'",
		"a.b":                   "'.' is refused here on purpose",
		strings.Repeat("z", 64): "longer than 63 bytes",
	}
	for name, want := range explain {
		_, err := AgentGateway(Input{ListenPort: testListenPort, Servers: []Server{validServer(name)}})
		if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), shown(name)) {
			t.Errorf("name %q: err = %v, want it to name %s and say %q", name, err, shown(name), want)
		}
	}
}

func TestPortBoundariesAccepted(t *testing.T) {
	for _, port := range []int{1, 65535} {
		if _, err := AgentGateway(Input{ListenPort: port, Servers: []Server{validServer("a")}}); err != nil {
			t.Errorf("port %d rejected: %v", port, err)
		}
	}
}

// TestRejectsBadURLs includes the characters the gateway's URI parser refuses
// (double quote, angle brackets, space) and the printable characters RFC 3986
// leaves out, which the emitter refuses on purpose even though
// --validate-only tolerates some of them.
func TestRejectsBadURLs(t *testing.T) {
	bad := []string{
		"", "ftp://h/mcp", "javascript:alert(1)", "http://", "http:///x", "//host/mcp", "host/mcp",
		"http://user:pw@host/mcp", "http://a b/mcp", "http://host/mcp\n", "http://h/é", "http://[::1", "http://h:99999999999/x",
		"file:///etc/passwd", "HTTP",
		`http://h/mcp?x="y"`, "http://h/<mcp>", "http://h/mcp?x=a>b", "http://h/mcp?x=a|b", "http://h/mcp?x=a^b",
		"http://h/mcp?x={y}", "http://h/mcp?x=`y`", `http://h/mcp\x`, "http://h/mcp?x=a\tb", "http://h/mcp\x7f", "http://h/mcp?x=a\x00b",
	}
	for _, raw := range bad {
		s := validServer("a")
		s.URL = raw
		requireInvalid(t, Input{ListenPort: testListenPort, Servers: []Server{s}})
	}
}

// TestAcceptsGoodURLs covers every RFC 3986 delimiter class in one place or
// another, the percent-encoded form, a bracketed IPv6 host and a dollar sign
// (RFC 3986 allows it; the emitter escapes it on the way out).
func TestAcceptsGoodURLs(t *testing.T) {
	good := []string{
		"http://127.0.0.1:3001/mcp", "https://example.com/mcp", "HTTPS://Example.com/mcp", "http://localhost", "https://h.example:8443/a/b?x=1",
		"http://127.0.0.1:3001/mcp?x=1&y=2", "http://h.example/p;q=1,2?x=a!b'c(d)*e+f=g", "http://[::1]:3001/mcp",
		"http://h.example/mcp?t=a%24b", "http://h.example/mcp?token=$UPSTREAM", "https://h.example/~user/mcp@v1", "http://h.example/mcp?x=a:b[0]",
	}
	for _, raw := range good {
		s := validServer("a")
		s.URL = raw
		if _, err := AgentGateway(Input{ListenPort: testListenPort, Servers: []Server{s}}); err != nil {
			t.Errorf("url %q rejected: %v", raw, err)
		}
	}
}

// TestURLAlphabetIsRFC3986 states the alphabet independently of the code:
// ALPHA, DIGIT, the unreserved marks, gen-delims and sub-delims of RFC 3986
// sections 2.2 and 2.3, plus the percent sign of section 2.1. Every other
// byte is refused, through the byte predicate and through AgentGateway.
func TestURLAlphabetIsRFC3986(t *testing.T) {
	const unreservedMarks, genDelims, subDelims, pctEncoding = "-._~", ":/?#[]@", "!$&'()*+,;=", "%"
	if urlPunctuation != unreservedMarks+genDelims+subDelims+pctEncoding {
		t.Fatalf("urlPunctuation = %q", urlPunctuation)
	}
	for c := 0; c < 256; c++ {
		b := byte(c)
		isAlnum := (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
		want := isAlnum || strings.IndexByte(urlPunctuation, b) >= 0
		if got := isURLByte(b); got != want {
			t.Errorf("isURLByte(%#x) = %v, want %v", b, got, want)
		}
		s := validServer("a")
		s.URL = "http://h.example/mcp?x=" + string([]byte{b})
		_, err := AgentGateway(Input{ListenPort: testListenPort, Servers: []Server{s}})
		if accepted := err == nil; accepted != want {
			t.Errorf("url with byte %#x in the query: accepted=%v, want %v (%v)", b, accepted, want, err)
		}
	}
}

func TestURLNotEchoedInError(t *testing.T) {
	for _, raw := range []string{"http://user:supersecret@host/mcp", `http://host/mcp?token=supersecret"`} {
		s := validServer("a")
		s.URL = raw
		_, err := AgentGateway(Input{ListenPort: testListenPort, Servers: []Server{s}})
		if err == nil || strings.Contains(err.Error(), "supersecret") {
			t.Errorf("want a credential-free error, got %v", err)
		}
	}
}

// TestProcessorAddr pins host:port as the only accepted form. The scheme and
// socket forms are ones agentgateway's --validate-only accepts but its schema
// does not document for processors[].host, so they stay refused on purpose.
func TestProcessorAddr(t *testing.T) {
	bad := []string{
		"", "nocolon", ":9001", "host:", "host:0", "host:65536", "host:+80", "host: 80", "host:80a", "host:-1",
		"a b:80", "host:80\n", "[::1]:9001", "::1:9001", "ho\"st:80", "hé.example:80", "-bad.example:80", "a..b:80",
		"host:123456", strings.Repeat("a", 64) + ":80", strings.Repeat("a.", 130) + "a:80",
		"unix:///tmp/p.sock", "unix:/tmp/p.sock", "https://127.0.0.1:9001", "http://127.0.0.1:9001", "127.0.0.1:9001/path",
	}
	for _, addr := range bad {
		s := validServer("a")
		s.ProcessorAddr = addr
		requireInvalid(t, Input{ListenPort: testListenPort, Servers: []Server{s}})
	}
	for _, addr := range []string{"127.0.0.1:1", "localhost:65535", "my_svc.ns.svc:9001", "A.example.com:80"} {
		s := validServer("a")
		s.ProcessorAddr = addr
		if _, err := AgentGateway(Input{ListenPort: testListenPort, Servers: []Server{s}}); err != nil {
			t.Errorf("addr %q rejected: %v", addr, err)
		}
	}
}

func TestSecretRules(t *testing.T) {
	pad := strings.Repeat("p", MinSecretLen)
	good := []string{
		"", strings.Repeat("x", MinSecretLen), strings.Repeat("x", MaxSecretLen), fixtureMetadataValue,
		`spaces 'single' "double" \back ~!@#$%^&*()_+-=[]{}|;:,.<>/?` + "`",
	}
	for _, secret := range good {
		s := validServer("a")
		s.Secret = secret
		if _, err := AgentGateway(Input{ListenPort: testListenPort, Servers: []Server{s}}); err != nil {
			t.Errorf("secret of %d bytes rejected: %v", len(secret), err)
		}
	}
	bad := []string{
		strings.Repeat("x", MinSecretLen-1), strings.Repeat("x", MaxSecretLen+1),
		"café" + pad, "line\nbreak" + pad, "del\x7f" + pad, "tab\t" + pad, "nul\x00" + pad, "bad\xffutf8" + pad,
	}
	for _, secret := range bad {
		s := validServer("a")
		s.Secret = secret
		requireInvalid(t, Input{ListenPort: testListenPort, Servers: []Server{s}})
	}
}

func TestSecretNotEchoedInError(t *testing.T) {
	for _, secret := range []string{"supersecret\t0123456789abcdef", "supersecret", "supersecret" + strings.Repeat("x", MaxSecretLen)} {
		s := validServer("a")
		s.Secret = secret
		_, err := AgentGateway(Input{ListenPort: testListenPort, Servers: []Server{s}})
		if err == nil || strings.Contains(err.Error(), "supersecret") {
			t.Errorf("want a secret-free error, got %v", err)
		}
	}
}

func TestInvalidInputProducesNoOutput(t *testing.T) {
	out, err := AgentGateway(Input{})
	if err == nil || out.YAML != nil || out.Skipped != nil || out.BodyHash != "" {
		t.Errorf("want error and zero Output, got %v %#v", err, out)
	}
}

func TestLongNameTruncatedInError(t *testing.T) {
	_, err := AgentGateway(Input{ListenPort: testListenPort, Servers: []Server{validServer(strings.Repeat("A", 5000))}})
	if err == nil || len(err.Error()) > 400 {
		t.Errorf("error should be short, got %d bytes", len(err.Error()))
	}
}

// TestParsePort pins the port reader shared by the listeners, the processor
// address and the URL check: plain decimal digits in range, nothing else.
func TestParsePort(t *testing.T) {
	for s, want := range map[string]int{"1": 1, "80": 80, "65535": 65535, "080": 80} {
		if got, ok := parsePort(s); !ok || got != want {
			t.Errorf("parsePort(%q) = %d, %v; want %d, true", s, got, ok, want)
		}
	}
	for _, s := range []string{"", "0", "65536", "+80", " 80", "80 ", "8a", "-1", "123456", "0x50"} {
		if got, ok := parsePort(s); ok || got != 0 {
			t.Errorf("parsePort(%q) = %d, %v; want 0, false", s, got, ok)
		}
	}
}

func requireInvalid(t *testing.T, in Input) {
	t.Helper()
	out, err := AgentGateway(in)
	if err == nil {
		t.Fatalf("expected an error, got output:\n%s", out.YAML)
	}
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("error does not wrap ErrInvalidInput: %v", err)
	}
	if out.YAML != nil || out.BodyHash != "" || out.Skipped != nil || out.Warning != "" {
		t.Errorf("output must be empty on error, got %#v", out)
	}
}
