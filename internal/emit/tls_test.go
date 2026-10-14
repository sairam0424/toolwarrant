package emit

import (
	"errors"
	"strings"
	"testing"
)

// The backendTLS fixture: the paths and the hostname the with_tls golden
// carries. They are the values cmd/toolwarrant's canary tests hand-build the
// block with, so the two sides of the file agree on one example; the paths
// are paths on a gateway host and exist nowhere in the test run (the binary
// tests substitute real files, tls_binary_test.go).
const (
	tlsGoldenCert     = "/etc/toolwarrant/gateway.pem"
	tlsGoldenKey      = "/etc/toolwarrant/gateway-key.pem"
	tlsGoldenRoot     = "/etc/toolwarrant/processor-ca.pem"
	tlsGoldenHostname = "toolwarrant-processor"
	// policiesLine is the opener of the processor's policies block at the
	// entry's field indent; the route's own policies key sits at indent 2 and
	// must not be counted with it.
	policiesLine = "        policies:\n"
	// remoteTLSProcessorWarning is the exact line for a TLS processor off
	// loopback; an operator reads it, so a wording change must be deliberate.
	remoteTLSProcessorWarning = "processor for server a at h.example:9001 is not on loopback: the hooks that decide what the gateway serves cross the network under TLS (backendTLS: the gateway presents its client certificate and verifies the processor's certificate under hostname toolwarrant-processor), and serve must require that certificate with --tls-client-ca, or carry the shared secret, to accept such a listener"
)

// tlsFixture is the golden block as input.
func tlsFixture() *ProcessorTLS {
	return &ProcessorTLS{Cert: tlsGoldenCert, Key: tlsGoldenKey, Root: tlsGoldenRoot, Hostname: tlsGoldenHostname}
}

// tlsBlock is the golden block as emit writes it: policies at indent 8,
// backendTLS at indent 10, the four quoted fields at indent 12, the indents
// the canary reads (cmd/toolwarrant liveconsts.go).
func tlsBlock(t *ProcessorTLS) string {
	return policiesLine + "          backendTLS:\n" +
		"            cert: " + quote(t.Cert) + "\n" +
		"            key: " + quote(t.Key) + "\n" +
		"            root: " + quote(t.Root) + "\n" +
		"            hostname: " + quote(t.Hostname) + "\n"
}

// withTLS returns s with the golden block.
func withTLS(s Server) Server {
	s.TLS = tlsFixture()
	return s
}

// tlsGoldenCases pins the file with the block: one server whose entry has no
// secret, so the block is followed by methods, and one with a secret, so it is
// followed by metadata.
func tlsGoldenCases() []goldenCase {
	return []goldenCase{{
		name: "with_tls",
		input: Input{ListenPort: testListenPort, Servers: []Server{
			withTLS(Server{Name: "github", URL: testUpstreamURL, ProcessorAddr: testProcessorAddr, ApprovedTools: []string{"get_file"}}),
			withTLS(Server{Name: "vault", URL: "http://127.0.0.1:3002/mcp", ProcessorAddr: "127.0.0.1:9002", Secret: fixtureMetadataValue, ApprovedTools: []string{"read_secret"}}),
		}},
	}}
}

// TestProcessorTLSIsWrittenUnderPolicies: the block sits after the
// request-header filter and before metadata (or methods, without a secret),
// once per server that asked for it, every value through quote, so a path
// with a quote, a backslash or a dollar sign cannot add a line or a key.
func TestProcessorTLSIsWrittenUnderPolicies(t *testing.T) {
	plain := withTLS(validServer("a"))
	plain.ApprovedTools = []string{"echo"}
	secret := plain
	secret.Secret = fixtureMetadataValue
	for name, s := range map[string]Server{"methods follow": plain, "metadata follows": secret} {
		out, err := AgentGateway(Input{ListenPort: testListenPort, Servers: []Server{s}})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		yaml := string(out.YAML)
		next := "        methods:\n"
		if s.Secret != "" {
			next = "        metadata:\n"
		}
		if got := strings.Count(yaml, requestHeadersBlock()+tlsBlock(s.TLS)+next); got != 1 {
			t.Errorf("%s: the block appears %d time(s) between the filter and %q:\n%s", name, got, strings.TrimSpace(next), yaml)
		}
		if got := strings.Count(yaml, policiesLine); got != 1 {
			t.Errorf("%s: %d processor policies blocks, want 1", name, got)
		}
		if got, ok := Verify(out.YAML); !ok || got != out.BodyHash {
			t.Errorf("%s: fresh output does not verify", name)
		}
	}

	hostile := withTLS(validServer("a"))
	hostile.TLS.Cert = `/etc/tw/it's "here"\x$HOME.pem`
	out, err := AgentGateway(Input{ListenPort: testListenPort, Servers: []Server{hostile}})
	if err != nil {
		t.Fatal(err)
	}
	want := `            cert: "/etc/tw/it's \"here\"\\x\u0024HOME.pem"` + "\n"
	if !strings.Contains(string(out.YAML), want) {
		t.Errorf("hostile path not written through quote:\n%s", out.YAML)
	}
	if strings.Contains(string(out.YAML), "$HOME") {
		t.Error("a raw dollar sign reached the file")
	}
}

// TestProcessorTLSRequiresEveryField: a block is all four fields or nothing;
// the error names the server and the field, and ErrInvalidInput is wrapped.
func TestProcessorTLSRequiresEveryField(t *testing.T) {
	clear := map[string]func(*ProcessorTLS){
		tlsCertKey:     func(p *ProcessorTLS) { p.Cert = "" },
		tlsKeyKey:      func(p *ProcessorTLS) { p.Key = "" },
		tlsRootKey:     func(p *ProcessorTLS) { p.Root = "" },
		tlsHostnameKey: func(p *ProcessorTLS) { p.Hostname = "" },
	}
	for field, drop := range clear {
		s := withTLS(validServer("alpha"))
		drop(s.TLS)
		_, err := AgentGateway(Input{ListenPort: testListenPort, Servers: []Server{s}})
		if err == nil || !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("%s empty: %v", field, err)
		}
		if msg := err.Error(); !strings.Contains(msg, "server alpha: backendTLS "+field+" is required") {
			t.Errorf("%s empty: %v", field, err)
		}
	}
	empty := validServer("alpha")
	empty.TLS = &ProcessorTLS{}
	requireInvalid(t, Input{ListenPort: testListenPort, Servers: []Server{empty}})
	if _, err := AgentGateway(Input{ListenPort: testListenPort, Servers: []Server{validServer("alpha")}}); err != nil {
		t.Errorf("no block: %v", err)
	}
}

// TestProcessorTLSPathsMustBeAbsolute: each path is absolute, printable ASCII
// and at most 4096 bytes; the gateway would read a relative path from its
// own working directory, and the emitter cannot know that directory.
func TestProcessorTLSPathsMustBeAbsolute(t *testing.T) {
	set := map[string]func(*ProcessorTLS, string){
		tlsCertKey: func(p *ProcessorTLS, v string) { p.Cert = v },
		tlsKeyKey:  func(p *ProcessorTLS, v string) { p.Key = v },
		tlsRootKey: func(p *ProcessorTLS, v string) { p.Root = v },
	}
	refused := map[string]string{
		"relative":       "gateway.pem",
		"dot relative":   "./gateway.pem",
		"nested":         "etc/toolwarrant/gateway.pem",
		"home":           "~/gateway.pem",
		"windows":        `C:\gateway.pem`,
		"non-ascii":      "/etc/caf\u00e9.pem",
		"control":        "/etc/x\x01.pem",
		"newline":        "/etc/x\n.pem",
		"too long":       "/" + strings.Repeat("a", maxTLSPathLen),
		"dollar then nl": "/etc/$\n",
	}
	accepted := []string{"/gateway.pem", "/etc/tool warrant/it's.pem", `/etc/\"quoted\".pem`, "/etc/$HOME.pem", "/" + strings.Repeat("a", maxTLSPathLen-1)}
	for field, apply := range set {
		for name, path := range refused {
			s := withTLS(validServer("a"))
			apply(s.TLS, path)
			_, err := AgentGateway(Input{ListenPort: testListenPort, Servers: []Server{s}})
			if err == nil || !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "backendTLS "+field) {
				t.Errorf("%s %s: %v", field, name, err)
			}
		}
		for _, path := range accepted {
			s := withTLS(validServer("a"))
			apply(s.TLS, path)
			if _, err := AgentGateway(Input{ListenPort: testListenPort, Servers: []Server{s}}); err != nil {
				t.Errorf("%s %q: %v", field, path, err)
			}
		}
	}
	s := withTLS(validServer("a"))
	s.TLS.Key = "relative.pem"
	_, err := AgentGateway(Input{ListenPort: testListenPort, Servers: []Server{s}})
	if err == nil || !strings.Contains(err.Error(), `backendTLS key "relative.pem" is not an absolute path`) {
		t.Errorf("relative key: %v", err)
	}
}

// TestProcessorTLSHostnameIsADNSName: the hostname is the name the gateway
// verifies the processor's certificate under and sends as SNI, so it is a DNS
// name and never an IP literal, a numeric spelling the resolver reads as one,
// a bracketed address or a host:port.
func TestProcessorTLSHostnameIsADNSName(t *testing.T) {
	accepted := []string{tlsGoldenHostname, "processor.internal.example", "a", "x_y", "PROCESSOR", strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)}
	for _, host := range accepted {
		s := withTLS(validServer("a"))
		s.TLS.Hostname = host
		if _, err := AgentGateway(Input{ListenPort: testListenPort, Servers: []Server{s}}); err != nil {
			t.Errorf("%q: %v", host, err)
		}
	}
	refused := map[string]string{
		"":                                "is required",
		"127.0.0.1":                       "IP address or a numeric spelling",
		"::1":                             "IP address or a numeric spelling",
		"2001:db8::1":                     "IP address or a numeric spelling",
		"127.1":                           "IP address or a numeric spelling",
		"0x7f.0.0.1":                      "IP address or a numeric spelling",
		"2130706433":                      "IP address or a numeric spelling",
		"[::1]":                           "is not a DNS name",
		"host:443":                        "is not a DNS name",
		"-bad":                            "is not a DNS name",
		"bad-":                            "is not a DNS name",
		"a..b":                            "is not a DNS name",
		"a b":                             "is not a DNS name",
		"host/":                           "is not a DNS name",
		tlsGoldenHostname + "\n":          "must be printable ASCII",
		"\u00fcber":                       "must be printable ASCII",
		strings.Repeat("a", maxHostLen+1): "is longer than",
	}
	for host, saying := range refused {
		s := withTLS(validServer("a"))
		s.TLS.Hostname = host
		_, err := AgentGateway(Input{ListenPort: testListenPort, Servers: []Server{s}})
		if err == nil || !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "backendTLS hostname") || !strings.Contains(err.Error(), saying) {
			t.Errorf("%q: %v, want one saying %q", host, err, saying)
		}
	}
}

// TestNoTLSMeansNoPolicies: an entry without Server.TLS carries no policies
// block and no backendTLS key, in every golden case but with_tls and beside an
// entry that carries one, so a file emitted today without the flag is byte
// for byte the file emitted before the block existed.
func TestNoTLSMeansNoPolicies(t *testing.T) {
	for _, tc := range goldenCases() {
		out, err := AgentGateway(tc.input)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		yaml := string(out.YAML)
		if tc.name == "with_tls" {
			if got := strings.Count(yaml, policiesLine); got != len(tc.input.Servers) {
				t.Errorf("with_tls: %d processor policies blocks, want %d", got, len(tc.input.Servers))
			}
			continue
		}
		if strings.Contains(yaml, policiesLine) || strings.Contains(yaml, backendTLSKey) {
			t.Errorf("%s: a file without Server.TLS carries a processor policies block:\n%s", tc.name, yaml)
		}
	}
	mixed := Input{ListenPort: testListenPort, Servers: []Server{
		{Name: "plain", URL: testUpstreamURL, ProcessorAddr: "127.0.0.1:9002", ApprovedTools: []string{"echo"}},
		withTLS(Server{Name: "guarded", URL: testUpstreamURL, ProcessorAddr: testProcessorAddr, ApprovedTools: []string{"echo"}}),
	}}
	out, err := AgentGateway(mixed)
	if err != nil {
		t.Fatal(err)
	}
	routes := splitRoutes(string(out.YAML))
	if len(routes) != 2 || !strings.Contains(routes[0], "guarded") || strings.Contains(routes[1], backendTLSKey) || strings.Count(routes[0], tlsBlock(tlsFixture())) != 1 {
		t.Errorf("the block leaked or went missing:\n%s", out.YAML)
	}
}

// TestWarningNamesTheLinkProtection: a processor off loopback is warned about
// either way; with the block the line says the hooks cross the network under
// TLS and names the hostname and the serve flag that authenticates them, and
// without it the plaintext line is unchanged. A loopback processor with the
// block adds no line.
func TestWarningNamesTheLinkProtection(t *testing.T) {
	remote := withTLS(validServer("a"))
	remote.ProcessorAddr = "h.example:9001"
	out, err := AgentGateway(Input{ListenPort: testListenPort, Servers: []Server{remote}})
	if err != nil {
		t.Fatal(err)
	}
	if out.Warning != remoteTLSProcessorWarning {
		t.Errorf("TLS warning:\n%s\nwant:\n%s", out.Warning, remoteTLSProcessorWarning)
	}
	plain := remote
	plain.TLS = nil
	out, err = AgentGateway(Input{ListenPort: testListenPort, Servers: []Server{plain}})
	if err != nil {
		t.Fatal(err)
	}
	if out.Warning != remoteProcessorWarning {
		t.Errorf("plaintext warning:\n%s\nwant:\n%s", out.Warning, remoteProcessorWarning)
	}
	local := withTLS(validServer("a"))
	out, err = AgentGateway(Input{ListenPort: testListenPort, Servers: []Server{local}})
	if err != nil || out.Warning != "" {
		t.Errorf("loopback with TLS: warning %q, err %v", out.Warning, err)
	}
	both := Input{ListenPort: testListenPort, Servers: []Server{
		{Name: "b", URL: testUpstreamURL, ProcessorAddr: "10.0.0.7:9002"}, remote,
	}}
	out, err = AgentGateway(both)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(out.Warning, "\n")
	if len(lines) != 2 || lines[0] != remoteTLSProcessorWarning || lines[1] != "processor for server b at 10.0.0.7:9002"+processorRisk {
		t.Errorf("two processors:\n%s", out.Warning)
	}
	for _, line := range lines {
		if !isPrintableASCII(line) {
			t.Errorf("warning line is not printable ASCII: %q", line)
		}
	}
}
