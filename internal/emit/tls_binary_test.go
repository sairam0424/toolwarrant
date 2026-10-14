package emit

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/testcert"
)

// What agentgateway v1.6.0's --validate-only does with the backendTLS block,
// pinned on the real binary: it reads the block's three files, so a path it
// cannot open fails validation and the files must be on the host that runs
// `emit --gateway-binary`; it parses the certificate and the key and refuses
// files that hold none; it does not parse the root bundle; and it accepts the
// partial and numeric shapes the emitter refuses, so those rules are the
// emitter's own. Whether the handshake succeeds is for scenario Q (planned).

// tlsFiles are the three real files of one test: a client certificate and
// key issued by a throwaway authority, and that authority as the root.
type tlsFiles struct {
	cert, key, root string
}

// realTLSFiles writes certificate material into a temp dir, owner-only.
func realTLSFiles(t *testing.T) tlsFiles {
	t.Helper()
	dir := t.TempDir()
	ca := testcert.NewAuthority(t, "toolwarrant emit test ca")
	cert, key := ca.Client(t, "gateway").Write(t, dir, "gateway")
	return tlsFiles{cert: cert, key: key, root: ca.Write(t, dir, "processor-ca")}
}

// garbageFile writes a file that is neither a certificate nor a key.
func garbageFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "garbage.pem")
	if err := os.WriteFile(path, []byte("not pem\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// freshTLSOutput emits one server whose block names the real files.
func freshTLSOutput(t *testing.T, f tlsFiles) Output {
	t.Helper()
	s := validServer("a")
	s.ApprovedTools = []string{"echo"}
	s.TLS = &ProcessorTLS{Cert: f.cert, Key: f.key, Root: f.root, Hostname: testcert.ServerName}
	out, err := AgentGateway(Input{ListenPort: testListenPort, Servers: []Server{s}})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// materialiseTLSPaths replaces the golden block's paths, which exist on no
// test host, with real files, so that a golden file that carries the block
// can be validated by the binary, which opens them. A file without the golden
// paths is returned unchanged.
func materialiseTLSPaths(t *testing.T, yaml []byte) []byte {
	t.Helper()
	if !bytes.Contains(yaml, []byte(tlsGoldenCert)) {
		return yaml
	}
	f := realTLSFiles(t)
	for golden, real := range map[string]string{tlsGoldenCert: f.cert, tlsGoldenKey: f.key, tlsGoldenRoot: f.root} {
		yaml = bytes.ReplaceAll(yaml, []byte(quote(golden)), []byte(quote(real)))
	}
	return yaml
}

// tlsLine is the indent-12 line of one field as emit writes it.
func tlsLine(key, value string) string { return "            " + key + ": " + quote(value) + "\n" }

// TestGatewayValidateOnlyOpensBackendTLSFiles: the real binary's
// --validate-only reads cert, key and root. A path that does not exist fails
// validation with `read resource file PATH`, one field at a time, so `emit
// --gateway-binary` needs the three files at those paths on the host that
// emits, readable by the user that emits; a relative path is read from the
// gateway's working directory, which is why the emitter refuses one. The root
// bundle is opened but not parsed: a file of garbage there validates, so a
// wrong root is found only in the handshake.
func TestGatewayValidateOnlyOpensBackendTLSFiles(t *testing.T) {
	binary := gatewayBinary(t)
	f := realTLSFiles(t)
	out := freshTLSOutput(t, f)
	requireValid(t, binary, out.YAML, "a backendTLS block naming three files that exist")
	missing := filepath.Join(t.TempDir(), "absent.pem")
	for key, path := range map[string]string{tlsCertKey: f.cert, tlsKeyKey: f.key, tlsRootKey: f.root} {
		broken := mutate(t, out.YAML, tlsLine(key, path), tlsLine(key, missing))
		requireRejectedSaying(t, binary, broken, "a backendTLS "+key+" that does not exist", "read resource file "+missing)
	}
	relative := mutate(t, out.YAML, tlsLine(tlsCertKey, f.cert), tlsLine(tlsCertKey, "gateway.pem"))
	requireRejectedSaying(t, binary, relative, "a relative backendTLS cert path", "read resource file ")
	garbage := mutate(t, out.YAML, tlsLine(tlsRootKey, f.root), tlsLine(tlsRootKey, garbageFile(t)))
	requireValid(t, binary, garbage, "a root bundle that holds no certificate (the binary reads it and does not parse it)")
}

// TestGatewayParsesBackendTLS proves the block is read by the real binary,
// not ignored: the emitted block validates, an unknown field inside it is
// refused naming the ten fields the schema has, a cert file that holds no
// certificate is refused with `no certificate`, a key file that holds no key
// with `no key`, and a hostname that is not a DNS name or an IP literal (an
// empty one, a bracketed address, a host:port, the resolver's numeric
// shorthand) with `invalid dns name`. The second half pins the lenient
// acceptances: the binary loads a block without a hostname, with an IPv4 or
// IPv6 literal as hostname, with a root but no client certificate, and an
// empty block, each of which the emitter refuses
// (TestProcessorTLSRequiresEveryField, TestProcessorTLSHostnameIsADNSName),
// so those rules are the emitter's own.
func TestGatewayParsesBackendTLS(t *testing.T) {
	binary := gatewayBinary(t)
	f := realTLSFiles(t)
	out := freshTLSOutput(t, f)
	requireValid(t, binary, out.YAML, "the emitted backendTLS block")
	hostname := tlsLine(tlsHostnameKey, testcert.ServerName)
	garbage := garbageFile(t)
	rejected := []struct{ what, old, replacement, saying string }{
		{"an unknown field in the block", hostname, "            hostnme: " + quote(testcert.ServerName) + "\n", "unknown field `hostnme`"},
		{"a cert file that holds no certificate", tlsLine(tlsCertKey, f.cert), tlsLine(tlsCertKey, garbage), "no certificate"},
		{"a key file that holds no key", tlsLine(tlsKeyKey, f.key), tlsLine(tlsKeyKey, garbage), "no key"},
		{"the key file named as the certificate", tlsLine(tlsCertKey, f.cert), tlsLine(tlsCertKey, f.key), "no certificate"},
		{"an empty hostname", hostname, tlsLine(tlsHostnameKey, ""), "invalid dns name"},
		{"a bracketed address as hostname", hostname, tlsLine(tlsHostnameKey, "[::1]"), "invalid dns name"},
		{"a host:port as hostname", hostname, tlsLine(tlsHostnameKey, "h:443"), "invalid dns name"},
		{"the resolver's shorthand as hostname", hostname, tlsLine(tlsHostnameKey, "127.1"), "invalid dns name"},
	}
	for _, tc := range rejected {
		requireRejectedSaying(t, binary, mutate(t, out.YAML, tc.old, tc.replacement), tc.what, tc.saying)
	}
	block := tlsBlock(&ProcessorTLS{Cert: f.cert, Key: f.key, Root: f.root, Hostname: testcert.ServerName})
	accepted := []struct{ what, old, replacement string }{
		{"a block without a hostname", hostname, ""},
		{"an IPv4 literal as hostname", hostname, tlsLine(tlsHostnameKey, "127.0.0.1")},
		{"an IPv6 literal as hostname", hostname, tlsLine(tlsHostnameKey, "::1")},
		{"a block with root and hostname only", tlsLine(tlsCertKey, f.cert) + tlsLine(tlsKeyKey, f.key), ""},
		{"an empty block", block, policiesLine + "          backendTLS: {}\n"},
	}
	for _, tc := range accepted {
		requireValid(t, binary, mutate(t, out.YAML, tc.old, tc.replacement), tc.what)
	}
	for _, in := range []Input{
		{ListenPort: testListenPort, Servers: []Server{{Name: "a", URL: testUpstreamURL, ProcessorAddr: testProcessorAddr, TLS: &ProcessorTLS{Cert: f.cert, Key: f.key, Root: f.root}}}},
		{ListenPort: testListenPort, Servers: []Server{{Name: "a", URL: testUpstreamURL, ProcessorAddr: testProcessorAddr, TLS: &ProcessorTLS{Root: f.root, Hostname: testcert.ServerName}}}},
	} {
		requireInvalid(t, in)
	}
	if strings.Count(string(out.YAML), block) != 1 {
		t.Errorf("the emitted block is not the pinned shape:\n%s", out.YAML)
	}
}
