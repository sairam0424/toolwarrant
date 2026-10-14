package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/emit"
	"github.com/sairam0424/toolwarrant/internal/testcert"
)

// The emit side of TLS on the processor link (D19): --processor-tls puts the
// gateway's backendTLS block on one server's entry, nothing of it is recorded
// in the catalog, the printed serve command carries placeholders for the
// processor's own files, and the emitter's rules (absolute paths, a DNS
// hostname, every field) are enforced through the flag.

// tlsSpec is the --processor-tls value for server name with the canary
// fixture's paths and hostname (livetls_test.go), so the file the canary tests
// hand-build and the file emit writes agree on one example.
func tlsSpec(name string) string {
	return name + "=cert=" + tlsCertPath + ",key=" + tlsKeyPath + ",root=" + tlsRootPath + ",hostname=" + tlsHostname
}

// emittedTLSBlock is the block as emit must write it: policies at indent 8,
// backendTLS at indent 10, the four quoted fields at indent 12, the indents
// liveconsts.go reads. It is the same text the canary tests insert.
func emittedTLSBlock() string { return tlsBlock(tlsCertPath, tlsKeyPath, tlsRootPath, tlsHostname) }

// TestEmitWritesBackendTLSForAProcessorOverride: with --processor-tls the
// server's processor entry carries the block after the request-header filter
// and before methods, the non-loopback warning says the hooks cross the
// network under TLS and names the hostname, the serve command carries the
// TLS placeholders, and nothing of the block reaches the catalog: server list
// and the audit log show no path, and the next emit without the flag writes
// an entry without the block, so the flag is given on every emit.
func TestEmitWritesBackendTLSForAProcessorOverride(t *testing.T) {
	c, _ := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	out := filepath.Join(t.TempDir(), "gateway.yaml")
	r := c.run("emit", "--out", out, "--processor", "s1=10.0.0.7:9001", "--processor-tls", tlsSpec("s1"))
	if r.code != exitOK {
		t.Fatalf("emit --processor-tls: exit %d: %s", r.code, r.stderr)
	}
	yaml := readFile(t, out)
	if got := strings.Count(yaml, emittedTLSBlock()+"        methods:\n"); got != 1 {
		t.Errorf("the block appears %d time(s) before methods:\n%s", got, yaml)
	}
	wantContains(t, "yaml", yaml, `host: "10.0.0.7:9001"`, "          - \"proxy-authorization\"\n"+emittedTLSBlock())
	if _, ok := emit.Verify([]byte(yaml)); !ok {
		t.Error("the written file does not verify")
	}
	wantContains(t, "stderr", r.stderr, "warning: processor for server s1 at 10.0.0.7:9001 is not on loopback: the hooks that decide what the gateway serves cross the network under TLS (backendTLS: the gateway presents its client certificate and verifies the processor's certificate under hostname "+tlsHostname+"), and serve must require that certificate with --tls-client-ca")
	wantNotContains(t, "stderr", r.stderr, "carries a shared secret\n")
	wantContains(t, "stdout", r.stdout, "serve --server s1 --target s1 --listen 10.0.0.7:9001 "+allowNonLoopbackFlag+tlsServePlaceholders)

	// Not persisted: the catalog records the address, never the block.
	wantNotContains(t, "server list", c.ok("server", "list"), tlsCertPath, tlsRootPath, "backendTLS", tlsHostname)
	for _, e := range c.auditEntries() {
		if strings.Contains(e.Detail, tlsCertPath) || strings.Contains(e.Detail, tlsHostname) || strings.Contains(e.Event, "tls") {
			t.Errorf("the block reached the audit log: %+v", e)
		}
	}
	r = c.run("emit", "--out", out)
	if r.code != exitOK {
		t.Fatalf("re-emit without the flag: exit %d: %s", r.code, r.stderr)
	}
	plain := readFile(t, out)
	wantNotContains(t, "re-emitted yaml", plain, "backendTLS", "        policies:\n", tlsHostname)
	wantContains(t, "re-emit stderr", r.stderr, "warning: processor for server s1 at 10.0.0.7:9001 is not on loopback", "carries a shared secret")
	wantNotContains(t, "re-emit stdout", r.stdout, tlsServePlaceholders, "changed from")

	// On loopback the block is written without any warning.
	r = c.run("emit", "--out", out, "--processor", "s1=127.0.0.1:9001", "--processor-tls", tlsSpec("s1"))
	if r.code != exitOK {
		t.Fatalf("emit on loopback: exit %d: %s", r.code, r.stderr)
	}
	wantContains(t, "loopback yaml", readFile(t, out), emittedTLSBlock())
	wantNotContains(t, "loopback stderr", r.stderr, "warning")
	wantContains(t, "loopback stdout", r.stdout, "serve --server s1 --target s1 --listen 127.0.0.1:9001"+tlsServePlaceholders)
	before := readFile(t, out)

	// The emitter's rules are reported as its errors, exit 1, and a refused
	// input leaves the file alone.
	cases := map[string]string{
		"relative path": "s1=cert=gateway.pem,key=" + tlsKeyPath + ",root=" + tlsRootPath + ",hostname=" + tlsHostname,
		"IP hostname":   "s1=cert=" + tlsCertPath + ",key=" + tlsKeyPath + ",root=" + tlsRootPath + ",hostname=127.0.0.1",
		"bad hostname":  "s1=cert=" + tlsCertPath + ",key=" + tlsKeyPath + ",root=" + tlsRootPath + ",hostname=-bad",
	}
	for name, spec := range cases {
		r = c.fail(exitFailure, "emit", "--out", out, "--processor-tls", spec)
		wantContains(t, name, r.stderr, "server s1: backendTLS", "emit again")
		if readFile(t, out) != before {
			t.Errorf("%s: a refused input touched the file", name)
		}
	}
	r = c.fail(exitFailure, "emit", "--out", out, "--processor-tls", cases["relative path"])
	wantContains(t, "relative path", r.stderr, `backendTLS cert "gateway.pem" is not an absolute path`)
}

// TestEmitProcessorTLSFlagGrammar: a value that is not
// NAME=cert=PATH,key=PATH,root=PATH,hostname=NAME is a usage error, exit 2,
// decided while the flags are parsed, so no file is written; the message names
// the grammar and escapes the value.
func TestEmitProcessorTLSFlagGrammar(t *testing.T) {
	c, _ := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	out := filepath.Join(t.TempDir(), "gateway.yaml")
	cases := map[string]struct{ value, saying string }{
		"no name":        {"cert=/a,key=/b,root=/c,hostname=h", "want " + processorTLSGrammar},
		"empty name":     {"=cert=/a,key=/b,root=/c,hostname=h", "want " + processorTLSGrammar},
		"empty spec":     {"s1=", "want " + processorTLSGrammar},
		"bare name":      {"s1", "want " + processorTLSGrammar},
		"three fields":   {"s1=cert=/a,key=/b,root=/c", "want 4 fields"},
		"five fields":    {"s1=cert=/a,key=/b,root=/c,hostname=h,alpn=h2", "want 4 fields"},
		"unknown field":  {"s1=cert=/a,key=/b,root=/c,hostnme=h", "unknown field hostnme=h"},
		"field twice":    {"s1=cert=/a,cert=/b,root=/c,hostname=h", "field cert given twice"},
		"empty value":    {"s1=cert=,key=/b,root=/c,hostname=h", "field cert is empty"},
		"no equals sign": {"s1=cert=/a,key=/b,root=/c,hostname", "unknown field hostname"},
		"hostile field":  {"s1=cert=/a,key=/b,root=/c,host" + esc + "name=h", `unknown field host\u{001B}name=h`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := c.sub(t).fail(exitUsage, "emit", "--out", out, "--processor-tls", tc.value)
			wantContains(t, "stderr", r.stderr, "processor-tls", tc.saying)
			wantNotContains(t, "stderr", r.stderr, esc)
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Errorf("a usage error wrote the file: %v", err)
			}
		})
	}
	r := c.fail(exitUsage, "emit", "--out", out, "--processor-tls", tlsSpec("s1"), "--processor-tls", tlsSpec("s1"))
	wantContains(t, "twice", r.stderr, "processor-tls", "server given twice")
	flags := processorTLSFlags{}
	if err := flags.Set(tlsSpec("s1")); err != nil {
		t.Fatal(err)
	}
	if got := flags.String(); got != tlsSpec("s1") {
		t.Errorf("String() = %q, want %q", got, tlsSpec("s1"))
	}
}

// TestEmitProcessorTLSNamesUnknownServer: a block for a server the catalog
// does not hold is a usage error, exit 2, as for --processor, because a flag
// that names nothing would leave the link it meant in plaintext; the name is
// escaped and no file is written.
func TestEmitProcessorTLSNamesUnknownServer(t *testing.T) {
	c, _ := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	out := filepath.Join(t.TempDir(), "gateway.yaml")
	r := c.fail(exitUsage, "emit", "--out", out, "--processor-tls", tlsSpec("nosuch"))
	wantContains(t, "stderr", r.stderr, flagProcessorTLS+" names unknown server nosuch")
	r = c.fail(exitUsage, "emit", "--out", out, "--processor-tls", tlsSpec("no"+esc+"such"))
	wantContains(t, "stderr", r.stderr, `names unknown server no\u{001B}such`)
	wantNotContains(t, "stderr", r.stderr, esc)
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Errorf("a usage error wrote the file: %v", err)
	}
	wantNotContains(t, "server list", c.ok("server", "list"), "nosuch")
}

// TestEmitPrintsTheServeCommandWithTLSPlaceholders: the serve command of a
// server with the block ends with the three TLS flags and placeholder names,
// after --secret-env when there is one, and the command of a server without
// the block is unchanged; the help text names the flag.
func TestEmitPrintsTheServeCommandWithTLSPlaceholders(t *testing.T) {
	c, _ := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	c.ok("server", "add", "s2", "http://127.0.0.1:3002/mcp")
	c.env[secretVar] = plant("secret")
	out := filepath.Join(t.TempDir(), "gateway.yaml")
	r := c.run("emit", "--out", out, "--secret-env", secretVar, "--processor-tls", tlsSpec("s2"))
	if r.code != exitOK {
		t.Fatalf("emit: exit %d: %s", r.code, r.stderr)
	}
	wantContains(t, "stdout", r.stdout,
		"  toolwarrant --db "+c.db+" serve --server s1 --target s1 --listen 127.0.0.1:9001 --secret-env "+secretVar+"\n",
		"  toolwarrant --db "+c.db+" serve --server s2 --target s2 --listen 127.0.0.1:9002 --secret-env "+secretVar+" --tls-cert PROCESSOR_CERT --tls-key PROCESSOR_KEY --tls-client-ca GATEWAY_CA\n")
	if got := strings.Count(r.stdout, tlsServePlaceholders); got != 1 {
		t.Errorf("placeholders printed %d time(s), want 1:\n%s", got, r.stdout)
	}
	yaml := readFile(t, out)
	if got := strings.Count(yaml, emittedTLSBlock()+"        metadata:\n"); got != 1 {
		t.Errorf("the block appears %d time(s) before metadata:\n%s", got, yaml)
	}
	if got := strings.Count(yaml, "backendTLS"); got != 1 {
		t.Errorf("backendTLS appears %d time(s), want 1 (s2 only):\n%s", got, yaml)
	}
	wantNotContains(t, "output", r.stdout+r.stderr, canary)
	wantContains(t, "help", c.ok("emit", "-h"), "-processor-tls", processorTLSGrammar, "gateway host")
}

// TestEmitWithTheGatewayBinaryNeedsTheTLSFilesOnThisHost: the real gateway's
// --validate-only opens the block's files (emit
// TestGatewayValidateOnlyOpensBackendTLSFiles), so emit --gateway-binary
// succeeds when the three paths exist on the emitting host and fails, exit 1
// with the gateway's `read resource file` message and no file written, when
// they do not.
func TestEmitWithTheGatewayBinaryNeedsTheTLSFilesOnThisHost(t *testing.T) {
	bin := realGatewayBinary(t)
	c, _ := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	dir := t.TempDir()
	ca := testcert.NewAuthority(t, "toolwarrant emit test ca")
	cert, key := ca.Client(t, "gateway").Write(t, dir, "gateway")
	root := ca.Write(t, dir, "processor-ca")
	out := filepath.Join(t.TempDir(), "gateway.yaml")
	real := "s1=cert=" + cert + ",key=" + key + ",root=" + root + ",hostname=" + testcert.ServerName
	r := c.run("emit", "--out", out, "--gateway-binary", bin, "--processor-tls", real)
	if r.code != exitOK {
		t.Fatalf("emit validated by the real gateway with real files: exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	wantContains(t, "stdout", r.stdout, "validated with "+bin+" "+validateOnlyFlag, "wrote "+out)
	yaml := readFile(t, out)
	wantContains(t, "yaml", yaml, "            hostname: \""+testcert.ServerName+"\"\n", "            root: \""+root+"\"\n")

	r = c.fail(exitFailure, "emit", "--out", out, "--gateway-binary", bin, "--processor-tls", tlsSpec("s1"))
	wantContains(t, "stderr", r.stderr, "refused the configuration, so nothing was written", "read resource file "+tlsCertPath)
	wantNotContains(t, "stdout", r.stdout, "wrote", "validated")
	if readFile(t, out) != yaml {
		t.Error("a refused file must leave the previous one in place")
	}
	entries, err := os.ReadDir(filepath.Dir(out))
	if err != nil || len(entries) != 1 {
		t.Errorf("files left behind: %v %v", entries, err)
	}
}
