package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	api "github.com/sairam0424/toolwarrant/internal/extmcpv1"
	"github.com/sairam0424/toolwarrant/internal/testcert"
)

// pemKeyMarker is the PEM header of a private key; no output of serve may
// carry it.
const pemKeyMarker = "PRIVATE KEY"

// tlsFiles is the certificate material of one serve TLS test, written
// owner-only into a temp dir: the processor's certificate and key, the
// authority that signed them and the gateway stand-in's client certificate,
// plus a second authority that nothing trusts.
type tlsFiles struct {
	ca       *testcert.Authority
	caPath   string
	certPath string
	keyPath  string
	client   testcert.Pair
	other    *testcert.Authority
}

func newTLSFiles(t *testing.T) *tlsFiles {
	t.Helper()
	dir := t.TempDir()
	ca := testcert.NewAuthority(t, "toolwarrant test ca")
	certPath, keyPath := ca.Server(t).Write(t, dir, "processor")
	return &tlsFiles{ca: ca, caPath: ca.Write(t, dir, "ca"), certPath: certPath, keyPath: keyPath, client: ca.Client(t, "gateway"), other: testcert.NewAuthority(t, "another ca")}
}

// serveArgs are the serve flags for s1 on a free loopback port with the
// processor's certificate and key, plus extra.
func (f *tlsFiles) serveArgs(extra ...string) []string {
	return append([]string{"serve", "--server", "s1", "--listen", "127.0.0.1:0", "--tls-cert", f.certPath, "--tls-key", f.keyPath}, extra...)
}

// dialTLS connects a gRPC client over TLS, verifying the processor under
// testcert.ServerName against roots and presenting certs (none for an
// anonymous client).
func dialTLS(t *testing.T, addr string, roots *x509.CertPool, certs ...tls.Certificate) (api.ExtMcpClient, context.Context) {
	t.Helper()
	creds := credentials.NewTLS(&tls.Config{RootCAs: roots, ServerName: testcert.ServerName, Certificates: certs, MinVersion: tls.VersionTLS13})
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	t.Cleanup(cancel)
	return api.NewExtMcpClient(conn), ctx
}

// wantUnavailable asserts a hook never reached the processor: the RPC fails
// with Unavailable, which is what a refused handshake looks like to the client.
func wantUnavailable(t *testing.T, ctx context.Context, client api.ExtMcpClient, what string) {
	t.Helper()
	_, err := client.CheckRequest(ctx, callHook("s1", "echo", nil))
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("%s: err = %v, want Unavailable", what, err)
	}
	t.Logf("%s: %v", what, err)
}

// The TLS flag grammar: certificate and key both or neither, a client CA only
// with both (usage errors, exit 2); a file that is missing or not PEM is a
// failure of the command (exit 1). No message carries key material.
func TestServeTLSFlagsNeedCertAndKeyTogether(t *testing.T) {
	c, _ := fixture(t)
	f := newTLSFiles(t)
	r := c.fail(exitUsage, "serve", "--server", "s1", "--listen", "127.0.0.1:0", "--tls-cert", f.certPath)
	wantContains(t, "stderr", r.stderr, "--tls-cert and --tls-key go together")
	r = c.fail(exitUsage, "serve", "--server", "s1", "--listen", "127.0.0.1:0", "--tls-key", f.keyPath)
	wantContains(t, "stderr", r.stderr, "--tls-cert and --tls-key go together")
	r = c.fail(exitUsage, "serve", "--server", "s1", "--listen", "127.0.0.1:0", "--tls-client-ca", f.caPath)
	wantContains(t, "stderr", r.stderr, "--tls-client-ca needs --tls-cert and --tls-key")

	missing := filepath.Join(t.TempDir(), "missing.crt")
	r = c.fail(exitFailure, f.serveArgs("--tls-client-ca", missing)...)
	wantContains(t, "stderr", r.stderr, "--tls-client-ca", "missing.crt")
	junk := filepath.Join(t.TempDir(), "junk.pem")
	if err := os.WriteFile(junk, []byte("not pem at all\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r = c.fail(exitFailure, f.serveArgs("--tls-client-ca", junk)...)
	wantContains(t, "stderr", r.stderr, "--tls-client-ca", "holds no PEM certificate")
	r = c.fail(exitFailure, "serve", "--server", "s1", "--listen", "127.0.0.1:0", "--tls-cert", junk, "--tls-key", f.keyPath)
	wantContains(t, "stderr", r.stderr, "--tls-cert and --tls-key")
	r = c.fail(exitFailure, "serve", "--server", "s1", "--listen", "127.0.0.1:0", "--tls-cert", f.certPath, "--tls-key", junk)
	wantContains(t, "stderr", r.stderr, "--tls-cert and --tls-key")
	wantNotContains(t, "stderr", r.stderr, pemKeyMarker)
}

// A unix socket is guarded by its file permissions and dialled in plaintext by
// the gateway, so the TLS flags are refused with it before anything is bound.
func TestServeTLSRefusesAUnixSocketListener(t *testing.T) {
	c, _ := fixture(t)
	f := newTLSFiles(t)
	path := filepath.Join(t.TempDir(), "p.sock")
	r := c.fail(exitUsage, "serve", "--server", "s1", "--listen", unixPrefix+path, "--tls-cert", f.certPath, "--tls-key", f.keyPath)
	wantContains(t, "stderr", r.stderr, "refused with --listen unix:", "plaintext")
	r = c.fail(exitUsage, "serve", "--server", "s1", "--listen", unixPrefix+path, "--tls-cert", f.certPath, "--tls-key", f.keyPath, "--tls-client-ca", f.caPath)
	wantContains(t, "stderr", r.stderr, "refused with --listen unix:")
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Errorf("the socket was created although the flags were refused: %v", err)
	}
}

// The private key must be owner-only, as the database is: whoever reads it can
// stand in for the processor. The certificate is public and may be shared; a
// key that is not a regular file is refused before it is opened.
func TestServeTLSRefusesAGroupReadableKey(t *testing.T) {
	c, _ := fixture(t)
	f := newTLSFiles(t)
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644} {
		if err := os.Chmod(f.keyPath, mode); err != nil {
			t.Fatal(err)
		}
		r := c.fail(exitFailure, f.serveArgs()...)
		wantContains(t, fmt.Sprintf("stderr for mode %04o", mode), r.stderr, "--tls-key", "readable by other users", fmt.Sprintf("%04o", mode), "chmod 600")
		wantNotContains(t, "stderr", r.stderr, pemKeyMarker)
	}
	if err := os.Chmod(f.keyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f.certPath, 0o644); err != nil {
		t.Fatal(err)
	}
	out, _, stop := c.start(f.serveArgs()...)
	waitListening(t, out)
	if code := stop(); code != exitOK {
		t.Fatalf("serve with a shared certificate and an owner-only key: exit %d:\n%s", code, out.String())
	}
	r := c.fail(exitFailure, "serve", "--server", "s1", "--listen", "127.0.0.1:0", "--tls-cert", f.certPath, "--tls-key", t.TempDir())
	wantContains(t, "stderr", r.stderr, "--tls-key", "is a directory")
}

// D19: over TLS the processor enforces approvals exactly as in
// plaintext, the listening line names the mode, and a shared secret given as
// well is still checked on every hook.
func TestServeTLSOverGRPCEnforcesApprovals(t *testing.T) {
	c, u := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	f := newTLSFiles(t)
	body := listBody(rawTools(t, u.url()))

	out, errb, stop := c.start(f.serveArgs("--tls-client-ca", f.caPath)...)
	client, ctx := dialTLS(t, waitListening(t, out), f.ca.Pool, f.client.TLS)
	res, err := client.CheckResponse(ctx, listHook("s1", body, nil))
	if err != nil || res.GetMutated() == nil {
		t.Fatalf("tools/list over TLS = %v, %v; want a filtered list", res, err)
	}
	if names := servedNames(t, res.GetMutated()); len(names) != 1 || names[0] != "echo" {
		t.Fatalf("served %v, want only echo", names)
	}
	denied, err := client.CheckRequest(ctx, callHook("s1", "wipe_database", nil))
	if err != nil || denied.GetError() == nil {
		t.Fatalf("wipe_database call = %v, %v; want a denial", denied, err)
	}
	allowed, err := client.CheckRequest(ctx, callHook("s1", "echo", nil))
	if err != nil || allowed.GetPass() == nil {
		t.Fatalf("echo call = %v, %v; want pass", allowed, err)
	}
	if code := stop(); code != exitOK {
		t.Fatalf("serve exit %d:\n%s", code, out.String())
	}
	wantContains(t, "stdout", out.String(), "guarding server s1, target s1, TLS 1.3 with a client certificate required (hooks are authenticated by the client certificate; no --secret-env)", "calls allowed=1 denied=1")
	wantNotContains(t, "output", out.String()+errb.String(), pemKeyMarker)

	out, _, stop = c.start(f.serveArgs()...)
	client, ctx = dialTLS(t, waitListening(t, out), f.ca.Pool)
	if allowed, err = client.CheckRequest(ctx, callHook("s1", "echo", nil)); err != nil || allowed.GetPass() == nil {
		t.Fatalf("echo call without a client certificate on a server-only listener = %v, %v; want pass", allowed, err)
	}
	if code := stop(); code != exitOK {
		t.Fatalf("serve exit %d:\n%s", code, out.String())
	}
	wantContains(t, "stdout", out.String(), "TLS 1.3 with a server certificate only (hooks are not authenticated: no --secret-env)")

	c.env[secretVar] = plant("shared")
	out, errb, stop = c.start(f.serveArgs("--tls-client-ca", f.caPath, "--secret-env", secretVar)...)
	client, ctx = dialTLS(t, waitListening(t, out), f.ca.Pool, f.client.TLS)
	if denied, err = client.CheckRequest(ctx, callHook("s1", "echo", nil)); err != nil || denied.GetError() == nil {
		t.Fatalf("call without the secret over mTLS = %v, %v; want a denial", denied, err)
	}
	if allowed, err = client.CheckRequest(ctx, callHook("s1", "echo", secretMetadata(t, plant("shared")))); err != nil || allowed.GetPass() == nil {
		t.Fatalf("call with the secret over mTLS = %v, %v; want pass", allowed, err)
	}
	if code := stop(); code != exitOK {
		t.Fatalf("serve exit %d:\n%s", code, out.String())
	}
	wantContains(t, "stdout", out.String(), "TLS 1.3 with a client certificate required (hooks must carry the shared secret)", "unauthenticated=1")
	wantNotContains(t, "output", out.String()+errb.String(), canary, pemKeyMarker)
}

// D19: with --tls-client-ca a connection without a certificate that
// authority signed never reaches a hook, and neither does a plaintext one;
// nothing is counted because nothing was read.
func TestServeTLSRefusesAClientWithoutACertificate(t *testing.T) {
	c, _ := fixture(t)
	f := newTLSFiles(t)
	out, _, stop := c.start(f.serveArgs("--tls-client-ca", f.caPath)...)
	addr := waitListening(t, out)

	anonymous, ctx := dialTLS(t, addr, f.ca.Pool)
	wantUnavailable(t, ctx, anonymous, "client without a certificate")
	impostor, ctx := dialTLS(t, addr, f.ca.Pool, f.other.Client(t, "impostor").TLS)
	wantUnavailable(t, ctx, impostor, "client certificate from another authority")
	plain, ctx := dial(t, addr)
	wantUnavailable(t, ctx, plain, "plaintext client")

	if code := stop(); code != exitOK {
		t.Fatalf("serve exit %d:\n%s", code, out.String())
	}
	wantContains(t, "stdout", out.String(), "calls allowed=0 denied=0", "unauthenticated=0")
}

// O-2: a client certificate authority satisfies the non-loopback rule in place
// of the shared secret; server-only TLS does not, and the permission flag is
// still needed. The accepted command fails later on the unknown server (exit
// 1), which shows the policy passed without binding the wildcard address.
func TestServeTLSClientCASatisfiesTheNonLoopbackRule(t *testing.T) {
	c, _ := fixture(t)
	f := newTLSFiles(t)
	exposed := []string{"--listen", "0.0.0.0:0", "--allow-non-loopback", "--tls-cert", f.certPath, "--tls-key", f.keyPath}
	r := c.fail(exitUsage, append([]string{"serve", "--server", "s1"}, exposed...)...)
	wantContains(t, "stderr", r.stderr, "without a shared secret or a client certificate authority", "--tls-client-ca", "--secret-env")
	r = c.fail(exitFailure, append([]string{"serve", "--server", "nope"}, append(exposed, "--tls-client-ca", f.caPath)...)...)
	wantContains(t, "stderr", r.stderr, "not found")
	r = c.fail(exitUsage, "serve", "--server", "s1", "--listen", "0.0.0.0:0", "--tls-cert", f.certPath, "--tls-key", f.keyPath, "--tls-client-ca", f.caPath)
	wantContains(t, "stderr", r.stderr, "not a loopback address", "--allow-non-loopback", "--tls-client-ca")
}
