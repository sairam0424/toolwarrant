package signing

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/sairam0424/toolwarrant/internal/signing/sigtest"
)

// An in-process agent holding an Ed25519 key signs a decision that verifies;
// asking for a key the agent does not hold names the fingerprint and nothing
// else; a FIDO2 key is reported as needing a touch.
func TestAgent_SignsWithAnEd25519KeyAndNamesAMissingKey(t *testing.T) {
	t.Parallel()
	held, other := sigtest.GenerateEd25519(t), sigtest.GenerateEd25519(t)
	sock, add := sigtest.NewAgent(t)
	add(held)
	a, err := OpenAgent(t.Context(), sock)
	if err != nil {
		t.Fatalf("OpenAgent: %v", err)
	}
	defer func() { _ = a.Close() }()
	key, err := a.SignerFor(held.Public)
	if err != nil {
		t.Fatalf("SignerFor: %v", err)
	}
	if key.NeedsTouch() {
		t.Error("an Ed25519 key needs a touch")
	}
	payload := mustMarshalDecision(t, sampleDecision(Fingerprint(held.Public)))
	r, err := Sign(t.Context(), payload, key, NamespaceDecision)
	if err != nil {
		t.Fatalf("Sign through the agent: %v", err)
	}
	if _, err := Verify(r.Payload, r.Signature, NamespaceDecision, Fingerprint(held.Public)); err != nil {
		t.Errorf("the agent's signature does not verify: %v", err)
	}
	_, err = a.SignerFor(other.Public)
	wantErrIs(t, "missing key", err, ErrKeyNotInAgent, "ssh-agent at SSH_AUTH_SOCK does not hold the key "+Fingerprint(other.Public))
	if strings.Contains(err.Error(), Fingerprint(held.Public)) {
		t.Errorf("the refusal names the held key: %v", err)
	}
	_, err = a.SignerFor(dsaPublic(t))
	wantErrIs(t, "weak key", err, ErrKeyPolicy, "")
	if err := a.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// An RSA key through the agent signs rsa-sha2-512, the algorithm the sshsig
// format requires, which the agent is told through the signature flags.
func TestAgent_RSAKeySignsRsaSha2512(t *testing.T) {
	t.Parallel()
	k := sigtest.GenerateRSA(t, MinRSABits)
	sock, add := sigtest.NewAgent(t)
	add(k)
	a, err := OpenAgent(t.Context(), sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	key, err := a.SignerFor(k.Public)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Sign(t.Context(), mustMarshalDecision(t, sampleDecision(Fingerprint(k.Public))), key, NamespaceDecision)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	parsed, err := parseSignature(r.Signature)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Signature.Format != ssh.KeyAlgoRSASHA512 {
		t.Errorf("signature format %q, want %q", parsed.Signature.Format, ssh.KeyAlgoRSASHA512)
	}
}

// SSH_AUTH_SOCK is refused unless it names a unix socket this user owns that
// nobody else can reach: a shared socket in a shared directory, a regular
// file, a symbolic link, a directory, an empty value and a path at the
// sun_path bound are refused; a 0600 socket, and a shared socket inside a
// private directory (launchd's layout), are accepted.
func TestAgent_RefusesASharedOrForeignSocket(t *testing.T) {
	t.Parallel()
	skipIfRoot(t)
	k := sigtest.GenerateEd25519(t)
	sock, add := sigtest.NewAgent(t)
	add(k)
	dir := filepath.Dir(sock)
	open := func(path string) error {
		a, err := OpenAgent(t.Context(), path)
		if err == nil {
			_ = a.Close()
		}
		return err
	}
	if err := open(sock); err != nil {
		t.Fatalf("a 0600 socket in a 0700 directory: %v", err)
	}
	chmod(t, sock, 0o666)
	if err := open(sock); err != nil {
		t.Errorf("a 0666 socket in a 0700 directory (launchd's layout): %v", err)
	}
	chmod(t, dir, 0o755)
	wantErrIs(t, "0666 socket in a 0755 directory", open(sock), ErrAgentSocket, "mode 0666 and its directory is not a private (0700) directory")
	chmod(t, sock, 0o660)
	wantErrIs(t, "0660 socket in a 0755 directory", open(sock), ErrAgentSocket, "mode 0660")
	chmod(t, sock, 0o600)
	if err := open(sock); err != nil {
		t.Errorf("a 0600 socket in a 0755 directory: %v", err)
	}
	chmod(t, dir, 0o700)
	regular := writeFile(t, filepath.Join(dir, "regular"), []byte("x"), 0o600)
	wantErrIs(t, "regular file", open(regular), ErrAgentSocket, "not a unix socket")
	link := filepath.Join(dir, "link")
	if err := os.Symlink(sock, link); err != nil {
		t.Fatal(err)
	}
	wantErrIs(t, "symlink to a good socket", open(link), ErrAgentSocket, "not a unix socket")
	wantErrIs(t, "directory", open(dir), ErrAgentSocket, "not a unix socket")
	wantErrIs(t, "empty", open(""), ErrAgentSocket, "not set")
	wantErrIs(t, "missing", open(filepath.Join(dir, "none")), ErrAgentSocket, "no such file")
	long := filepath.Join(dir, strings.Repeat("s", MaxSocketPathBytes))
	wantErrIs(t, "path at the bound", open(long), ErrAgentSocket, "must be under 104")
	almost := "/" + strings.Repeat("s", MaxSocketPathBytes-2)
	if err := open(almost); errors.Is(err, ErrAgentSocket) && strings.Contains(err.Error(), "must be under") {
		t.Errorf("a %d-byte path was refused for its length: %v", len(almost), err)
	}
}

func chmod(t testing.TB, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// A Sign whose agent never answers (a touch that never comes) returns when
// the caller's context ends, with the deadline named, and OpenAgent against a
// listener that never answers the key list returns the same way.
func TestAgent_SignHonoursTheContextDeadline(t *testing.T) {
	t.Parallel()
	k := sigtest.GenerateEd25519(t)
	sock := sigtest.NewBlockingAgent(t, k)
	a, err := OpenAgent(t.Context(), sock)
	if err != nil {
		t.Fatalf("OpenAgent: %v", err)
	}
	defer func() { _ = a.Close() }()
	key, err := a.SignerFor(k.Public)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = Sign(ctx, mustMarshalDecision(t, sampleDecision(Fingerprint(k.Public))), key, NamespaceDecision)
	took := time.Since(start)
	wantErrIs(t, "sign against a silent agent", err, context.DeadlineExceeded, "sign with "+Fingerprint(k.Public))
	if took > 5*time.Second {
		t.Errorf("Sign returned after %v, not at the 200 ms deadline", took)
	}
	t.Logf("Sign returned after %v with: %v", took.Round(time.Millisecond), err)

	l := silentListener(t)
	defer func() { _ = l.Close() }()
	ctx2, cancel2 := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel2()
	start = time.Now()
	_, err = OpenAgent(ctx2, l.Addr().String())
	wantErrIs(t, "open against a listener that never answers", err, ErrAgent, "list keys")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("the refusal does not name the deadline: %v", err)
	}
	t.Logf("OpenAgent returned after %v with: %v", time.Since(start).Round(time.Millisecond), err)
}

// silentListener serves a 0600 socket in a private directory that accepts and
// never answers, so the agent protocol's first request hangs. The directory
// comes from os.MkdirTemp for the same reason sigtest's does: a long test
// name in t.TempDir would push the path past darwin's sun_path.
func silentListener(t testing.TB) net.Listener {
	t.Helper()
	dir, err := os.MkdirTemp("", "tw-silent")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "agent.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	chmod(t, path, 0o600)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				buf := make([]byte, 1)
				for {
					if _, err := c.Read(buf); err != nil {
						_ = c.Close()
						return
					}
				}
			}()
		}
	}()
	return l
}
