// Package sigtest generates throwaway SSH keys and serves throwaway ssh-agents
// for the tests of internal/signing, cmd/toolwarrant and the end-to-end test.
// Nothing here is checked into the tree: every key is made when a test asks,
// as internal/testcert does for certificates, so the repository holds no key
// material, and the package is imported by test files only.
package sigtest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	// PrivateFileMode is how WriteKeyFile stores a private key: owner-only,
	// which is what the signing package requires of one.
	PrivateFileMode os.FileMode = 0o600
	// PublicFileMode is how WritePublicKey stores a .pub: world-readable, as
	// ssh-keygen leaves it, since the signing package reads a public key
	// under the shape rules only.
	PublicFileMode os.FileMode = 0o644
	// socketMode is what OpenSSH's ssh-agent gives its socket.
	socketMode os.FileMode = 0o600
	// socketName is the file name of a served agent's socket; the directory
	// comes from os.TempDir, not t.TempDir, because a long test name would
	// push the path past the 104-byte sun_path of darwin.
	socketName = "agent.sock"
	// comment is the comment every generated key carries where one is written.
	comment = "sigtest"
)

// Key is one generated key in the three forms a test needs: the raw private
// key for an agent keyring or a key file, the ssh.Signer over it, and the
// public half.
type Key struct {
	Private crypto.PrivateKey
	Signer  ssh.Signer
	Public  ssh.PublicKey
}

// GenerateEd25519 makes an Ed25519 key.
func GenerateEd25519(t testing.TB) Key {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return fromPrivate(t, priv)
}

// GenerateECDSA makes an ECDSA key on curve (P-256, P-384 or P-521).
func GenerateECDSA(t testing.TB, curve elliptic.Curve) Key {
	t.Helper()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return fromPrivate(t, priv)
}

// GenerateRSA makes an RSA key of bits; 3072 is the smallest the signing
// package accepts and 2048 the size its refusal tests use.
func GenerateRSA(t testing.TB, bits int) Key {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return fromPrivate(t, priv)
}

// fromPrivate wraps a raw private key.
func fromPrivate(t testing.TB, priv crypto.PrivateKey) Key {
	t.Helper()
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return Key{Private: priv, Signer: signer, Public: signer.PublicKey()}
}

// Serve serves a on a fresh unix socket in a private temporary directory and
// returns the socket path, with the socket itself 0600 as OpenSSH's ssh-agent
// makes it. The listener closes when the test ends; a connection still open
// then ends when its client closes.
func Serve(t testing.TB, a agent.Agent) (sock string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "tw-sigtest")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock = filepath.Join(dir, socketName)
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sock, socketMode); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = agent.ServeAgent(a, c)
				_ = c.Close()
			}()
		}
	}()
	t.Cleanup(func() {
		_ = l.Close()
		<-done
	})
	return sock
}

// NewAgent serves an in-process keyring agent and returns its socket and a
// function that adds a key to it.
func NewAgent(t testing.TB) (sock string, add func(Key)) {
	t.Helper()
	keyring := agent.NewKeyring()
	sock = Serve(t, keyring)
	return sock, func(k Key) {
		if err := keyring.Add(agent.AddedKey{PrivateKey: k.Private, Comment: comment}); err != nil {
			t.Fatal(err)
		}
	}
}

// NewBlockingAgent serves an agent that lists keys but never answers a Sign
// until the test ends: what a FIDO2 key whose touch never comes looks like to
// the caller, for the tests of --sign-timeout and the context deadline.
func NewBlockingAgent(t testing.TB, keys ...Key) (sock string) {
	t.Helper()
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	return Serve(t, &blockingAgent{keys: keys, stop: stop})
}

// NewSilentAgent serves an agent that accepts a connection and answers
// nothing, not even the key list, until the test ends: what a hung forwarded
// agent looks like to the caller, for the tests of signing.AgentTimeout and
// of the refusal that names it.
func NewSilentAgent(t testing.TB) (sock string) {
	t.Helper()
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	return Serve(t, &blockingAgent{stop: stop, silent: true})
}

// blockingAgent is the agent NewBlockingAgent and NewSilentAgent serve.
type blockingAgent struct {
	keys   []Key
	stop   <-chan struct{}
	silent bool // List waits too, so the first request hangs
}

// errBlocking is what a blocked request returns once the test ends, and what
// every unsupported operation returns.
var errBlocking = errors.New("sigtest: blocking agent")

// List returns the public keys as an agent does, or, for a silent agent,
// waits until the test ends.
func (b *blockingAgent) List() ([]*agent.Key, error) {
	if b.silent {
		<-b.stop
		return nil, errBlocking
	}
	out := make([]*agent.Key, 0, len(b.keys))
	for _, k := range b.keys {
		out = append(out, &agent.Key{Format: k.Public.Type(), Blob: k.Public.Marshal(), Comment: comment})
	}
	return out, nil
}

// Sign waits until the test ends.
func (b *blockingAgent) Sign(ssh.PublicKey, []byte) (*ssh.Signature, error) {
	<-b.stop
	return nil, errBlocking
}

// SignWithFlags waits until the test ends.
func (b *blockingAgent) SignWithFlags(ssh.PublicKey, []byte, agent.SignatureFlags) (*ssh.Signature, error) {
	<-b.stop
	return nil, errBlocking
}

// Add is not supported.
func (b *blockingAgent) Add(agent.AddedKey) error { return errBlocking }

// Remove is not supported.
func (b *blockingAgent) Remove(ssh.PublicKey) error { return errBlocking }

// RemoveAll is not supported.
func (b *blockingAgent) RemoveAll() error { return errBlocking }

// Lock is not supported.
func (b *blockingAgent) Lock([]byte) error { return errBlocking }

// Unlock is not supported.
func (b *blockingAgent) Unlock([]byte) error { return errBlocking }

// Signers is not supported; the protocol server never calls it.
func (b *blockingAgent) Signers() ([]ssh.Signer, error) { return nil, errBlocking }

// Extension is not supported.
func (b *blockingAgent) Extension(string, []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

// WriteKeyFile writes k as an unencrypted OpenSSH private key file named name
// in dir, owner-only, and returns its path.
func WriteKeyFile(t testing.TB, dir, name string, k Key) string {
	t.Helper()
	block, err := ssh.MarshalPrivateKey(k.Private, comment)
	if err != nil {
		t.Fatal(err)
	}
	return writeFile(t, filepath.Join(dir, name), pem.EncodeToMemory(block), PrivateFileMode)
}

// WriteEncryptedKeyFile writes k as a passphrase-protected OpenSSH private key
// file, owner-only, for the tests that prove such a file is refused.
func WriteEncryptedKeyFile(t testing.TB, dir, name string, k Key, passphrase string) string {
	t.Helper()
	block, err := ssh.MarshalPrivateKeyWithPassphrase(k.Private, comment, []byte(passphrase))
	if err != nil {
		t.Fatal(err)
	}
	return writeFile(t, filepath.Join(dir, name), pem.EncodeToMemory(block), PrivateFileMode)
}

// WritePublicKey writes k's public half as ssh-keygen writes a .pub: one line
// `type base64 comment`, world-readable, and returns its path.
func WritePublicKey(t testing.TB, dir, name string, k Key) string {
	t.Helper()
	line := strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(k.Public)), "\n") + " " + comment + "\n"
	return writeFile(t, filepath.Join(dir, name), []byte(line), PublicFileMode)
}

// writeFile writes data at path with exactly mode, whatever the umask.
func writeFile(t testing.TB, path string, data []byte, mode os.FileMode) string {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}
