package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	"github.com/sairam0424/toolwarrant/internal/signing"
	"github.com/sairam0424/toolwarrant/internal/textdiff"
	"github.com/sairam0424/toolwarrant/internal/trust"
)

// The key an operator signs with and the root a catalog is pinned to (D22
// (h); owner decisions O-13 and O-18). The key is named by path only, never
// by value: a public key file means "ask ssh-agent for exactly this key" and
// the agent is never asked to sign with another; anything else is read as an
// unencrypted OpenSSH private key under the export key's file rules (a regular
// owner-only file, no link followed, no pipe waited on, bounded size) and an
// encrypted one is refused with the agent named. internal/signing applies
// those rules; this file decides where the path and the socket come from and
// bounds every signature by --sign-timeout. Fingerprints are the only key
// material any output of this program carries.
const (
	envSSHKey     = "TOOLWARRANT_SSH_KEY"
	envTrustRoot  = "TOOLWARRANT_TRUST_ROOT"
	envAuthSock   = "SSH_AUTH_SOCK"
	flagSSHKey    = "ssh-key"
	flagTrustRoot = "trust-root"
	flagSignWait  = "sign-timeout"
	flagExpect    = "expect-head"
	expectHelp    = "fail unless the audit head is this hash you recorded, and never sign again when it moved"
	// defaultSignTimeout bounds one signature: a FIDO2 touch, a forwarded
	// agent, a slow key file host (O-17; 60 s rather than 90).
	defaultSignTimeout = 60 * time.Second
	// fingerprintPrefix and fingerprintBase64Len pin the shape --trust-root
	// must have: `SHA256:` and 43 unpadded base64 characters that decode to
	// 32 bytes, as ssh-keygen -l prints a fingerprint. The signing package
	// applies the same shape to the fingerprints inside a payload; the two
	// are kept in step by TestTrustRootShape.
	fingerprintPrefix    = "SHA256:"
	fingerprintBase64Len = 43
	fingerprintBytes     = 32
)

// errSignTimeout is the refusal when a signature did not arrive within
// --sign-timeout; nothing was written, since the write follows the signature.
var errSignTimeout = errors.New("signing timed out")

// cliSigner is the operator's key for one command: the signing key, its
// fingerprint (the only name the key has in any output), the bound on one
// signature and the stream the touch hint goes to.
type cliSigner struct {
	key     signing.SigningKey
	fp      string
	timeout time.Duration
	hint    *stream
}

// keySource is the key the operator named: --ssh-key, then TOOLWARRANT_SSH_KEY;
// the agent socket is SSH_AUTH_SOCK as this process read it. ok is false when
// no key was named.
func (a *app) keySource() (src signing.KeySource, ok bool) {
	path := a.globals.sshKey
	if path == "" {
		path = a.getenv(envSSHKey)
	}
	if path == "" {
		return signing.KeySource{}, false
	}
	return signing.KeySource{Path: path, AuthSock: a.getenv(envAuthSock)}, true
}

// optionalSigner resolves the key the operator named, or returns nil when
// none was named. Resolving means opening the key: the agent is dialled and
// must hold the key, or the private key file is read under the file rules, so
// a key that is refused is refused here, before the catalog is touched.
func (a *app) optionalSigner(c *command) (*cliSigner, error) {
	if a.globals.signTimeout <= 0 {
		return nil, &usageError{msg: "--" + flagSignWait + " must be positive", cmd: c}
	}
	src, ok := a.keySource()
	if !ok {
		return nil, nil
	}
	key, err := src.Open(a.ctx)
	if err != nil {
		return nil, fmt.Errorf("--%s %s: %w", flagSSHKey, textdiff.Escape(src.Path), err)
	}
	return &cliSigner{key: key, fp: signing.Fingerprint(key.PublicKey()), timeout: a.globals.signTimeout, hint: a.stderr}, nil
}

// requireSigner is optionalSigner for the commands that cannot run without a
// key (the trust commands that write); meaning says what the key is for.
func (a *app) requireSigner(c *command, meaning string) (*cliSigner, error) {
	s, err := a.optionalSigner(c)
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, &usageError{msg: fmt.Sprintf("trust %s needs --%s PATH (or %s): %s", c.name, flagSSHKey, envSSHKey, meaning), cmd: c}
	}
	return s, nil
}

// pub is the key's public half, for the key line a trust list stores.
func (s *cliSigner) pub() ssh.PublicKey { return s.key.PublicKey() }

// sign signs payload under ns, bounded by the signer's timeout. A FIDO2 key is
// announced first, since the agent then waits for a touch. A timeout is its
// own refusal (errSignTimeout) and writes nothing: every write follows the
// signature. The signing package verifies the signer's output before
// returning it, so a hostile agent's bytes never reach the catalog.
func (s *cliSigner) sign(parent context.Context, payload []byte, ns signing.Namespace) (signing.Record, error) {
	if s.key.NeedsTouch() {
		s.hint.printf("touch your security key for %s\n", s.fp)
	}
	ctx, cancel := context.WithTimeout(parent, s.timeout)
	defer cancel()
	rec, err := signing.Sign(ctx, payload, s.key, ns)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) && parent.Err() == nil {
			return signing.Record{}, fmt.Errorf("%w after %v waiting for the agent; nothing was written", errSignTimeout, s.timeout)
		}
		return signing.Record{}, err
	}
	return rec, nil
}

// close drops the key: the agent connection is closed, a file key's bytes
// are cleared, and nothing signs after it.
func (s *cliSigner) close() {
	if s != nil {
		_ = s.key.Close()
	}
}

// trustRoot is the fingerprint every open pins the trust bootstrap to:
// --trust-root, then TOOLWARRANT_TRUST_ROOT, empty for none. A value that is
// not a fingerprint is a usage error rather than a pin that can never match.
func (a *app) trustRoot() (string, error) {
	root := a.globals.trustRoot
	if root == "" {
		root = a.getenv(envTrustRoot)
	}
	if root == "" {
		return "", nil
	}
	if !isFingerprint(root) {
		return "", &usageError{msg: fmt.Sprintf("--%s %s is not a key fingerprint: it must be %s followed by %d base64 characters, as ssh-keygen -l prints one", flagTrustRoot, textdiff.Escape(root), fingerprintPrefix, fingerprintBase64Len)}
	}
	return root, nil
}

// isFingerprint reports whether s is a SHA256: fingerprint as ssh-keygen -l
// prints one: the prefix and 43 unpadded standard-base64 characters that
// decode to 32 bytes.
func isFingerprint(s string) bool {
	rest, ok := strings.CutPrefix(s, fingerprintPrefix)
	if !ok || len(rest) != fingerprintBase64Len {
		return false
	}
	raw, err := base64.RawStdEncoding.Strict().DecodeString(rest)
	return err == nil && len(raw) == fingerprintBytes
}

// operatorOf finds the operator the trust list in force names for a key.
func operatorOf(view catalog.TrustView, fp string) (trust.Operator, bool) {
	for _, op := range view.Signers {
		if op.Fingerprint == fp {
			return op, true
		}
	}
	return trust.Operator{}, false
}

// signedActor is the person a signed command acts as (O-13): the operator the
// trust list in force names for the key. A key the list does not name signs
// nothing (exit 1, the fingerprint named); a label given with --as,
// TOOLWARRANT_ACTOR or --by that names another person is a usage error, so
// the audit log never carries a name the key does not back; without a label
// the operator's name is the actor.
func (a *app) signedActor(c *command, view catalog.TrustView, fp string, label catalog.Actor, explicit bool) (catalog.Actor, error) {
	op, ok := operatorOf(view, fp)
	if !ok {
		return catalog.Actor{}, fmt.Errorf("%w: the key %s is not in trust list v%d in force since entry %d; run \"%s trust show\" to see whose keys are listed", catalog.ErrNotASigner, fp, view.Version, view.ListSeq, programName)
	}
	if explicit && label.Name != op.Name {
		return catalog.Actor{}, &usageError{msg: fmt.Sprintf("--as %s names another operator than the key %s, which the trust list lists for %s", cell(label.Name), fp, cell(op.Name)), cmd: c}
	}
	return catalog.Actor{Name: op.Name, Type: catalog.ActorHuman}, nil
}

// labelGiven reports whether the operator named themselves with --as or
// TOOLWARRANT_ACTOR; with a key the name is otherwise derived from the key.
func (a *app) labelGiven() bool {
	return a.globals.actor != "" || a.getenv(envActor) != ""
}

// signerList renders the operators of a trust list as `name SHA256:...`, in
// list order, for the lines the trust commands print.
func signerList(ops []trust.Operator) string {
	parts := make([]string, 0, len(ops))
	for _, op := range ops {
		parts = append(parts, cell(op.Name)+" "+op.Fingerprint)
	}
	return strings.Join(parts, ", ")
}
