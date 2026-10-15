package signing

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// ErrNoAgent is returned when the key path holds a public key, so the private
// half must be in ssh-agent, and no socket was given.
var ErrNoAgent = errors.New("signing: the key file holds a public key, so its private half must be in ssh-agent, and SSH_AUTH_SOCK is not set")

// ErrKeyOptions is returned when a public key line carries authorized_keys
// options, which name no key the agent can be asked for.
var ErrKeyOptions = errors.New("signing: the public key line carries options; name the key as `type base64 [comment]`")

// KeySource is how the CLI names a key (O-18): one path, read the way
// `ssh-keygen -Y sign -f` reads it. A file whose first line is an
// authorized_keys public key means "this key, through the agent at AuthSock";
// any other file is read as an unencrypted OpenSSH private key under the file
// rules. AuthSock is the value of SSH_AUTH_SOCK as the CLI read it; the
// package reads no environment.
type KeySource struct {
	Path     string
	AuthSock string
}

// Open resolves the source to a SigningKey. The caller closes the key when
// the command ends.
func (s KeySource) Open(ctx context.Context) (SigningKey, error) {
	kf, err := readKeyFile(s.Path)
	if err != nil {
		return nil, err
	}
	defer clear(kf.data)
	pub, isPublic, err := publicKeyLine(kf.data)
	if err != nil {
		return nil, err
	}
	if isPublic {
		return s.openAgentKey(ctx, pub)
	}
	if err := checkPrivateKeyMode(kf.entryMode); err != nil {
		return nil, err
	}
	if err := checkPrivateKeyMode(kf.openMode); err != nil {
		return nil, err
	}
	return parsePrivateKey(kf.data)
}

// publicKeyLine reports whether the file's first line is a public key as
// ssh-keygen writes a .pub (`type base64 comment`), and which key. A line
// with authorized_keys options is an error, not a private key.
func publicKeyLine(data []byte) (ssh.PublicKey, bool, error) {
	line, _, _ := bytes.Cut(bytes.TrimSpace(data), []byte("\n"))
	pub, _, options, _, err := ssh.ParseAuthorizedKey(line)
	if err != nil {
		return nil, false, nil
	}
	if len(options) != 0 {
		return nil, false, ErrKeyOptions
	}
	return pub, true, nil
}

// openAgentKey asks the agent at AuthSock for pub, after the key policy.
func (s KeySource) openAgentKey(ctx context.Context, pub ssh.PublicKey) (SigningKey, error) {
	if err := CheckKeyPolicy(pub); err != nil {
		return nil, err
	}
	if s.AuthSock == "" {
		return nil, fmt.Errorf("%w (key %s)", ErrNoAgent, Fingerprint(pub))
	}
	a, err := OpenAgent(ctx, s.AuthSock)
	if err != nil {
		return nil, err
	}
	key, err := a.SignerFor(pub)
	if err != nil {
		_ = a.Close()
		return nil, err
	}
	return key, nil
}
