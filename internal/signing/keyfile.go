package signing

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"syscall"

	"golang.org/x/crypto/ssh"
)

var (
	// ErrKeyFile is returned for a key path that is not a regular owner-only
	// file holding exactly one unencrypted OpenSSH private key.
	ErrKeyFile = errors.New("signing: key file refused")
	// ErrEncryptedKey is returned for a passphrase-protected key file; the
	// CLI never reads a passphrase, the agent does.
	ErrEncryptedKey = errors.New("signing: key file is passphrase-protected; load the key into ssh-agent; toolwarrant does not read passphrases")
	// ErrKeyClosed is returned by a key file's signer after Close.
	ErrKeyClosed = errors.New("signing: key was closed")
	// errKeyNotRegular names what a refused directory entry is not.
	errKeyNotRegular = errors.New("not a regular file")
)

// keyFile is what readKeyFile returns: the bytes, bounded, and the modes of
// the directory entry and of the open file, both checked for the shape and,
// for a private key, both checked for the sharing bits.
type keyFile struct {
	data      []byte
	entryMode fs.FileMode
	openMode  fs.FileMode
}

// readKeyFile opens path under the export key's rules generalised (the rules
// are those of checkPrivateKeyMode and readPrivateKeyFile in
// internal/export/sign.go, repeated here rather than moved so that the export
// and its tests stay as they are; a change to one must be made in both): the entry
// is a regular file by Lstat (no link followed, no directory, no pipe), the
// open follows no link and blocks on no pipe (O_NOFOLLOW, O_NONBLOCK), the
// open file is a regular file again, and at most MaxKeyFileBytes are read.
// The sharing bits are the caller's to check, because a public key file may
// be world-readable and a private one may not.
func readKeyFile(path string) (keyFile, error) {
	if path == "" {
		return keyFile{}, fmt.Errorf("%w: key path is empty", ErrKeyFile)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return keyFile{}, fmt.Errorf("%w: %v", ErrKeyFile, err)
	}
	if err := checkRegular(fi.Mode()); err != nil {
		return keyFile{}, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return keyFile{}, fmt.Errorf("%w: open: %v", ErrKeyFile, err)
	}
	defer func() { _ = f.Close() }()
	ofi, err := f.Stat()
	if err != nil {
		return keyFile{}, fmt.Errorf("%w: inspect: %v", ErrKeyFile, err)
	}
	if err := checkRegular(ofi.Mode()); err != nil {
		return keyFile{}, err
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxKeyFileBytes+1))
	if err != nil {
		clear(data)
		return keyFile{}, fmt.Errorf("%w: read: %v", ErrKeyFile, err)
	}
	if len(data) > MaxKeyFileBytes {
		clear(data)
		return keyFile{}, fmt.Errorf("%w: larger than %d bytes, which no key file is", ErrKeyFile, MaxKeyFileBytes)
	}
	return keyFile{data: data, entryMode: fi.Mode(), openMode: ofi.Mode()}, nil
}

// checkRegular refuses a directory entry that is not a regular file.
func checkRegular(mode fs.FileMode) error {
	switch {
	case mode&fs.ModeSymlink != 0:
		return fmt.Errorf("%w: a symbolic link, %w; name the file itself", ErrKeyFile, errKeyNotRegular)
	case mode.IsDir():
		return fmt.Errorf("%w: a directory, %w", ErrKeyFile, errKeyNotRegular)
	case !mode.IsRegular():
		return fmt.Errorf("%w: %w (a pipe, a socket or a device)", ErrKeyFile, errKeyNotRegular)
	}
	return nil
}

// checkPrivateKeyMode refuses a private key that group or others can reach.
func checkPrivateKeyMode(mode fs.FileMode) error {
	if perm := mode.Perm(); perm&sharedBits != 0 {
		return fmt.Errorf("%w: private key is readable by other users (mode %04o); whoever reads it can sign a decision, so chmod 600 it", ErrKeyFile, perm)
	}
	return nil
}

// ReadPrivateKeyFile reads an unencrypted OpenSSH private key under the file
// rules, with the sharing bits checked on the entry and on the open file, and
// returns it as a SigningKey after the key policy. A passphrase-protected key
// is refused with the agent named. Every buffer the key passed through is
// cleared before the function returns; Close clears the key itself.
func ReadPrivateKeyFile(path string) (SigningKey, error) {
	kf, err := readKeyFile(path)
	if err != nil {
		return nil, err
	}
	defer clear(kf.data)
	if err := checkPrivateKeyMode(kf.entryMode); err != nil {
		return nil, err
	}
	if err := checkPrivateKeyMode(kf.openMode); err != nil {
		return nil, err
	}
	return parsePrivateKey(kf.data)
}

// parsePrivateKey turns the bytes of a key file into a SigningKey: exactly one
// PEM block, no passphrase, a key type the policy accepts.
func parsePrivateKey(data []byte) (SigningKey, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%w: not a PEM private key (an OpenSSH private key file begins with -----BEGIN OPENSSH PRIVATE KEY-----)", ErrKeyFile)
	}
	defer clear(block.Bytes)
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("%w: holds more than one PEM block", ErrKeyFile)
	}
	raw, err := ssh.ParseRawPrivateKey(data)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		return nil, ErrEncryptedKey
	}
	if err != nil {
		return nil, fmt.Errorf("%w: not an OpenSSH private key: %v", ErrKeyFile, err)
	}
	signer, err := ssh.NewSignerFromKey(raw)
	if err != nil {
		zeroKey(raw)
		return nil, fmt.Errorf("%w: %v", ErrKeyFile, err)
	}
	if err := CheckKeyPolicy(signer.PublicKey()); err != nil {
		zeroKey(raw)
		return nil, err
	}
	as, ok := signer.(ssh.AlgorithmSigner)
	if !ok {
		zeroKey(raw)
		return nil, fmt.Errorf("%w: the key cannot choose a signature algorithm", ErrKeyFile)
	}
	return &fileKey{AlgorithmSigner: as, raw: raw}, nil
}

// zeroKey clears what the standard library lets a caller clear of a parsed
// private key: the Ed25519 seed bytes. An ECDSA or RSA key keeps its secret
// in values that cannot be overwritten through the public API (the signer
// uses an internal copy), so those are left to the collector; the closed
// flag of fileKey is what guarantees that no key signs after Close.
func zeroKey(raw crypto.PrivateKey) {
	switch k := raw.(type) {
	case ed25519.PrivateKey:
		clear(k)
	case *ed25519.PrivateKey:
		clear(*k)
	}
}

// fileKey is a key read from a file; it never asks for a touch, and after
// Close it signs nothing.
type fileKey struct {
	ssh.AlgorithmSigner
	raw    crypto.PrivateKey
	closed bool
}

// NeedsTouch is false: a file key signs without anyone present.
func (k *fileKey) NeedsTouch() bool { return false }

// Sign refuses after Close.
func (k *fileKey) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	if k.closed {
		return nil, ErrKeyClosed
	}
	return k.AlgorithmSigner.Sign(rand, data)
}

// SignWithAlgorithm refuses after Close.
func (k *fileKey) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	if k.closed {
		return nil, ErrKeyClosed
	}
	return k.AlgorithmSigner.SignWithAlgorithm(rand, data, algorithm)
}

// Close marks the key closed and clears what can be cleared.
func (k *fileKey) Close() error {
	k.closed = true
	zeroKey(k.raw)
	k.raw = nil
	return nil
}
