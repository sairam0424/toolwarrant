package export

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"syscall"
)

// The signature of the manifest (D21 e). The signing key is an Ed25519 private
// key in a PKCS#8 PEM file that only its owner can read, named by path and
// read once per export; it is never taken from the environment or a flag
// value, never printed, and zeroed by the caller when the export is done. The
// signature covers the exact bytes of the complete MANIFEST.json, whose digests
// cover every tool file, so one signature binds the whole export to the audit
// head the manifest records. The public key is written beside the signature
// for whoever reads the export; a verifier trusts only the key it holds itself
// and refuses a directory whose recorded key is another one.
const (
	// signatureName holds the base64 Ed25519 signature over MANIFEST.json,
	// one line. publicKeyName holds the signer's public key as PKIX PEM.
	signatureName = manifestName + ".sig"
	publicKeyName = manifestName + ".pub"

	// maxSignatureFileBytes bounds the signature file read back: a 64-byte
	// signature is 88 base64 characters and a newline.
	maxSignatureFileBytes = 256
	// MaxKeyFileBytes bounds a PEM key file, the signing key ReadSigningKey
	// opens and the public key this package reads back from MANIFEST.json.pub
	// or a caller hands to ParsePublicKey: an Ed25519 PKCS#8 or PKIX block is
	// a few lines, so anything larger is not a key this package reads. It is
	// exported so that the CLI's --pub-key reader applies the same bound.
	MaxKeyFileBytes = 8 << 10
	// keySharedBits are the permission bits that give group or others any
	// access to the signing key, the catalog's rule for the database file.
	keySharedBits os.FileMode = 0o077

	pemPrivateKeyType = "PRIVATE KEY"
	pemPublicKeyType  = "PUBLIC KEY"
)

// errKeyNotRegular is why a signing key path was refused: the directory entry
// is not a regular file. The message names what was found.
var errKeyNotRegular = errors.New("not a regular file")

// ReadSigningKey reads the Ed25519 signing key at path. The path must name a
// regular file that group and others cannot reach (mode 0600 or stricter): a
// symbolic link, a directory or any other entry is refused before the open, and
// the open itself follows no link and blocks on no pipe (O_NOFOLLOW,
// O_NONBLOCK), with the open file checked again. The file must hold exactly
// one PEM block of type PRIVATE KEY whose PKCS#8 content is an Ed25519 key;
// any other key type is refused. Every buffer the key passed through is
// zeroed before the function returns; the caller zeroes the returned key.
func ReadSigningKey(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("export: signing key path is empty")
	}
	if err := checkPrivateKeyEntry(path); err != nil {
		return nil, err
	}
	data, err := readPrivateKeyFile(path)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	block, rest := pem.Decode(data)
	if block == nil || block.Type != pemPrivateKeyType {
		return nil, errors.New("export: signing key is not a PEM " + pemPrivateKeyType + " block (PKCS#8)")
	}
	defer clear(block.Bytes)
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("export: signing key file holds more than one PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("export: signing key is not a PKCS#8 private key: %w", err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("export: signing key is %T, not an Ed25519 key", parsed)
	}
	return key, nil
}

// checkPrivateKeyEntry refuses, by Lstat and before any open, a signing key
// path that is not a regular file or that other users can reach.
func checkPrivateKeyEntry(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("export: signing key: %w", err)
	}
	return checkPrivateKeyMode(fi.Mode())
}

// checkPrivateKeyMode is the rule for the signing key's directory entry: a
// regular file whose mode gives group and others nothing.
func checkPrivateKeyMode(mode fs.FileMode) error {
	switch {
	case mode&fs.ModeSymlink != 0:
		return fmt.Errorf("export: signing key is a symbolic link, %w; name the file itself", errKeyNotRegular)
	case mode.IsDir():
		return fmt.Errorf("export: signing key is a directory, %w", errKeyNotRegular)
	case !mode.IsRegular():
		return fmt.Errorf("export: signing key is %w", errKeyNotRegular)
	}
	if perm := mode.Perm(); perm&keySharedBits != 0 {
		return fmt.Errorf("export: signing key is readable by other users (mode %04o); whoever reads it can sign an export, so chmod 600 it", perm)
	}
	return nil
}

// readPrivateKeyFile opens the key without following a link or waiting on a
// pipe, checks what it opened against the same rule as the entry, and reads
// at most MaxKeyFileBytes.
func readPrivateKeyFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("export: open signing key: %w", err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("export: inspect signing key: %w", err)
	}
	if err := checkPrivateKeyMode(fi.Mode()); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxKeyFileBytes+1))
	if err != nil {
		clear(data)
		return nil, fmt.Errorf("export: read signing key: %w", err)
	}
	if len(data) > MaxKeyFileBytes {
		clear(data)
		return nil, fmt.Errorf("export: signing key file is larger than %d bytes, which no Ed25519 key file is", MaxKeyFileBytes)
	}
	return data, nil
}

// ParsePublicKey parses one PKIX PEM block of type PUBLIC KEY and requires an
// Ed25519 key. It is how a verifier reads the key it holds, and how this
// package reads the key an export directory records.
func ParsePublicKey(pemBytes []byte) (ed25519.PublicKey, error) {
	block, rest := pem.Decode(pemBytes)
	if block == nil || block.Type != pemPublicKeyType {
		return nil, errors.New("export: public key is not a PEM " + pemPublicKeyType + " block (PKIX)")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("export: public key file holds more than one PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("export: public key is not a PKIX public key: %w", err)
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("export: public key is %T, not an Ed25519 key", parsed)
	}
	return pub, nil
}

// encodePublicKey renders an Ed25519 public key as PKIX PEM, the form
// MANIFEST.json.pub holds and ParsePublicKey reads back.
func encodePublicKey(pub ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("export: encode public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemPublicKeyType, Bytes: der}), nil
}

// signManifest writes the public key and then the signature over manifest,
// each only when its bytes differ from the file already there, so a re-run
// with the same key and manifest touches nothing (Ed25519 signatures are
// deterministic). The signature goes last: a crash between the two leaves a
// signature that does not verify, never one that does over a key that is not
// on disk. A nil key writes nothing and leaves both files as they are.
func signManifest(root *os.Root, manifest []byte, key ed25519.PrivateKey) error {
	if key == nil {
		return nil
	}
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return errors.New("export: signing key has no Ed25519 public key")
	}
	pubPEM, err := encodePublicKey(pub)
	if err != nil {
		return err
	}
	if err := writeIfChanged(root, publicKeyName, pubPEM); err != nil {
		return err
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(key, manifest)) + "\n"
	return writeIfChanged(root, signatureName, []byte(sig))
}

// readSmallFile reads a regular file directly inside root, bounded by max. It
// reports whether the file exists; a symlink, a directory or an oversized
// file is an error, never read through.
func readSmallFile(root *os.Root, name string, max int64) ([]byte, bool, error) {
	fi, err := root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("export: stat %s: %w", name, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, true, fmt.Errorf("export: %s is a symlink or not a regular file", name)
	}
	if fi.Size() > max {
		return nil, true, fmt.Errorf("export: %s is larger than %d bytes", name, max)
	}
	data, err := root.ReadFile(name)
	if err != nil {
		return nil, true, fmt.Errorf("export: read %s: %w", name, err)
	}
	return data, true, nil
}

// readSignature reads MANIFEST.json.sig: one line of base64 holding exactly an
// Ed25519 signature. A missing file is reported as such, because the usual
// cause is an export that was never signed.
func readSignature(root *os.Root) ([]byte, error) {
	data, exists, err := readSmallFile(root, signatureName, maxSignatureFileBytes)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.New("export: " + signatureName + " not found; the export was not signed (run export --sign-key)")
	}
	sig, err := base64.StdEncoding.DecodeString(string(bytes.TrimRight(data, "\r\n")))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("export: " + signatureName + " does not hold a base64 Ed25519 signature")
	}
	return sig, nil
}

// readRecordedPublicKey reads the key MANIFEST.json.pub records.
func readRecordedPublicKey(root *os.Root) (ed25519.PublicKey, error) {
	data, exists, err := readSmallFile(root, publicKeyName, MaxKeyFileBytes)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.New("export: " + publicKeyName + " not found; the export was not signed (run export --sign-key)")
	}
	pub, err := ParsePublicKey(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", publicKeyName, err)
	}
	return pub, nil
}

// signatureFiles is Commit's guard over the two signature files: none, or both
// with the signature verifying over manifest under the recorded key. It returns
// the names to stage. One file without the other, or a signature over an
// earlier manifest (an unsigned export after a signed one), is refused, so the
// history never records a signature that does not sign what it sits beside.
func signatureFiles(root *os.Root, manifest []byte) ([]string, error) {
	haveSig, err := entryExists(root, signatureName)
	if err != nil {
		return nil, err
	}
	havePub, err := entryExists(root, publicKeyName)
	if err != nil {
		return nil, err
	}
	if !haveSig && !havePub {
		return nil, nil
	}
	if haveSig != havePub {
		return nil, errors.New("export: " + signatureName + " and " + publicKeyName + " go together, found one without the other; run export --sign-key again or remove it before committing")
	}
	pub, err := readRecordedPublicKey(root)
	if err != nil {
		return nil, err
	}
	sig, err := readSignature(root)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(pub, manifest, sig) {
		return nil, errors.New("export: " + signatureName + " does not sign the current " + manifestName + " (an export since the signed one was not signed); run export --sign-key again or remove " + signatureName + " and " + publicKeyName + " before committing")
	}
	return []string{signatureName, publicKeyName}, nil
}

// entryExists reports whether name exists directly inside root, whatever it is.
func entryExists(root *os.Root, name string) (bool, error) {
	_, err := root.Lstat(name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("export: stat %s: %w", name, err)
	}
	return true, nil
}
