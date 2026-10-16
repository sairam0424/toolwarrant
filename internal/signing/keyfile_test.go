package signing

import (
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/signing/sigtest"
)

// dsaKeyFile writes a `DSA PRIVATE KEY` PEM with a 1024-bit P, the shape
// ssh.ParseRawPrivateKey reads into a *dsa.PrivateKey; the policy refuses the
// type before any arithmetic.
func dsaKeyFile(t testing.TB, dir string) string {
	t.Helper()
	der, err := asn1.Marshal(struct {
		Version       int
		P, Q, G, Y, X *big.Int
	}{0, dsaP(), dsaQ(), big.NewInt(4), big.NewInt(8), big.NewInt(3)})
	if err != nil {
		t.Fatal(err)
	}
	return writeFile(t, filepath.Join(dir, "dsa.key"), pem.EncodeToMemory(&pem.Block{Type: "DSA PRIVATE KEY", Bytes: der}), 0o600)
}

// keyBodyLines returns the base64 lines of a PEM file: the material no error
// may carry.
func keyBodyLines(t testing.TB, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, l := range strings.Split(string(data), "\n") {
		if l != "" && !strings.HasPrefix(l, "-----") {
			lines = append(lines, l)
		}
	}
	return lines
}

// A private key is read only from a regular owner-only file holding exactly
// one unencrypted OpenSSH private key of an accepted type; a shared mode, a
// symbolic link, a directory, a pipe, an oversized file, two PEM blocks, a
// public key, a passphrase-protected key, a DSA key and an RSA-2048 key are
// each refused, and no refusal carries a line of the key.
func TestKeyFile_RefusesEveryUnsafeShape(t *testing.T) {
	t.Parallel()
	skipIfRoot(t)
	dir := t.TempDir()
	ed := sigtest.GenerateEd25519(t)
	good := sigtest.WriteKeyFile(t, dir, "good.key", ed)
	key, err := ReadPrivateKeyFile(good)
	if err != nil || Fingerprint(key.PublicKey()) != Fingerprint(ed.Public) || key.NeedsTouch() {
		t.Fatalf("ReadPrivateKeyFile on an owner-only Ed25519 key = %v, %v", key, err)
	}
	ec := sigtest.WriteKeyFile(t, dir, "ec.key", sigtest.GenerateECDSA(t, elliptic.P384()))
	if _, err := ReadPrivateKeyFile(ec); err != nil {
		t.Errorf("an owner-only ECDSA P-384 key: %v", err)
	}
	link := filepath.Join(dir, "link.key")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	pipe := filepath.Join(dir, "pipe.key")
	if err := syscall.Mkfifo(pipe, 0o600); err != nil {
		t.Fatal(err)
	}
	goodBytes, err := os.ReadFile(good)
	if err != nil {
		t.Fatal(err)
	}
	two := writeFile(t, filepath.Join(dir, "two.key"), append(append([]byte{}, goodBytes...), goodBytes...), 0o600)
	big := writeFile(t, filepath.Join(dir, "big.key"), append(append([]byte{}, goodBytes...), strings.Repeat("\n", MaxKeyFileBytes)...), 0o600)
	cases := map[string]struct {
		path string
		want error
		text string
	}{
		"mode 0644":     {sigtest.WriteKeyFile(t, dir, "shared.key", ed), ErrKeyFile, "readable by other users (mode 0644)"},
		"mode 0640":     {sigtest.WriteKeyFile(t, dir, "group.key", ed), ErrKeyFile, "mode 0640"},
		"mode 0604":     {sigtest.WriteKeyFile(t, dir, "other.key", ed), ErrKeyFile, "mode 0604"},
		"symlink":       {link, ErrKeyFile, "symbolic link"},
		"directory":     {dir, ErrKeyFile, "a directory"},
		"pipe":          {pipe, ErrKeyFile, "a pipe, a socket or a device"},
		"missing":       {filepath.Join(dir, "none.key"), ErrKeyFile, "no such file"},
		"empty path":    {"", ErrKeyFile, "key path is empty"},
		"oversized":     {big, ErrKeyFile, "larger than 16384 bytes"},
		"two blocks":    {two, ErrKeyFile, "more than one PEM block"},
		"public key":    {writeFile(t, filepath.Join(dir, "pub.key"), []byte(MarshalKey(ed.Public)+"\n"), 0o600), ErrKeyFile, "not a PEM private key"},
		"garbage":       {writeFile(t, filepath.Join(dir, "garbage.key"), []byte("not pem at all\n"), 0o600), ErrKeyFile, "not a PEM private key"},
		"garbage block": {writeFile(t, filepath.Join(dir, "block.key"), pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: []byte("junk")}), 0o600), ErrKeyFile, "not an OpenSSH private key"},
		"encrypted":     {sigtest.WriteEncryptedKeyFile(t, dir, "enc.key", ed, "correct horse"), ErrEncryptedKey, "load the key into ssh-agent; toolwarrant does not read passphrases"},
		"dsa":           {dsaKeyFile(t, dir), ErrKeyPolicy, "ssh-dss keys are refused"},
		"rsa 2048":      {sigtest.WriteKeyFile(t, dir, "rsa2048.key", sigtest.GenerateRSA(t, 2048)), ErrKeyPolicy, "2048 bits is below 3072"},
	}
	chmod(t, cases["mode 0644"].path, 0o644)
	chmod(t, cases["mode 0640"].path, 0o640)
	chmod(t, cases["mode 0604"].path, 0o604)
	for label, c := range cases {
		_, err := ReadPrivateKeyFile(c.path)
		wantErrIs(t, label, err, c.want, c.text)
		if err == nil {
			continue
		}
		for _, l := range keyBodyLines(t, good) {
			if strings.Contains(err.Error(), l) {
				t.Errorf("%s: the error carries a line of the key", label)
			}
		}
		if strings.Contains(err.Error(), base64.StdEncoding.EncodeToString(ed.Private.(interface{ Seed() []byte }).Seed())) {
			t.Errorf("%s: the error carries the seed", label)
		}
		if strings.Contains(err.Error(), "PRIVATE KEY") {
			t.Errorf("%s: the error carries the PEM marker, which no output may: %v", label, err)
		}
	}
}

// A closed key signs nothing: Sign after Close is refused by name for every
// key type, whether or not the type's secret could be cleared.
func TestKeyFile_ClosedKeySignsNothing(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for _, k := range []sigtest.Key{sigtest.GenerateEd25519(t), sigtest.GenerateECDSA(t, elliptic.P256())} {
		path := sigtest.WriteKeyFile(t, dir, k.Public.Type()+".key", k)
		key, err := ReadPrivateKeyFile(path)
		if err != nil {
			t.Fatal(err)
		}
		payload := mustMarshalDecision(t, sampleDecision(Fingerprint(k.Public)))
		if _, err := Sign(t.Context(), payload, key, NamespaceDecision); err != nil {
			t.Fatalf("%s: Sign before Close: %v", k.Public.Type(), err)
		}
		if err := key.Close(); err != nil {
			t.Fatal(err)
		}
		_, err = Sign(t.Context(), payload, key, NamespaceDecision)
		wantErrIs(t, k.Public.Type()+" after Close", err, ErrKeyClosed, "sign with "+Fingerprint(k.Public))
	}
}
