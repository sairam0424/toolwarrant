package signing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/sairam0424/toolwarrant/internal/signing/sigtest"
)

// rsaPublic makes an ssh-rsa public key of exactly bits without generating a
// private key: the policy reads the modulus size only.
func rsaPublic(t testing.TB, bits int) ssh.PublicKey {
	t.Helper()
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	n.Add(n, big.NewInt(1))
	pub, err := ssh.NewPublicKey(&rsa.PublicKey{N: n, E: 65537})
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// dsaP is a 1024-bit odd number standing in for a DSA prime: x/crypto reads
// an ssh-dss key only at 1024, 2048 or 3072 bits, and the policy refuses the
// type before any arithmetic, so no real parameters are needed.
func dsaP() *big.Int {
	return new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 1023), big.NewInt(1))
}

// dsaQ is the 160-bit sub-prime stand-in that goes with dsaP.
func dsaQ() *big.Int {
	return new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 159), big.NewInt(1))
}

// dsaPublic makes an ssh-dss public key from its wire form, which the parsers
// accept and the policy refuses; crypto/dsa itself is not imported.
func dsaPublic(t testing.TB) ssh.PublicKey {
	t.Helper()
	wire := ssh.Marshal(struct {
		Type       string
		P, Q, G, Y *big.Int
	}{"ssh-dss", dsaP(), dsaQ(), big.NewInt(4), big.NewInt(8)})
	pub, err := ssh.ParsePublicKey(wire)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// skEd25519Public builds an sk-ssh-ed25519@openssh.com key in wire form from
// an Ed25519 public key and the application string a FIDO2 key carries.
func skEd25519Public(t testing.TB) ssh.PublicKey {
	t.Helper()
	k := sigtest.GenerateEd25519(t)
	wire := ssh.Marshal(struct {
		Type        string
		KeyBytes    []byte
		Application string
	}{ssh.KeyAlgoSKED25519, k.Public.Marshal()[len(k.Public.Marshal())-32:], "ssh:"})
	pub, err := ssh.ParsePublicKey(wire)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// skECDSAPublic builds an sk-ecdsa-sha2-nistp256@openssh.com key in wire form.
func skECDSAPublic(t testing.TB) ssh.PublicKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	point, err := priv.PublicKey.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	wire := ssh.Marshal(struct {
		Type        string
		Curve       string
		KeyBytes    []byte
		Application string
	}{ssh.KeyAlgoSKECDSA256, "nistp256", point.Bytes(), "ssh:"})
	pub, err := ssh.ParsePublicKey(wire)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// certificate wraps a key in an OpenSSH certificate, a type the policy refuses.
func certificate(t testing.TB, k sigtest.Key) ssh.PublicKey {
	t.Helper()
	cert := &ssh.Certificate{Key: k.Public, CertType: ssh.UserCert, ValidBefore: ssh.CertTimeInfinity}
	if err := cert.SignCert(rand.Reader, k.Signer); err != nil {
		t.Fatal(err)
	}
	return cert
}

// The key policy accepts Ed25519, the three NIST curves, the two FIDO2 types
// and RSA from 3072 bits; it refuses ssh-dss, RSA-2048, certificates and nil.
func TestCheckKeyPolicy_RefusesDSAAndRSABelow3072AndAcceptsTheSKTypes(t *testing.T) {
	t.Parallel()
	ed := sigtest.GenerateEd25519(t)
	accepted := map[string]ssh.PublicKey{
		"ssh-ed25519":          ed.Public,
		"ecdsa-sha2-nistp256":  sigtest.GenerateECDSA(t, elliptic.P256()).Public,
		"ecdsa-sha2-nistp384":  sigtest.GenerateECDSA(t, elliptic.P384()).Public,
		"ecdsa-sha2-nistp521":  sigtest.GenerateECDSA(t, elliptic.P521()).Public,
		"sk-ssh-ed25519":       skEd25519Public(t),
		"sk-ecdsa-sha2-nistp2": skECDSAPublic(t),
		"ssh-rsa 3072":         rsaPublic(t, 3072),
		"ssh-rsa 4096":         rsaPublic(t, 4096),
	}
	for label, pub := range accepted {
		if err := CheckKeyPolicy(pub); err != nil {
			t.Errorf("%s refused: %v", label, err)
		}
	}
	refused := map[string]struct {
		pub  ssh.PublicKey
		want string
	}{
		"ssh-dss":      {dsaPublic(t), "ssh-dss keys are refused"},
		"ssh-rsa 2048": {rsaPublic(t, 2048), "ssh-rsa key of 2048 bits is below 3072"},
		"ssh-rsa 3071": {rsaPublic(t, 3071), "3071 bits is below 3072"},
		"certificate":  {certificate(t, ed), `key type "ssh-ed25519-cert-v01@openssh.com" is not one of`},
		"nil":          {nil, "no key"},
	}
	for label, c := range refused {
		err := CheckKeyPolicy(c.pub)
		wantErrIs(t, label, err, ErrKeyPolicy, c.want)
	}
	if !NeedsTouch(skEd25519Public(t)) || !NeedsTouch(skECDSAPublic(t)) || NeedsTouch(ed.Public) || NeedsTouch(nil) {
		t.Error("NeedsTouch is wrong for a key type")
	}
}

// Fingerprint prints what `ssh-keygen -l` prints for the same key.
func TestFingerprint_MatchesSshKeygen(t *testing.T) {
	t.Parallel()
	sshKeygen(t)
	dir := t.TempDir()
	for _, k := range []sigtest.Key{sigtest.GenerateEd25519(t), sigtest.GenerateECDSA(t, elliptic.P256())} {
		pub := sigtest.WritePublicKey(t, dir, k.Public.Type()+".pub", k)
		out, err := runSSHKeygen(t, dir, nil, nil, "-l", "-f", pub)
		if err != nil {
			t.Fatalf("ssh-keygen -l: %v", err)
		}
		if fp := Fingerprint(k.Public); !strings.Contains(out, " "+fp+" ") {
			t.Errorf("ssh-keygen -l printed %q, which does not carry %s", strings.TrimSpace(out), fp)
		}
		if !isFingerprint(Fingerprint(k.Public)) {
			t.Errorf("Fingerprint %q is not the shape the payload rules accept", Fingerprint(k.Public))
		}
	}
	for _, bad := range []string{"", "SHA256:", "MD5:aa:bb", "SHA256:" + strings.Repeat("A", 42), "SHA256:" + strings.Repeat("A", 44), "sha256:" + strings.Repeat("A", 43)} {
		if isFingerprint(bad) {
			t.Errorf("%q accepted as a fingerprint", bad)
		}
	}
	if err := os.Remove(filepath.Join(dir, "ssh-ed25519.pub")); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseAuthorizedKey("ssh-dss AAAA"); !errors.Is(err, ErrKeyLine) {
		t.Errorf("a short ssh-dss line: %v", err)
	}
}
