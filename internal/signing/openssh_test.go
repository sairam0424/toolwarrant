package signing

import (
	"crypto/elliptic"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/signing/sigtest"
)

// The interop tests run against the host's ssh-keygen (OpenSSH 10.3p1 here,
// OpenSSH on the ubuntu runners) and skip with the reason where there is
// none. They are the proof that an auditor with stock OpenSSH re-verifies a
// toolwarrant record and that a record OpenSSH made verifies here.

// interopKeys are the key types both sides exchange: Ed25519, ECDSA P-256 and
// RSA at the smallest accepted size.
func interopKeys(t testing.TB) map[string]sigtest.Key {
	t.Helper()
	return map[string]sigtest.Key{
		"ed25519":  sigtest.GenerateEd25519(t),
		"ecdsa256": sigtest.GenerateECDSA(t, elliptic.P256()),
		"rsa3072":  sigtest.GenerateRSA(t, MinRSABits),
	}
}

// A signature Sign made, armored, passes `ssh-keygen -Y verify` under the
// decision namespace with the signer's key in allowed_signers, and fails under
// `-n git`, for every key type; and both readers refuse the same armored file
// with text before the header, ssh-keygen with "missing header".
func TestSign_ProducesASignatureSshKeygenVerifiesUnderTheNamespace(t *testing.T) {
	t.Parallel()
	sshKeygen(t)
	for label, k := range interopKeys(t) {
		dir := t.TempDir()
		payload := mustMarshalDecision(t, sampleDecision(Fingerprint(k.Public)))
		r := mustSign(t, payload, k, NamespaceDecision)
		armored, err := Armor(r.Signature)
		if err != nil {
			t.Fatal(err)
		}
		sig := writeFile(t, filepath.Join(dir, "decision.sig"), armored, 0o600)
		allowed := writeAllowedSigners(t, dir, sampleActor, k)
		out, err := runSSHKeygen(t, dir, payload, nil, "-Y", "verify", "-f", allowed, "-I", sampleActor, "-n", string(NamespaceDecision), "-s", sig)
		if err != nil || !strings.Contains(out, "Good \"decision@toolwarrant.invalid\" signature for alice") {
			t.Errorf("%s: ssh-keygen -Y verify = %v: %s", label, err, out)
		}
		if _, err := runSSHKeygen(t, dir, payload, nil, "-Y", "verify", "-f", allowed, "-I", sampleActor, "-n", "git", "-s", sig); err == nil {
			t.Errorf("%s: ssh-keygen -Y verify accepted the signature under -n git", label)
		}
		if _, err := runSSHKeygen(t, dir, payload, nil, "-Y", "verify", "-f", allowed, "-I", "bob", "-n", string(NamespaceDecision), "-s", sig); err == nil {
			t.Errorf("%s: ssh-keygen -Y verify accepted the signature for a principal the file does not name", label)
		}
		if _, err := runSSHKeygen(t, dir, flipByte(payload, 0), nil, "-Y", "verify", "-f", allowed, "-I", sampleActor, "-n", string(NamespaceDecision), "-s", sig); err == nil {
			t.Errorf("%s: ssh-keygen -Y verify accepted a changed payload", label)
		}
		if _, err := runSSHKeygen(t, dir, payload, nil, "-Y", "check-novalidate", "-n", string(NamespaceDecision), "-s", sig); err != nil {
			t.Errorf("%s: ssh-keygen -Y check-novalidate: %v", label, err)
		}
		prefixed := append([]byte("junk\n"), armored...)
		junk := writeFile(t, filepath.Join(dir, "junk.sig"), prefixed, 0o600)
		out, err = runSSHKeygen(t, dir, payload, nil, "-Y", "check-novalidate", "-n", string(NamespaceDecision), "-s", junk)
		if err == nil || !strings.Contains(out, "missing header") {
			t.Errorf("%s: ssh-keygen -Y check-novalidate read past text before the header: %v: %s", label, err, out)
		}
		_, err = Unarmor(prefixed)
		wantErrIs(t, label+": Unarmor of text before the header, which ssh-keygen refuses", err, ErrSignatureFormat, "")
	}
}

// A signature `ssh-keygen -Y sign` made from a key file verifies here under
// the decision namespace and under no other, and one made under `-n git` is
// refused as a namespace mismatch, for every key type.
func TestVerify_AcceptsASignatureSshKeygenMadeAndRefusesItUnderAnotherNamespace(t *testing.T) {
	t.Parallel()
	sshKeygen(t)
	for label, k := range interopKeys(t) {
		dir := t.TempDir()
		keyFile := sigtest.WriteKeyFile(t, dir, "id", k)
		sigtest.WritePublicKey(t, dir, "id.pub", k)
		payload := mustMarshalDecision(t, sampleDecision(Fingerprint(k.Public)))
		msg := writeFile(t, filepath.Join(dir, "decision.json"), payload, 0o600)
		if _, err := runSSHKeygen(t, dir, nil, nil, "-Y", "sign", "-n", string(NamespaceDecision), "-f", keyFile, msg); err != nil {
			t.Fatalf("%s: ssh-keygen -Y sign: %v", label, err)
		}
		blob := unarmorFile(t, msg+".sig")
		pub, err := Verify(payload, blob, NamespaceDecision, Fingerprint(k.Public))
		if err != nil || Fingerprint(pub) != Fingerprint(k.Public) {
			t.Errorf("%s: Verify of ssh-keygen's signature = %v, %v", label, pub, err)
		}
		_, err = Verify(payload, blob, NamespaceTrust, Fingerprint(k.Public))
		wantErrIs(t, label+" under the trust namespace", err, ErrNamespaceMismatch, "")
		_, err = Verify(flipByte(payload, 0), blob, NamespaceDecision, Fingerprint(k.Public))
		wantErrIs(t, label+" over a changed payload", err, ErrSignature, "")
		if err := os.Remove(msg + ".sig"); err != nil {
			t.Fatal(err)
		}
		if _, err := runSSHKeygen(t, dir, nil, nil, "-Y", "sign", "-n", "git", "-f", keyFile, msg); err != nil {
			t.Fatalf("%s: ssh-keygen -Y sign -n git: %v", label, err)
		}
		_, err = Verify(payload, unarmorFile(t, msg+".sig"), NamespaceDecision, Fingerprint(k.Public))
		wantErrIs(t, label+" git signature as a decision", err, ErrNamespaceMismatch, `"git"`)
	}
}

// unarmorFile reads an armored signature file into its wire blob.
func unarmorFile(t testing.TB, path string) []byte {
	t.Helper()
	armored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := Unarmor(armored)
	if err != nil {
		t.Fatalf("Unarmor of %s: %v", filepath.Base(path), err)
	}
	return blob
}

// The round trip the CHANGELOG names, through the agent in both directions:
// ssh-keygen signs with `-f id.pub` against the in-process agent (its
// SSH_AUTH_SOCK is the child's environment, never this process's) and Verify
// accepts it; Sign through the same agent produces a signature ssh-keygen
// verifies; and the two signatures are over the same bytes under the same
// namespace, so each side's output satisfies the other's verifier.
func TestOpenSSH_SignatureVerifiesWithSshKeygenAndTheReverse(t *testing.T) {
	t.Parallel()
	sshKeygen(t)
	k := sigtest.GenerateEd25519(t)
	sock, add := sigtest.NewAgent(t)
	add(k)
	dir := t.TempDir()
	pubFile := sigtest.WritePublicKey(t, dir, "id.pub", k)
	payload := mustMarshalDecision(t, sampleDecision(Fingerprint(k.Public)))
	msg := writeFile(t, filepath.Join(dir, "decision.json"), payload, 0o600)
	env := []string{"SSH_AUTH_SOCK=" + sock}

	if _, err := runSSHKeygen(t, dir, nil, env, "-Y", "sign", "-n", string(NamespaceDecision), "-f", pubFile, msg); err != nil {
		t.Fatalf("ssh-keygen -Y sign through the agent: %v", err)
	}
	theirs := unarmorFile(t, msg+".sig")
	if _, err := Verify(payload, theirs, NamespaceDecision, Fingerprint(k.Public)); err != nil {
		t.Errorf("Verify of ssh-keygen's agent signature: %v", err)
	}

	a, err := OpenAgent(t.Context(), sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	key, err := a.SignerFor(k.Public)
	if err != nil {
		t.Fatal(err)
	}
	ours, err := Sign(t.Context(), payload, key, NamespaceDecision)
	if err != nil {
		t.Fatalf("Sign through the agent: %v", err)
	}
	armored, err := Armor(ours.Signature)
	if err != nil {
		t.Fatal(err)
	}
	ourSig := writeFile(t, filepath.Join(dir, "ours.sig"), armored, 0o600)
	allowed := writeAllowedSigners(t, dir, sampleActor, k)
	out, err := runSSHKeygen(t, dir, payload, nil, "-Y", "verify", "-f", allowed, "-I", sampleActor, "-n", string(NamespaceDecision), "-s", ourSig)
	if err != nil || !strings.Contains(out, "Good \"decision@toolwarrant.invalid\" signature for alice with ED25519 key "+Fingerprint(k.Public)) {
		t.Errorf("ssh-keygen -Y verify of our signature = %v: %s", err, out)
	}
	if _, err := runSSHKeygen(t, dir, payload, nil, "-Y", "verify", "-f", allowed, "-I", sampleActor, "-n", string(NamespaceDecision), "-s", msg+".sig"); err != nil {
		t.Errorf("ssh-keygen -Y verify of its own signature: %v", err)
	}
	if _, err := Verify(payload, theirs, NamespaceDecision, Fingerprint(k.Public)); err != nil {
		t.Errorf("Verify of ssh-keygen's signature after our own: %v", err)
	}
}
