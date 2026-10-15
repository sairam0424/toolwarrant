package trust

import (
	"crypto/elliptic"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/signing"
	"github.com/sairam0424/toolwarrant/internal/signing/sigtest"
)

// AllowedSigners renders one line per key, in list order, each
// `NAME namespaces="decision@toolwarrant.invalid,trust@toolwarrant.invalid" TYPE BASE64`,
// and the file is one stock ssh-keygen reads: a decision Sign made under the
// decision namespace and a list under the trust namespace each verify with
// `-Y verify -f FILE -I NAME -n NAMESPACE` for the key's own principal, for an
// Ed25519, an ECDSA P-256 and an RSA-3072 key; `-Y find-principals` names the
// principal; the same signature is refused under `-n git`, for another listed
// principal, and over a changed payload. Skips with the reason where there is
// no ssh-keygen (this host has OpenSSH 10.3p1).
func TestAllowedSigners_RendersOneLinePerKeyWithBothNamespacesAndSshKeygenAcceptsIt(t *testing.T) {
	t.Parallel()
	sshKeygen(t)
	ops := []named{
		{"alice", sigtest.GenerateEd25519(t)},
		{"bob", sigtest.GenerateECDSA(t, elliptic.P256())},
		{"carol", sigtest.GenerateRSA(t, signing.MinRSABits)},
	}
	r := mustValidate(t, listOf(1, ops...))
	file, err := AllowedSigners(r)
	if err != nil {
		t.Fatal(err)
	}
	var want strings.Builder
	for _, op := range ops {
		want.WriteString(op.name + ` namespaces="decision@toolwarrant.invalid,trust@toolwarrant.invalid" ` + signing.MarshalKey(op.key.Public) + "\n")
	}
	if string(file) != want.String() {
		t.Fatalf("AllowedSigners =\n%s\nwant\n%s", file, want.String())
	}
	dir := t.TempDir()
	allowed := writeFile(t, filepath.Join(dir, "allowed_signers"), file, 0o600)
	decision, list := samplePayloads(t, r, ops[0].key)
	for _, op := range ops {
		verifyWithSSHKeygen(t, dir, allowed, op, decision, signing.NamespaceDecision)
		verifyWithSSHKeygen(t, dir, allowed, op, list, signing.NamespaceTrust)
	}
}

// samplePayloads marshals a decision by alice and the list r came from,
// signed by key, as the two payload kinds the file must cover.
func samplePayloads(t testing.TB, r Record, key sigtest.Key) (decision, list []byte) {
	t.Helper()
	d := signing.Decision{
		Actor: r.Signers[0].Name, Catalog: sampleCatalog, Digest: sampleDigest, Kind: signing.KindApprove,
		PrevHead: samplePrevHead, Server: "mock", SignedAt: sampleTime(), Signer: fp(key), Tool: "echo",
	}
	decision, err := signing.MarshalDecision(d)
	if err != nil {
		t.Fatal(err)
	}
	signers := make([]signing.Signer, 0, len(r.Signers))
	for _, op := range r.Signers {
		signers = append(signers, signing.Signer{Key: op.Key, Name: op.Name})
	}
	list, err = signing.MarshalTrustList(signing.TrustList{
		Catalog: sampleCatalog, PrevHead: samplePrevHead, SignedAt: sampleTime(),
		Signer: fp(key), Signers: signers, Threshold: r.Threshold, Version: r.Version,
	})
	if err != nil {
		t.Fatal(err)
	}
	return decision, list
}

// verifyWithSSHKeygen signs payload with op's key under ns through Sign,
// armors it and drives ssh-keygen over the rendered file.
func verifyWithSSHKeygen(t testing.TB, dir, allowed string, op named, payload []byte, ns signing.Namespace) {
	t.Helper()
	label := op.name + " under " + string(ns)
	rec, err := signing.Sign(t.Context(), payload, op.key.Signer, ns)
	if err != nil {
		t.Fatalf("%s: Sign: %v", label, err)
	}
	armored, err := signing.Armor(rec.Signature)
	if err != nil {
		t.Fatal(err)
	}
	sig := writeFile(t, filepath.Join(dir, op.name+"-"+strings.Split(string(ns), "@")[0]+".sig"), armored, 0o600)
	out, err := runSSHKeygen(t, dir, payload, "-Y", "verify", "-f", allowed, "-I", op.name, "-n", string(ns), "-s", sig)
	if err != nil || !strings.Contains(out, `Good "`+string(ns)+`" signature for `+op.name) {
		t.Errorf("%s: ssh-keygen -Y verify = %v: %s", label, err, out)
	}
	out, err = runSSHKeygen(t, dir, nil, "-Y", "find-principals", "-f", allowed, "-s", sig)
	if err != nil || strings.TrimSpace(out) != op.name {
		t.Errorf("%s: ssh-keygen -Y find-principals = %v: %q", label, err, out)
	}
	if _, err := runSSHKeygen(t, dir, payload, "-Y", "verify", "-f", allowed, "-I", op.name, "-n", "git", "-s", sig); err == nil {
		t.Errorf("%s: ssh-keygen -Y verify accepted the signature under -n git", label)
	}
	other := "alice"
	if op.name == other {
		other = "bob"
	}
	if _, err := runSSHKeygen(t, dir, payload, "-Y", "verify", "-f", allowed, "-I", other, "-n", string(ns), "-s", sig); err == nil {
		t.Errorf("%s: ssh-keygen -Y verify accepted the signature for %s, another listed principal", label, other)
	}
	changed := append([]byte{}, payload...)
	changed[0] ^= 0x01
	if _, err := runSSHKeygen(t, dir, changed, "-Y", "verify", "-f", allowed, "-I", op.name, "-n", string(ns), "-s", sig); err == nil {
		t.Errorf("%s: ssh-keygen -Y verify accepted a changed payload", label)
	}
}
