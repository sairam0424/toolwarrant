package signing

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/signing/sigtest"
)

// A KeySource whose path holds a public key (world-readable, with a comment,
// as ssh-keygen writes a .pub) signs through the agent at AuthSock; one whose
// path holds a private key signs from the file; a public key with no socket,
// with options, or not held by the agent is refused, and so is a shared
// private key even though it would parse.
func TestKeySource_PublicKeyPathSignsThroughTheAgentAndPrivateKeyPathSignsFromTheFile(t *testing.T) {
	t.Parallel()
	skipIfRoot(t)
	dir := t.TempDir()
	held, other := sigtest.GenerateEd25519(t), sigtest.GenerateEd25519(t)
	sock, add := sigtest.NewAgent(t)
	add(held)
	pub := sigtest.WritePublicKey(t, dir, "held.pub", held)
	priv := sigtest.WriteKeyFile(t, dir, "other.key", other)
	payload := mustMarshalDecision(t, sampleDecision(Fingerprint(held.Public)))

	viaAgent, err := KeySource{Path: pub, AuthSock: sock}.Open(t.Context())
	if err != nil {
		t.Fatalf("public key path with an agent: %v", err)
	}
	r, err := Sign(t.Context(), payload, viaAgent, NamespaceDecision)
	if err != nil || r.Signer != Fingerprint(held.Public) {
		t.Fatalf("Sign through the agent = %v, %v", r.Signer, err)
	}
	if err := viaAgent.Close(); err != nil {
		t.Error(err)
	}
	viaFile, err := KeySource{Path: priv}.Open(t.Context())
	if err != nil {
		t.Fatalf("private key path: %v", err)
	}
	r, err = Sign(t.Context(), payload, viaFile, NamespaceDecision)
	if err != nil || r.Signer != Fingerprint(other.Public) {
		t.Fatalf("Sign from the file = %v, %v", r.Signer, err)
	}
	_ = viaFile.Close()

	_, err = KeySource{Path: pub}.Open(t.Context())
	wantErrIs(t, "public key without a socket", err, ErrNoAgent, "SSH_AUTH_SOCK is not set (key "+Fingerprint(held.Public)+")")
	_, err = KeySource{Path: sigtest.WritePublicKey(t, dir, "other.pub", other), AuthSock: sock}.Open(t.Context())
	wantErrIs(t, "public key the agent does not hold", err, ErrKeyNotInAgent, Fingerprint(other.Public))
	options := writeFile(t, filepath.Join(dir, "options.pub"), []byte(`namespaces="git" `+MarshalKey(held.Public)+" c\n"), 0o644)
	_, err = KeySource{Path: options, AuthSock: sock}.Open(t.Context())
	wantErrIs(t, "public key with options", err, ErrKeyOptions, "")
	dsa := writeFile(t, filepath.Join(dir, "dsa.pub"), []byte(MarshalKey(dsaPublic(t))+"\n"), 0o644)
	_, err = KeySource{Path: dsa, AuthSock: sock}.Open(t.Context())
	wantErrIs(t, "weak public key", err, ErrKeyPolicy, "ssh-dss")
	shared := sigtest.WriteKeyFile(t, dir, "shared.key", other)
	chmod(t, shared, 0o644)
	_, err = KeySource{Path: shared}.Open(t.Context())
	wantErrIs(t, "shared private key", err, ErrKeyFile, "mode 0644")
	_, err = KeySource{}.Open(t.Context())
	wantErrIs(t, "no path", err, ErrKeyFile, "key path is empty")
	_, err = KeySource{Path: filepath.Join(dir, "none")}.Open(t.Context())
	wantErrIs(t, "missing path", err, ErrKeyFile, "")
	_, err = KeySource{Path: pub, AuthSock: filepath.Join(dir, "no.sock")}.Open(t.Context())
	wantErrIs(t, "public key with a missing socket", err, ErrAgentSocket, "")
}

// No refusal of a key source carries private material: not a line of the key
// file, not the seed, not the word PRIVATE KEY from a body; the only key text
// an error holds is a SHA256: fingerprint.
func TestKeySource_NeverPrintsPrivateMaterialInAnError(t *testing.T) {
	t.Parallel()
	skipIfRoot(t)
	dir := t.TempDir()
	ed := sigtest.GenerateEd25519(t)
	rsa := sigtest.GenerateRSA(t, 2048)
	sock, _ := sigtest.NewAgent(t)
	sources := map[string]KeySource{
		"encrypted":     {Path: sigtest.WriteEncryptedKeyFile(t, dir, "enc.key", ed, "pass")},
		"shared":        {Path: sigtest.WriteKeyFile(t, dir, "shared.key", ed)},
		"rsa 2048":      {Path: sigtest.WriteKeyFile(t, dir, "rsa.key", rsa)},
		"dsa":           {Path: dsaKeyFile(t, dir)},
		"two blocks":    {Path: filepath.Join(dir, "two.key")},
		"not in agent":  {Path: sigtest.WritePublicKey(t, dir, "ed.pub", ed), AuthSock: sock},
		"no agent":      {Path: sigtest.WritePublicKey(t, dir, "ed2.pub", ed)},
		"garbage block": {Path: filepath.Join(dir, "block.key")},
	}
	chmod(t, sources["shared"].Path, 0o644)
	edBytes, err := os.ReadFile(sigtest.WriteKeyFile(t, dir, "ed.key", ed))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, sources["two blocks"].Path, append(append([]byte{}, edBytes...), edBytes...), 0o600)
	writeFile(t, sources["garbage block"].Path, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n"+strings.Repeat("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=", 3)+"\n-----END OPENSSH PRIVATE KEY-----\n"), 0o600)
	secrets := keyBodyLines(t, filepath.Join(dir, "ed.key"))
	secrets = append(secrets, keyBodyLines(t, sources["rsa 2048"].Path)...)
	secrets = append(secrets, keyBodyLines(t, sources["encrypted"].Path)...)
	for label, src := range sources {
		_, err := src.Open(t.Context())
		if err == nil {
			t.Errorf("%s: opened", label)
			continue
		}
		msg := err.Error()
		for _, s := range secrets {
			if strings.Contains(msg, s) {
				t.Errorf("%s: the error carries a line of a key: %s", label, msg)
			}
		}
		if strings.Contains(msg, "QUJDREVG") {
			t.Errorf("%s: the error echoes the file body: %s", label, msg)
		}
		if n := strings.Count(msg, "SHA256:"); n > 1 {
			t.Errorf("%s: the error names %d fingerprints: %s", label, n, msg)
		}
		if errors.Is(err, ErrKeyNotInAgent) && !strings.Contains(msg, Fingerprint(ed.Public)) {
			t.Errorf("%s: the refusal does not name the key by fingerprint: %s", label, msg)
		}
	}
}
