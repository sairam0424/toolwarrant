package export

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The signing key is read from a path only, and only when the file is a
// regular one that nobody else can read and holds exactly one PKCS#8 Ed25519
// key; every other shape is refused before anything is exported (D21 e). The
// refusal names the shape, never the key.
func TestReadSigningKey_RefusesEveryUnsafeShape(t *testing.T) {
	skipIfRoot(t)
	pub, priv := newSigningKey(t)
	dir := t.TempDir()
	good := writeSigningKey(t, dir, priv)
	key, err := ReadSigningKey(good)
	if err != nil || !key.Public().(ed25519.PublicKey).Equal(pub) {
		t.Fatalf("ReadSigningKey on an owner-only PKCS#8 key = %v, want the key", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.key")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	two := writeKeyFile(t, filepath.Join(dir, "two.key"), pemPrivateKeyType, der, 0o600)
	writeFile(t, two, readFile(t, two)+readFile(t, two))
	garbage := filepath.Join(dir, "garbage.key")
	writeFile(t, garbage, "not pem at all")
	if err := os.Chmod(garbage, 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		path string
		want string
	}{
		"mode 0644":          {writeKeyFile(t, filepath.Join(dir, "shared.key"), pemPrivateKeyType, der, 0o644), "readable by other users (mode 0644)"},
		"mode 0640":          {writeKeyFile(t, filepath.Join(dir, "group.key"), pemPrivateKeyType, der, 0o640), "readable by other users (mode 0640)"},
		"mode 0604":          {writeKeyFile(t, filepath.Join(dir, "other.key"), pemPrivateKeyType, der, 0o604), "readable by other users (mode 0604)"},
		"symlink":            {link, "symbolic link"},
		"directory":          {dir, "is a directory"},
		"missing":            {filepath.Join(dir, "none.key"), "no such file"},
		"public key as key":  {writeKeyFile(t, filepath.Join(dir, "pub.key"), pemPublicKeyType, pubDER, 0o600), "not a PEM PRIVATE KEY block (PKCS#8)"},
		"not pem":            {garbage, "not a PEM PRIVATE KEY block (PKCS#8)"},
		"garbage der":        {writeKeyFile(t, filepath.Join(dir, "der.key"), pemPrivateKeyType, []byte("junk"), 0o600), "not a PKCS#8 private key"},
		"ecdsa pkcs8":        {writeKeyFile(t, filepath.Join(dir, "ec.key"), pemPrivateKeyType, newECDSAKeyDER(t), 0o600), "not an Ed25519 key"},
		"two pem blocks":     {two, "more than one PEM block"},
		"empty path":         {"", "path is empty"},
		"regular file 0600+": {good, ""},
	}
	for label, c := range cases {
		_, err := ReadSigningKey(c.path)
		if c.want == "" {
			if err != nil {
				t.Errorf("%s: %v", label, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %v, want one naming %q", label, err, c.want)
		}
		if err != nil && strings.Contains(err.Error(), base64.StdEncoding.EncodeToString(priv.Seed())) {
			t.Errorf("%s: the error carries key material", label)
		}
	}
}

// A signed Write leaves the signature and the public key beside the manifest,
// the signature verifies over the manifest's exact bytes, a second identical
// Write touches nothing, and a moved head re-signs.
func TestWrite_SignsTheManifestAndASecondWriteTouchesNothing(t *testing.T) {
	pub, priv := newSigningKey(t)
	dir := t.TempDir()
	tools := []Tool{mkTool(t, "s", "a", "1"), mkTool(t, "t", "b", "2")}
	mustWriteWith(t, dir, signedOpts(priv), tools...)
	snap := snapshot(t, dir)
	for _, name := range []string{signatureName, publicKeyName} {
		e, ok := snap[name]
		if !ok {
			t.Fatalf("%s was not written; files: %v", name, names(snap))
		}
		if e.Mode != 0o644 {
			t.Errorf("%s mode = %v, want 0644", name, e.Mode)
		}
	}
	recorded, err := ParsePublicKey([]byte(snap[publicKeyName].Content))
	if err != nil || !recorded.Equal(pub) {
		t.Fatalf("%s = %v, %v; want the signer's key", publicKeyName, recorded, err)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(snap[signatureName].Content, "\n"))
	if err != nil || !ed25519.Verify(pub, []byte(snap[manifestName].Content), sig) {
		t.Fatalf("%s does not verify over the manifest bytes: %v", signatureName, err)
	}

	mustWriteWith(t, dir, signedOpts(priv), tools...)
	if again := snapshot(t, dir); len(again) != len(snap) {
		t.Fatalf("files changed on a repeat: %v -> %v", names(snap), names(again))
	} else {
		for p, e := range snap {
			if again[p] != e {
				t.Errorf("%s changed on a repeat Write: %+v -> %+v", p, e, again[p])
			}
		}
	}

	moved := signedOpts(priv)
	moved.AuditHead = otherHead
	mustWriteWith(t, dir, moved, tools...)
	after := snapshot(t, dir)
	if after[signatureName].Content == snap[signatureName].Content {
		t.Error("the signature did not change although the manifest did")
	}
	if after[publicKeyName] != snap[publicKeyName] {
		t.Error("the public key file changed although the key did not")
	}
	if rep := mustVerify(t, dir, pub, otherHead); rep.Files != 2 || rep.Version != 3 || rep.AuditHead != otherHead || rep.DigestProfile != testProfile {
		t.Fatalf("Verify after the move = %+v", rep)
	}
}

// A Write without a key never touches the two signature files: a signature
// from an earlier run stays beside the newer manifest, and Verify refuses the
// pair instead of passing a stale signature.
func TestWrite_WithoutAKeyLeavesTheSignatureFilesAloneAndVerifyRefusesThem(t *testing.T) {
	pub, priv := newSigningKey(t)
	dir := t.TempDir()
	tool := mkTool(t, "s", "a", "1")
	mustWriteWith(t, dir, signedOpts(priv), tool)
	signed := snapshot(t, dir)
	mustWriteWith(t, dir, headOpts(otherHead), tool)
	after := snapshot(t, dir)
	for _, name := range []string{signatureName, publicKeyName} {
		if after[name] != signed[name] {
			t.Errorf("%s was touched by an unsigned Write", name)
		}
	}
	wantVerifyError(t, dir, pub, "", signatureName+" is not a signature over "+manifestName)
	mustWriteWith(t, dir, signedOpts(priv), tool)
	mustVerify(t, dir, pub, testHead)
}

// Commit stages the signature and the public key beside the manifest, and
// refuses a signature that does not sign the current manifest or one file
// without the other, so the history never records a signature over an older
// manifest as if it covered the files beside it.
func TestCommit_StagesTheSignatureFilesAndRefusesAStalePair(t *testing.T) {
	requireGit(t)
	_, priv := newSigningKey(t)
	dir := filepath.Join(t.TempDir(), "approved")
	tool := mkTool(t, "s", "one", "v1")
	mustWriteWith(t, dir, signedOpts(priv), tool)
	if !mustCommit(t, dir, "export: signed") {
		t.Fatal("first commit must report committed=true")
	}
	if got := git(t, dir, "ls-files"); got != "MANIFEST.json\nMANIFEST.json.pub\nMANIFEST.json.sig\ns/one.json" {
		t.Fatalf("tracked files = %q", got)
	}

	mustWriteWith(t, dir, headOpts(otherHead), tool)
	_, err := Commit(bgCtx(), dir, "export: unsigned after signed", alice)
	if err == nil || !strings.Contains(err.Error(), "does not sign the current "+manifestName) {
		t.Fatalf("Commit with a stale signature = %v, want a refusal naming it", err)
	}
	if got := commitCount(t, dir); got != 1 {
		t.Fatalf("commits = %d after the refusal, want 1", got)
	}

	if err := os.Remove(filepath.Join(dir, publicKeyName)); err != nil {
		t.Fatal(err)
	}
	_, err = Commit(bgCtx(), dir, "export: one file", alice)
	if err == nil || !strings.Contains(err.Error(), "go together") {
		t.Fatalf("Commit with the signature alone = %v, want a refusal", err)
	}
	if err := os.Remove(filepath.Join(dir, signatureName)); err != nil {
		t.Fatal(err)
	}
	if !mustCommit(t, dir, "export: unsigned") {
		t.Fatal("an unsigned export with both files gone commits")
	}
	if got := git(t, dir, "ls-files"); got != "MANIFEST.json\ns/one.json" {
		t.Fatalf("tracked files after the unsigned commit = %q", got)
	}

	moved := signedOpts(priv)
	moved.AuditHead = otherHead
	mustWriteWith(t, dir, moved, tool)
	if !mustCommit(t, dir, "export: signed again") {
		t.Fatal("a re-signed export commits")
	}
	if got := git(t, dir, "ls-files"); !strings.Contains(got, signatureName) || !strings.Contains(got, publicKeyName) {
		t.Fatalf("tracked files after re-signing = %q", got)
	}
}
