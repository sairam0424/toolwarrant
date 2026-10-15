package export

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// bgCtx is the context of tests that do not care about cancellation.
func bgCtx() context.Context { return context.Background() }

// signedExport writes two tools of two servers, signed with a fresh key, and
// returns the directory with the signer's public key.
func signedExport(t *testing.T) (string, ed25519.PublicKey) {
	t.Helper()
	pub, priv := newSigningKey(t)
	dir := filepath.Join(t.TempDir(), "approved")
	mustWriteWith(t, dir, signedOpts(priv), mkTool(t, "s", "a", "1"), mkTool(t, "t", "b", "2"))
	return dir, pub
}

// flipByte changes one byte of the file at p.
func flipByte(t *testing.T, p string, at int) {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	b[at] ^= 1
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// swapBase64Char replaces the base64 character at offset i of the file with
// another character of the standard alphabet, so the text still decodes and
// the signature it decodes to is a different one. flipByte would do for a
// tool file, but a flipped bit in base64 text may leave the alphabet, and
// then Verify refuses the text as not base64 before it checks the signature
// (the ci run 38691818349 of 2026-10-15 saw that message instead).
func swapBase64Char(t *testing.T, path string, i int) {
	t.Helper()
	b := []byte(readFile(t, path))
	if i >= len(b) {
		t.Fatalf("%s is %d bytes, no byte %d", path, len(b), i)
	}
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	writeFile(t, path, string(b))
}

// The round trip: a signed export verifies with the signer's public key, with
// and without the recorded head, and the report says what was checked.
func TestVerify_RoundTripsASignedExport(t *testing.T) {
	dir, pub := signedExport(t)
	rep := mustVerify(t, dir, pub, "")
	if rep != (VerifyReport{Version: 3, Files: 2, AuditHead: testHead, DigestProfile: testProfile}) {
		t.Fatalf("Verify = %+v", rep)
	}
	mustVerify(t, dir, pub, testHead)
	mustVerify(t, dir, pub, strings.ToUpper(testHead))
	wantVerifyError(t, dir, pub, otherHead, "audit head mismatch", testHead, otherHead)
	wantVerifyError(t, dir, pub, "not-a-head", "expected audit head is not a hex sha256")
	// The repository Commit keeps is not an extra entry.
	if err := os.Mkdir(filepath.Join(dir, gitDirName), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, gitDirName, "HEAD"), "ref: refs/heads/main\n")
	mustVerify(t, dir, pub, testHead)
}

// Every way the directory can disagree with the signed manifest fails closed
// with a message that names what was found: a flipped byte, a missing, extra,
// renamed or nested entry, a symlink, a wrong key, an edited manifest or
// signature, an unsigned or unfinished export, and a directory that is not one.
func TestVerify_FailsClosedOnEveryTamper(t *testing.T) {
	otherPub, _ := newSigningKey(t)
	cases := map[string]struct {
		tamper func(t *testing.T, dir string)
		pub    ed25519.PublicKey // nil means the signer's
		want   []string
	}{
		"flipped byte in a tool file": {func(t *testing.T, dir string) { flipByte(t, filepath.Join(dir, "s", "a.json"), 3) }, nil, []string{`"s/a.json"`, "does not hash to its digest"}},
		"missing tool file":           {func(t *testing.T, dir string) { mustRemove(t, filepath.Join(dir, "t", "b.json")) }, nil, []string{`"t/b.json"`, "listed in MANIFEST.json but missing"}},
		"extra file at the top":       {func(t *testing.T, dir string) { writeFile(t, filepath.Join(dir, "notes.txt"), "x") }, nil, []string{"1 entry not listed in MANIFEST.json", `"notes.txt"`}},
		"extra file in a server dir":  {func(t *testing.T, dir string) { writeFile(t, filepath.Join(dir, "s", "c.json"), "{}\n") }, nil, []string{"not listed", `"s/c.json"`}},
		"renamed tool file": {func(t *testing.T, dir string) {
			mustRename(t, filepath.Join(dir, "s", "a.json"), filepath.Join(dir, "s", "A.json.bak"))
		}, nil, []string{`"s/a.json"`, "missing"}},
		"extra directory":  {func(t *testing.T, dir string) { mustMkdir(t, filepath.Join(dir, "u")) }, nil, []string{"not listed", `"u"`}},
		"nested directory": {func(t *testing.T, dir string) { mustMkdir(t, filepath.Join(dir, "s", "deep")) }, nil, []string{"not listed", `"s/deep"`}},
		"symlink inside": {func(t *testing.T, dir string) {
			mustSymlink(t, filepath.Join(dir, "s", "a.json"), filepath.Join(dir, "s", "link.json"))
		}, nil, []string{`"s/link.json"`, "symlink"}},
		"tool file without newline": {func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "s", "a.json"), strings.TrimSuffix(readFile(t, filepath.Join(dir, "s", "a.json")), "\n"))
		}, nil, []string{`"s/a.json"`, "newline"}},
		"wrong public key": {func(*testing.T, string) {}, otherPub, []string{publicKeyName + " records another public key"}},
		"recorded key swapped": {func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, publicKeyName), string(mustPKIX(t, otherPub)))
		}, nil, []string{publicKeyName + " records another public key"}},
		"edited manifest":    {func(t *testing.T, dir string) { editHead(t, dir) }, nil, []string{signatureName + " is not a signature over " + manifestName}},
		"edited signature":   {func(t *testing.T, dir string) { swapBase64Char(t, filepath.Join(dir, signatureName), 10) }, nil, []string{signatureName + " is not a signature over"}},
		"garbage signature":  {func(t *testing.T, dir string) { writeFile(t, filepath.Join(dir, signatureName), "***\n") }, nil, []string{"does not hold a base64 Ed25519 signature"}},
		"signature missing":  {func(t *testing.T, dir string) { mustRemove(t, filepath.Join(dir, signatureName)) }, nil, []string{signatureName + " not found", "export --sign-key"}},
		"public key missing": {func(t *testing.T, dir string) { mustRemove(t, filepath.Join(dir, publicKeyName)) }, nil, []string{publicKeyName + " not found"}},
		"signature is a directory": {func(t *testing.T, dir string) {
			mustRemove(t, filepath.Join(dir, signatureName))
			mustMkdir(t, filepath.Join(dir, signatureName))
		}, nil, []string{signatureName, "not a regular file"}},
		"pending manifest":       {func(t *testing.T, dir string) { markPending(t, dir) }, nil, []string{"is pending"}},
		"manifest missing":       {func(t *testing.T, dir string) { mustRemove(t, filepath.Join(dir, manifestName)) }, nil, []string{manifestName + " not found"}},
		"manifest not ours":      {func(t *testing.T, dir string) { writeFile(t, filepath.Join(dir, manifestName), `{"version":9}`) }, nil, []string{"not a manifest this version reads"}},
		"directory is a symlink": {func(t *testing.T, dir string) { mustRename(t, dir, dir+".real"); mustSymlink(t, dir+".real", dir) }, nil, []string{"directory is a symlink"}},
		"directory missing":      {func(t *testing.T, dir string) { mustRemoveAll(t, dir) }, nil, []string{"stat directory"}},
	}
	for label, c := range cases {
		t.Run(label, func(t *testing.T) {
			dir, pub := signedExport(t)
			mustVerify(t, dir, pub, testHead)
			c.tamper(t, dir)
			if c.pub != nil {
				pub = c.pub
			}
			wantVerifyError(t, dir, pub, "", c.want...)
		})
	}
}

// A version 2 manifest from the previous release, signed by hand, verifies by
// signature and files but carries no head, so an expectation fails.
func TestVerify_ReadsAVersionTwoManifestWithoutAHead(t *testing.T) {
	pub, priv := newSigningKey(t)
	dir := t.TempDir()
	tool := mkTool(t, "s", "a", "1")
	mustWrite(t, dir, tool)
	raw := readFile(t, filepath.Join(dir, manifestName))
	v2 := strings.Replace(raw, `"version": 3,`, `"version": 2,`, 1)
	v2 = strings.Replace(v2, `  "audit_head": "`+testHead+`",`+"\n", "", 1)
	v2 = strings.Replace(v2, `  "digest_profile": "`+testProfile+`",`+"\n", "", 1)
	writeFile(t, filepath.Join(dir, manifestName), v2)
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := signManifest(root, []byte(v2), priv); err != nil {
		t.Fatal(err)
	}
	if rep := mustVerify(t, dir, pub, ""); rep != (VerifyReport{Version: 2, Files: 1}) {
		t.Fatalf("Verify of a version 2 export = %+v", rep)
	}
	wantVerifyError(t, dir, pub, testHead, "version 2", "no audit head")
}

// The public key a verifier holds must be an Ed25519 key of the right size.
func TestVerify_RefusesAKeyOfTheWrongSize(t *testing.T) {
	dir, _ := signedExport(t)
	wantVerifyError(t, dir, ed25519.PublicKey(make([]byte, 16)), "", "not an Ed25519 key")
}

func mustRemove(t *testing.T, p string) {
	t.Helper()
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
}

func mustRemoveAll(t *testing.T, p string) {
	t.Helper()
	if err := os.RemoveAll(p); err != nil {
		t.Fatal(err)
	}
}

func mustRename(t *testing.T, from, to string) {
	t.Helper()
	if err := os.Rename(from, to); err != nil {
		t.Fatal(err)
	}
}

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.Mkdir(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

// mustPKIX renders pub as the PEM MANIFEST.json.pub holds.
func mustPKIX(t *testing.T, pub ed25519.PublicKey) []byte {
	t.Helper()
	data, err := encodePublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// editHead changes one digit of the audit head inside the manifest, keeping
// its shape, so the document still parses but no longer matches the signature.
func editHead(t *testing.T, dir string) {
	t.Helper()
	p := filepath.Join(dir, manifestName)
	raw := readFile(t, p)
	edited := strings.Replace(raw, `"audit_head": "`+testHead+`"`, `"audit_head": "`+otherHead+`"`, 1)
	if edited == raw {
		t.Fatal("the head was not found in the manifest")
	}
	writeFile(t, p, edited)
}

// markPending rewrites the manifest's status, as an interrupted Write leaves
// it.
func markPending(t *testing.T, dir string) {
	t.Helper()
	p := filepath.Join(dir, manifestName)
	raw := readFile(t, p)
	edited := strings.Replace(raw, `"status": "complete"`, `"status": "pending"`, 1)
	if edited == raw {
		t.Fatal("the status was not found in the manifest")
	}
	writeFile(t, p, edited)
}
