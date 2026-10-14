package export

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fixedTime is a non-UTC instant so tests prove the manifest converts to UTC.
var fixedTime = time.Date(2026, 10, 7, 14, 30, 5, 0, time.FixedZone("CEST", 2*60*60))

// testHead and testProfile are the catalog fields most tests record; a test
// about the fields themselves builds its own.
const (
	testHead    = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
	testProfile = "full-v1"
)

// testOpts are the options of a Write that records the fixed head and profile
// and signs nothing.
var testOpts = Options{AuditHead: testHead, DigestProfile: testProfile}

// signedOpts are testOpts with key as the signing key.
func signedOpts(key ed25519.PrivateKey) Options {
	return Options{AuditHead: testHead, DigestProfile: testProfile, SignKey: key}
}

// headOpts are testOpts with another audit head, for a Write after the log
// moved.
func headOpts(head string) Options {
	return Options{AuditHead: head, DigestProfile: testProfile}
}

// otherHead is a second well-formed audit head.
var otherHead = strings.Repeat("0f", 32)

// newSigningKey generates an Ed25519 key for one test; no key material is in
// the tree.
func newSigningKey(t testing.TB) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// writeKeyFile writes a PEM block to path with mode.
func writeKeyFile(t testing.TB, path, blockType string, der []byte, mode os.FileMode) string {
	t.Helper()
	data := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// writeSigningKey writes priv as an owner-only PKCS#8 PEM file in dir and
// returns its path.
func writeSigningKey(t testing.TB, dir string, priv ed25519.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return writeKeyFile(t, filepath.Join(dir, "export.key"), pemPrivateKeyType, der, 0o600)
}

// newECDSAKeyDER is a PKCS#8 key that is not Ed25519.
func newECDSAKeyDER(t testing.TB) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// mustVerify runs Verify and fails the test on error.
func mustVerify(t testing.TB, dir string, pub ed25519.PublicKey, expectHead string) VerifyReport {
	t.Helper()
	rep, err := Verify(dir, pub, expectHead)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return rep
}

// wantVerifyError runs Verify, requires it to fail and requires the message to
// hold every fragment.
func wantVerifyError(t testing.TB, dir string, pub ed25519.PublicKey, expectHead string, fragments ...string) {
	t.Helper()
	_, err := Verify(dir, pub, expectHead)
	if err == nil {
		t.Fatalf("Verify passed, want a refusal naming %q", fragments)
	}
	for _, f := range fragments {
		if !strings.Contains(err.Error(), f) {
			t.Errorf("Verify error %q lacks %q", err, f)
		}
	}
}

// mkTool builds a Tool whose Canonical bytes and Digest agree. body varies the
// content so tests can produce "the definition changed" cases.
func mkTool(t testing.TB, server, name, body string) Tool {
	t.Helper()
	canon, err := json.Marshal(map[string]string{"description": body, "name": name})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canon)
	return Tool{
		Server:     server,
		Name:       name,
		Digest:     hex.EncodeToString(sum[:]),
		Canonical:  canon,
		ApprovedBy: "alice@example.com",
		ApprovedAt: fixedTime,
		VersionNo:  1,
	}
}

// entry is one file or directory in a tree snapshot.
type entry struct {
	Mode    fs.FileMode
	Content string
	ModTime time.Time
}

// snapshot records every path under dir (without following symlinks) with its
// mode and content, so tests can assert byte-identical directories.
func snapshot(t testing.TB, dir string) map[string]entry {
	t.Helper()
	out := map[string]entry{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		e := entry{Mode: info.Mode(), ModTime: info.ModTime()}
		if info.Mode().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			e.Content = string(b)
		}
		out[rel] = e
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot %s: %v", dir, err)
	}
	return out
}

// names lists the relative paths of a snapshot, for compact assertions.
func names(s map[string]entry) []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	return out
}

// readFile fails the test if the file cannot be read.
func readFile(t testing.TB, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// writeFile creates p, and its directory, with content.
func writeFile(t testing.TB, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// mustWrite runs Write and fails the test on error.
func mustWrite(t testing.TB, dir string, tools ...Tool) Report {
	t.Helper()
	rep, err := Write(dir, tools, testOpts)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	return rep
}

// mustWriteWith is mustWrite with explicit options.
func mustWriteWith(t testing.TB, dir string, opts Options, tools ...Tool) Report {
	t.Helper()
	rep, err := Write(dir, tools, opts)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	return rep
}

// wantReport compares the counts of rep with the expected ones and requires
// that nothing was skipped. Report holds a slice, so == cannot compare it.
func wantReport(t testing.TB, rep Report, written, removed, unchanged int) {
	t.Helper()
	if rep.Written != written || rep.Removed != removed || rep.Unchanged != unchanged || len(rep.Skipped) != 0 {
		t.Fatalf("report = %+v, want written=%d removed=%d unchanged=%d and nothing skipped", rep, written, removed, unchanged)
	}
}

// readManifest parses MANIFEST.json in dir with the package's own parser.
func readManifest(t testing.TB, dir string) manifestDoc {
	t.Helper()
	doc, ok := parseManifest([]byte(readFile(t, filepath.Join(dir, manifestName))))
	if !ok {
		t.Fatalf("MANIFEST.json in %s does not parse", dir)
	}
	return doc
}

// appendGitConfig appends text to dir/.git/config, the way an operator or an
// attacker with write access to the repository would.
func appendGitConfig(t testing.TB, dir, text string) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(dir, gitDirName, "config"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(text); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// skipIfRoot skips permission-based tests when the process can ignore modes.
func skipIfRoot(t testing.TB) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("SKIP: running as root, file modes do not restrict writes")
	}
}

// lockDir makes dir read-only for the rest of the test and restores it on
// cleanup so t.TempDir can delete it.
func lockDir(t testing.TB, dir string) {
	t.Helper()
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
}
