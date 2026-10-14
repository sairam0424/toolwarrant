package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/export"
	"github.com/sairam0424/toolwarrant/internal/gate"
)

// exportKeys is the key material of one export signing test, generated when
// the test runs: the signer's private key as an owner-only PKCS#8 PEM file,
// its public key as a PKIX PEM file, and another key's public key.
type exportKeys struct {
	priv, pub, otherPub string
	seed                string // base64 of the private seed, which no output may carry
}

func newExportKeys(t *testing.T) exportKeys {
	t.Helper()
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return exportKeys{
		priv:     writePEM(t, filepath.Join(dir, "export.key"), "PRIVATE KEY", mustPKCS8(t, priv), 0o600),
		pub:      writePEM(t, filepath.Join(dir, "export.pub"), "PUBLIC KEY", mustPKIXDER(t, pub), 0o644),
		otherPub: writePEM(t, filepath.Join(dir, "other.pub"), "PUBLIC KEY", mustPKIXDER(t, otherPub), 0o644),
		seed:     base64.StdEncoding.EncodeToString(priv.Seed()),
	}
}

func mustPKCS8(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func mustPKIXDER(t *testing.T, pub any) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// writePEM writes one PEM block to path with mode and returns the path.
func writePEM(t *testing.T, path, blockType string, der []byte, mode os.FileMode) string {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

var auditHeadLine = regexp.MustCompile(`audit head ([0-9a-f]{64})`)

// headOf extracts the audit head an export or verify printed.
func headOf(t *testing.T, out string) string {
	t.Helper()
	m := auditHeadLine.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no audit head in:\n%s", out)
	}
	return m[1]
}

// D21 (e): a signed export round-trips through export verify with the signer's
// public key; the manifest records the audit head audit verify prints; a
// flipped byte, a missing file, an extra file, a wrong key and a wrong
// expected head each fail closed with exit 1 naming the cause; a crawl moves
// the head and the next export re-signs with no tool file rewritten; --commit
// stages the signature and the public key and refuses a signature left behind
// by an earlier export.
func TestExportSignsTheManifestAndVerifyRoundTrips(t *testing.T) {
	c, _ := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	keys := newExportKeys(t)
	dir := filepath.Join(t.TempDir(), "approved")

	r := c.run("export", "--dir", dir, "--sign-key", keys.priv)
	if r.code != exitOK {
		t.Fatalf("export --sign-key: exit %d: %s", r.code, r.stderr)
	}
	wantContains(t, "stdout", r.stdout, "exported 1 approved tools", "1 written", manifestFile+" records audit head ", "digest profile "+gate.DigestProfile,
		"signed "+manifestFile+" with the key at "+keys.priv, signatureFile+" and "+publicKeyFile)
	wantNotContains(t, "output", r.stdout+r.stderr, "-----BEGIN", keys.seed)
	head := headOf(t, r.stdout)
	wantContains(t, "audit verify", c.ok("audit", "verify"), "head "+head)
	wantContains(t, "manifest", readFile(t, filepath.Join(dir, manifestFile)), `"version": 3`, `"audit_head": "`+head+`"`, `"digest_profile": "`+gate.DigestProfile+`"`)
	for _, name := range []string{signatureFile, publicKeyFile} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}

	out := c.ok("export", "verify", "--dir", dir, "--pub-key", keys.pub)
	wantContains(t, "verify", out, "export ok: 1 files in "+dir, "which the key in "+keys.pub+" signed", "audit head "+head, "digest profile "+gate.DigestProfile, "--expect-head")
	out = c.ok("export", "verify", "--dir", dir, "--pub-key", keys.pub, "--expect-head", head)
	wantNotContains(t, "verify with the head", out, "compare the head")
	r = c.fail(exitFailure, "export", "verify", "--dir", dir, "--pub-key", keys.pub, "--expect-head", strings.Repeat("0", 64))
	wantContains(t, "stderr", r.stderr, "audit head mismatch", head)

	toolFile := filepath.Join(dir, "s1", "echo.json")
	snapshot := readFile(t, toolFile)
	if err := os.WriteFile(toolFile, []byte(strings.Replace(snapshot, `"name":"echo"`, `"name":"ecko"`, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	r = c.fail(exitFailure, "export", "verify", "--dir", dir, "--pub-key", keys.pub)
	wantContains(t, "stderr after a flipped byte", r.stderr, "export in "+dir+" does not verify", `"s1/echo.json"`, "does not hash to its digest")
	if err := os.Remove(toolFile); err != nil {
		t.Fatal(err)
	}
	r = c.fail(exitFailure, "export", "verify", "--dir", dir, "--pub-key", keys.pub)
	wantContains(t, "stderr after a removal", r.stderr, `"s1/echo.json"`, "listed in "+manifestFile+" but missing")
	out = c.ok("export", "--dir", dir, "--sign-key", keys.priv)
	wantContains(t, "re-export", out, "1 written, 0 removed, 0 unchanged")
	c.ok("export", "verify", "--dir", dir, "--pub-key", keys.pub, "--expect-head", head)
	stray := filepath.Join(dir, "stray.txt")
	if err := os.WriteFile(stray, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	r = c.fail(exitFailure, "export", "verify", "--dir", dir, "--pub-key", keys.pub)
	wantContains(t, "stderr after an extra file", r.stderr, "not listed in "+manifestFile, `"stray.txt"`)
	if err := os.Remove(stray); err != nil {
		t.Fatal(err)
	}
	r = c.fail(exitFailure, "export", "verify", "--dir", dir, "--pub-key", keys.otherPub)
	wantContains(t, "stderr with the wrong key", r.stderr, publicKeyFile+" records another public key")

	// The crawl appends to the log: the head moves, the manifest and the
	// signature follow, the tool file is untouched.
	c.ok("crawl", "s1")
	out = c.ok("export", "--dir", dir, "--sign-key", keys.priv)
	wantContains(t, "export after the crawl", out, "0 written, 0 removed, 1 unchanged")
	moved := headOf(t, out)
	if moved == head {
		t.Fatal("the audit head did not move with the crawl")
	}
	r = c.fail(exitFailure, "export", "verify", "--dir", dir, "--pub-key", keys.pub, "--expect-head", head)
	wantContains(t, "stderr with the old head", r.stderr, "audit head mismatch")
	c.ok("export", "verify", "--dir", dir, "--pub-key", keys.pub, "--expect-head", moved)

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	out = c.ok("--as", "alice", "export", "--dir", dir, "--sign-key", keys.priv, "--commit")
	wantContains(t, "commit", out, "committed as alice <alice@"+emailDomain+">")
	tracked, err := exec.Command("git", "-C", dir, "ls-files").Output()
	if err != nil {
		t.Fatal(err)
	}
	wantContains(t, "tracked files", string(tracked), manifestFile+"\n", signatureFile+"\n", publicKeyFile+"\n", "s1/echo.json")
	c.ok("crawl", "s1")
	r = c.fail(exitFailure, "--as", "alice", "export", "--dir", dir, "--commit")
	wantContains(t, "stderr for a stale signature", r.stderr, signatureFile+" does not sign the current "+manifestFile, "export --sign-key again")
	c.ok("--as", "alice", "export", "--dir", dir, "--sign-key", keys.priv, "--commit")
}

// The signing key is refused before the catalog is opened and before anything
// is written when it is readable by others, a symbolic link, a directory,
// missing, not a PKCS#8 PRIVATE KEY block, or not an Ed25519 key; the refusal
// names the flag, the path and the shape, and never the key.
func TestExportRefusesAnUnsafeSigningKeyBeforeTouchingAnything(t *testing.T) {
	c, _ := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	keys := newExportKeys(t)
	kdir := t.TempDir()
	link := filepath.Join(kdir, "link.key")
	if err := os.Symlink(keys.priv, link); err != nil {
		t.Fatal(err)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shared := filepath.Join(kdir, "shared.key")
	if err := os.WriteFile(shared, []byte(readFile(t, keys.priv)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o644); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct{ path, want string }{
		"mode 0644":    {shared, "readable by other users (mode 0644); whoever reads it can sign an export, so chmod 600 it"},
		"symlink":      {link, "symbolic link"},
		"directory":    {kdir, "is a directory"},
		"missing":      {filepath.Join(kdir, "none.key"), "no such file"},
		"not pkcs8":    {writePEM(t, filepath.Join(kdir, "pub-as-key.key"), "PUBLIC KEY", []byte(pemBody(t, keys.pub)), 0o600), "not a PEM PRIVATE KEY block (PKCS#8)"},
		"not ed25519":  {writePEM(t, filepath.Join(kdir, "ec.key"), "PRIVATE KEY", mustPKCS8(t, ec), 0o600), "not an Ed25519 key"},
		"garbage pem":  {writePEM(t, filepath.Join(kdir, "junk.key"), "PRIVATE KEY", []byte("junk"), 0o600), "not a PKCS#8 private key"},
		"empty string": {"", ""},
	}
	for label, k := range cases {
		dir := filepath.Join(t.TempDir(), "approved")
		if k.want == "" {
			c.ok("export", "--dir", dir, "--sign-key="+k.path) // an empty value means no signing
			if _, err := os.Stat(filepath.Join(dir, signatureFile)); err == nil {
				t.Errorf("%s: a signature was written without a key", label)
			}
			continue
		}
		r := c.fail(exitFailure, "export", "--dir", dir, "--sign-key", k.path)
		wantContains(t, "stderr for "+label, r.stderr, flagSignKey+" "+k.path, k.want)
		wantNotContains(t, "stderr for "+label, r.stderr, "-----BEGIN", keys.seed)
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Errorf("%s: the export directory was created although the key was refused: %v", label, err)
		}
	}
}

// export verify needs both flags, its help and the export help name the new
// flags and the subcommand, and a public key file that is not one (garbage, a
// private key, a directory, or a file past the export package's bound for a
// PEM key file, refused before it is parsed with a message that names a key
// file), or a directory that is not an export, fail with exit 1 naming what
// was found.
func TestExportVerifyUsageHelpAndRefusals(t *testing.T) {
	c := newCLI(t)
	keys := newExportKeys(t)
	dir := t.TempDir()
	r := c.fail(exitUsage, "export", "verify")
	wantContains(t, "stderr", r.stderr, "--dir is required", "usage: toolwarrant [global flags] export verify --dir DIR --pub-key FILE [--expect-head HEX]")
	r = c.fail(exitUsage, "export", "verify", "--dir", dir)
	wantContains(t, "stderr", r.stderr, "--pub-key is required")
	r = c.fail(exitUsage, "export", "verify", "--dir", dir, "--pub-key", keys.pub, "extra")
	wantContains(t, "stderr", r.stderr, "expected 0 argument(s)")

	wantContains(t, "help", c.ok("help"), "export --dir DIR [--sign-key PATH] [--commit] [--git-name N --git-email E]", "export verify --dir DIR --pub-key FILE [--expect-head HEX]")
	wantContains(t, "help export", c.ok("help", "export"), "-sign-key", "-commit", "never from the environment or a flag value", "subcommands:", "export verify --dir DIR --pub-key FILE [--expect-head HEX]")
	wantContains(t, "help export verify", c.ok("help", "export", "verify"), "-dir", "-pub-key", "-expect-head", "opens no database")
	wantContains(t, "export verify -h", c.ok("export", "verify", "-h"), "-pub-key")

	garbage := filepath.Join(t.TempDir(), "garbage.pub")
	if err := os.WriteFile(garbage, []byte("not a key"), 0o644); err != nil {
		t.Fatal(err)
	}
	r = c.fail(exitFailure, "export", "verify", "--dir", dir, "--pub-key", garbage)
	wantContains(t, "stderr", r.stderr, flagPubKey+" "+garbage, "not a PEM PUBLIC KEY block (PKIX)")
	r = c.fail(exitFailure, "export", "verify", "--dir", dir, "--pub-key", keys.priv)
	wantContains(t, "stderr", r.stderr, "not a PEM PUBLIC KEY block (PKIX)")
	wantNotContains(t, "stderr", r.stderr, keys.seed)
	r = c.fail(exitFailure, "export", "verify", "--dir", dir, "--pub-key", t.TempDir())
	wantContains(t, "stderr", r.stderr, flagPubKey, "is a directory")
	oversized := filepath.Join(t.TempDir(), "big.pub")
	if err := os.WriteFile(oversized, append([]byte(readFile(t, keys.pub)), bytes.Repeat([]byte{'\n'}, export.MaxKeyFileBytes)...), 0o644); err != nil {
		t.Fatal(err)
	}
	r = c.fail(exitFailure, "export", "verify", "--dir", dir, "--pub-key", oversized)
	wantContains(t, "stderr", r.stderr, flagPubKey+" "+oversized, "larger than "+strconv.Itoa(export.MaxKeyFileBytes)+" bytes, which no PEM public key file is")
	r = c.fail(exitFailure, "export", "verify", "--dir", dir, "--pub-key", keys.pub)
	wantContains(t, "stderr", r.stderr, "export in "+dir+" does not verify", manifestFile+" not found")
	r = c.fail(exitFailure, "export", "verify", "--dir", filepath.Join(dir, "missing"), "--pub-key", keys.pub)
	wantContains(t, "stderr", r.stderr, "stat directory")
}

// pemBody returns the DER inside the one PEM block of the file at path.
func pemBody(t *testing.T, path string) string {
	t.Helper()
	block, _ := pem.Decode([]byte(readFile(t, path)))
	if block == nil {
		t.Fatalf("%s holds no PEM block", path)
	}
	return string(block.Bytes)
}
