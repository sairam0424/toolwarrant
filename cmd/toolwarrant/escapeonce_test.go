package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/export"
)

// hostileFiles plants, under dir, the operator-given paths of the escape probe,
// each with an ESC byte in its name built at run time: a directory, a
// world-readable file that is not PEM, a file larger than any PEM key file,
// and a symbolic link to target.
func hostileFiles(t *testing.T, dir, target string) (hdir, file, big, link string) {
	t.Helper()
	hdir, file, big, link = filepath.Join(dir, esc+"[2Jdir"), filepath.Join(dir, esc+"[2Jfile.pem"), filepath.Join(dir, esc+"[2Jbig.pem"), filepath.Join(dir, esc+"[2Jlink.db")
	if err := os.Mkdir(hdir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("not pem at all\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(big, []byte(strings.Repeat("x", export.MaxKeyFileBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	return hdir, file, big, link
}

// escapedOnce asserts that the one hostile value a refusal embedded came out as
// one \u{001B}: never the raw byte, and never the doubled backslash the older
// sites printed while they escaped the value and describe escaped the whole
// sentence again.
func escapedOnce(t *testing.T, where, s string) {
	t.Helper()
	n, doubled, raw := strings.Count(s, `\u{001B}`), strings.Contains(s, `\\u{001B}`), strings.Contains(s, esc)
	if n != 1 || doubled || raw {
		t.Errorf("%s: want one \\u{001B} and neither a doubled backslash nor the raw byte; got %d, doubled %t, raw %t in %q", where, n, doubled, raw, s)
	}
}

// TestRefusalsEscapeHostileValuesOnce drives a path or a flag value holding an
// ESC byte through one refusal of every kind that embeds the value in an error
// describe prints: the key file of --pub-key, the directory and the signing
// key of export, the TLS files of serve, the output file of emit, the database
// path, --expect-head of audit verify, and a line of the emitted file verify
// reads. Each sentence is escaped once, where it is printed, so the operator
// reads the value as given. The usage errors, which exitCode prints as
// written, are not in this table and keep escaping their values themselves.
func TestRefusalsEscapeHostileValuesOnce(t *testing.T) {
	t.Parallel()
	c, _ := fixture(t)
	f := newTLSFiles(t)
	keys := newExportKeys(t)
	dir := t.TempDir()
	hdir, file, big, link := hostileFiles(t, dir, c.db)
	cases := []struct {
		name, db, want string
		args           []string
	}{
		{"pub-key directory", "", "is a directory, not a regular file", []string{"export", "verify", "--dir", dir, "--pub-key", hdir}},
		{"pub-key too large", "", "is larger than", []string{"export", "verify", "--dir", dir, "--pub-key", big}},
		{"pub-key not PEM", "", "not a PEM PUBLIC KEY block", []string{"export", "verify", "--dir", dir, "--pub-key", file}},
		{"export directory", "", "does not verify", []string{"export", "verify", "--dir", hdir, "--pub-key", keys.pub}},
		{"signing key", "", "readable by other users", []string{"export", "--dir", filepath.Join(dir, "approved"), "--sign-key", file}},
		{"tls client authority", "", "holds no PEM certificate", f.serveArgs("--tls-client-ca", file)},
		{"tls key", "", "readable by other users", []string{"serve", "--server", "s1", "--listen", "127.0.0.1:0", "--tls-cert", f.certPath, "--tls-key", file}},
		{"emit output", "", "is a directory, not a regular file", []string{"emit", "--out", hdir}},
		{"database missing", filepath.Join(dir, esc+"[2Jmissing.db"), "does not exist", []string{"list"}},
		{"database symlink", link, "is a symbolic link", []string{"init"}},
		{"audit flag", "", "audit head mismatch", []string{"audit", "verify", "--expect-head", esc + "[2Jdead"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			run := c.sub(t)
			if tc.db != "" {
				run = &cli{t: t, db: tc.db, env: c.env}
			}
			r := run.fail(exitFailure, tc.args...)
			wantContains(t, "stderr", r.stderr, tc.want)
			escapedOnce(t, tc.name, r.stderr)
		})
	}
	// The emitted-file parser's sentences reach describe through verify's
	// live comparison; the line they quote is escaped there, once.
	_, err := emittedConfig([]byte("gateways:\n    port: 1" + esc + "\n"))
	if err == nil {
		t.Fatal("a gateway key outside a gateway was accepted")
	}
	escapedOnce(t, "emitted file line", describe(err))
}
