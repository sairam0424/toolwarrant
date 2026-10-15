package trust

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/sairam0424/toolwarrant/internal/signing"
	"github.com/sairam0424/toolwarrant/internal/signing/sigtest"
)

// The fixed sample values of the tests: a catalog identity, a head and an
// instant, all of the shapes the payload rules require. No test source holds
// an invisible character; the hostile names are built with cp at run time.
const (
	sampleCatalog  = "0123456789abcdef0123456789abcdef"
	samplePrevHead = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	sampleDigest   = "a3f1c9d2e4b56789a3f1c9d2e4b56789a3f1c9d2e4b56789a3f1c9d2e4b56789"
	// skipNoSSHKeygen is the reason the interop test gives when the host has
	// no OpenSSH; this host (10.3p1) and the ubuntu runners have it.
	skipNoSSHKeygen = "SKIP: ssh-keygen is not on PATH; the allowed_signers interop test needs it"
)

// sampleTime is the instant every sample list is signed at.
func sampleTime() time.Time { return time.Date(2026, 10, 15, 12, 30, 45, 0, time.UTC) }

// named is one operator of a sample list before it is marshalled.
type named struct {
	name string
	key  sigtest.Key
}

// fp is the fingerprint of a generated key.
func fp(k sigtest.Key) string { return signing.Fingerprint(k.Public) }

// listOf builds a signing.TrustList of version v naming ops in order, with
// the payload's signer field set to the first operator's key; the rule
// functions take the verified signer separately, so the field is informative
// here.
func listOf(v int, ops ...named) signing.TrustList {
	signers := make([]signing.Signer, 0, len(ops))
	for _, op := range ops {
		signers = append(signers, signing.Signer{Key: signing.MarshalKey(op.key.Public), Name: op.name})
	}
	signer := ""
	if len(ops) > 0 {
		signer = fp(ops[0].key)
	}
	return signing.TrustList{
		Catalog: sampleCatalog, PrevHead: samplePrevHead, SignedAt: sampleTime(),
		Signer: signer, Signers: signers, Threshold: Threshold, Version: v,
	}
}

// mustValidate fails the test when a sample list is refused.
func mustValidate(t testing.TB, l signing.TrustList) Record {
	t.Helper()
	r, err := Validate(l)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	return r
}

// wantErrIs fails unless err wraps target and, when substr is not empty,
// names substr.
func wantErrIs(t testing.TB, label string, err, target error, substr string) {
	t.Helper()
	if err == nil {
		t.Errorf("%s: no error, want one wrapping %v", label, target)
		return
	}
	if !errors.Is(err, target) {
		t.Errorf("%s: error %v does not wrap %v", label, err, target)
	}
	if substr != "" && !strings.Contains(err.Error(), substr) {
		t.Errorf("%s: error %v does not name %q", label, err, substr)
	}
}

// cp builds a string from code points at run time, so no test source holds an
// invisible or format character literally (the catalog's tests do the same).
func cp(runes ...rune) string {
	var b strings.Builder
	for _, r := range runes {
		b.WriteRune(r)
	}
	return b.String()
}

// Code points the tests build hostile names from, as the catalog's table does.
const (
	zwsp      = 0x200B // zero width space (Cf)
	acuteMark = 0x0301 // combining acute: "e" + this is the NFD form of e-acute
	eAcute    = 0x00E9
	fullA     = 0xFF21 // full-width A, NFKC folds it to A
	kelvin    = 0x212A // Kelvin sign, NFKC folds it to K
	fiLigat   = 0xFB01 // fi ligature, NFKC folds it to "fi"
)

// sshKeygen returns the path of ssh-keygen or skips the test with the reason.
func sshKeygen(t testing.TB) string {
	t.Helper()
	path, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip(skipNoSSHKeygen)
	}
	return path
}

// runSSHKeygen runs ssh-keygen in dir with stdin and returns its combined
// output; the error is the process's. Nothing is added to this process's
// environment.
func runSSHKeygen(t testing.TB, dir string, stdin []byte, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(sshKeygen(t), args...)
	cmd.Dir = dir
	cmd.Env = os.Environ()
	if stdin != nil {
		cmd.Stdin = strings.NewReader(string(stdin))
	}
	out, err := cmd.CombinedOutput()
	t.Logf("ssh-keygen %s: %s", strings.Join(args, " "), strings.TrimSpace(string(out)))
	return string(out), err
}

// writeFile writes data at path with mode and returns path.
func writeFile(t testing.TB, path string, data []byte, mode os.FileMode) string {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	return path
}
