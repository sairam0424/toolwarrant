package signing

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sairam0424/toolwarrant/internal/signing/sigtest"
)

// The fixed sample values of the tests: a catalog identity, two digests, one
// head and one instant, all of the shapes the payload rules require.
const (
	sampleCatalog  = "0123456789abcdef0123456789abcdef"
	sampleDigest   = "a3f1c9d2e4b56789a3f1c9d2e4b56789a3f1c9d2e4b56789a3f1c9d2e4b56789"
	samplePrevHead = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	sampleServer   = "mock"
	sampleTool     = "echo"
	sampleActor    = "alice"
	// skipNoSSHKeygen is the reason the interop tests give when the host has
	// no OpenSSH; this host and the ubuntu runners have it, so they run.
	skipNoSSHKeygen = "SKIP: ssh-keygen is not on PATH; the OpenSSH interop tests need it"
)

// sampleTime is the instant every sample record is signed at.
func sampleTime() time.Time { return time.Date(2026, 10, 15, 12, 30, 45, 0, time.UTC) }

// sampleDecision is an approval by alice of echo on mock, signed by fp.
func sampleDecision(fp string) Decision {
	return Decision{
		Actor: sampleActor, Catalog: sampleCatalog, Digest: sampleDigest, Kind: KindApprove,
		PrevHead: samplePrevHead, Server: sampleServer, SignedAt: sampleTime(), Signer: fp, Tool: sampleTool,
	}
}

// sampleTrustList is a version-1 list naming keys as alice, bob, ... signed
// by the first key.
func sampleTrustList(keys ...sigtest.Key) TrustList {
	names := []string{"alice", "bob", "carol", "dave"}
	signers := make([]Signer, 0, len(keys))
	for i, k := range keys {
		signers = append(signers, Signer{Key: MarshalKey(k.Public), Name: names[i%len(names)]})
	}
	return TrustList{
		Catalog: sampleCatalog, PrevHead: samplePrevHead, SignedAt: sampleTime(),
		Signer: Fingerprint(keys[0].Public), Signers: signers, Threshold: 1, Version: 1,
	}
}

// mustMarshalDecision fails the test when the sample does not marshal.
func mustMarshalDecision(t testing.TB, d Decision) []byte {
	t.Helper()
	b, err := MarshalDecision(d)
	if err != nil {
		t.Fatalf("MarshalDecision: %v", err)
	}
	return b
}

// mustMarshalTrustList fails the test when the sample does not marshal.
func mustMarshalTrustList(t testing.TB, l TrustList) []byte {
	t.Helper()
	b, err := MarshalTrustList(l)
	if err != nil {
		t.Fatalf("MarshalTrustList: %v", err)
	}
	return b
}

// mustSign fails the test when the sample does not sign.
func mustSign(t testing.TB, payload []byte, k sigtest.Key, ns Namespace) Record {
	t.Helper()
	r, err := Sign(t.Context(), payload, k.Signer, ns)
	if err != nil {
		t.Fatalf("Sign: %v", err)
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

// flipByte returns a copy of b with the bit 0x01 of b[i] flipped.
func flipByte(b []byte, i int) []byte {
	out := bytes.Clone(b)
	out[i] ^= 0x01
	return out
}

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
// output; the error is the process's. env entries are added to the child's
// environment (SSH_AUTH_SOCK for the agent cases), never to this process's.
func runSSHKeygen(t testing.TB, dir string, stdin []byte, env []string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(sshKeygen(t), args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	t.Logf("ssh-keygen %s: %s", strings.Join(args, " "), strings.TrimSpace(string(out)))
	return string(out), err
}

// writeAllowedSigners writes an allowed_signers file naming k as principal.
func writeAllowedSigners(t testing.TB, dir, principal string, k sigtest.Key) string {
	t.Helper()
	path := filepath.Join(dir, "allowed_signers")
	line := principal + " " + MarshalKey(k.Public) + "\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// writeFile writes data at path with mode and returns path.
func writeFile(t testing.TB, path string, data []byte, mode os.FileMode) string {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// skipIfRoot skips a test whose refusals rest on file modes, which root
// ignores.
func skipIfRoot(t testing.TB) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("SKIP: running as root, file modes do not restrict access")
	}
}
