package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/sairam0424/toolwarrant/internal/signing"
	"github.com/sairam0424/toolwarrant/internal/signing/sigtest"
)

func TestApproveSignsWithAKeyFileAndRefusesAnUnsafeOne(t *testing.T) {
	t.Parallel()
	l := newSignedLab(t)
	l.bootstrap(t)
	delete(l.env, envAuthSock) // no agent from here on: the file path signs
	echo := l.tool("s1", "echo").Pending
	before := l.verifiedHead()
	dir := t.TempDir()
	shared := filepath.Join(dir, "shared.key")
	data, err := os.ReadFile(l.aliceFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shared, data, 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.key")
	if err := os.Symlink(l.aliceFile, link); err != nil {
		t.Fatal(err)
	}
	encrypted := sigtest.WriteEncryptedKeyFile(t, dir, "locked.key", l.alice, "passphrase")
	cases := []struct {
		name, path, want string
	}{
		{"world-readable", shared, "readable by other users"},
		{"symbolic link", link, "symbolic link"},
		{"directory", dir, "a directory"},
		{"encrypted", encrypted, "load the key into ssh-agent"},
		{"public key without an agent", l.alicePub, "SSH_AUTH_SOCK is not set"},
		{"missing", filepath.Join(dir, "none.key"), "no such file"},
	}
	private, _ := keyMaterial(t, l.alice, l.aliceFile)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := l.sub(t).fail(exitFailure, "--ssh-key", tc.path, "approve", "s1", "echo", "--hash", echo)
			wantContains(t, "stderr", r.stderr, tc.want)
			wantNotContains(t, "output", r.stdout+r.stderr, private...)
		})
	}
	if after := l.verifiedHead(); after != before {
		t.Fatalf("a refused key moved the head from %s to %s", before, after)
	}
	out := l.ok("--ssh-key", l.aliceFile, "approve", "s1", "echo", "--hash", echo)
	if actor, fp, _, _ := signedAs(t, out); actor != "alice" || fp != fpOf(l.alice) {
		t.Errorf("signed as %s with %s", actor, fp)
	}
	wantNotContains(t, "approve output", out, private...)
}

func TestApproveTouchHintIsPrintedForASecurityKey(t *testing.T) {
	t.Parallel()
	c, _ := fixture(t)
	sock, pub := newSKAgent(t)
	c.env[envAuthSock] = sock
	skPub := filepath.Join(t.TempDir(), "sk.pub")
	if err := os.WriteFile(skPub, ssh.MarshalAuthorizedKey(pub), 0o644); err != nil {
		t.Fatal(err)
	}
	fp := signing.Fingerprint(pub)
	r := c.run("--as", "alice", "--ssh-key", skPub, "trust", "init")
	if r.code != exitOK {
		t.Fatalf("trust init with the security key: exit %d\n%s\n%s", r.code, r.stdout, r.stderr)
	}
	wantContains(t, "init stderr", r.stderr, "touch your security key for "+fp)
	wantContains(t, "init stdout", r.stdout, "alice "+fp, "record the trust root "+fp)
	echo := c.tool("s1", "echo").Pending
	r = c.run("--ssh-key", skPub, "approve", "s1", "echo", "--hash", echo)
	if r.code != exitOK {
		t.Fatalf("approve with the security key: exit %d\n%s\n%s", r.code, r.stdout, r.stderr)
	}
	wantContains(t, "approve stderr", r.stderr, "touch your security key for "+fp)
	if actor, got, _, _ := signedAs(t, r.stdout); actor != "alice" || got != fp {
		t.Errorf("signed as %s with %s, want alice with %s", actor, got, fp)
	}
	wantContains(t, "trust show", c.ok("trust", "show"), "sk-ssh-ed25519@openssh.com")
	wantContains(t, "audit verify", c.ok("audit", "verify"), "signed records ok: 1 decisions and 1 trust lists verified")
}

func TestSigningTimeoutWritesNothing(t *testing.T) {
	t.Parallel()
	l := newSignedLab(t)
	l.bootstrap(t)
	before := l.verifiedHead()
	echo := l.tool("s1", "echo").Pending
	l.env[envAuthSock] = sigtest.NewBlockingAgent(t, l.alice)
	r := l.fail(exitFailure, "--sign-timeout", "200ms", "--ssh-key", l.alicePub, "approve", "s1", "echo", "--hash", echo)
	wantContains(t, "stderr", r.stderr, "signing timed out after 200ms waiting for the agent; nothing was written")
	wantNotContains(t, "stderr", r.stderr, adviceInterrupted)
	if after := l.verifiedHead(); after != before {
		t.Errorf("the timed-out signature moved the head from %s to %s", before, after)
	}
	if tv := l.tool("s1", "echo"); tv.Approved != "" {
		t.Errorf("the timed-out approve was written: %+v", tv.toolJSON)
	}
	r = l.fail(exitFailure, "--sign-timeout", "200ms", "--ssh-key", l.alicePub, "trust", "add", "bob", "--key", l.bobPub)
	wantContains(t, "trust add", r.stderr, "signing timed out after 200ms")
	wantContains(t, "trust show", l.ok("trust", "show"), "trust list v1 (entry ")
}

// Every command of the signed flow, on success and on every refusal, prints
// fingerprints and nothing else of a key: no PEM marker, no base64 of the
// seed, the private key or the key file's body; the public key's base64 only
// where it is the output (trust show --json and --allowed-signers, and audit
// list --json, whose payloads carry the key lines a trust list stores).
func TestNoOutputCarriesKeyMaterial(t *testing.T) {
	t.Parallel()
	l := newSignedLab(t)
	alicePrivate, alicePublic := keyMaterial(t, l.alice, l.aliceFile)
	bobPrivate, bobPublic := keyMaterial(t, l.bob, l.bobFile)
	forbidden := append(alicePrivate, bobPrivate...)
	publicOK := map[string]bool{"trust show --json": true, "trust show --allowed-signers": true, "audit list --json": true}
	dir := t.TempDir()
	shared := filepath.Join(dir, "shared.key")
	data, err := os.ReadFile(l.bobFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shared, data, 0o644); err != nil {
		t.Fatal(err)
	}
	encrypted := sigtest.WriteEncryptedKeyFile(t, dir, "locked.key", l.bob, "passphrase")
	blocking := sigtest.NewBlockingAgent(t, l.bob)
	echo := l.tool("s1", "echo").Pending
	add := l.tool("s1", "add").Pending
	runs := []struct {
		name string
		env  map[string]string
		args []string
	}{
		{"approve before the bootstrap with a key", nil, []string{"--ssh-key", l.alicePub, "approve", "s1", "echo", "--hash", echo}},
		{"trust init", nil, []string{"--as", "alice", "--ssh-key", l.alicePub, "trust", "init"}},
		{"trust init again", nil, []string{"--as", "alice", "--ssh-key", l.alicePub, "trust", "init"}},
		{"approve", nil, []string{"--ssh-key", l.alicePub, "approve", "s1", "echo", "--hash", echo}},
		{"approve without a key", nil, []string{"approve", "s1", "add", "--hash", add}},
		{"approve with an unlisted key file", nil, []string{"--ssh-key", l.bobFile, "approve", "s1", "add", "--hash", add}},
		{"approve with a shared key file", nil, []string{"--ssh-key", shared, "approve", "s1", "add", "--hash", add}},
		{"approve with an encrypted key file", nil, []string{"--ssh-key", encrypted, "approve", "s1", "add", "--hash", add}},
		{"approve with a key the agent lacks", nil, []string{"--ssh-key", l.bobPub, "approve", "s1", "add", "--hash", add}},
		{"approve with a mismatched label", nil, []string{"--as", "bob", "--ssh-key", l.alicePub, "approve", "s1", "add", "--hash", add}},
		{"approve that times out", map[string]string{envAuthSock: blocking}, []string{"--sign-timeout", "200ms", "--ssh-key", l.alicePub, "approve", "s1", "add", "--hash", add}},
		{"trust add", nil, []string{"--ssh-key", l.alicePub, "trust", "add", "bob", "--key", l.bobPub}},
		{"disable by bob's key file", nil, []string{"--ssh-key", l.bobFile, "disable", "s1", "echo"}},
		{"enable", nil, []string{"--ssh-key", l.alicePub, "enable", "s1", "echo"}},
		{"reject", nil, []string{"--ssh-key", l.alicePub, "reject", "s1", "echo", "--hash", echo}},
		{"rollback refused", nil, []string{"--ssh-key", l.alicePub, "rollback", "s1", "echo", "--to", add}},
		{"server pause", nil, []string{"--ssh-key", l.alicePub, "server", "pause", "s1"}},
		{"server resume", nil, []string{"--ssh-key", l.alicePub, "server", "resume", "s1"}},
		{"budget reset", nil, []string{"--ssh-key", l.alicePub, "budget", "reset", "s1", "echo"}},
		{"trust remove own key", nil, []string{"--ssh-key", l.alicePub, "trust", "remove", "alice"}},
		{"trust remove", nil, []string{"--ssh-key", l.bobFile, "trust", "remove", "alice"}},
		{"trust show", nil, []string{"trust", "show"}},
		{"trust show --json", nil, []string{"trust", "show", "--json"}},
		{"trust show --allowed-signers", nil, []string{"trust", "show", "--allowed-signers"}},
		{"show", nil, []string{"show", "s1", "echo"}},
		{"show --json", nil, []string{"show", "s1", "echo", "--json"}},
		{"list", nil, []string{"list"}},
		{"audit verify", nil, []string{"audit", "verify"}},
		{"audit list", nil, []string{"audit", "list"}},
		{"audit list --json", nil, []string{"audit", "list", "--json"}},
		{"help", nil, []string{"help"}},
	}
	for _, run := range runs {
		saved := map[string]string{}
		for k, v := range run.env {
			saved[k] = l.env[k]
			l.env[k] = v
		}
		r := l.run(run.args...)
		for k, v := range saved {
			l.env[k] = v
		}
		out := r.stdout + r.stderr
		wantNotContains(t, run.name, out, forbidden...)
		if !publicOK[run.name] {
			wantNotContains(t, run.name+" (public key)", out, alicePublic, bobPublic)
		}
	}
}

// The shape --trust-root must have is the one the signing package prints and
// requires inside a payload, so a recorded root always passes.
func TestTrustRootShape(t *testing.T) {
	t.Parallel()
	for _, k := range []sigtest.Key{sigtest.GenerateEd25519(t), sigtest.GenerateRSA(t, 3072)} {
		if fp := signing.Fingerprint(k.Public); !isFingerprint(fp) {
			t.Errorf("isFingerprint(%s) = false", fp)
		}
	}
	fp := signing.Fingerprint(sigtest.GenerateEd25519(t).Public)
	for _, bad := range []string{"", "SHA256:", fp[:len(fp)-1], fp + "=", strings.ToLower(fp), "MD5:" + fp[7:], "sha256:" + fp[7:], fp + "x"} {
		if isFingerprint(bad) {
			t.Errorf("isFingerprint(%q) = true", bad)
		}
	}
}

func TestEveryCommandRefusesACatalogWhoseRootIsNotTheTrustRoot(t *testing.T) {
	t.Parallel()
	l := newSignedLab(t)
	root, _ := l.bootstrap(t)
	echo := l.tool("s1", "echo").Pending
	wrong := fpOf(l.bob)
	commands := [][]string{
		{"list"}, {"show", "s1", "echo"}, {"trust", "show"}, {"audit", "verify"},
		{"--ssh-key", l.alicePub, "approve", "s1", "echo", "--hash", echo},
		{"--ssh-key", l.alicePub, "trust", "add", "bob", "--key", l.bobPub},
		{"server", "list"},
	}
	for _, args := range commands {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			r := l.sub(t).fail(exitFailure, append([]string{"--trust-root", wrong}, args...)...)
			wantContains(t, "output", r.stdout+r.stderr, "pinned trust root")
		})
	}
	// audit list is the forensic view and lists the log whatever the pin
	// says; its --json form withholds the records and says why.
	wantContains(t, "audit list", l.ok("--trust-root", wrong, "audit", "list"), "trust.bootstrap")
	r := l.run("--trust-root", wrong, "audit", "list", "--json")
	if r.code != exitOK || !strings.Contains(r.stderr, "signed records not shown: ") || !strings.Contains(r.stderr, "pinned trust root") || strings.Contains(r.stdout, "BEGIN SSH SIGNATURE") {
		t.Errorf("audit list --json under the wrong root = %+v", r)
	}
	l.env[envTrustRoot] = wrong
	r = l.fail(exitFailure, "list")
	wantContains(t, "env root", r.stderr, "pinned trust root")
	l.env[envTrustRoot] = root
	l.ok("list")
	l.ok("--ssh-key", l.alicePub, "approve", "s1", "echo", "--hash", echo)
	wantContains(t, "audit verify under the right root", l.ok("audit", "verify"), "signed records ok")
	delete(l.env, envTrustRoot)
	// A catalog never bootstrapped is refused under any root.
	fresh, _ := fixture(t)
	r = fresh.fail(exitFailure, "--trust-root", root, "list")
	wantContains(t, "no bootstrap", r.stderr, "no trust list", "trust root")
	if tv := fresh.tool("s1", "echo"); tv.Approved != "" {
		t.Errorf("fresh catalog: %+v", tv.toolJSON)
	}
}
