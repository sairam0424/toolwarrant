package main

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/signing"
)

func TestTrustInitRecordsTheBootstrapAndPrintsTheRoot(t *testing.T) {
	t.Parallel()
	l := newSignedLab(t)
	out := l.ok("--as", "alice", "--ssh-key", l.alicePub, "trust", "init")
	wantContains(t, "trust init", out, "trust list v1 recorded at entry ", "alice "+fpOf(l.alice), "record the trust root "+fpOf(l.alice)+" with the audit head ",
		"decisions from entry ", "on must be signed by a listed key", "--trust-root", envTrustRoot)
	m := rootLine.FindStringSubmatch(out)
	if m == nil || m[1] != fpOf(l.alice) {
		t.Fatalf("root line = %v", m)
	}
	if head := l.verifiedHead(); head != m[2] {
		t.Errorf("trust init printed head %s, audit verify says %s", m[2], head)
	}
	entries := l.auditEntries()
	last := entries[len(entries)-1]
	if last.Event != "trust.bootstrap" || last.Actor != "alice" || last.ActorType != "human" || last.Subject != "@trust" || !strings.HasPrefix(last.Detail, "version=1 signers=1 signer="+fpOf(l.alice)) {
		t.Errorf("bootstrap entry = %+v", last)
	}
	seq := entryAtLine.FindStringSubmatch(out)
	wantContains(t, "trust show", l.ok("trust", "show"), "trust list v1 (entry "+seq[1]+"), root "+fpOf(l.alice)+" (entry "+seq[1]+"), signed records: 0 decisions, 1 lists",
		"NAME", "FINGERPRINT", "TYPE", "SINCE", "alice", "ssh-ed25519", "entry "+seq[1])
}

func TestTrustInitRefusesASecondBootstrapAndTheSystemActor(t *testing.T) {
	t.Parallel()
	l := newSignedLab(t)
	r := l.fail(exitUsage, "--as", "alice", "trust", "init")
	wantContains(t, "no key", r.stderr, "trust init needs --ssh-key PATH", envSSHKey)
	r = l.fail(exitUsage, "--as", "crawler", "--ssh-key", l.alicePub, "trust", "init")
	wantContains(t, "system actor", r.stderr, "the system actor cannot start the trust list; pass --as with your own name")
	wantNotContains(t, "system actor", r.stderr, "cannot approve")
	l.bootstrap(t)
	r = l.fail(exitFailure, "--as", "alice", "--ssh-key", l.alicePub, "trust", "init")
	wantContains(t, "second init", r.stderr, "already has a trust list (v1", "trust add")
	// Nothing was written by the refused runs: one bootstrap, no rotation.
	n := 0
	for _, e := range l.auditEntries() {
		if e.Subject == "@trust" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d trust entries, want 1", n)
	}
}

func TestTrustAddAndRemoveRotateTheListAndRefuseTheLastSigner(t *testing.T) {
	t.Parallel()
	l := newSignedLab(t)
	r := l.fail(exitFailure, "--ssh-key", l.alicePub, "trust", "add", "bob", "--key", l.bobPub)
	wantContains(t, "add without a list", r.stderr, "no trust list", "trust init")
	l.bootstrap(t)
	out := l.ok("--ssh-key", l.alicePub, "trust", "add", "bob", "--key", l.bobPub)
	wantContains(t, "add", out, "trust list v2 recorded at entry ", "alice "+fpOf(l.alice)+", bob "+fpOf(l.bob), "; signed as alice")
	r = l.fail(exitFailure, "--ssh-key", l.alicePub, "trust", "add", "carol", "--key", l.bobPub)
	wantContains(t, "duplicate key", r.stderr, "both hold the key")
	r = l.fail(exitFailure, "--ssh-key", l.alicePub, "trust", "add", "alice", "--key", l.bobPub)
	wantContains(t, "duplicate name", r.stderr, "both name")

	// bob signs with his key file (no agent needed) and is the actor.
	delete(l.env, envAuthSock)
	add := l.tool("s1", "add").Pending
	out = l.ok("--ssh-key", l.bobFile, "approve", "s1", "add", "--hash", add)
	if actor, fp, _, _ := signedAs(t, out); actor != "bob" || fp != fpOf(l.bob) {
		t.Errorf("signed as %s with %s, want bob with %s", actor, fp, fpOf(l.bob))
	}
	l.env[envAuthSock] = l.sock

	r = l.fail(exitFailure, "--ssh-key", l.alicePub, "trust", "remove", "alice")
	wantContains(t, "own removal", r.stderr, "a key cannot sign its own removal; sign with a key that stays")
	r = l.fail(exitFailure, "--ssh-key", l.bobFile, "trust", "remove", "carol")
	wantContains(t, "unknown", r.stderr, "carol is not in the trust list")
	out = l.ok("--ssh-key", l.bobFile, "trust", "remove", "alice")
	wantContains(t, "remove", out, "trust list v3 recorded at entry ", ": bob "+fpOf(l.bob)+"; signed as bob; decisions signed before this entry stand")
	wantNotContains(t, "remove", out, "alice "+fpOf(l.alice))
	r = l.fail(exitFailure, "--ssh-key", l.bobFile, "trust", "remove", "bob")
	wantContains(t, "last signer", r.stderr, "the trust list must keep at least one signer")

	// alice's key is out of the list: her decisions are refused, bob's
	// earlier approval stands.
	echo := l.tool("s1", "echo").Pending
	r = l.fail(exitFailure, "--ssh-key", l.alicePub, "approve", "s1", "echo", "--hash", echo)
	wantContains(t, "removed key", r.stderr, "the key "+fpOf(l.alice)+" is not in trust list v3", adviceNotASigner)
	if tv := l.tool("s1", "add"); tv.Approved != add {
		t.Errorf("bob's approval was undone: %+v", tv.toolJSON)
	}
	out = l.ok("--ssh-key", l.bobFile, "trust", "add", "alice", "--key", l.alicePub)
	wantContains(t, "re-add", out, "trust list v4 recorded at entry ", "bob "+fpOf(l.bob)+", alice "+fpOf(l.alice))
	l.ok("--ssh-key", l.alicePub, "approve", "s1", "echo", "--hash", echo)
	wantContains(t, "audit verify", l.ok("audit", "verify"), "signed records ok: 2 decisions and 4 trust lists verified; trust list v4 in force (bob "+fpOf(l.bob)+", alice "+fpOf(l.alice)+")")
}

func TestTrustShowPrintsTheListTheAllowedSignersFileAndJSON(t *testing.T) {
	t.Parallel()
	l := newSignedLab(t)
	out := l.ok("trust", "show")
	wantContains(t, "no list", out, "no trust list; decisions are attributed by name only (L13)", "trust init")
	var empty trustShowJSON
	l.jsonInto(&empty, "trust", "show", "--json")
	if empty.InForce || empty.Version != 0 || len(empty.Signers) != 0 {
		t.Errorf("trust show --json without a list = %+v", empty)
	}
	r := l.run("trust", "show", "--allowed-signers")
	if r.code != exitOK || r.stdout != "" || !strings.Contains(r.stderr, "no trust list") {
		t.Errorf("--allowed-signers without a list = %+v", r)
	}

	root, _ := l.bootstrap(t)
	l.ok("--ssh-key", l.alicePub, "trust", "add", "bob", "--key", l.bobPub)
	echo := l.tool("s1", "echo").Pending
	l.ok("--ssh-key", l.alicePub, "approve", "s1", "echo", "--hash", echo)
	out = l.ok("trust", "show")
	wantContains(t, "show", out, "trust list v2 (entry ", "root "+root+" (entry ", "signed records: 1 decisions, 2 lists", "alice", "bob", fpOf(l.alice), fpOf(l.bob), "ssh-ed25519")
	wantNotContains(t, "show", out, base64.StdEncoding.EncodeToString(l.alice.Public.Marshal()))
	var view trustShowJSON
	l.jsonInto(&view, "trust", "show", "--json")
	if !view.InForce || view.Version != 2 || view.Root != root || view.SignedDecisions != 1 || view.Lists != 2 || len(view.Signers) != 2 {
		t.Fatalf("trust show --json = %+v", view)
	}
	if s := view.Signers[1]; s.Name != "bob" || s.Fingerprint != fpOf(l.bob) || s.Key != signing.MarshalKey(l.bob.Public) || s.Type != "ssh-ed25519" || s.SinceEntry != view.ListEntry {
		t.Errorf("bob's row = %+v (list entry %d)", s, view.ListEntry)
	}
	if s := view.Signers[0]; s.SinceEntry != view.BootstrapEntry {
		t.Errorf("alice's since = %d, want the bootstrap %d", s.SinceEntry, view.BootstrapEntry)
	}
	allowed := l.ok("trust", "show", "--allowed-signers")
	lines := nonEmptyLines(allowed)
	if len(lines) != 2 || lines[0] != `alice namespaces="decision@toolwarrant.invalid,trust@toolwarrant.invalid" `+signing.MarshalKey(l.alice.Public) || !strings.HasPrefix(lines[1], "bob namespaces=") {
		t.Fatalf("allowed_signers:\n%s", allowed)
	}
	t.Run("ssh-keygen verifies a decision from audit list --json", func(t *testing.T) {
		keygen, err := exec.LookPath("ssh-keygen")
		if err != nil {
			t.Skipf("ssh-keygen is not on PATH, the interop sub-step cannot run: %v", err)
		}
		dir := t.TempDir()
		allowedFile := filepath.Join(dir, "allowed_signers")
		if err := os.WriteFile(allowedFile, []byte(allowed), 0o600); err != nil {
			t.Fatal(err)
		}
		var rows []auditEntryJSON
		l.jsonInto(&rows, "audit", "list", "--json")
		var rec *signedRecordJSON
		for _, e := range rows {
			if e.Event == eventDecisionSigned {
				rec = e.Signed
			}
		}
		if rec == nil {
			t.Fatal("no decision.signed entry carries a record")
		}
		payload, err := base64.StdEncoding.DecodeString(rec.Payload)
		if err != nil {
			t.Fatal(err)
		}
		sigFile := filepath.Join(dir, "decision.sig")
		if err := os.WriteFile(sigFile, []byte(rec.Signature), 0o600); err != nil {
			t.Fatal(err)
		}
		verify := exec.Command(keygen, "-Y", "verify", "-f", allowedFile, "-I", "alice", "-n", string(signing.NamespaceDecision), "-s", sigFile)
		verify.Stdin = strings.NewReader(string(payload))
		if out, err := verify.CombinedOutput(); err != nil || !strings.Contains(string(out), "Good") {
			t.Fatalf("ssh-keygen -Y verify: %v\n%s", err, out)
		}
		check := exec.Command(keygen, "-Y", "check-novalidate", "-n", string(signing.NamespaceDecision), "-s", sigFile)
		check.Stdin = strings.NewReader(string(payload))
		if out, err := check.CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen -Y check-novalidate: %v\n%s", err, out)
		}
		wrong := exec.Command(keygen, "-Y", "verify", "-f", allowedFile, "-I", "alice", "-n", "git", "-s", sigFile)
		wrong.Stdin = strings.NewReader(string(payload))
		if err := wrong.Run(); err == nil {
			t.Fatal("ssh-keygen accepted the decision signature under the git namespace")
		}
	})
}

func TestTrustUsageHelpAndRefusals(t *testing.T) {
	t.Parallel()
	l := newSignedLab(t)
	wantContains(t, "help trust", l.ok("help", "trust"), "trust init [--expect-head HEX]", "trust add NAME --key PUBKEY_FILE [--expect-head HEX]", "trust remove NAME [--expect-head HEX]", "trust show [--json | --allowed-signers]")
	wantContains(t, "help trust add", l.ok("help", "trust", "add"), "-key", "-expect-head")
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"trust alone", []string{"trust"}, "needs a subcommand"},
		{"unknown", []string{"trust", "frob"}, "unknown trust subcommand"},
		{"add without name", []string{"--ssh-key", l.alicePub, "trust", "add"}, "expected 1 argument(s)"},
		{"add without key", []string{"--ssh-key", l.alicePub, "trust", "add", "bob"}, "--key is required"},
		{"add the system actor", []string{"--ssh-key", l.alicePub, "trust", "add", "crawler", "--key", l.bobPub}, "system actor"},
		{"add as the system actor", []string{"--as", "crawler", "--ssh-key", l.alicePub, "trust", "add", "bob", "--key", l.bobPub}, "the system actor cannot change the trust list; pass --as with your own name"},
		{"remove as the system actor", []string{"--as", "crawler", "--ssh-key", l.alicePub, "trust", "remove", "bob"}, "the system actor cannot change the trust list; pass --as with your own name"},
		{"add without a signer", []string{"trust", "add", "bob", "--key", l.bobPub}, "trust add needs --ssh-key PATH"},
		{"remove without a signer", []string{"trust", "remove", "bob"}, "trust remove needs --ssh-key PATH"},
		{"show both forms", []string{"trust", "show", "--json", "--allowed-signers"}, "exclusive"},
		{"malformed trust root", []string{"--trust-root", "junk", "trust", "show"}, "not a key fingerprint"},
		{"md5 trust root", []string{"--trust-root", "MD5:aa:bb", "list"}, "not a key fingerprint"},
		{"sign timeout zero", []string{"--sign-timeout", "0", "--ssh-key", l.alicePub, "trust", "init"}, "--sign-timeout must be positive"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := l.sub(t).fail(exitUsage, tc.args...)
			wantContains(t, "stderr", r.stderr, tc.want)
			// No trust refusal borrows the decision sentence, which names
			// approve, reject and the other decisions and not the trust list.
			wantNotContains(t, "stderr", r.stderr, systemActorCannotDecide)
		})
	}
	// A public key file that is not one, and one with authorized_keys options.
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.pub")
	if err := os.WriteFile(bad, []byte("not a key\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	withOptions := filepath.Join(dir, "opts.pub")
	if err := os.WriteFile(withOptions, []byte("no-pty "+signing.MarshalKey(l.bob.Public)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	l.bootstrap(t)
	r := l.fail(exitFailure, "--ssh-key", l.alicePub, "trust", "add", "bob", "--key", bad)
	wantContains(t, "bad key file", r.stderr, "not an SSH public key")
	hostile := filepath.Join(dir, "\x1b[2Jbad.pub")
	if err := os.WriteFile(hostile, []byte("not a key\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r = l.fail(exitFailure, "--ssh-key", l.alicePub, "trust", "add", "bob", "--key", hostile)
	wantContains(t, "hostile key path", r.stderr, "not an SSH public key")
	if n := strings.Count(r.stderr, `\u{001B}`); n != 1 || strings.Contains(r.stderr, `\\u{001B}`) || strings.Contains(r.stderr, "\x1b") {
		t.Errorf("--key is escaped %d times in %q", n, r.stderr)
	}
	r = l.fail(exitFailure, "--ssh-key", l.alicePub, "trust", "add", "bob", "--key", withOptions)
	wantContains(t, "options", r.stderr, "carries options")
	r = l.fail(exitFailure, "--ssh-key", l.alicePub, "trust", "add", "bob", "--key", dir)
	wantContains(t, "directory", r.stderr, "is a directory")
}
