package main

import (
	"strings"
	"testing"
)

// Once a trust list is in force every one of the eight decisions needs a key:
// exit 2 with the fix, before anything about the tool is read.
func TestDecisionsRequireAKeyOnceATrustListIsInForce(t *testing.T) {
	t.Parallel()
	l := newSignedLab(t)
	l.bootstrap(t)
	echo := l.tool("s1", "echo").Pending
	before := l.verifiedHead()
	commands := [][]string{
		{"approve", "s1", "echo", "--hash", echo},
		{"reject", "s1", "echo", "--hash", echo},
		{"disable", "s1", "echo"},
		{"enable", "s1", "echo"},
		{"rollback", "s1", "echo", "--to", echo},
		{"server", "pause", "s1"},
		{"server", "resume", "s1"},
		{"budget", "reset", "s1", "echo"},
	}
	for _, args := range commands {
		t.Run(strings.Join(args[:2], " "), func(t *testing.T) {
			r := l.sub(t).fail(exitUsage, append([]string{"--as", "alice"}, args...)...)
			wantContains(t, "stderr", r.stderr, "signing is required since the trust bootstrap at entry ", "--ssh-key PATH", envSSHKey)
		})
	}
	if after := l.verifiedHead(); after != before {
		t.Errorf("a refused decision moved the head from %s to %s", before, after)
	}
}

func TestApproveSignsThroughTheAgentAndPrintsTheHead(t *testing.T) {
	t.Parallel()
	l := newSignedLab(t)
	_, head := l.bootstrap(t)
	echo := l.tool("s1", "echo").Pending
	out := l.ok("--ssh-key", l.alicePub, "approve", "s1", "echo", "--hash", echo[:shortDigestLen])
	wantContains(t, "approve", out, "approved s1/echo at "+echo, "signed as alice with "+fpOf(l.alice)+" over head "+head+"; audit head now ")
	_, _, over, now := signedAs(t, out)
	if over != head {
		t.Errorf("signed over %s, the head before was %s", over, head)
	}
	if verified := l.verifiedHead(); verified != now {
		t.Errorf("printed head %s, audit verify says %s", now, verified)
	}
	entries := l.auditEntries()
	var signed, approved auditRow
	for _, e := range entries {
		switch e.Event {
		case eventDecisionSigned:
			signed = e
		case "version.approved":
			approved = e
		}
	}
	if signed.Actor != "alice" || signed.Subject != "s1/echo" || !strings.HasPrefix(signed.Detail, "kind=approve digest="+echo+" signer="+fpOf(l.alice)+" sigref=") {
		t.Errorf("decision.signed entry = %+v", signed)
	}
	if approved.Seq <= signed.Seq || !strings.HasSuffix(approved.Detail, " signed="+itoa(signed.Seq)) {
		t.Errorf("version.approved entry = %+v, want it after seq %d and naming signed=%d", approved, signed.Seq, signed.Seq)
	}
	if tv := l.tool("s1", "echo"); tv.Approved != echo || tv.State != "enabled" {
		t.Errorf("after the signed approve: %+v", tv.toolJSON)
	}
	wantContains(t, "audit verify", l.ok("audit", "verify"), "signed records ok: 1 decisions and 1 trust lists verified")
}

func TestApproveDerivesTheActorFromTheKeyAndRefusesAMismatch(t *testing.T) {
	t.Parallel()
	l := newSignedLab(t)
	l.bootstrap(t)
	echo := l.tool("s1", "echo").Pending
	r := l.fail(exitUsage, "--as", "bob", "--ssh-key", l.alicePub, "approve", "s1", "echo", "--hash", echo)
	wantContains(t, "mismatch", r.stderr, "--as bob names another operator than the key "+fpOf(l.alice)+", which the trust list lists for alice")
	l.env[envActor] = "bob"
	r = l.fail(exitUsage, "--ssh-key", l.alicePub, "approve", "s1", "echo", "--hash", echo)
	wantContains(t, "env mismatch", r.stderr, "--as bob names another operator")
	delete(l.env, envActor)
	if tv := l.tool("s1", "echo"); tv.Approved != "" {
		t.Fatalf("a refused label approved: %+v", tv.toolJSON)
	}
	// No label at all: the key names the person.
	out := l.ok("--ssh-key", l.alicePub, "approve", "s1", "echo", "--hash", echo)
	if actor, _, _, _ := signedAs(t, out); actor != "alice" {
		t.Errorf("signed as %s, want alice", actor)
	}
	entries := l.auditEntries()
	if last := entries[len(entries)-1]; last.Event != "version.approved" || last.Actor != "alice" {
		t.Errorf("last entry = %+v", last)
	}
	// The same spelled upper-case is the same person after normalisation.
	l.ok("--as", "ALICE", "--ssh-key", l.alicePub, "disable", "s1", "echo")
}

func TestApproveRetriesOnceWhenTheHeadMovedWhileSigning(t *testing.T) {
	t.Parallel()
	l := newSignedLab(t)
	l.bootstrap(t)
	echo := l.tool("s1", "echo").Pending
	calls := 0
	once := func() {
		if calls++; calls == 1 {
			l.ok("crawl", "s1")
		}
	}
	r := l.runHooked(once, "--ssh-key", l.alicePub, "approve", "s1", "echo", "--hash", echo)
	if r.code != exitOK {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	wantContains(t, "stderr", r.stderr, "the log grew while you signed; signing again")
	wantContains(t, "stdout", r.stdout, "approved s1/echo at "+echo, "signed as alice with ")
	if calls != 2 {
		t.Errorf("signed %d times, want 2", calls)
	}
	_, _, over, now := signedAs(t, r.stdout)
	if over == now || l.verifiedHead() != now {
		t.Errorf("signed over %s, head now %s, verified %s", over, now, l.verifiedHead())
	}
	if n := strings.Count(l.ok("audit", "list"), eventDecisionSigned); n != 1 {
		t.Errorf("%d decision.signed entries, want 1: the first signature was never written", n)
	}

	// A log that moves under every signature is refused after the retry.
	l.ok("--ssh-key", l.alicePub, "disable", "s1", "echo")
	calls = 0
	always := func() { calls++; l.ok("crawl", "s1") }
	r = l.runHooked(always, "--ssh-key", l.alicePub, "enable", "s1", "echo")
	if r.code != exitFailure {
		t.Fatalf("exit %d, want 1\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	wantContains(t, "stderr", r.stderr, "the log grew while you signed; signing again", "the log moved twice while you signed; stop the scheduled crawl and try again", "audit head mismatch")
	if calls != 2 {
		t.Errorf("signed %d times, want exactly 2", calls)
	}
	if tv := l.tool("s1", "echo"); tv.State != "disabled" {
		t.Errorf("the refused enable changed the state: %+v", tv.toolJSON)
	}
}

func TestApproveExpectHeadRefusesAMovedLogWithoutARetry(t *testing.T) {
	t.Parallel()
	l := newSignedLab(t)
	_, head := l.bootstrap(t)
	echo := l.tool("s1", "echo").Pending
	// A stale head is refused before anything is signed.
	r := l.fail(exitFailure, "--ssh-key", l.alicePub, "approve", "s1", "echo", "--hash", echo, "--expect-head", strings.Repeat("0", 64))
	wantContains(t, "stale", r.stderr, "audit head mismatch", "expected 0000", "found "+head, "nothing was signed")
	wantNotContains(t, "stale", r.stderr, "signing again")
	// The value is escaped once, when the refusal is printed.
	r = l.fail(exitFailure, "--ssh-key", l.alicePub, "approve", "s1", "echo", "--hash", echo, "--expect-head", "\x1b[2Jdead")
	wantContains(t, "hostile head", r.stderr, "audit head mismatch")
	if n := strings.Count(r.stderr, `\u{001B}`); n != 1 || strings.Contains(r.stderr, `\\u{001B}`) || strings.Contains(r.stderr, "\x1b") {
		t.Errorf("--expect-head is escaped %d times in %q", n, r.stderr)
	}
	// The right head, moved under the signature: refused, no second signature.
	calls := 0
	move := func() { calls++; l.ok("crawl", "s1") }
	r = l.runHooked(move, "--ssh-key", l.alicePub, "approve", "s1", "echo", "--hash", echo, "--expect-head", strings.ToUpper(head))
	if r.code != exitFailure || calls != 1 {
		t.Fatalf("exit %d after %d signatures, want 1 and 1\nstdout: %s\nstderr: %s", r.code, calls, r.stdout, r.stderr)
	}
	wantContains(t, "moved", r.stderr, "audit head mismatch")
	wantNotContains(t, "moved", r.stderr, "signing again", "moved twice")
	if tv := l.tool("s1", "echo"); tv.Approved != "" {
		t.Fatalf("a refused approve was written: %+v", tv.toolJSON)
	}
	// The head as it is now: signed and written.
	now := l.verifiedHead()
	out := l.ok("--ssh-key", l.alicePub, "approve", "s1", "echo", "--hash", echo, "--expect-head", now)
	if _, _, over, _ := signedAs(t, out); over != now {
		t.Errorf("signed over %s, want %s", over, now)
	}
}

func TestApproveWithoutATrustListWarnsOnStderrAndRefusesAKey(t *testing.T) {
	t.Parallel()
	l := newSignedLab(t)
	echo := l.tool("s1", "echo").Pending
	r := l.fail(exitUsage, "--as", "alice", "--ssh-key", l.alicePub, "approve", "s1", "echo", "--hash", echo)
	wantContains(t, "key without a list", r.stderr, "the catalog has no trust list; run \"toolwarrant trust init\" first", "verified against")
	r = l.fail(exitUsage, "--as", "alice", "approve", "s1", "echo", "--hash", echo, "--expect-head", strings.Repeat("0", 64))
	wantContains(t, "expect-head without a list", r.stderr, "--expect-head compares the head inside a signed write and the catalog has no trust list")
	if tv := l.tool("s1", "echo"); tv.Approved != "" {
		t.Fatalf("a refused approve was written: %+v", tv.toolJSON)
	}
	r = l.run("--as", "alice", "approve", "s1", "echo", "--hash", echo)
	if r.code != exitOK {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	wantContains(t, "stdout", r.stdout, "approved s1/echo at "+echo)
	wantNotContains(t, "stdout", r.stdout, "signed as")
	wantContains(t, "stderr", r.stderr, "warning: this decision is not signed: the catalog has no trust list (L13)", "trust init")
	l.u.set("echo", echoV2)
	l.ok("crawl", "s1") // a proposal since the last decision, which a budget reset needs
	for _, args := range [][]string{{"budget", "reset", "s1", "echo"}, {"disable", "s1", "echo"}, {"server", "pause", "s1"}, {"server", "resume", "s1"}} {
		r = l.run(append([]string{"--as", "alice"}, args...)...)
		if r.code != exitOK || !strings.Contains(r.stderr, "this decision is not signed") {
			t.Errorf("%v: exit %d, stderr %q", args, r.code, r.stderr)
		}
	}
}

func TestRollbackRejectDisableEnablePauseResumeAndBudgetResetSignLikeApprove(t *testing.T) {
	t.Parallel()
	l := newSignedLab(t)
	l.bootstrap(t)
	v1 := l.tool("s1", "echo").Pending
	sign := func(kind string, args ...string) {
		t.Helper()
		out := l.ok(append([]string{"--ssh-key", l.alicePub}, args...)...)
		actor, fp, _, head := signedAs(t, out)
		if actor != "alice" || fp != fpOf(l.alice) || head != l.verifiedHead() {
			t.Fatalf("%v: signed as %s with %s, head %s (verified %s)", args, actor, fp, head, l.verifiedHead())
		}
		entries := l.auditEntries()
		var signed auditRow
		for _, e := range entries {
			if e.Event == eventDecisionSigned {
				signed = e
			}
		}
		if !strings.HasPrefix(signed.Detail, "kind="+kind+" ") {
			t.Fatalf("%v: newest decision.signed = %+v, want kind=%s", args, signed, kind)
		}
		for _, e := range entries[signed.Seq:] {
			if !strings.HasSuffix(e.Detail, " signed="+itoa(signed.Seq)) {
				t.Fatalf("%v: entry %+v does not name signed=%d", args, e, signed.Seq)
			}
		}
	}
	sign("approve", "approve", "s1", "echo", "--hash", v1)
	l.u.set("echo", echoV2)
	l.ok("crawl", "s1")
	v2 := l.tool("s1", "echo").Pending
	sign("reject", "reject", "s1", "echo", "--hash", v2)
	sign("disable", "disable", "s1", "echo")
	sign("enable", "enable", "s1", "echo")
	l.u.set("echo", echoV3)
	l.ok("crawl", "s1")
	v3 := l.tool("s1", "echo").Pending
	sign("approve", "approve", "s1", "echo", "--hash", v3)
	sign("rollback", "rollback", "s1", "echo", "--to", v1)
	sign("pause", "server", "pause", "s1")
	sign("resume", "server", "resume", "s1")
	l.u.set("echo", "Echoes, fourth draft.")
	l.ok("crawl", "s1") // a proposal since the last decision, which a budget reset needs
	sign("budget_reset", "budget", "reset", "s1", "echo")
	wantContains(t, "audit verify", l.ok("audit", "verify"), "signed records ok: 9 decisions and 1 trust lists verified")
	if tv := l.tool("s1", "echo"); tv.Approved != v1 || tv.State != "changed_pending_reapproval" {
		t.Errorf("after the signed history: %+v", tv.toolJSON)
	}
}

func TestDecisionsAfterTheBootstrapRefuseAnUnlistedKey(t *testing.T) {
	t.Parallel()
	l := newSignedLab(t)
	l.bootstrap(t)
	before := l.verifiedHead()
	echo := l.tool("s1", "echo").Pending
	r := l.fail(exitFailure, "--ssh-key", l.bobFile, "approve", "s1", "echo", "--hash", echo)
	wantContains(t, "unlisted", r.stderr, "the key "+fpOf(l.bob)+" is not in trust list v1", adviceNotASigner)
	if n := strings.Count(r.stderr, "trust show"); n != 1 {
		t.Errorf("the trust show advice appears %d times, want once:\n%s", n, r.stderr)
	}
	wantNotContains(t, "unlisted", r.stdout+r.stderr, "approved s1/echo", "PRIVATE KEY")
	if after := l.verifiedHead(); after != before {
		t.Errorf("the refused key moved the head from %s to %s", before, after)
	}
	if tv := l.tool("s1", "echo"); tv.Approved != "" {
		t.Errorf("the refused key approved: %+v", tv.toolJSON)
	}
}
