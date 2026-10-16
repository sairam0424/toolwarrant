//go:build e2e

package e2e

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// scenarioSRotation: bob removes the reviewer; the last signer cannot remove
// itself; the removed key signs nothing from that entry on; bob adds the
// reviewer back so the later scenarios keep approving as her.
func scenarioSRotation(t *testing.T, s *stack, lab *sshLab) {
	out := s.twOK(t, flagSSHKey, lab.bobPub, "trust", "remove", reviewer)
	mustContain(t, "trust remove reviewer by bob", out, "trust list v3 recorded at entry", bob+" "+lab.bobFP, signedLinePrefix+bob, "decisions signed before this entry stand")
	mustNotContain(t, "trust remove reviewer by bob", out, reviewer+" "+lab.reviewerFP)
	head := s.auditHead(t)

	r := s.twFail(t, exitFailure, flagSSHKey, lab.bobPub, "trust", "remove", bob)
	mustContain(t, "trust remove of the last signer", r.stderr, "the trust list must keep at least one signer")
	echo := s.tool(t, "mock", "echo")
	r = s.twFail(t, exitFailure, "--as", reviewer, flagSSHKey, lab.reviewerPub, "approve", "mock", "echo", "--hash", echo.Approved)
	mustContain(t, "the removed reviewer's approve", r.stderr, "the key "+lab.reviewerFP+" is not in trust list v3")
	if h := s.auditHead(t); h != head {
		t.Errorf("the two refusals moved the audit head from %s to %s; a refused command writes nothing", head[:shortDigest], h[:shortDigest])
	}

	out = s.twOK(t, flagSSHKey, lab.bobPub, "trust", "add", reviewer, "--key", lab.reviewerPub)
	mustContain(t, "trust add reviewer by bob", out, "trust list v4 recorded at entry", reviewer+" "+lab.reviewerFP, bob+" "+lab.bobFP, signedLinePrefix+bob)
	s.note(t, "S: the rotation removed the reviewer (v3, signed by bob), refused bob's own removal as the last signer and the removed key's approve, and added the reviewer back (v4): %s", strings.TrimSpace(lastLineWith(out, "trust list v4")))
}

// scenarioSForgeries repeats the two decision forgeries of orchestrator
// decision 14 through the built binary, with mock's processor stopped and the
// catalog backed up first, as the recovery procedure has it: a correctly
// sealed version.approved of the pending wipe_database appended with raw SQL
// after the bootstrap, and, after a signed disable of echo, a correctly
// sealed crawl-shaped tool.reverted that leaves disabled with the state
// column edited to match. Each makes the processor exit 1 at open naming the
// entry and audit verify exit 1 naming it; the backup is restored after each.
func scenarioSForgeries(t *testing.T, s *stack, lab *sshLab) {
	stats := lastLineWith(s.stopProcessor(t, "mock"), statsPrefix)
	s.note(t, "S: mock's processor stopped before the forgeries printed: %s", stats)

	backup := s.backupCatalog(t, "unsigned-approval")
	wipe := s.tool(t, "mock", "wipe_database")
	if wipe.Pending == "" || wipe.Approved != "" {
		t.Fatalf("wipe_database must be pending and never approved for the forgery: %+v", wipe)
	}
	seq := appendSealed(t, s.db, forgedApproval(reviewer, "mock", "wipe_database", wipe.Pending))
	sentence := fmt.Sprintf("audit entry %d is a version.approved after the trust bootstrap (entry %d) and names no signed record", seq, lab.bootstrapSeq)
	s.expectForgeryRefused(t, lab, "an unsigned approval appended after the bootstrap", sentence)
	s.restoreCatalog(t, backup)
	mustContain(t, "audit verify after the restore", s.twOK(t, "audit", "verify"), auditOKPrefix, "integrity ok", "signed records ok")

	echo := s.tool(t, "mock", "echo")
	mustContain(t, "signed disable before the second forgery", s.twOK(t, flagSSHKey, lab.reviewerPub, "disable", "mock", "echo"), "disabled mock/echo", signedLinePrefix+reviewer)
	backup = s.backupCatalog(t, "crawl-shaped-revert")
	seq = appendSealed(t, s.db, forgedRevert("mock", "echo", echo.Approved))
	execSQL(t, s.db, `UPDATE tools SET state = 'enabled' WHERE name = 'echo'`)
	sentence = fmt.Sprintf(`audit entry %d moves tool "mock/echo" from "disabled" to "enabled" under event "tool.reverted", which no crawl can do`, seq)
	s.expectForgeryRefused(t, lab, "a crawl-shaped entry that leaves disabled", sentence)
	s.restoreCatalog(t, backup)

	mustContain(t, "signed enable after the restore", s.twOK(t, flagSSHKey, lab.reviewerPub, "enable", "mock", "echo"), "state is now pending_review")
	s.approve(t, "mock", "echo", s.tool(t, "mock", "echo").Pending)
}

// expectForgeryRefused starts mock's processor on the forged file without a
// root and requires it to exit 1 at open with the walk's sentence, then runs
// audit verify under the recorded root and requires exit 1 with the same
// sentence as an integrity problem.
func (s *stack) expectForgeryRefused(t *testing.T, lab *sshLab, what, sentence string) {
	t.Helper()
	code, out := s.startProcessorExpectingExit(t, "mock", "")
	if code != exitFailure {
		t.Errorf("the processor started on %s exited %d, want %d:\n%s", what, code, exitFailure, out)
	}
	mustContain(t, "the processor's output on "+what, out, sentence)
	r := s.tw(t, nil, flagTrustRoot, lab.root, "audit", "verify")
	if r.code != exitFailure {
		t.Errorf("audit verify on %s: exit %d, want %d\nstdout: %s\nstderr: %s", what, r.code, exitFailure, r.stdout, r.stderr)
	}
	mustContain(t, "audit verify on "+what, r.stdout, "integrity problem", sentence)
	s.note(t, "S: %s: the processor exited %d at open and audit verify exited %d, both naming %q", what, code, r.code, sentence)
}

// scenarioSTrustRoot: mock's processor restarted under the root of a key
// nobody enrolled exits 1 at open naming the bootstrap's signer; restarted
// under the recorded root it prints the signed-decisions line and serves, and
// from here on every command and processor of the run carries the root; a
// signed approve with --expect-head set to the head recorded at trust init is
// refused as a head mismatch and signs nothing.
func scenarioSTrustRoot(t *testing.T, s *stack, lab *sshLab) {
	code, out := s.startProcessorExpectingExit(t, "mock", lab.strangerFP)
	if code != exitFailure {
		t.Errorf("the processor under a stranger's --trust-root exited %d, want %d:\n%s", code, exitFailure, out)
	}
	wrong := fmt.Sprintf("the trust bootstrap at entry %d was signed by %s, not the pinned trust root %s", lab.bootstrapSeq, lab.reviewerFP, lab.strangerFP)
	mustContain(t, "the processor's output under a stranger's root", out, wrong)
	s.note(t, "S: under --trust-root %s the processor exited %d at open: %s", lab.strangerFP, code, wrong)

	s.trustRoot = lab.root
	_, entries := s.auditSummary(t)
	t0 := time.Now()
	p := s.startProcessor(t, "mock", nil)
	listening := since(t0)
	waitForOutput(t, p, signedDecisionsPrefix, 0)
	line := fmt.Sprintf("signed decisions: enforced from entry %d (trust list v4, 2 signers, root %s at entry %d)", lab.bootstrapSeq+1, lab.root, lab.bootstrapSeq)
	mustContain(t, "the processor's stdout under the recorded root", p.output(p.stdout), line)
	cs := s.eventuallyServes(t, "mock", "add", "echo")
	served := since(t0)
	s.expectAllowed(t, cs, "echo", "hello")
	s.expectDenied(t, cs, "wipe_database")
	s.note(t, "S: mock's processor restarted under --trust-root %s on a log of %d entries was listening %s after its start (the open-time walk verified every signed record) and served add and echo %s after it; it printed: %s", lab.root, entries, listening, served, line)

	echo := s.tool(t, "mock", "echo")
	r := s.twFail(t, exitFailure, flagSSHKey, lab.reviewerPub, "approve", "mock", "echo", "--hash", echo.Approved, "--expect-head", lab.initHead)
	mustContain(t, "approve with a stale --expect-head", r.stderr, "audit head mismatch: expected "+lab.initHead, "nothing was signed")
	mustNotContain(t, "approve with a stale --expect-head", r.stdout, signedLinePrefix)
}

// scenarioSRestore puts the shipped descriptions back on echo and add, crawls
// and re-approves both with signed decisions, so the stack serves what it
// served before S at the digests it was at, with the trust list, the key and
// the root in place for the scenarios that follow.
func scenarioSRestore(t *testing.T, s *stack, echoBefore, addBefore toolRow) {
	s.describe(t, "mock", "echo", echoV1)
	s.describe(t, "mock", "add", addV1)
	mustContain(t, "crawl after the shipped descriptions came back", s.twOK(t, "crawl", "mock"), "DRIFT", "changed=2")
	echo, add := s.tool(t, "mock", "echo"), s.tool(t, "mock", "add")
	if echo.Pending != echoBefore.Approved || add.Pending != addBefore.Approved {
		t.Fatalf("after the shipped descriptions came back the pending digests are echo %s and add %s, want the digests approved before S, %s and %s",
			echo.Pending, add.Pending, echoBefore.Approved, addBefore.Approved)
	}
	s.approve(t, "mock", "echo", echo.Pending)
	s.approve(t, "mock", "add", add.Pending)
	s.expectServing(t)
	_, entries := s.auditSummary(t)
	s.note(t, "S: the stack is back at the digests approved before S, with %d audit entries, every decision since the bootstrap signed, every command and processor under the recorded root from here on", entries)
}
