//go:build e2e

package e2e

import (
	"encoding/base64"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	// echoS and addS are the descriptions scenario S puts on mock's two
	// approved tools so that each has a pending digest to approve with a
	// signature; the shipped ones come back before the scenario ends.
	echoS = "Echoes the message back. Signed in scenario S."
	addS  = "Adds two numbers. Signed in scenario S."
	// addV1 is the mock upstream's shipped description of add
	// (cmd/mockupstream), as echoV1 is echo's.
	addV1 = "Adds two numbers."
	// noTrustListLine is what trust show prints before any list, and the
	// L13 warning is what every unsigned decision prints on stderr.
	noTrustListLine = "no trust list; decisions are attributed by name only (L13)"
	unsignedWarning = "warning: this decision is not signed: the catalog has no trust list (L13)"
	// decisionNamespace is the sshsig namespace of a decision record, the
	// -n argument of ssh-keygen -Y verify (internal/signing).
	decisionNamespace = "decision@toolwarrant.invalid"
	// eventDecisionSigned and eventCrawlCompleted are the two events the
	// audit list --json check reads: the first carries a signed record, the
	// second never does.
	eventDecisionSigned = "decision.signed"
	eventCrawlCompleted = "crawl.completed"
	// signedDecisionsPrefix starts the processor's line about the decisions
	// it serves (D22 (h)).
	signedDecisionsPrefix = "signed decisions: "
	// sshKeygen is the OpenSSH tool an auditor verifies a record with; the
	// sub-step skips loudly when it is not on PATH.
	sshKeygen = "ssh-keygen"
)

// auditEntryS is the part of one audit list --json entry scenario S reads:
// the seq, the event, the actor and the signed record, null for every event
// but the three signed ones.
type auditEntryS struct {
	Seq    int64  `json:"seq"`
	Event  string `json:"event"`
	Actor  string `json:"actor"`
	Signed *struct {
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
		Signer    string `json:"signer"`
	} `json:"signed"`
}

// scenarioS: signed per-person decisions and the operator trust list through
// the built binary against the real gateway (D22; limit L13 closed with its
// stated residual). The lab agent of sshlab_test.go holds reviewer's and
// bob's keys; the catalog has served A to R unsigned. The scenario walks the
// operator's whole path: the refusals before the bootstrap, trust init and
// the root it prints, a decision without a key refused, the signed approve
// through the agent that the gateway then serves, the --as label held to the
// key, bob enrolled and approving with a key file and no agent, disable,
// enable and approve signed, what audit verify, a wrong --trust-root, audit
// list --json and stock ssh-keygen say, the rotation that removes and
// re-adds the reviewer, the two forgeries of orchestrator decision 14 through
// the built binary (an unsigned approval after the bootstrap; a crawl-shaped
// entry that leaves disabled), each refused by the processor at open and
// named by audit verify, the processor refused under a wrong root and served
// under the recorded one, and --expect-head against a stale head. It runs
// right after R, while mock is the only server, because it restarts mock's
// processor; it leaves the stack approving as the reviewer with her key and
// every later command under the recorded root.
func scenarioS(t *testing.T, s *stack) {
	lab := newSSHLab(t, s)
	s.authSock = lab.sock
	echoBefore, addBefore := s.tool(t, "mock", "echo"), s.tool(t, "mock", "add")
	scenarioSBootstrap(t, s, lab)
	scenarioSDecisions(t, s, lab)
	scenarioSAudit(t, s, lab)
	scenarioSRotation(t, s, lab)
	scenarioSForgeries(t, s, lab)
	scenarioSTrustRoot(t, s, lab)
	scenarioSRestore(t, s, echoBefore, addBefore)
}

// scenarioSBootstrap: trust show before any list; a key on a catalog without
// a list is a usage error naming trust init; trust init without an agent is
// refused; with the agent it records the bootstrap and prints the root and
// the head, which the scenario records as an operator would; a decision
// without a key is then a usage error naming --ssh-key.
func scenarioSBootstrap(t *testing.T, s *stack, lab *sshLab) {
	mustContain(t, "trust show before any list", s.twOK(t, "trust", "show"), noTrustListLine)
	s.describe(t, "mock", "echo", echoS)
	s.describe(t, "mock", "add", addS)
	mustContain(t, "crawl after the two drifts", s.twOK(t, "crawl", "mock"), "DRIFT", "changed=2")
	echoPending := s.pendingDigest(t, "mock", "echo")

	r := s.twFail(t, exitUsage, flagSSHKey, lab.reviewerPub, "approve", "mock", "echo", "--hash", echoPending)
	mustContain(t, "approve with a key and no trust list", r.stderr, "the catalog has no trust list", "trust init")
	r = s.withoutAgent(func() cliResult { return s.tw(t, nil, "--as", reviewer, flagSSHKey, lab.reviewerPub, "trust", "init") })
	if r.code != exitFailure {
		t.Fatalf("trust init with a .pub and no SSH_AUTH_SOCK: exit %d, want %d\nstdout: %s\nstderr: %s", r.code, exitFailure, r.stdout, r.stderr)
	}
	mustContain(t, "trust init without an agent", r.stderr, "SSH_AUTH_SOCK is not set", lab.reviewerFP)
	mustContain(t, "trust show after the refused init", s.twOK(t, "trust", "show"), noTrustListLine)

	out := s.twOK(t, "--as", reviewer, flagSSHKey, lab.reviewerPub, "trust", "init")
	mustContain(t, "trust init", out, "trust list v1 recorded at entry", reviewer+" "+lab.reviewerFP,
		"record the trust root "+lab.reviewerFP+" with the audit head", "pass it as --trust-root")
	lab.root = lab.reviewerFP
	lab.initHead = fieldAfter(out, "with the audit head ")
	seq, err := strconv.ParseInt(strings.TrimSuffix(fieldAfter(out, "recorded at entry "), ":"), 10, 64)
	if err != nil || len(lab.initHead) != hexDigestLen {
		t.Fatalf("trust init printed no entry number and head to record (%v, head %q):\n%s", err, lab.initHead, out)
	}
	lab.bootstrapSeq = seq
	if head := s.auditHead(t); head != lab.initHead {
		t.Errorf("trust init printed head %s but audit verify prints %s", lab.initHead[:shortDigest], head[:shortDigest])
	}
	s.note(t, "S: trust init recorded the bootstrap at entry %d with root %s and head %s; the operator records both outside the database", seq, lab.root, lab.initHead[:shortDigest])
	mustContain(t, "trust show after init", s.twOK(t, "trust", "show"), "trust list v1 (entry "+strconv.FormatInt(seq, 10)+")", "root "+lab.root, reviewer)

	r = s.twFail(t, exitUsage, "--as", reviewer, "approve", "mock", "echo", "--hash", echoPending)
	mustContain(t, "approve without a key after the bootstrap", r.stderr, "signing is required since the trust bootstrap at entry "+strconv.FormatInt(seq, 10), flagSSHKey)
}

// scenarioSDecisions: the signed approve of echo through the agent, which the
// gateway serves; --as naming another operator than the key is refused; bob
// is enrolled and approves add with his key file and no agent; disable,
// enable and approve signed as the reviewer.
func scenarioSDecisions(t *testing.T, s *stack, lab *sshLab) {
	s.sshKey = lab.reviewerPub
	echoPending, addPending := s.pendingDigest(t, "mock", "echo"), s.pendingDigest(t, "mock", "add")
	t0 := time.Now()
	r := s.approve(t, "mock", "echo", echoPending)
	signing := since(t0)
	mustContain(t, "signed approve", r.stdout, signedLinePrefix+reviewer+" with "+lab.reviewerFP+" over head ", "audit head now")
	cs := s.eventuallyServes(t, "mock", "echo")
	s.expectAllowed(t, cs, "echo", "hello")
	s.note(t, "S: the signed approve of echo through the agent took %s for the whole CLI run, signature included, and the gateway then served echo: %s", signing, strings.TrimSpace(lastLineWith(r.stdout, signedLinePrefix)))

	r = s.twFail(t, exitUsage, "--as", bob, flagSSHKey, lab.reviewerPub, "approve", "mock", "add", "--hash", addPending)
	mustContain(t, "--as bob with reviewer's key", r.stderr, "--as bob names another operator than the key "+lab.reviewerFP, "lists for "+reviewer)

	out := s.twOK(t, flagSSHKey, lab.reviewerPub, "trust", "add", bob, "--key", lab.bobPub)
	mustContain(t, "trust add bob", out, "trust list v2 recorded at entry", bob+" "+lab.bobFP, signedLinePrefix+reviewer)
	r = s.withoutAgent(func() cliResult {
		return s.tw(t, nil, flagSSHKey, lab.bobKey, "approve", "mock", "add", "--hash", addPending)
	})
	if r.code != exitOK {
		t.Fatalf("bob's approve with his key file and no agent: exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	mustContain(t, "bob's approve", r.stdout, "approved mock/add at "+addPending, signedLinePrefix+bob+" with "+lab.bobFP)
	cs = s.eventuallyServes(t, "mock", "add", "echo")
	s.expectAllowed(t, cs, "add", "5")

	mustContain(t, "signed disable", s.twOK(t, flagSSHKey, lab.reviewerPub, "disable", "mock", "echo"), "disabled mock/echo", signedLinePrefix+reviewer)
	cs = s.eventuallyServes(t, "mock", "add")
	s.expectDenied(t, cs, "echo")
	mustContain(t, "signed enable", s.twOK(t, flagSSHKey, lab.reviewerPub, "enable", "mock", "echo"), "state is now pending_review", signedLinePrefix+reviewer)
	row := s.tool(t, "mock", "echo")
	if row.Pending != echoPending {
		t.Fatalf("after the signed enable the pending digest is %q, want the previously approved %s", row.Pending, echoPending)
	}
	s.approve(t, "mock", "echo", row.Pending)
	s.expectAllowed(t, s.eventuallyServes(t, "mock", "add", "echo"), "echo", "hello")
}

// scenarioSAudit: audit verify counts the records, names the list in force
// and the root and lists no unsigned approval in service once both tools were
// re-approved signed; under the root of a key nobody enrolled it fails; audit
// list --json carries the records for the decisions and null for a crawl
// entry; stock ssh-keygen verifies one record against trust show's file.
func scenarioSAudit(t *testing.T, s *stack, lab *sshLab) {
	out := s.twOK(t, "audit", "verify")
	mustContain(t, "audit verify after the signed decisions", out, auditOKPrefix, "integrity ok",
		"signed records ok: 5 decisions and 2 trust lists verified", "trust list v2 in force", "root "+lab.root+" at entry "+strconv.FormatInt(lab.bootstrapSeq, 10))
	mustNotContain(t, "audit verify after both legacy approvals were re-approved signed", out, "unsigned approvals in service")
	s.note(t, "S: audit verify: %s", strings.TrimSpace(lastLineWith(out, "signed records ok")))

	r := s.twFail(t, exitFailure, flagTrustRoot, lab.strangerFP, "audit", "verify")
	mustContain(t, "audit verify under a stranger's root", r.stdout+r.stderr, "the trust bootstrap at entry "+strconv.FormatInt(lab.bootstrapSeq, 10)+" was signed by "+lab.reviewerFP+", not the pinned trust root "+lab.strangerFP)

	var entries []auditEntryS
	s.jsonInto(t, &entries, "audit", "list", "--json")
	var decisions, crawls int
	var reviewers *auditEntryS
	for i, e := range entries {
		switch {
		case e.Event == eventDecisionSigned && e.Signed == nil:
			t.Errorf("audit list --json: entry %d is a %s with a null signed field", e.Seq, e.Event)
		case e.Event == eventDecisionSigned:
			decisions++
			if reviewers == nil && e.Actor == reviewer && e.Signed.Signer == lab.reviewerFP {
				reviewers = &entries[i]
			}
		case e.Event == eventCrawlCompleted && e.Signed != nil:
			t.Errorf("audit list --json: entry %d is a %s with a signed record", e.Seq, e.Event)
		case e.Event == eventCrawlCompleted:
			crawls++
		}
	}
	if decisions != 5 || crawls == 0 || reviewers == nil {
		t.Fatalf("audit list --json: %d decision.signed entries with records (want 5), %d crawl entries without (want some), reviewer's record found %v", decisions, crawls, reviewers != nil)
	}
	s.verifyWithSSHKeygen(t, lab, reviewers)
}

// verifyWithSSHKeygen hands one decision record and trust show's
// allowed_signers file to the host's ssh-keygen -Y verify, the auditor's
// path that needs no toolwarrant binary, and records its verdict; without
// ssh-keygen on PATH it says so and moves on.
func (s *stack) verifyWithSSHKeygen(t *testing.T, lab *sshLab, e *auditEntryS) {
	t.Helper()
	keygen, err := exec.LookPath(sshKeygen)
	if err != nil {
		s.note(t, "S: %s is not on PATH (%v); the stock-OpenSSH verification of entry %d was not run", sshKeygen, err, e.Seq)
		return
	}
	allowed := s.writeLabFile(t, "allowed_signers", []byte(s.twOK(t, "trust", "show", "--allowed-signers")))
	payload, err := base64.StdEncoding.DecodeString(e.Signed.Payload)
	if err != nil {
		t.Fatalf("audit list --json: the payload of entry %d is not base64: %v", e.Seq, err)
	}
	payloadFile := s.writeLabFile(t, "payload", payload)
	sig := s.writeLabFile(t, "decision.sig", []byte(e.Signed.Signature))
	cmd := exec.Command(keygen, "-Y", "verify", "-f", allowed, "-I", reviewer, "-n", decisionNamespace, "-s", sig)
	cmd.Stdin = strings.NewReader(string(payload))
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), `Good "`+decisionNamespace+`" signature for `+reviewer) {
		t.Fatalf("%s -Y verify on entry %d (payload %s): %v\n%s", sshKeygen, e.Seq, payloadFile, err, out)
	}
	s.note(t, "S: %s -Y verify -f allowed_signers -I %s -n %s on the record of entry %d printed: %s", sshKeygen, reviewer, decisionNamespace, e.Seq, strings.TrimSpace(string(out)))
}
