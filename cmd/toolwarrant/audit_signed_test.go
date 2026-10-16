package main

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/signing"
)

func TestAuditVerifyReportsTheSignedRecordsAndLegacyApprovals(t *testing.T) {
	t.Parallel()
	l := newSignedLab(t)
	wantContains(t, "no list", l.ok("audit", "verify"), "signed records: none; the catalog has no trust list (L13 open)", "trust init", headReminder)
	echo := l.tool("s1", "echo").Pending
	l.approve("alice", "s1", "echo", echo) // a legacy approval, before the bootstrap
	root, _ := l.bootstrap(t)
	entries := l.auditEntries()
	bootstrap := entries[len(entries)-1]
	add := l.tool("s1", "add").Pending
	l.ok("--ssh-key", l.alicePub, "approve", "s1", "add", "--hash", add)
	out := l.ok("audit", "verify")
	wantContains(t, "verify", out, "audit log ok", "integrity ok",
		"signed records ok: 1 decisions and 1 trust lists verified; trust list v1 in force (alice "+root+"); root "+root+" at entry "+itoa(bootstrap.Seq)+"; "+itoa(bootstrap.Seq-1)+" entries before the bootstrap are unsigned history vouched for by alice",
		"unsigned approvals in service: 1 (approved before the cut-over at entry "+itoa(bootstrap.Seq)+"; re-approve them to sign them): s1/echo", headReminder)
	// Re-approving the legacy approval (disable, enable, approve, each
	// signed) removes it from the list.
	l.ok("--ssh-key", l.alicePub, "disable", "s1", "echo")
	l.ok("--ssh-key", l.alicePub, "enable", "s1", "echo")
	l.ok("--ssh-key", l.alicePub, "approve", "s1", "echo", "--hash", echo)
	out = l.ok("audit", "verify")
	wantContains(t, "re-approved", out, "signed records ok: 4 decisions and 1 trust lists verified")
	wantNotContains(t, "re-approved", out, "unsigned approvals in service")
}

// A record rewritten under its entry is named by the integrity report with
// the walk's sentence, and every other command refuses the file.
func TestAuditVerifyNamesAForgedSignedRecord(t *testing.T) {
	t.Parallel()
	l := newSignedLab(t)
	l.bootstrap(t)
	echo := l.tool("s1", "echo").Pending
	l.ok("--ssh-key", l.alicePub, "approve", "s1", "echo", "--hash", echo)
	var signedSeq int64
	for _, e := range l.auditEntries() {
		if e.Event == eventDecisionSigned {
			signedSeq = e.Seq
		}
	}
	replaceSignedRecord(t, l.db, signedSeq)
	r := l.fail(exitFailure, "audit", "verify")
	wantContains(t, "stdout", r.stdout, "audit log ok", "integrity problem: ", "signed record of audit entry "+itoa(signedSeq)+" was replaced")
	wantNotContains(t, "stdout", r.stdout, "integrity ok", "signed records ok", headReminder)
	wantContains(t, "stderr", r.stderr, "problem(s) listed above", adviceCorrupt)
	r = l.fail(exitFailure, "list")
	wantContains(t, "list", r.stderr, adviceCorrupt)
	r = l.fail(exitFailure, "--ssh-key", l.alicePub, "disable", "s1", "echo")
	wantContains(t, "disable", r.stderr, adviceCorrupt)
}

func TestAuditListJSONCarriesTheSignedRecord(t *testing.T) {
	t.Parallel()
	l := newSignedLab(t)
	l.bootstrap(t)
	echo := l.tool("s1", "echo").Pending
	l.ok("--ssh-key", l.alicePub, "approve", "s1", "echo", "--hash", echo)
	var rows []auditEntryJSON
	l.jsonInto(&rows, "audit", "list", "--json")
	signed := 0
	for _, e := range rows {
		if !isSignedEvent(e.Event) {
			if e.Signed != nil {
				t.Errorf("entry %d (%s) carries a record", e.Seq, e.Event)
			}
			continue
		}
		signed++
		if e.Signed == nil {
			t.Fatalf("entry %d (%s) carries no record", e.Seq, e.Event)
		}
		if e.Signed.Signer != fpOf(l.alice) || !strings.HasPrefix(e.Signed.Signature, "-----BEGIN SSH SIGNATURE-----\n") {
			t.Errorf("entry %d: signer %s, signature %q", e.Seq, e.Signed.Signer, e.Signed.Signature)
		}
		payload, err := base64.StdEncoding.DecodeString(e.Signed.Payload)
		if err != nil {
			t.Fatal(err)
		}
		want := signing.TypeDecision
		if isTrustEvent(e.Event) {
			want = signing.TypeTrustList
		}
		if !strings.Contains(string(payload), `"type":"`+want+`"`) {
			t.Errorf("entry %d: payload %s is not a %s", e.Seq, payload, want)
		}
		sig, err := signing.Unarmor([]byte(e.Signed.Signature))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := signing.Verify(payload, sig, signingNamespace(e.Event), e.Signed.Signer); err != nil {
			t.Errorf("entry %d: %v", e.Seq, err)
		}
	}
	if signed != 2 {
		t.Errorf("%d signed entries, want 2", signed)
	}
	// On a broken file the listing goes on with null in every signed field
	// and says why on stderr; audit verify is the judge.
	replaceSignedRecord(t, l.db, rows[len(rows)-3].Seq)
	r := l.run("audit", "list", "--json")
	if r.code != exitOK {
		t.Fatalf("audit list --json on the broken file: exit %d\n%s", r.code, r.stderr)
	}
	wantContains(t, "stderr", r.stderr, "signed records not shown: ", "run \"toolwarrant audit verify\"")
	var broken []auditEntryJSON
	l.jsonInto(&broken, "audit", "list", "--json")
	for _, e := range broken {
		if e.Signed != nil {
			t.Errorf("entry %d still carries a record on the broken file", e.Seq)
		}
	}
	if len(broken) != len(rows) {
		t.Errorf("%d entries listed, want %d", len(broken), len(rows))
	}
}

// signingNamespace is the namespace a signed event's record is verified under.
func signingNamespace(event string) signing.Namespace {
	if event == eventDecisionSigned {
		return signing.NamespaceDecision
	}
	return signing.NamespaceTrust
}
