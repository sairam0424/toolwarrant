package main

import (
	"testing"
)

func TestShowNamesTheSignerOrTheLegacyApproval(t *testing.T) {
	t.Parallel()
	l := newSignedLab(t)
	echo := l.tool("s1", "echo").Pending
	out := l.ok("show", "s1", "echo")
	wantNotContains(t, "nothing approved", out, "approved by")
	if tv := l.tool("s1", "echo"); tv.Signer != nil {
		t.Errorf("signer while nothing is approved: %+v", tv.Signer)
	}
	l.approve("alice", "s1", "echo", echo)
	wantContains(t, "no list", l.ok("show", "s1", "echo"), "approved by alice, unsigned (no trust list)")
	if tv := l.tool("s1", "echo"); tv.Signer != nil {
		t.Errorf("signer of an unsigned approval: %+v", tv.Signer)
	}
	l.bootstrap(t)
	entries := l.auditEntries()
	bootstrap := entries[len(entries)-1].Seq
	wantContains(t, "legacy", l.ok("show", "s1", "echo"), "approved by alice, unsigned (before the cut-over at entry "+itoa(bootstrap)+")")
	add := l.tool("s1", "add").Pending
	l.ok("--ssh-key", l.alicePub, "approve", "s1", "add", "--hash", add)
	entries = l.auditEntries()
	var signedSeq int64
	for _, e := range entries {
		if e.Event == eventDecisionSigned {
			signedSeq = e.Seq
		}
	}
	wantContains(t, "signed", l.ok("show", "s1", "add"), "approved by alice, signed with "+fpOf(l.alice)+" (audit entry "+itoa(signedSeq)+")")
	tv := l.tool("s1", "add")
	if tv.Signer == nil || tv.Signer.Operator != "alice" || tv.Signer.Key != fpOf(l.alice) || tv.Signer.Entry != signedSeq {
		t.Errorf("show --json signer = %+v, want alice %s at %d", tv.Signer, fpOf(l.alice), signedSeq)
	}
	// Re-approved after the bootstrap, echo is signed too.
	l.ok("--ssh-key", l.alicePub, "disable", "s1", "echo")
	l.ok("--ssh-key", l.alicePub, "enable", "s1", "echo")
	l.ok("--ssh-key", l.alicePub, "approve", "s1", "echo", "--hash", echo)
	wantContains(t, "re-approved", l.ok("show", "s1", "echo"), "approved by alice, signed with "+fpOf(l.alice))
}
