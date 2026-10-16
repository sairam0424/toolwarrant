package main

import (
	"strings"
	"testing"
)

func TestServePrintsTheSignedDecisionsLineAndRefusesWithoutABootstrapUnderTrustRoot(t *testing.T) {
	t.Parallel()
	l := newSignedLab(t)
	out, _, stop := l.start("serve", "--server", "s1", "--listen", "127.0.0.1:0")
	waitListening(t, out)
	if code := stop(); code != exitOK {
		t.Fatalf("serve exit %d:\n%s", code, out.String())
	}
	wantContains(t, "no list", out.String(), "signed decisions: not enabled; the catalog has no trust list (L13 open); run \"toolwarrant trust init\"")

	root := fpOf(l.alice)
	r := l.fail(exitFailure, "--trust-root", root, "serve", "--server", "s1", "--listen", "127.0.0.1:0")
	wantContains(t, "pinned without a bootstrap", r.stderr, "no trust list", "trust root "+root, adviceNoTrustListPinned)
	wantNotContains(t, "pinned without a bootstrap", r.stderr, adviceCorrupt)
	wantNotContains(t, "pinned without a bootstrap", r.stdout, "listening on")

	_, _ = l.bootstrap(t)
	entries := l.auditEntries()
	bootstrap := entries[len(entries)-1].Seq
	for _, args := range [][]string{{}, {"--trust-root", root}} {
		out, _, stop = l.start(append(args, "serve", "--server", "s1", "--listen", "127.0.0.1:0")...)
		waitListening(t, out)
		if code := stop(); code != exitOK {
			t.Fatalf("serve %v exit %d:\n%s", args, code, out.String())
		}
		wantContains(t, "with a list", out.String(), "signed decisions: enforced from entry "+itoa(bootstrap+1)+" (trust list v1, 1 signers, root "+root+" at entry "+itoa(bootstrap)+")")
	}
}

func TestServeTrustRootRefusesAnotherBootstrap(t *testing.T) {
	t.Parallel()
	l := newSignedLab(t)
	root, _ := l.bootstrap(t)
	r := l.fail(exitFailure, "--trust-root", fpOf(l.bob), "serve", "--server", "s1", "--listen", "127.0.0.1:0")
	wantContains(t, "other root", r.stderr, "signed by "+root, "not the pinned trust root "+fpOf(l.bob), adviceCorrupt)
	wantNotContains(t, "other root", r.stdout, "listening on")
	l.env[envTrustRoot] = root
	out, _, stop := l.start("serve", "--server", "s1", "--listen", "127.0.0.1:0")
	waitListening(t, out)
	if code := stop(); code != exitOK {
		t.Fatalf("serve exit %d:\n%s", code, out.String())
	}
	wantContains(t, "right root", out.String(), "signed decisions: enforced from entry ")
}

// A correctly sealed version.approved appended by whoever can write the file
// after the bootstrap, without a key, makes the processor's next reload fail
// and every hook deny: nothing appended without a listed key can approve.
func TestServeDeniesEveryHookAfterAnUnsignedApprovalIsAppended(t *testing.T) {
	t.Parallel()
	l := newSignedLab(t)
	l.bootstrap(t)
	echo := l.tool("s1", "echo").Pending
	l.ok("--ssh-key", l.alicePub, "approve", "s1", "echo", "--hash", echo)
	out, errb, stop := l.start("serve", "--server", "s1", "--listen", "127.0.0.1:0")
	addr := waitListening(t, out)
	client, ctx := dial(t, addr)
	body := listBody(rawTools(t, l.u.url()))
	res, err := client.CheckResponse(ctx, listHook("s1", body, nil))
	if err != nil || res.GetMutated() == nil {
		t.Fatalf("list before the forgery = %v, %v", res, err)
	}
	if names := servedNames(t, res.GetMutated()); len(names) != 1 || names[0] != "echo" {
		t.Fatalf("served %v, want only echo", names)
	}
	allowed, err := client.CheckRequest(ctx, callHook("s1", "echo", nil))
	if err != nil || allowed.GetPass() == nil {
		t.Fatalf("echo call before the forgery = %v, %v", allowed, err)
	}

	add := l.tool("s1", "add").Pending
	seq := appendSealed(t, l.db, forgedApproval("alice", "s1", "add", add))
	denied, err := client.CheckResponse(ctx, listHook("s1", body, nil))
	if err != nil || denied.GetError() == nil || !strings.Contains(denied.GetError().GetReason(), "catalog unavailable") {
		t.Fatalf("list after the forgery = %v, %v; want a catalog unavailable denial", denied, err)
	}
	call, err := client.CheckRequest(ctx, callHook("s1", "echo", nil))
	if err != nil || call.GetError() == nil || !strings.Contains(call.GetError().GetReason(), "catalog unavailable") {
		t.Fatalf("echo call after the forgery = %v, %v; want a catalog unavailable denial", call, err)
	}
	forged, err := client.CheckRequest(ctx, callHook("s1", "add", nil))
	if err != nil || forged.GetError() == nil {
		t.Fatalf("add call after the forgery = %v, %v; want a denial", forged, err)
	}
	if code := stop(); code != exitOK {
		t.Fatalf("serve exit %d:\n%s", code, out.String())
	}
	wantContains(t, "serve stderr", errb.String(), "audit entry "+itoa(seq)+" is a version.approved after the trust bootstrap")
	// The CLI refuses the file too, and audit verify names the entry.
	r := l.fail(exitFailure, "list")
	wantContains(t, "list", r.stderr, "is a version.approved after the trust bootstrap", adviceCorrupt)
	r = l.fail(exitFailure, "audit", "verify")
	wantContains(t, "audit verify", r.stdout, "integrity problem: ", "audit entry "+itoa(seq)+" is a version.approved after the trust bootstrap")
}
