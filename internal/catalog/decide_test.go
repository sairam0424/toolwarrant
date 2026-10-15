package catalog

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
	"github.com/sairam0424/toolwarrant/internal/signing"
	"github.com/sairam0424/toolwarrant/internal/trust"
)

// Decide, the write side of signed decisions (D22 (b); O-13, O-16, O-17):
// what a signed decision writes, what it refuses, and the compare-and-set on
// prev_head.

// A signed approval writes the decision.signed entry first, chained from the
// head the payload names, then the lifecycle entries of the approval, each
// carrying signed=N with N the seq of that entry and all sharing its time; the
// entry's sigref token is the record's digest, the row holds the exact bytes,
// the receipt names the entry and the new head, the trust view counts one
// decision, and the snapshot serves the digest. A fresh Store verifies the
// record once at open.
func TestDecide_SignedApprovalWritesTheSignedEntryFirstAndTheLifecycleEntriesNameIt(t *testing.T) {
	t.Parallel()
	s, path, alice, _ := trustedCatalog(t)
	d := pendingSum(t)
	head, before := mustHead(t, s), auditCount(t, s)
	rec := signDecision(t, s, alice, signing.KindApprove, "alpha", "sum", d)
	r, err := s.Decide(bg, decisionFor(alice, signing.KindApprove, "alpha", "sum", d, rec))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if r.Seq != int64(before)+1 || r.Head != mustHead(t, s) {
		t.Errorf("Receipt = %+v, want seq %d and the new head %s", r, before+1, mustHead(t, s))
	}
	tx := entriesOfTransaction(t, s, r.Seq)
	if len(tx) != 2 || tx[0].Seq != r.Seq || tx[0].Event != evDecisionSigned || tx[1].Event != string(lifecycle.EvApproved) || tx[1].Hash != r.Head {
		t.Fatalf("the transaction wrote %d entries: %+v; want decision.signed then version.approved ending at the receipt's head", len(tx), tx)
	}
	signed := tx[0]
	if signed.PrevHash != head || signed.Subject != "alpha/sum" || signed.Actor != "alice" || signed.ActorType != string(ActorHuman) || signed.BeforeHash != "" || signed.AfterHash != "" {
		t.Errorf("decision.signed entry = %+v, want prev_hash %s about alpha/sum by alice with no before or after hash", signed, head)
	}
	if want := "kind=approve digest=" + d + " signer=" + alice.fp() + " sigref=" + signing.RecordDigest(*rec); signed.Detail != want {
		t.Errorf("detail = %q, want %q", signed.Detail, want)
	}
	if token, ok := detailField(tx[1].Detail, fieldSigned); !ok || token != itoa(r.Seq) || tx[1].AfterHash != d || !strings.HasSuffix(tx[1].Detail, signedNote(r.Seq)) {
		t.Errorf("version.approved detail = %q, want it to end with %q and to approve %s", tx[1].Detail, signedNote(r.Seq), d[:12])
	}
	var stored signing.Record
	if err := rawDB(t, path).QueryRowContext(bg, `SELECT payload, signer_fingerprint, signature FROM signed_records WHERE seq = ?`, r.Seq).
		Scan(&stored.Payload, &stored.Signer, &stored.Signature); err != nil {
		t.Fatalf("read the row: %v", err)
	}
	if string(stored.Payload) != string(rec.Payload) || stored.Signer != rec.Signer || string(stored.Signature) != string(rec.Signature) {
		t.Error("the row does not hold the exact record that was signed")
	}
	payload, err := signing.ParseDecision(stored.Payload)
	if err != nil || payload.PrevHead != signed.PrevHash {
		t.Errorf("stored prev_head %s, entry prev_hash %s (%v): the two must be one value", payload.PrevHead, signed.PrevHash, err)
	}
	if view := mustTrustList(t, s); view.SignedDecisions != 1 {
		t.Errorf("TrustList = %+v, want one signed decision", view)
	}
	if snap := mustSnapshot(t, s, "alpha"); !snap.Serves("sum", d) {
		t.Errorf("the signed approval is not served: %+v", snap.Tools["sum"])
	}
	mustBeClean(t, s, "after the signed approval")
	fresh, err := OpenWith(path, OpenOptions{ReadOnly: true})
	if err != nil {
		t.Fatalf("fresh open: %v", err)
	}
	defer func() { _ = fresh.Close() }()
	if n := fresh.chain.verifiedSignatures(); n != 3 {
		t.Errorf("a fresh open verified %d signatures, want 3: two trust records and one decision", n)
	}
	if snap := mustSnapshot(t, fresh, "alpha"); !snap.Serves("sum", d) {
		t.Error("a fresh Store does not serve the signed approval")
	}
}

// A payload signed over a head the log has left behind (a crawl landed
// between the read and the decision) is refused with ErrHeadMoved, nothing
// is written, and the same payload and signature a second time (a replay of
// a decision that was recorded) is refused the same way: the compare-and-set
// of finding 12 is the head, and the head moved when the decision was recorded.
func TestDecide_RefusesAPayloadWhosePrevHeadIsNotThePin(t *testing.T) {
	t.Parallel()
	s, path, alice, _ := trustedCatalog(t)
	d := pendingSum(t)
	stale := signDecision(t, s, alice, signing.KindApprove, "alpha", "sum", d)
	mustCrawl(t, s, "alpha", tool("echo", "v1"), tool("sum", "v1"), tool("new", "v1"))
	n, rows := auditCount(t, s), mustCount(t, rawDB(t, path), `SELECT COUNT(*) FROM signed_records`)
	_, err := s.Decide(bg, decisionFor(alice, signing.KindApprove, "alpha", "sum", d, stale))
	if !errors.Is(err, ErrHeadMoved) || !strings.Contains(err.Error(), "audit head mismatch") {
		t.Fatalf("Decide over a stale head = %v, want ErrHeadMoved", err)
	}
	if auditCount(t, s) != n || mustCount(t, rawDB(t, path), `SELECT COUNT(*) FROM signed_records`) != rows || mustTool(t, s, "alpha", "sum").Approved != "" {
		t.Fatal("the refused decision left something behind")
	}
	mustBeClean(t, s, "after the refusal")
}

// The same payload and signature a second time: the first Decide moved the
// head, so the replay names a prev_head that is no longer the pin.
func TestDecide_RefusesAReplayedSignature(t *testing.T) {
	t.Parallel()
	s, _, alice, _ := trustedCatalog(t)
	d := pendingSum(t)
	rec := signDecision(t, s, alice, signing.KindApprove, "alpha", "sum", d)
	if _, err := s.Decide(bg, decisionFor(alice, signing.KindApprove, "alpha", "sum", d, rec)); err != nil {
		t.Fatal(err)
	}
	n := auditCount(t, s)
	_, err := s.Decide(bg, decisionFor(alice, signing.KindApprove, "alpha", "sum", d, rec))
	if !errors.Is(err, ErrHeadMoved) {
		t.Fatalf("a replayed record = %v, want ErrHeadMoved", err)
	}
	if auditCount(t, s) != n {
		t.Error("the replay wrote something")
	}
}

// A decision signed for another catalog, byte for byte with its signature, is
// refused by the catalog it was not made for before any lock is taken: the
// identity is inside the signed bytes.
func TestDecide_RefusesAPayloadSignedForAnotherCatalog(t *testing.T) {
	t.Parallel()
	s, _, alice, _ := trustedCatalog(t)
	other, _, _, _ := trustedCatalog(t)
	d := pendingSum(t)
	foreign := signDecisionPayload(t, decisionOf(other.identity, mustHead(t, s), alice, signing.KindApprove, "alpha", "sum", d), alice)
	_, err := s.Decide(bg, decisionFor(alice, signing.KindApprove, "alpha", "sum", d, foreign))
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "signed for another catalog") {
		t.Fatalf("Decide with another catalog's payload = %v, want ErrInvalid naming the other catalog", err)
	}
	if mustTool(t, s, "alpha", "sum").Approved != "" {
		t.Error("the foreign decision approved something")
	}
}

// A valid signature from a key the list does not name is not authorisation
// (finding 6): refused as ErrNotASigner, nothing written.
func TestDecide_ValidSignatureFromAnUnlistedKeyIsNotAuthorization(t *testing.T) {
	t.Parallel()
	s, _, _, _ := trustedCatalog(t)
	carol := newOperator(t, "carol")
	d := pendingSum(t)
	rec := signDecision(t, s, carol, signing.KindApprove, "alpha", "sum", d)
	n := auditCount(t, s)
	_, err := s.Decide(bg, decisionFor(carol, signing.KindApprove, "alpha", "sum", d, rec))
	if !errors.Is(err, ErrNotASigner) || !errors.Is(err, trust.ErrUnauthorizedSigner) {
		t.Fatalf("Decide by an unlisted key = %v, want ErrNotASigner wrapping trust.ErrUnauthorizedSigner", err)
	}
	if auditCount(t, s) != n {
		t.Error("the refused decision wrote something")
	}
}

// A key the newest trust list no longer names signs nothing from the rotation
// on: bob decides under v2, is removed by v3, and his next decision is
// ErrNotASigner, while his earlier one stands (removal is not retroactive).
func TestDecide_RefusesAKeyRevokedByTheNewestTrustList(t *testing.T) {
	t.Parallel()
	s, _, alice, bob := trustedCatalog(t)
	d := pendingSum(t)
	mustDecide(t, s, bob, signing.KindApprove, "alpha", "sum", d)
	mustSetTrust(t, s, 3, alice, alice)
	rec := signDecision(t, s, bob, signing.KindDisable, "alpha", "sum", "")
	_, err := s.Decide(bg, decisionFor(bob, signing.KindDisable, "alpha", "sum", "", rec))
	if !errors.Is(err, ErrNotASigner) {
		t.Fatalf("Decide by a removed key = %v, want ErrNotASigner", err)
	}
	if snap := mustSnapshot(t, s, "alpha"); !snap.Serves("sum", d) {
		t.Error("bob's approval before his removal is no longer served; removal is not retroactive")
	}
	mustBeClean(t, s, "after the removal")
}

// --as is a label that must name the key's operator (O-13): a payload whose
// actor is bob, signed by alice's key, is refused with the key's owner named,
// and a payload whose actor is not the deciding actor is a usage error before
// any lock is taken.
func TestDecide_LabelMustEqualTheSignersOperatorName(t *testing.T) {
	t.Parallel()
	s, _, alice, bob := trustedCatalog(t)
	d := pendingSum(t)
	asBob := signDecisionPayload(t, signing.Decision{Actor: "bob", Catalog: s.identity, Digest: d, Kind: signing.KindApprove,
		PrevHead: mustHead(t, s), Server: "alpha", SignedAt: listSignedAt(), Signer: alice.fp(), Tool: "sum"}, alice)
	_, err := s.Decide(bg, decisionFor(bob, signing.KindApprove, "alpha", "sum", d, asBob))
	if !errors.Is(err, ErrNotASigner) || !errors.Is(err, trust.ErrAnotherOperatorsKey) || !strings.Contains(err.Error(), "the key belongs to alice") {
		t.Fatalf("alice's key under bob's name = %v, want ErrNotASigner saying the key belongs to alice", err)
	}
	mine := signDecision(t, s, alice, signing.KindApprove, "alpha", "sum", d)
	_, err = s.Decide(bg, Decision{Kind: signing.KindApprove, Server: "alpha", Tool: "sum", Digest: d, By: bob.actor(), Signed: mine})
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), `signed for actor "alice" but is made as "bob"`) {
		t.Fatalf("alice's payload made as bob = %v, want ErrInvalid naming both", err)
	}
	if mustTool(t, s, "alpha", "sum").Approved != "" {
		t.Error("a refused decision approved something")
	}
}

// Once a trust list is in force every one of the eight kinds is refused
// without a signed record, with the fixed sentence, and nothing is written;
// the old entry points are those unsigned decisions.
func TestDecide_UnsignedDecisionAfterTheBootstrapIsRefused(t *testing.T) {
	t.Parallel()
	s, _, _, _ := trustedCatalog(t)
	d := pendingSum(t)
	n := auditCount(t, s)
	unsigned := map[string]func() error{
		"approve":      func() error { return s.Approve(bg, "alpha", "sum", d, alice) },
		"reject":       func() error { return s.Reject(bg, "alpha", "sum", d, alice) },
		"rollback":     func() error { return s.Rollback(bg, "alpha", "echo", digestOf(t, "echo", "v1"), alice) },
		"disable":      func() error { return s.Disable(bg, "alpha", "echo", alice) },
		"enable":       func() error { return s.Enable(bg, "alpha", "echo", alice) },
		"pause":        func() error { return s.PauseServer(bg, "alpha", alice) },
		"resume":       func() error { return s.ResumeServer(bg, "alpha", alice) },
		"budget_reset": func() error { return s.ResetProposalBudget(bg, "alpha", "echo", alice) },
		"Decide without a record": func() error {
			_, err := s.Decide(bg, Decision{Kind: signing.KindApprove, Server: "alpha", Tool: "sum", Digest: d, By: alice})
			return err
		},
	}
	for name, run := range unsigned {
		if err := run(); !errors.Is(err, ErrSignatureRequired) || !strings.Contains(err.Error(), "this decision must be signed") {
			t.Errorf("%s unsigned after the bootstrap = %v, want ErrSignatureRequired", name, err)
		}
	}
	if auditCount(t, s) != n {
		t.Error("a refused unsigned decision wrote something")
	}
	mustBeClean(t, s, "after the refusals")
}

// Before any bootstrap the unsigned entry points write exactly what v0.3
// wrote: no decision.signed entry, no row, no signed= token, and the eight
// kinds all work (O-12).
func TestDecide_UnsignedDecisionBeforeTheBootstrapStillWorks(t *testing.T) {
	t.Parallel()
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	richHistory(t, s)
	mustBeClean(t, s, "after an unsigned history")
	entries, err := s.AuditEntries(bg, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Event == evDecisionSigned || strings.Contains(e.Detail, fieldSigned+"=") {
			t.Errorf("entry %d (%s) carries a signed token or record before any bootstrap: %q", e.Seq, e.Event, e.Detail)
		}
	}
	if n := mustCount(t, rawDB(t, path), `SELECT COUNT(*) FROM signed_records`); n != 0 {
		t.Errorf("%d signed_records rows before any bootstrap", n)
	}
	if r, err := s.Decide(bg, Decision{Kind: signing.KindDisable, Server: "alpha", Tool: "sum", By: alice}); err != nil || r.Seq != 0 || r.Head != mustHead(t, s) {
		t.Errorf("an unsigned Decide = %+v, %v; want seq 0 and the new head", r, err)
	}
	if rep := mustIntegrity(t, s); rep.LegacyApprovalsInService != nil {
		t.Errorf("legacy approvals listed without a bootstrap: %v", rep.LegacyApprovalsInService)
	}
}

// Every one of the eight kinds signs: the decision.signed entry comes first,
// its tokens name the kind and the digest (or none), every entry of the
// transaction carries its seq as signed=N, and the trust view counts them.
func TestDecide_EveryKindSignsAndItsEntriesCarryTheToken(t *testing.T) {
	t.Parallel()
	s, _, alice, bob := trustedCatalog(t)
	v1, v2, v3 := digestOf(t, "sum", "v1"), digestOf(t, "sum", "v2"), digestOf(t, "sum", "v3")
	steps := []struct {
		prepare func()
		by      operator
		kind    signing.Kind
		tool    string
		digest  string
		events  []string
	}{
		{nil, alice, signing.KindApprove, "sum", v1, []string{string(lifecycle.EvApproved)}},
		{func() { mustCrawl(t, s, "alpha", tool("sum", "v2")) }, bob, signing.KindReject, "sum", v2, []string{string(lifecycle.EvRejected)}},
		{func() { mustCrawl(t, s, "alpha", tool("sum", "v3")) }, alice, signing.KindApprove, "sum", v3, []string{string(lifecycle.EvSuperseded), string(lifecycle.EvApproved)}},
		{nil, bob, signing.KindRollback, "sum", v1, []string{string(lifecycle.EvSuperseded), string(lifecycle.EvRolledBack)}},
		{nil, alice, signing.KindDisable, "sum", "", []string{string(lifecycle.EvDisabled)}},
		{nil, bob, signing.KindEnable, "sum", "", []string{string(lifecycle.EvSuperseded), string(lifecycle.EvProposed), string(lifecycle.EvEnabled)}},
		{func() {
			for i := 0; i <= MaxProposalsPerDecision; i++ {
				mustCrawl(t, s, "alpha", tool("sum", fmt.Sprintf("b%02d", i)))
			}
		}, alice, signing.KindBudgetReset, "sum", "", []string{evBudgetReset}},
		{nil, bob, signing.KindPause, "", "", []string{evServerPaused}},
		{nil, alice, signing.KindResume, "", "", []string{evServerResumed}},
	}
	for i, st := range steps {
		if st.prepare != nil {
			st.prepare()
		}
		r := mustDecide(t, s, st.by, st.kind, "alpha", st.tool, st.digest)
		tx := entriesOfTransaction(t, s, r.Seq)
		if len(tx) != len(st.events)+1 || tx[0].Seq != r.Seq {
			t.Fatalf("step %d (%s): transaction = %v, want decision.signed then %v", i, st.kind, auditEventsOf(tx), st.events)
		}
		if k, _ := detailField(tx[0].Detail, fieldKind); k != string(st.kind) || tx[0].Subject != decisionSubject(st.kind, "alpha", st.tool) {
			t.Errorf("step %d: decision.signed = %+v, want kind %s about %s", i, tx[0], st.kind, decisionSubject(st.kind, "alpha", st.tool))
		}
		if dg, _ := detailField(tx[0].Detail, fieldDigest); dg != orNoDigest(st.digest) {
			t.Errorf("step %d: digest token %s, want %s", i, dg, orNoDigest(st.digest))
		}
		for j, e := range tx[1:] {
			if e.Event != st.events[j] || !strings.HasSuffix(e.Detail, signedNote(r.Seq)) || e.Actor != st.by.name {
				t.Errorf("step %d: entry %d = %s %q by %s, want %s ending with %q by %s", i, e.Seq, e.Event, e.Detail, e.Actor, st.events[j], signedNote(r.Seq), st.by.name)
			}
		}
	}
	if view := mustTrustList(t, s); view.SignedDecisions != len(steps) {
		t.Errorf("TrustList counts %d signed decisions, want %d", view.SignedDecisions, len(steps))
	}
	mustBeClean(t, s, "after every kind")
	if _, err := s.VerifyAudit(bg); err != nil {
		t.Error(err)
	}
}

// auditEventsOf lists the events of entries.
func auditEventsOf(entries []audit.Entry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Event)
	}
	return out
}

// A decision whose kind, digest or tool does not fit is refused before any
// lock is taken, and a signed decision whose payload names another decision
// than the one made is ErrInvalid.
func TestDecide_RefusesADecisionWhoseShapeOrPayloadDoesNotFit(t *testing.T) {
	t.Parallel()
	s, _, alice, _ := trustedCatalog(t)
	d := pendingSum(t)
	cases := map[string]Decision{
		"an unknown kind":           {Kind: "bless", Server: "alpha", Tool: "sum", By: alice.actor()},
		"a digest on a disable":     {Kind: signing.KindDisable, Server: "alpha", Tool: "sum", Digest: d, By: alice.actor()},
		"no digest on an approve":   {Kind: signing.KindApprove, Server: "alpha", Tool: "sum", By: alice.actor()},
		"a tool on a pause":         {Kind: signing.KindPause, Server: "alpha", Tool: "sum", By: alice.actor()},
		"no tool on an approve":     {Kind: signing.KindApprove, Server: "alpha", Digest: d, By: alice.actor()},
		"a payload of another tool": {Kind: signing.KindApprove, Server: "alpha", Tool: "sum", Digest: d, By: alice.actor(), Signed: signDecision(t, s, alice, signing.KindApprove, "alpha", "echo", d)},
		"a payload of another kind": {Kind: signing.KindApprove, Server: "alpha", Tool: "sum", Digest: d, By: alice.actor(), Signed: signDecision(t, s, alice, signing.KindReject, "alpha", "sum", d)},
	}
	for name, dec := range cases {
		if _, err := s.Decide(bg, dec); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s = %v, want ErrInvalid", name, err)
		}
	}
	if _, err := s.Decide(bg, Decision{Kind: signing.KindApprove, Server: "alpha", Tool: "sum", Digest: d, By: crawler}); !errors.Is(err, ErrHumanRequired) {
		t.Errorf("a system actor = %v, want ErrHumanRequired", err)
	}
	fresh := newStore(t)
	rec := signDecision(t, fresh, alice, signing.KindApprove, "alpha", "sum", d)
	if _, err := fresh.Decide(bg, decisionFor(alice, signing.KindApprove, "alpha", "sum", d, rec)); !errors.Is(err, ErrNoTrustList) {
		t.Errorf("a signed decision on a catalog without a trust list = %v, want ErrNoTrustList", err)
	}
	mustBeClean(t, s, "after the refusals")
}
