package catalog

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
	"github.com/sairam0424/toolwarrant/internal/signing"
	"github.com/sairam0424/toolwarrant/internal/signing/sigtest"
	"github.com/sairam0424/toolwarrant/internal/trust"
)

// SetTrust, the write side of the trust list (D22 (c)): what a bootstrap and a
// rotation write, what they refuse, and the compare-and-set on prev_head.

// The bootstrap is one trust.bootstrap entry about @trust and one row at its
// seq: the entry's sigref token is the record's digest, its prev_hash is the
// head the payload named, the row holds the exact bytes that were signed, and
// the view shows version 1, the root and the seq. A fresh Store verifies it
// once at open and shows the same; a bootstrap on an empty log names the
// genesis.
func TestSetTrust_BootstrapWritesAVersionOneListSignedByItsOwnKeyAndBindsItToTheChain(t *testing.T) {
	t.Parallel()
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	d := approvedEcho(t, s) // the legacy history the bootstrap attests
	alice := newOperator(t, "alice")
	if view := mustTrustList(t, s); view.InForce() {
		t.Fatalf("a fresh catalog has a trust list: %+v", view)
	}
	before, head := auditCount(t, s), mustHead(t, s)
	rec := signList(t, listFor(s.identity, head, 1, alice, alice), alice.key)
	r, err := s.SetTrust(bg, rec, alice.actor())
	if err != nil {
		t.Fatalf("SetTrust: %v", err)
	}
	if r.Seq != int64(before)+1 || r.Head != mustHead(t, s) {
		t.Errorf("Receipt = %+v, want seq %d and the new head %s", r, before+1, mustHead(t, s))
	}
	e := entryOf(t, s, evTrustBootstrap)
	if e.Seq != r.Seq || e.Hash != r.Head || e.Subject != trustSubject || e.Actor != "alice" || e.ActorType != string(ActorHuman) ||
		e.PrevHash != head || e.BeforeHash != "" || e.AfterHash != "" {
		t.Errorf("bootstrap entry = %+v, want seq %d, hash %s, about %s by alice, prev_hash %s", e, r.Seq, r.Head, trustSubject, head)
	}
	want := "version=1 signers=1 signer=" + alice.fp() + " sigref=" + signing.RecordDigest(rec)
	if e.Detail != want {
		t.Errorf("detail = %q, want %q", e.Detail, want)
	}
	var stored signing.Record
	if err := rawDB(t, path).QueryRowContext(bg, `SELECT payload, signer_fingerprint, signature FROM signed_records WHERE seq = ?`, r.Seq).
		Scan(&stored.Payload, &stored.Signer, &stored.Signature); err != nil {
		t.Fatalf("read the row: %v", err)
	}
	if string(stored.Payload) != string(rec.Payload) || stored.Signer != rec.Signer || string(stored.Signature) != string(rec.Signature) {
		t.Error("the row does not hold the exact record that was signed")
	}
	list, err := signing.ParseTrustList(stored.Payload)
	if err != nil || list.PrevHead != e.PrevHash {
		t.Errorf("stored prev_head %s, entry prev_hash %s (%v): the two must be one value", list.PrevHead, e.PrevHash, err)
	}
	view := mustTrustList(t, s)
	if view.Version != 1 || view.BootstrapSeq != r.Seq || view.ListSeq != r.Seq || view.Root != alice.fp() || view.Lists != 1 || view.SignedDecisions != 0 ||
		!slices.Equal(signerNames(view), []string{"alice"}) || view.Signers[0].Fingerprint != alice.fp() {
		t.Errorf("TrustList = %+v", view)
	}
	mustBeClean(t, s, "after the bootstrap")
	if sum, err := s.VerifyAudit(bg); err != nil || sum.Head != r.Head {
		t.Errorf("VerifyAudit = %+v, %v; want head %s", sum, err, r.Head)
	}
	if snap := mustSnapshot(t, s, "alpha"); !snap.Serves("echo", d) {
		t.Error("the legacy approval is no longer served; the bootstrap attests the history, it does not revoke it (O-12)")
	}
	fresh, err := OpenWith(path, OpenOptions{ReadOnly: true})
	if err != nil {
		t.Fatalf("fresh open after the bootstrap: %v", err)
	}
	defer func() { _ = fresh.Close() }()
	if got := mustTrustList(t, fresh); got.Version != 1 || got.Root != alice.fp() || got.ListSeq != r.Seq {
		t.Errorf("fresh TrustList = %+v", got)
	}
	if n := fresh.chain.verifiedSignatures(); n != 1 {
		t.Errorf("a fresh open verified %d signatures, want 1", n)
	}

	empty := newStore(t)
	rec = signList(t, listFor(empty.identity, audit.Genesis, 1, alice, alice), alice.key)
	if r, err := empty.SetTrust(bg, rec, alice.actor()); err != nil || r.Seq != 1 {
		t.Fatalf("bootstrap on an empty log = %+v, %v", r, err)
	}
	if e := entryOf(t, empty, evTrustBootstrap); e.PrevHash != audit.Genesis {
		t.Errorf("the first entry's prev_hash = %s, want the genesis", e.PrevHash)
	}
}

// A second bootstrap, a rotation signed by a key the list in force does not
// hold, and a list naming a key outside the policy are each refused before
// anything is written; the key that cannot sign at all is refused by the
// signing package itself.
func TestSetTrust_RefusesASecondBootstrapAnUnlistedKeyAndAWeakKey(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	alice, bob, carol := newOperator(t, "alice"), newOperator(t, "bob"), newOperator(t, "carol")
	weak := operator{name: "bob", key: sigtest.GenerateRSA(t, 2048)}
	mustSetTrust(t, s, 1, alice, alice)
	head, n := mustHead(t, s), auditCount(t, s)
	id := s.identity
	for _, tc := range []struct {
		name    string
		rec     signing.Record
		by      operator
		wantErr []error
		text    string
	}{
		{"a second bootstrap", signList(t, listFor(id, head, 1, bob, bob), bob.key), bob, []error{ErrInvalid, trust.ErrSecondBootstrap}, "cannot start twice"},
		{"a rotation signed by an unlisted key", signList(t, listFor(id, head, 2, carol, alice, carol), carol.key), carol, []error{ErrNotASigner, trust.ErrSignerNotInBothLists}, "not signed by a key of both"},
		{"a list naming an RSA-2048 key", signList(t, listFor(id, head, 2, alice, alice, weak), alice.key), alice, []error{ErrInvalid, trust.ErrList, signing.ErrKeyPolicy}, "below 3072"},
	} {
		_, err := s.SetTrust(bg, tc.rec, tc.by.actor())
		for _, want := range tc.wantErr {
			if !errors.Is(err, want) {
				t.Errorf("%s: SetTrust = %v, want it to wrap %v", tc.name, err, want)
			}
		}
		if err == nil || !strings.Contains(err.Error(), tc.text) {
			t.Errorf("%s: SetTrust = %v, want %q", tc.name, err, tc.text)
		}
	}
	if _, err := signing.Sign(bg, []byte(`{}`), weak.key.Signer, signing.NamespaceTrust); !errors.Is(err, signing.ErrKeyPolicy) {
		t.Errorf("signing with an RSA-2048 key = %v, want ErrKeyPolicy", err)
	}
	if got := auditCount(t, s); got != n || mustHead(t, s) != head {
		t.Errorf("%d entries and head %s after the refusals, want %d and %s: nothing may be written", got, mustHead(t, s), n, head)
	}
	if view := mustTrustList(t, s); view.Version != 1 || view.Lists != 1 {
		t.Errorf("TrustList = %+v, want version 1 untouched", view)
	}
	mustBeClean(t, s, "after the refusals")
}

// A rotation signed by a key of both lists adds an operator; the new operator
// may then rotate in turn. The view follows: version, list seq, the root
// unchanged, the names in order.
func TestSetTrust_RotationAddsAKeySignedByAKeyOfBothLists(t *testing.T) {
	t.Parallel()
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	alice, bob, carol := newOperator(t, "alice"), newOperator(t, "bob"), newOperator(t, "carol")
	r1 := mustSetTrust(t, s, 1, alice, alice)
	r2 := mustSetTrust(t, s, 2, alice, alice, bob)
	view := mustTrustList(t, s)
	if view.Version != 2 || view.BootstrapSeq != r1.Seq || view.ListSeq != r2.Seq || view.Root != alice.fp() || view.Lists != 2 ||
		!slices.Equal(signerNames(view), []string{"alice", "bob"}) {
		t.Errorf("after the rotation: %+v", view)
	}
	e := entryOf(t, s, evTrustRotated)
	if e.Seq != r2.Seq || e.Hash != r2.Head || e.PrevHash != r1.Head || !strings.HasPrefix(e.Detail, "version=2 signers=2 signer="+alice.fp()+" sigref=") {
		t.Errorf("rotation entry = %+v", e)
	}
	r3 := mustSetTrust(t, s, 3, bob, alice, bob, carol)
	view = mustTrustList(t, s)
	if view.Version != 3 || view.ListSeq != r3.Seq || view.Root != alice.fp() || !slices.Equal(signerNames(view), []string{"alice", "bob", "carol"}) {
		t.Errorf("after bob's rotation: %+v", view)
	}
	mustBeClean(t, s, "after three lists")
	fresh, err := OpenWith(path, OpenOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fresh.Close() }()
	if got := mustTrustList(t, fresh); got.Version != 3 || got.Lists != 3 || fresh.chain.verifiedSignatures() != 3 {
		t.Errorf("fresh open: %+v, %d signatures verified; want version 3 and 3 verifications", got, fresh.chain.verifiedSignatures())
	}
}

// Removing a key takes a signature from a key that stays: a key cannot sign
// its own removal, the last signer cannot remove itself, and an empty list
// cannot even be marshalled. Revocation is publication of a list without the
// key (finding 10).
func TestSetTrust_RemovalNeedsAKeyThatStaysAndTheLastSignerCannotBeRemoved(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	alice, bob, carol := newOperator(t, "alice"), newOperator(t, "bob"), newOperator(t, "carol")
	mustSetTrust(t, s, 1, alice, alice)
	mustSetTrust(t, s, 2, alice, alice, bob)
	id := s.identity
	rec := signList(t, listFor(id, mustHead(t, s), 3, alice, bob), alice.key)
	if _, err := s.SetTrust(bg, rec, alice.actor()); !errors.Is(err, ErrNotASigner) || !errors.Is(err, trust.ErrSignerNotInBothLists) {
		t.Errorf("alice signing her own removal = %v, want ErrNotASigner", err)
	}
	r3 := mustSetTrust(t, s, 3, bob, bob)
	if view := mustTrustList(t, s); view.Version != 3 || view.ListSeq != r3.Seq || !slices.Equal(signerNames(view), []string{"bob"}) {
		t.Errorf("after bob removed alice: %+v", view)
	}
	rec = signList(t, listFor(id, mustHead(t, s), 4, bob, carol), bob.key)
	if _, err := s.SetTrust(bg, rec, bob.actor()); !errors.Is(err, ErrNotASigner) {
		t.Errorf("the last signer handing the list to a new key = %v, want ErrNotASigner", err)
	}
	if _, err := signing.MarshalTrustList(listFor(id, mustHead(t, s), 4, bob)); !errors.Is(err, signing.ErrPayload) {
		t.Errorf("an empty list = %v, want ErrPayload: a list is never emptied", err)
	}
	if view := mustTrustList(t, s); view.Version != 3 || !slices.Equal(signerNames(view), []string{"bob"}) {
		t.Errorf("after the refusals: %+v", view)
	}
	mustBeClean(t, s, "after the removals")
}

// A list signed for another catalog is refused by the catalog it was not
// signed for and accepted by the one it was: the identity is inside the
// signed bytes.
func TestSetTrust_RefusesAPayloadSignedForAnotherCatalog(t *testing.T) {
	t.Parallel()
	a, b := newStore(t), newStore(t)
	alice := newOperator(t, "alice")
	rec := signList(t, listFor(b.identity, audit.Genesis, 1, alice, alice), alice.key)
	_, err := a.SetTrust(bg, rec, alice.actor())
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "signed for another catalog") {
		t.Errorf("SetTrust with another catalog's identity = %v, want ErrInvalid naming the other catalog", err)
	}
	if auditCount(t, a) != 0 || mustTrustList(t, a).InForce() {
		t.Error("the refused record left something behind")
	}
	if _, err := b.SetTrust(bg, rec, alice.actor()); err != nil {
		t.Errorf("the same record on the catalog it names = %v", err)
	}
}

// Only a person records a trust list: the system actor and a malformed actor
// are refused before the record is looked at, and a read-only Store refuses
// to write one.
func TestSetTrust_RequiresAHumanActor(t *testing.T) {
	t.Parallel()
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	alice := newOperator(t, "alice")
	rec := signList(t, listFor(s.identity, audit.Genesis, 1, alice, alice), alice.key)
	if _, err := s.SetTrust(bg, rec, crawler); !errors.Is(err, ErrHumanRequired) {
		t.Errorf("SetTrust by the crawler = %v, want ErrHumanRequired", err)
	}
	if _, err := s.SetTrust(bg, rec, Actor{Name: "alice", Type: ActorType("robot")}); !errors.Is(err, ErrInvalid) {
		t.Errorf("SetTrust by an actor of an unknown type = %v, want ErrInvalid", err)
	}
	if auditCount(t, s) != 0 || mustTrustList(t, s).InForce() {
		t.Error("a refused actor wrote something")
	}
	ro, err := OpenWith(path, OpenOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ro.Close() }()
	if _, err := ro.SetTrust(bg, rec, alice.actor()); !errors.Is(err, ErrReadOnly) {
		t.Errorf("SetTrust on a read-only Store = %v, want ErrReadOnly", err)
	}
}

// TrustEntries lists the bootstrap and every rotation in sequence order and
// nothing else, through the subject index (the plan is pinned by
// TestAnchorQueries_StayOnTheAuditLogBySubjectIndex); before the bootstrap it
// is empty.
func TestTrustEntries_ListsTheBootstrapAndEveryRotationInOrder(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	approvedEcho(t, s)
	if entries, err := s.TrustEntries(bg); err != nil || len(entries) != 0 {
		t.Fatalf("TrustEntries before the bootstrap = %v, %v; want none", entries, err)
	}
	alice, bob := newOperator(t, "alice"), newOperator(t, "bob")
	bootstrap := mustSetTrust(t, s, 1, alice, alice)
	mustCrawl(t, s, "alpha", tool("echo", "v1"), tool("sum", "v1"))
	rotation := mustSetTrust(t, s, 2, alice, alice, bob)
	mustCrawl(t, s, "alpha", tool("echo", "v1"))
	entries, err := s.TrustEntries(bg)
	if err != nil {
		t.Fatalf("TrustEntries: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("TrustEntries returned %d entries, want the bootstrap and the rotation: %+v", len(entries), entries)
	}
	if entries[0].Seq != bootstrap.Seq || entries[0].Event != evTrustBootstrap || entries[1].Seq != rotation.Seq || entries[1].Event != evTrustRotated {
		t.Errorf("TrustEntries = %+v, want seq %d %s then seq %d %s", entries, bootstrap.Seq, evTrustBootstrap, rotation.Seq, evTrustRotated)
	}
	for _, e := range entries {
		if e.Subject != trustSubject {
			t.Errorf("entry %d is about %q, want %q", e.Seq, e.Subject, trustSubject)
		}
	}
}
