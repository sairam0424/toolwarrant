package catalog

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
	"github.com/sairam0424/toolwarrant/internal/trust"
)

// The pinned trust root, the suffix walk, the one-snapshot signing state, the
// forensic open and the integrity report over the trust records.

// With a trust root pinned, a catalog whose bootstrap another key signed is
// refused at open by a read-only and a read-write Store with the fixed
// sentence, and accepted under the right root; a forensic open applies the
// pin on its first view and its Integrity names the bootstrap (and, with no
// list in force after it, the rotation that followed). A root that is not a
// SHA256: fingerprint is ErrInvalid.
func TestOpen_PinnedTrustRootRefusesAnotherBootstrapAndAcceptsTheRightOne(t *testing.T) {
	t.Parallel()
	s, path, alice, bob := trustedCatalog(t)
	seq := mustTrustList(t, s).BootstrapSeq
	sentence := fmt.Sprintf("the trust bootstrap at entry %d was signed by %s, not the pinned trust root %s; the catalog was re-bootstrapped or replaced", seq, alice.fp(), bob.fp())
	for name, opts := range map[string]OpenOptions{"read-only": {ReadOnly: true}, "read-write": {Policy: lifecycle.DefaultPolicy()}} {
		opts.TrustRoot = bob.fp()
		wrong, err := OpenWith(path, opts)
		if wrong != nil {
			_ = wrong.Close()
		}
		wantCorruptNaming(t, name+" open under bob's root", err, sentence)
		if !errors.Is(err, trust.ErrNotThePinnedRoot) {
			t.Errorf("%s open under bob's root = %v, want it to wrap trust.ErrNotThePinnedRoot", name, err)
		}
		opts.TrustRoot = alice.fp()
		right, err := OpenWith(path, opts)
		if err != nil {
			t.Fatalf("%s open under alice's root: %v", name, err)
		}
		if view := mustTrustList(t, right); view.Version != 2 || view.Root != alice.fp() {
			t.Errorf("%s TrustList under the right root = %+v", name, view)
		}
		_ = right.Close()
	}
	f := forensicOpen(t, path, bob.fp())
	_, err := f.Tools(bg, "")
	wantCorruptNaming(t, "forensic Tools under bob's root", err, sentence)
	rep := mustIntegrity(t, f)
	if rep.TrustListsInvalid != 2 {
		t.Errorf("Integrity under bob's root = %+v, want the bootstrap refused and the rotation after it, which then finds no list in force", rep)
	}
	problemMentioning(t, rep, sentence, "before any bootstrap; no list is in force")
	if _, err := OpenWith(path, OpenOptions{ReadOnly: true, TrustRoot: "md5:not-a-fingerprint"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("open with a malformed root = %v, want ErrInvalid", err)
	}
}

// A trust root pinned against a catalog that was never bootstrapped is a
// refusal: the pin says the operator bootstrapped this catalog, so a file
// without a bootstrap is another file or a history cut back below it. Without
// the pin the catalog opens as v0.3 did; once bootstrapped, the pin accepts.
func TestOpen_PinnedTrustRootRefusesACatalogWithoutABootstrap(t *testing.T) {
	t.Parallel()
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	approvedEcho(t, s)
	alice := newOperator(t, "alice")
	for name, opts := range map[string]OpenOptions{"read-only": {ReadOnly: true}, "read-write": {Policy: lifecycle.DefaultPolicy()}} {
		opts.TrustRoot = alice.fp()
		pinned, err := OpenWith(path, opts)
		if pinned != nil {
			_ = pinned.Close()
		}
		wantCorruptNaming(t, name+" open with a root and no bootstrap", err, "the catalog has no trust list and a trust root")
		if !errors.Is(err, ErrNoTrustList) {
			t.Errorf("%s open = %v, want it to wrap ErrNoTrustList", name, err)
		}
		opts.TrustRoot = ""
		plain, err := OpenWith(path, opts)
		if err != nil {
			t.Fatalf("%s open without a root: %v", name, err)
		}
		_ = plain.Close()
	}
	mustSetTrust(t, s, 1, alice, alice)
	pinned, err := OpenWith(path, OpenOptions{ReadOnly: true, TrustRoot: alice.fp()})
	if err != nil {
		t.Fatalf("open with the root after the bootstrap: %v", err)
	}
	defer func() { _ = pinned.Close() }()
	if view := mustTrustList(t, pinned); view.Root != alice.fp() {
		t.Errorf("TrustList = %+v", view)
	}
}

// A long-lived read-only Store (the processor's) sees a new trust list on its
// next read without reopening: the suffix walk verifies the appended record,
// one signature per record, and a crawl-only reload verifies none (O-15).
// The writer's own memory and a fresh open count the same.
func TestReload_ANewTrustListEntersTheStateOnTheSuffixWalk(t *testing.T) {
	t.Parallel()
	w, path := newStoreAt(t, lifecycle.DefaultPolicy())
	mustAddServer(t, w, "alpha")
	mustCrawl(t, w, "alpha", tool("echo", "v1"))
	ro, err := OpenWith(path, OpenOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ro.Close() }()
	alice, bob := newOperator(t, "alice"), newOperator(t, "bob")
	if view := mustTrustList(t, ro); view.InForce() || ro.chain.verifiedSignatures() != 0 {
		t.Fatalf("before the bootstrap: %+v, %d verified", view, ro.chain.verifiedSignatures())
	}
	r1 := mustSetTrust(t, w, 1, alice, alice)
	if view := mustTrustList(t, ro); view.Version != 1 || view.ListSeq != r1.Seq || ro.chain.verifiedSignatures() != 1 {
		t.Errorf("after the bootstrap: %+v, %d verified; want version 1 and one verification", view, ro.chain.verifiedSignatures())
	}
	r2 := mustSetTrust(t, w, 2, alice, alice, bob)
	if view := mustTrustList(t, ro); view.Version != 2 || view.ListSeq != r2.Seq || len(view.Signers) != 2 || ro.chain.verifiedSignatures() != 2 {
		t.Errorf("after the rotation: %+v, %d verified; want version 2 and two verifications", view, ro.chain.verifiedSignatures())
	}
	mustCrawl(t, w, "alpha", tool("echo", "v2"))
	mustSnapshot(t, ro, "alpha")
	if view := mustTrustList(t, ro); view.Version != 2 || ro.chain.verifiedSignatures() != 2 {
		t.Errorf("after a crawl-only reload: %+v, %d verified; a crawl-only reload verifies no signature", view, ro.chain.verifiedSignatures())
	}
	mustSnapshot(t, w, "alpha")
	if n := w.chain.verifiedSignatures(); n != 2 {
		t.Errorf("the writer verified %d signatures, want 2: its own records once each, on the walk after each commit", n)
	}
	fresh, err := OpenWith(path, OpenOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fresh.Close() }()
	mustSnapshot(t, fresh, "alpha")
	if n := fresh.chain.verifiedSignatures(); n != 2 {
		t.Errorf("a fresh open verified %d signatures over two reads, want 2: every signed entry once at open", n)
	}
}

// signingSeen is one SigningState result: the head and the list version it
// came with.
type signingSeen struct {
	head    string
	version int
}

// The head, the identity and the trust list a signer is handed come from one
// snapshot (O-17): a writer rotates the list for pinRaceDuration while two
// readers, one on the writer's Store and one on a read-only Store of the same
// file, call SigningState throughout; every head a reader returned must be one
// the writer recorded, with the version that commit left.
func TestSigningState_IdentityHeadAndTrustComeFromOneSnapshot(t *testing.T) {
	t.Parallel()
	w, path := newStoreAt(t, lifecycle.DefaultPolicy())
	approvedEcho(t, w)
	alice, bob := newOperator(t, "alice"), newOperator(t, "bob")
	mustSetTrust(t, w, 1, alice, alice)
	ro, err := OpenWith(path, OpenOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ro.Close() }()
	states := map[string]int{}
	record := func(when string) {
		t.Helper()
		st, err := w.SigningState(bg)
		if err != nil {
			t.Fatalf("SigningState %s: %v", when, err)
		}
		states[st.Head] = st.Trust.Version
	}
	record("after the bootstrap")
	var (
		mu       sync.Mutex
		seen     []signingSeen
		firstErr error
		readers  sync.WaitGroup
	)
	stop := make(chan struct{})
	for _, r := range []*Store{w, ro} {
		readers.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				st, err := r.SigningState(bg)
				mu.Lock()
				if err != nil && firstErr == nil {
					firstErr = err
				} else if err == nil {
					seen = append(seen, signingSeen{head: st.Head, version: st.Trust.Version})
					if st.Identity != w.identity {
						firstErr = fmt.Errorf("identity %s, want %s", st.Identity, w.identity)
					}
				}
				mu.Unlock()
			}
		})
	}
	writes := 0
	for deadline := time.Now().Add(pinRaceDuration); time.Now().Before(deadline); writes++ {
		st, err := w.SigningState(bg)
		if err != nil {
			close(stop)
			t.Fatal(err)
		}
		ops := []operator{alice}
		if writes%2 == 0 {
			ops = append(ops, bob)
		}
		rec := signList(t, listFor(st.Identity, st.Head, st.Trust.Version+1, alice, ops...), alice.key)
		if _, err := w.SetTrust(bg, rec, alice.actor()); err != nil {
			close(stop)
			t.Fatalf("rotation %d: %v", writes, err)
		}
		record("after a rotation")
	}
	close(stop)
	readers.Wait()
	t.Logf("%d rotations, %d SigningState calls, %d distinct heads", writes, len(seen), len(states))
	if firstErr != nil {
		t.Fatalf("a reader failed: %v", firstErr)
	}
	if writes < 2 || len(seen) == 0 {
		t.Fatalf("the race was not exercised: %d writes, %d reads", writes, len(seen))
	}
	mismatches, unknown := 0, 0
	for _, r := range seen {
		want, ok := states[r.head]
		switch {
		case !ok:
			unknown++
		case want != r.version:
			mismatches++
		}
	}
	if mismatches != 0 || unknown != 0 {
		t.Errorf("%d results paired a list version with the head of another commit and %d named a head the writer never committed", mismatches, unknown)
	}
}

// A forensic open does not walk at open: it opens a file whose trust record
// the walk refuses, verifies the chain alone (VerifyAudit passes, the chain is
// intact), lists the entries, and names the record on its first checked view
// and in its integrity report, while a read-only open refuses the file at
// open.
func TestForensicOpen_VerifiesTrustLazilyAndNamesTheBrokenRecord(t *testing.T) {
	t.Parallel()
	s, path, alice, bob := trustedCatalog(t)
	carol := newOperator(t, "carol")
	seq := forgeTrust(t, rawDB(t, path), s.identity, evTrustRotated, 5, alice, alice.actor(), alice, bob, carol)
	sentence := fmt.Sprintf("trust list at entry %d has version 5, expected 3 (exactly one above the list in force)", seq)
	ro, err := OpenWith(path, OpenOptions{ReadOnly: true})
	if ro != nil {
		_ = ro.Close()
	}
	wantCorruptNaming(t, "read-only open", err, sentence)

	f := forensicOpen(t, path, "")
	if sum, err := f.VerifyAudit(bg); err != nil || int64(sum.Entries) != seq {
		t.Errorf("VerifyAudit = %+v, %v; the chain is intact up to the forged entry", sum, err)
	}
	if entries, err := f.AuditEntries(bg, 0, 0); err != nil || int64(len(entries)) != seq || entries[len(entries)-1].Event != evTrustRotated {
		t.Errorf("AuditEntries = %d, %v; the listing shows the forged entry", len(entries), err)
	}
	_, err = f.Tools(bg, "")
	wantCorruptNaming(t, "forensic Tools", err, sentence)
	_, err = f.TrustList(bg)
	wantCorruptNaming(t, "forensic TrustList", err, sentence)
	rep := mustIntegrity(t, f)
	if rep.TrustListsInvalid != 1 || rep.ChainBreaks != 0 {
		t.Errorf("Integrity = %+v", rep)
	}
	problemMentioning(t, rep, sentence)
}

// Integrity reports every trust problem the walk would refuse, one line each
// with the walk's sentence, and goes on past each refusal with the list in
// force unchanged, so a later well-formed rotation is folded; it also names a
// row of no signed entry and an entry of no row. The walk itself stops at the
// first refusal. Under a pinned root the bootstrap is refused and the records
// after it find no list.
func TestIntegrity_ReportsEveryTrustProblemTheWalkRefuses(t *testing.T) {
	t.Parallel()
	s, path, alice, bob := trustedCatalog(t)
	carol, dave := newOperator(t, "carol"), newOperator(t, "dave")
	db := rawDB(t, path)
	id := s.identity
	skipped := forgeTrust(t, db, id, evTrustRotated, 4, alice, alice.actor(), alice, bob, carol)
	second := forgeTrust(t, db, id, evTrustBootstrap, 1, carol, carol.actor(), carol)
	outsider := forgeTrust(t, db, id, evTrustRotated, 3, carol, carol.actor(), alice, bob, carol)
	accepted := forgeTrust(t, db, id, evTrustRotated, 3, bob, bob.actor(), alice, bob, carol)
	rec := signList(t, listFor(id, rawHead(t, db), 4, alice, alice, bob, carol, dave), alice.key)
	token := appendSigned(t, db, forgedEntry{by: alice.actor(), event: evTrustRotated, subject: trustSubject, detail: "version=7 signers=4"}, rec)
	mustExec(t, db, insertSignedRecordSQL, 1, rec.Payload, rec.Signer, rec.Signature) // an orphan row under the server.added entry
	f := forgedEntry{by: alice.actor(), event: evTrustRotated, subject: trustSubject, detail: "version=4 signers=4", withoutRow: true}
	rowless := appendSigned(t, db, f, signList(t, listFor(id, rawHead(t, db), 4, alice, alice, bob, carol, dave), alice.key))

	_, err := s.Snapshot(bg, "alpha")
	wantCorruptNaming(t, "the long-lived Store", err, fmt.Sprintf("trust list at entry %d has version 4, expected 3", skipped))
	fo := forensicOpen(t, path, "")
	if _, err := fo.VerifyAudit(bg); err != nil {
		t.Errorf("VerifyAudit = %v; every forged entry is correctly sealed", err)
	}
	rep := mustIntegrity(t, fo)
	if rep.TrustListsInvalid != 3 || rep.SignedRecordsInvalid != 2 || rep.SignedRecordsOrphaned != 1 || rep.ChainBreaks != 0 {
		t.Errorf("Integrity = %+v; want 3 refused lists, 2 invalid records, 1 orphan row", rep)
	}
	problemMentioning(t, rep,
		fmt.Sprintf("trust list at entry %d has version 4, expected 3 (exactly one above the list in force)", skipped),
		fmt.Sprintf("a second trust bootstrap at entry %d; the trust list cannot start twice", second),
		fmt.Sprintf("the trust list at entry %d is not signed by a key of both the list in force and the new list", outsider),
		fmt.Sprintf(`audit entry %d says version="7" but its signed trust list is version 4`, token),
		fmt.Sprintf("audit entry %d is a trust.rotated with no signed record at its seq", rowless),
		`signed_records row 1 belongs to audit entry 1, a "server.added", which carries no signed record`)
	for _, p := range rep.Problems {
		if strings.Contains(p, fmt.Sprintf("entry %d ", accepted)) {
			t.Errorf("the well-formed rotation at %d was reported: %q", accepted, p)
		}
	}
	pinned := forensicOpen(t, path, bob.fp())
	rep = mustIntegrity(t, pinned)
	problemMentioning(t, rep, fmt.Sprintf("the trust bootstrap at entry %d was signed by %s, not the pinned trust root %s", mustTrustListSeq(t, path), alice.fp(), bob.fp()))
}

// mustTrustListSeq reads the seq of the first trust.bootstrap entry of the
// file through a raw handle.
func mustTrustListSeq(t *testing.T, path string) int64 {
	t.Helper()
	for _, e := range rawEntries(t, rawDB(t, path)) {
		if e.Event == evTrustBootstrap {
			return e.Seq
		}
	}
	t.Fatal("no bootstrap entry")
	return 0
}
