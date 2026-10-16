package catalog

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
	"github.com/sairam0424/toolwarrant/internal/signing"
)

// The serving path under signed decisions (D21 (d) must hold): signature
// verification happens in the walk only, the anchor pass adds one parse and
// one lookup per anchored entry and reads no bytes, and a forged approval
// without a key is refused on every path.

// Two decision records swapped under their entries (the no-update guard
// dropped and restored): a read-only Store whose pin lay below them walks the
// suffix on its next Snapshot and refuses at the first, every fresh open
// refuses at open, and Integrity names both records and the two approvals
// that name them. The writer, whose pin lay above the rows, keeps serving:
// the serving path reads no row (O-15), the restart and audit verify catch
// the swap.
func TestSnapshot_SwappedSignedRecordRowIsCorrupt(t *testing.T) {
	t.Parallel()
	s, path, alice, bob := trustedCatalog(t)
	ro, err := OpenWith(path, OpenOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ro.Close() }()
	mustSnapshot(t, ro, "alpha")
	r1 := mustDecide(t, s, alice, signing.KindApprove, "alpha", "sum", pendingSum(t))
	mustCrawl(t, s, "alpha", tool("echo", "v1"), tool("sum", "v1"), tool("new", "v1"))
	r2 := mustDecide(t, s, bob, signing.KindApprove, "alpha", "new", digestOf(t, "new", "v1"))
	mustSnapshot(t, s, "alpha")
	db := rawDB(t, path)
	rows, err := readSignedRecords(bg, db, []int64{r1.Seq, r2.Seq})
	if err != nil || len(rows) != 2 {
		t.Fatalf("read the two rows: %d, %v", len(rows), err)
	}
	mustExec(t, db, `DROP TRIGGER signed_records_no_update`)
	for from, to := range map[int64]int64{r1.Seq: r2.Seq, r2.Seq: r1.Seq} {
		rec := rows[from]
		mustExec(t, db, `UPDATE signed_records SET payload = ?, signer_fingerprint = ?, signature = ? WHERE seq = ?`, rec.Payload, rec.Signer, rec.Signature, to)
	}
	restoreGuard(t, db, "signed_records_no_update")
	mustExec(t, db, `UPDATE meta SET value = value + 1 WHERE key = 'generation'`)
	sentence := fmt.Sprintf("the signed record of audit entry %d was replaced", r1.Seq)

	_, err = ro.Snapshot(bg, "alpha")
	wantCorruptNaming(t, "the read-only Store's Snapshot over the swapped rows", err, sentence)
	if pin := ro.loadPin(); pin.seq >= r1.Seq {
		t.Errorf("the read-only pin advanced to %d past the refused record at %d", pin.seq, r1.Seq)
	}
	if _, err := s.Snapshot(bg, "alpha"); err != nil {
		t.Errorf("the writer's Snapshot = %v; the swapped rows lie below its pin and the serving path reads none of them", err)
	}
	opensRefuseNaming(t, path, sentence)
	f := forensicOpen(t, path, "")
	if _, err := f.VerifyAudit(bg); err != nil {
		t.Errorf("VerifyAudit = %v; the chain is intact", err)
	}
	rep := mustIntegrity(t, f)
	if rep.SignedRecordsInvalid != 2 || rep.UnsignedDecisionsAfterBootstrap != 2 {
		t.Errorf("Integrity = %+v, want both records refused and both approvals naming them counted", rep)
	}
	problemMentioning(t, rep, sentence, fmt.Sprintf("the signed record of audit entry %d was replaced", r2.Seq))
}

// After the bootstrap the snapshot serves a signed approval from its anchored
// digest without reading the bytes (a bytes-only rewrite changes nothing it
// serves and nothing it hashes: one anchor entry per tool), and an approval
// appended without a signed record is refused on the same path. Extends
// TestSnapshot_ReadsNoCanonicalBytesAndStillServesTheAnchoredDigest.
func TestSnapshot_ServesOnlySignedApprovalsAfterTheBootstrapAndReadsNoBytes(t *testing.T) {
	t.Parallel()
	s, path, alice, _ := trustedCatalog(t)
	d := pendingSum(t)
	mustDecide(t, s, alice, signing.KindApprove, "alpha", "sum", d)
	before := mustSnapshot(t, s, "alpha")
	tamperCanonical(t, path, d, []byte(`{"name":"sum"}`))
	hashed, verified := s.chain.hashCount(), s.chain.verifiedSignatures()
	after := mustSnapshot(t, s, "alpha")
	if after.Tools["sum"] != before.Tools["sum"] || !after.Serves("sum", d) || !after.Serves("echo", digestOf(t, "echo", "v1")) {
		t.Errorf("policy after a bytes-only rewrite = %+v, want the anchored digests unchanged", after.Tools)
	}
	if got := s.chain.hashCount() - hashed; got != 2 {
		t.Errorf("the reload hashed %d entries, want 2: one anchor entry per tool, the signed= rule hashes nothing", got)
	}
	if s.chain.verifiedSignatures() != verified {
		t.Error("the reload verified a signature; the serving path verifies none")
	}
	if _, err := s.Versions(bg, "alpha", "sum"); !errors.Is(err, ErrCorrupt) {
		t.Errorf("Versions = %v, want ErrCorrupt: the paths that hand out bytes hash them", err)
	}
	mustCrawl(t, s, "alpha", tool("echo", "v1"), tool("sum", "v1"), tool("new", "v1"))
	seq := appendEntry(t, rawDB(t, path), forgedApproval(alice.actor(), "new", digestOf(t, "new", "v1"), "").entry())
	_, err := s.Snapshot(bg, "alpha")
	wantCorruptNaming(t, "Snapshot after an unsigned approval was appended", err, unsignedSentence(seq, string(lifecycle.EvApproved), mustTrustListSeq(t, path)))
}

// A crawl-only reload verifies no signature: the read-only Store verifies the
// record of a signed approval once, on the reload that meets it, and nothing
// on the reload after a crawl; the writer verifies its own record once, on
// the walk after the commit, and nothing on its own crawls.
func TestSnapshot_ReloadAfterACrawlVerifiesNoSignature(t *testing.T) {
	t.Parallel()
	s, path, alice, _ := trustedCatalog(t)
	ro, err := OpenWith(path, OpenOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ro.Close() }()
	mustSnapshot(t, ro, "alpha")
	base := ro.chain.verifiedSignatures()
	mustDecide(t, s, alice, signing.KindApprove, "alpha", "sum", pendingSum(t))
	mustSnapshot(t, ro, "alpha")
	if n := ro.chain.verifiedSignatures() - base; n != 1 {
		t.Errorf("the reload that met the signed approval verified %d signatures, want 1", n)
	}
	mustSnapshot(t, s, "alpha") // the writer walks its own record on the read after the commit
	writer := s.chain.verifiedSignatures()
	for i := 0; i < 3; i++ {
		mustCrawl(t, s, "alpha", tool("echo", "v1"), tool("sum", "v1"), tool("new", fmt.Sprintf("v%d", i)))
		mustSnapshot(t, ro, "alpha")
	}
	if n := ro.chain.verifiedSignatures() - base; n != 1 {
		t.Errorf("three crawl-only reloads verified %d more signatures, want 0", n-1)
	}
	mustSnapshot(t, s, "alpha")
	if s.chain.verifiedSignatures() != writer {
		t.Error("the writer re-verified a signature on a crawl-only reload")
	}
}

// Two signed approvals over one head, from two handles on one file: exactly
// one is recorded and the other is refused with ErrHeadMoved and writes
// nothing, round after round (finding 12). The loser signs again over the new
// head and wins the next round.
func TestConcurrency_TwoSignedApprovalsOverOneHeadLetExactlyOneWin(t *testing.T) {
	t.Parallel()
	s, path, alice, bob := trustedCatalog(t)
	other := openStore(t, path, lifecycle.DefaultPolicy())
	const rounds = 6
	names := make([]CrawledTool, 0, 2*rounds)
	for i := 0; i < 2*rounds; i++ {
		names = append(names, tool(fmt.Sprintf("t%02d", i), "v1"))
	}
	mustCrawl(t, s, "alpha", append(names, tool("echo", "v1"), tool("sum", "v1"))...)
	wins := map[string]int{}
	for i := 0; i < rounds; i++ {
		st, err := s.SigningState(bg)
		if err != nil {
			t.Fatal(err)
		}
		type attempt struct {
			who  operator
			s    *Store
			tool string
		}
		attempts := []attempt{{alice, s, fmt.Sprintf("t%02d", 2*i)}, {bob, other, fmt.Sprintf("t%02d", 2*i+1)}}
		errs := make([]error, len(attempts))
		var wg sync.WaitGroup
		for j, a := range attempts {
			d := digestOf(t, a.tool, "v1")
			rec := signDecisionPayload(t, decisionOf(st.Identity, st.Head, a.who, signing.KindApprove, "alpha", a.tool, d), a.who)
			wg.Go(func() {
				_, errs[j] = a.s.Decide(bg, decisionFor(a.who, signing.KindApprove, "alpha", a.tool, d, rec))
			})
		}
		wg.Wait()
		won, lost := 0, 0
		for j, err := range errs {
			switch {
			case err == nil:
				won++
				wins[attempts[j].who.name]++
			case errors.Is(err, ErrHeadMoved):
				lost++
			default:
				t.Fatalf("round %d, %s: %v", i, attempts[j].who.name, err)
			}
		}
		if won != 1 || lost != 1 {
			t.Fatalf("round %d: %d won and %d lost, want exactly one of each", i, won, lost)
		}
	}
	t.Logf("wins: %v", wins)
	if view := mustTrustList(t, s); view.SignedDecisions != rounds {
		t.Errorf("TrustList counts %d signed decisions, want %d: one per round", view.SignedDecisions, rounds)
	}
	checkPrevHeadsAreDecisionPrevHashes(t, path)
	mustBeClean(t, s, "after the rounds")
}

// checkPrevHeadsAreDecisionPrevHashes requires every decision record's
// prev_head to be the prev_hash of its entry.
func checkPrevHeadsAreDecisionPrevHashes(t *testing.T, path string) {
	t.Helper()
	db := rawDB(t, path)
	entries := rawEntries(t, db)
	rows, err := readSignedRecords(bg, db, signedSeqs(entries))
	if err != nil {
		t.Fatal(err)
	}
	for seq, rec := range rows {
		if entries[seq-1].Event != evDecisionSigned {
			continue
		}
		d, err := signing.ParseDecision(rec.Payload)
		if err != nil || d.PrevHead != entries[seq-1].PrevHash {
			t.Errorf("row %d: stored prev_head %s, entry prev_hash %s (%v)", seq, d.PrevHead, entries[seq-1].PrevHash, err)
		}
	}
}

// The review-style end-to-end forgery after the bootstrap, with no key: the
// guards dropped and re-created, the approvals row, the version status, the
// pointer and the state column written as an approval writes them, and a
// correctly sealed version.approved appended at the head. Open, Snapshot,
// Approved, Versions, every decision and Integrity refuse or name it, so the
// gate serves nothing of it; VerifyAudit alone is green, as D14 admits.
func TestReview_ForgedSignedApprovalWithoutAKeyIsRefusedEverywhere(t *testing.T) {
	t.Parallel()
	s, path, alice, _ := trustedCatalog(t)
	mustSnapshot(t, s, "alpha")
	d := pendingSum(t)
	db := rawDB(t, path)
	ddl := triggerDDL(t, db, "tool_versions_immutable")
	mustExec(t, db, `DROP TRIGGER tool_versions_immutable`)
	mustExec(t, db, `UPDATE tool_versions SET status = 'approved', ever_approved = 1 WHERE digest = ?`, d)
	mustExec(t, db, ddl)
	mustExec(t, db, `UPDATE tools SET state = 'enabled', approved_version_id = (SELECT id FROM tool_versions WHERE digest = ?), proposals_since_decision = 0 WHERE name = 'sum'`, d)
	entries := rawEntries(t, db)
	ts := entries[len(entries)-1].TS
	mustExec(t, db, `INSERT INTO approvals (version_id, decision, approver, actor_type, hash_seen, at) VALUES ((SELECT id FROM tool_versions WHERE digest = ?), 'approve', 'alice', 'human', ?, ?)`, d, d, ts)
	f := forgedApproval(alice.actor(), "sum", d, "")
	f.ts = ts
	seq := appendEntry(t, db, f.entry())
	sentence := unsignedSentence(seq, string(lifecycle.EvApproved), mustTrustListSeq(t, path))

	paths := map[string]func() error{
		"Snapshot": func() error { _, err := s.Snapshot(bg, "alpha"); return err },
		"Approved": func() error { _, err := s.Approved(bg); return err },
		"Versions": func() error { _, err := s.Versions(bg, "alpha", "sum"); return err },
		"Tools":    func() error { _, err := s.Tools(bg, "alpha"); return err },
		"a signed decision": func() error {
			rec := signDecisionPayload(t, decisionOf(s.identity, rawHead(t, db), alice, signing.KindDisable, "alpha", "sum", ""), alice)
			_, err := s.Decide(bg, decisionFor(alice, signing.KindDisable, "alpha", "sum", "", rec))
			return err
		},
		"a crawl": func() error {
			_, err := s.RecordCrawl(bg, crawlOf(tool("echo", "v1"), tool("sum", "v1")), crawler)
			return err
		},
	}
	for name, run := range paths {
		if err := run(); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), sentence) {
			t.Errorf("%s = %v, want ErrCorrupt naming the unsigned approval", name, err)
		}
	}
	opensRefuseNaming(t, path, sentence)
	fo := forensicOpen(t, path, "")
	if _, err := fo.VerifyAudit(bg); err != nil {
		t.Errorf("VerifyAudit = %v; the chain is intact, which is what D14 admits", err)
	}
	rep := mustIntegrity(t, fo)
	if rep.UnsignedDecisionsAfterBootstrap != 1 {
		t.Errorf("Integrity = %+v", rep)
	}
	problemMentioning(t, rep, sentence)
}
