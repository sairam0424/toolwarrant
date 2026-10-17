package catalog

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/signing"
)

// The parallel half of the signed-record walk (D23 (a); the v0.5 plan, PR
// 8.1). The signatures of a page are verified by a pool of goroutines and the
// rules applied by one loop in seq order, so what is pinned here is that the
// pool changes nothing an observer can see: the memory after a page equals
// the serial result, the first refusal in seq order is the one reported
// whatever the worker count, a refused page records nothing, a cancelled
// context stops the pool and comes back as the context's error, and Integrity
// prints the refusals in seq order.

// genesisInput is the pageInput of a walk from the genesis over one page with
// workers goroutines: no memory before the page, no earlier outcome or state,
// as the open-time walk of a small catalog starts.
func genesisInput(identity string, workers int) pageInput {
	return pageInput{identity: identity, workers: workers,
		lookup:    func(int64) (signedOutcome, bool) { return signedOutcome{}, false },
		lastState: func(string) (toolLast, bool) { return toolLast{}, false }}
}

// workerCounts are the pool sizes every ordering test runs under: the serial
// case, a few small pools and more goroutines than the machine has cores.
func workerCounts() []int {
	return []int{1, 2, 3, runtime.NumCPU(), 2 * runtime.NumCPU()}
}

// swapSignedRows swaps the signed_records rows at seqs a and b under their
// entries, the no-update guard dropped and restored, and bumps the generation
// as any write would (the technique of
// TestWalk_RefusesASwappedSignedRecordBecauseTheTokenDisagrees): both entries'
// sigref tokens then disagree with their rows.
func swapSignedRows(t *testing.T, db *sql.DB, a, b int64) {
	t.Helper()
	rows, err := readSignedRecords(bg, db, []int64{a, b})
	if err != nil || len(rows) != 2 {
		t.Fatalf("read the two rows: %d, %v", len(rows), err)
	}
	mustExec(t, db, `DROP TRIGGER signed_records_no_update`)
	for from, to := range map[int64]int64{a: b, b: a} {
		rec := rows[from]
		mustExec(t, db, `UPDATE signed_records SET payload = ?, signer_fingerprint = ?, signature = ? WHERE seq = ?`, rec.Payload, rec.Signer, rec.Signature, to)
	}
	restoreGuard(t, db, "signed_records_no_update")
	mustExec(t, db, `UPDATE meta SET value = value + 1 WHERE key = 'generation'`)
}

// unlistedSentence is rule 4's refusal of a record signed by a key the list
// in force (version v) does not name.
func unlistedSentence(seq int64, by operator, v int) string {
	return fmt.Sprintf("signed record of entry %d: signer %s is not in trust list v%d in force at that entry", seq, by.fp(), v)
}

// The same page through one goroutine and through as many as the machine has
// cores gives the same memory after the page (the trust list in force, the
// decision outcomes, the open transaction, the tool states and the count of
// verified records), and, with a record the rules refuse appended, the same
// refusal: the pool computes what the serial loop then consumes, nothing more.
func TestWalk_ParallelVerificationGivesTheSerialResult(t *testing.T) {
	t.Parallel()
	s, path, alice, bob := trustedCatalog(t)
	carol := newOperator(t, "carol")
	mustDecide(t, s, alice, signing.KindApprove, "alpha", "sum", pendingSum(t))
	mustDecide(t, s, bob, signing.KindDisable, "alpha", "echo", "")
	mustCrawl(t, s, "alpha", tool("echo", "v1"), tool("sum", "v1"))
	mustDecide(t, s, bob, signing.KindEnable, "alpha", "echo", "")
	mustSetTrust(t, s, 3, bob, alice, bob, carol)
	db := rawDB(t, path)
	page := rawEntries(t, db)
	serial, err := verifySignedPage(bg, db, page, genesisInput(s.identity, 1))
	if err != nil {
		t.Fatalf("the serial walk: %v", err)
	}
	parallel, err := verifySignedPage(bg, db, page, genesisInput(s.identity, runtime.NumCPU()))
	if err != nil {
		t.Fatalf("the parallel walk: %v", err)
	}
	if serial.verified != 6 || len(serial.signed) != 3 || serial.trust.state.Current == nil || serial.trust.state.Current.Version != 3 {
		t.Fatalf("test setup: the serial walk verified %d records, %d decisions, list %+v; want 6, 3 and version 3", serial.verified, len(serial.signed), serial.trust.state)
	}
	if !reflect.DeepEqual(serial, parallel) {
		t.Errorf("the parallel walk differs from the serial one:\nserial   %+v\nparallel %+v", serial, parallel)
	}

	dave := newOperator(t, "dave")
	seq, _ := forgeDecision(t, db, s.identity, dave, dave.actor(), signing.KindApprove, "alpha", "echo", digestOf(t, "echo", "v1"))
	page = rawEntries(t, db)
	_, serialErr := verifySignedPage(bg, db, page, genesisInput(s.identity, 1))
	_, parallelErr := verifySignedPage(bg, db, page, genesisInput(s.identity, runtime.NumCPU()))
	wantCorruptNaming(t, "the serial walk", serialErr, unlistedSentence(seq, dave, 3))
	if parallelErr == nil || serialErr == nil || parallelErr.Error() != serialErr.Error() {
		t.Errorf("the parallel walk refuses with %v, the serial one with %v; the sentence is the same", parallelErr, serialErr)
	}
}

// Two records refused on one page (the bootstrap's and the rotation's rows
// swapped, so both sigref tokens disagree; two accepted decisions after them
// so the page holds more signed entries than the two): the sentence names the
// lower seq under every worker count, twenty runs each, since a slot's
// refusal is reported only when the serial loop reaches its entry, whatever
// the goroutines' timing; every fresh open says the same.
func TestWalk_FirstRefusalInSeqOrderWinsUnderParallelVerification(t *testing.T) {
	t.Parallel()
	s, path, alice, bob := trustedCatalog(t)
	mustDecide(t, s, alice, signing.KindApprove, "alpha", "sum", pendingSum(t))
	mustDecide(t, s, bob, signing.KindDisable, "alpha", "echo", "")
	view := mustTrustList(t, s)
	a, b := view.BootstrapSeq, view.ListSeq
	db := rawDB(t, path)
	swapSignedRows(t, db, a, b)
	first := fmt.Sprintf("the signed record of audit entry %d was replaced", a)
	second := fmt.Sprintf("the signed record of audit entry %d was replaced", b)
	page := rawEntries(t, db)
	for _, workers := range workerCounts() {
		for run := range 20 {
			_, err := verifySignedPage(bg, db, page, genesisInput(s.identity, workers))
			if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), first) || strings.Contains(err.Error(), second) {
				t.Fatalf("%d workers, run %d: %v; want ErrCorrupt naming entry %d, the first refusal in seq order, and not entry %d", workers, run, err, a, b)
			}
		}
	}
	opensRefuseNaming(t, path, first)
}

// suffixAfter is the file's entries past seq, read through a raw handle: the
// page a long-lived Store pinned at seq walks next.
func suffixAfter(t *testing.T, db *sql.DB, seq int64) []audit.Entry {
	t.Helper()
	var suffix []audit.Entry
	for _, e := range rawEntries(t, db) {
		if e.Seq > seq {
			suffix = append(suffix, e)
		}
	}
	return suffix
}

// poolAcceptsEveryRecord runs the pool alone over page and requires n slots,
// each holding a parsed decision and no refusal.
func poolAcceptsEveryRecord(t *testing.T, db *sql.DB, page []audit.Entry, identity string, n int) {
	t.Helper()
	rows, err := readSignedRecords(bg, db, signedSeqs(page))
	if err != nil {
		t.Fatal(err)
	}
	slots, err := preverifyPage(bg, page, rows, identity, runtime.NumCPU())
	if err != nil || len(slots) != n {
		t.Fatalf("preverifyPage over the page = %d slots, %v; want %d, one per signed record", len(slots), err, n)
	}
	for i, pv := range slots {
		if pv.err != nil || pv.decision == nil {
			t.Errorf("slot %d = %s; the pure half accepts every record of this page", i, describePreverified(pv))
		}
	}
}

// A page refused by the rules records nothing, though the pool verified every
// signature on it: three records appended past a long-lived Store's pin, an
// accepted one, one by an unlisted key and an accepted one after it. The pool
// fills all three slots and refuses none (the refusal is rule 4's, applied by
// the serial loop; poolAcceptsEveryRecord); the Store's next read refuses
// naming the unlisted record,
// its pin stays where it was, below the refused entry, its count of verified
// records does not move (the accepted record before the refusal sits on the
// refused page and is not counted), the accepted record's outcome is not
// remembered and the list in force is the one before the page.
func TestWalk_ARefusedPageVerifiesButRecordsNothing(t *testing.T) {
	t.Parallel()
	s, path, alice, _ := trustedCatalog(t)
	ro, err := OpenWith(path, OpenOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ro.Close() }()
	mustSnapshot(t, ro, "alpha")
	pin, verified := ro.loadPin(), ro.chain.verifiedSignatures()
	listBefore, _ := ro.chain.signedState()
	db, id := rawDB(t, path), s.identity
	dave := newOperator(t, "dave")
	accepted, _ := forgeDecision(t, db, id, alice, alice.actor(), signing.KindApprove, "alpha", "sum", pendingSum(t))
	refused, _ := forgeDecision(t, db, id, dave, dave.actor(), signing.KindApprove, "alpha", "echo", digestOf(t, "echo", "v1"))
	forgeDecision(t, db, id, alice, alice.actor(), signing.KindDisable, "alpha", "echo", "")
	poolAcceptsEveryRecord(t, db, suffixAfter(t, db, pin.seq), id, 3)

	sentence := unlistedSentence(refused, dave, 2)
	_, err = ro.Snapshot(bg, "alpha")
	wantCorruptNaming(t, "the long-lived Store's next Snapshot", err, sentence)
	if p := ro.loadPin(); p != pin || p.seq >= refused {
		t.Errorf("the pin moved from %d to %d; a refused page records nothing and the pin stays below entry %d", pin.seq, p.seq, refused)
	}
	if n := ro.chain.verifiedSignatures(); n != verified {
		t.Errorf("verified = %d, want %d: the accepted record at %d sits on the refused page and is not counted", n, verified, accepted)
	}
	if _, ok := ro.chain.lookupSigned(accepted); ok {
		t.Errorf("the outcome of the accepted record at %d was remembered from a refused page", accepted)
	}
	if listAfter, _ := ro.chain.signedState(); !reflect.DeepEqual(listAfter, listBefore) {
		t.Errorf("the trust memory moved from %+v to %+v on a refused page", listBefore, listAfter)
	}
	opensRefuseNaming(t, path, sentence)
}

// cancelAfterQuery is a queryer that runs each query under a context that
// cannot be cancelled and cancels the walk's own context once the query has
// returned: the rows of the page are read whole, and the pool is the first
// step of the walk to meet the cancellation.
type cancelAfterQuery struct {
	queryer
	cancel context.CancelFunc
}

// QueryContext runs the query to completion and then cancels the walk.
func (q cancelAfterQuery) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	rows, err := q.queryer.QueryContext(context.WithoutCancel(ctx), query, args...)
	q.cancel()
	return rows, err
}

// poolWritesNoSlotOnceCancelled runs the pool (fillSlots) over the signed
// entries of page under ctx, already cancelled, a hundred times per worker
// count, and requires the context's error and every slot untouched each time:
// the feeder reads the context before every index, so no goroutine is handed
// one. A select alone between the send and ctx.Done() would hand one out in a
// few percent of the runs on a page of this size, Go picking at random among
// the ready cases, and the walk would then run the rules on a cancelled
// context and could come back with a refusal, or with nothing wrong.
func poolWritesNoSlotOnceCancelled(t *testing.T, ctx context.Context, page []audit.Entry, rows map[int64]signing.Record, identity string) {
	t.Helper()
	signed := slices.DeleteFunc(slices.Clone(page), func(e audit.Entry) bool { return !isSignedEvent(e.Event) })
	for _, workers := range workerCounts() {
		for run := range 100 {
			slots := make([]preverified, len(signed))
			if err := fillSlots(ctx, slots, signed, rows, identity, workers); !errors.Is(err, context.Canceled) {
				t.Fatalf("%d workers, run %d: fillSlots under a cancelled context = %v; want context.Canceled", workers, run, err)
			}
			for i, pv := range slots {
				if pv != (preverified{}) {
					t.Fatalf("%d workers, run %d: slot %d was written (%s) under a context cancelled before the pool started", workers, run, i, describePreverified(pv))
				}
			}
		}
	}
}

// A cancelled context stops the pool between entries and the walk returns the
// context's error, bare, not a refusal: first the pool alone under a context
// cancelled before it starts (no slots, and over many runs no slot written,
// poolWritesNoSlotOnceCancelled), then the whole page walk under a context the
// row read cancels once the rows are in hand, on a page that holds a record
// the rules would refuse, which under a live context is the refusal the same
// page gets. The page carries eleven signed records so that the pool has
// goroutines parked on its channel when the feeder looks at the context.
func TestWalk_PreverifyHonoursTheContext(t *testing.T) {
	t.Parallel()
	s, path, alice, _ := trustedCatalog(t)
	db, id := rawDB(t, path), s.identity
	dave := newOperator(t, "dave")
	seq, _ := forgeDecision(t, db, id, dave, dave.actor(), signing.KindApprove, "alpha", "sum", pendingSum(t))
	for range 8 {
		forgeDecision(t, db, id, alice, alice.actor(), signing.KindDisable, "alpha", "echo", "")
	}
	page := rawEntries(t, db)
	rows, err := readSignedRecords(bg, db, signedSeqs(page))
	if err != nil || len(rows) != 11 {
		t.Fatalf("test setup: %d signed records, %v; want 11", len(rows), err)
	}

	cancelled, cancel := context.WithCancel(bg)
	cancel()
	slots, err := preverifyPage(cancelled, page, rows, id, runtime.NumCPU())
	if !errors.Is(err, context.Canceled) || slots != nil {
		t.Errorf("preverifyPage under a cancelled context = %d slots, %v; want no slots and context.Canceled", len(slots), err)
	}
	poolWritesNoSlotOnceCancelled(t, cancelled, page, rows, id)

	for _, workers := range workerCounts() {
		ctx, cancel := context.WithCancel(bg)
		defer cancel()
		_, err := verifySignedPage(ctx, cancelAfterQuery{queryer: db, cancel: cancel}, page, genesisInput(id, workers))
		if !errors.Is(err, context.Canceled) || err.Error() != context.Canceled.Error() {
			t.Errorf("%d workers: the walk under a context cancelled after the row read = %v; want context.Canceled itself, neither the refusal nor the row read's error", workers, err)
		}
	}
	_, err = verifySignedPage(bg, db, page, genesisInput(id, runtime.NumCPU()))
	wantCorruptNaming(t, "the same page under a live context", err, unlistedSentence(seq, dave, 2))
}

// problemIndex is the position of the first problem line holding fragment,
// -1 when none does.
func problemIndex(rep IntegrityReport, fragment string) int {
	return slices.IndexFunc(rep.Problems, func(p string) bool { return strings.Contains(p, fragment) })
}

// Integrity folds the preverified records in seq order: a record the rules
// refuse (an unlisted key) and, after it, one the pure half refuses (a payload
// naming another catalog) are two problem lines in that order whatever the
// pool's timing, each under SignedRecordsInvalid, an accepted record after
// both is not reported, since the fold keeps the list in force past a refused
// record, and the three existing Integrity tests through the fold hold.
func TestIntegrity_FoldsThePreverifiedRecordsInOrder(t *testing.T) {
	t.Parallel()
	s, path, alice, _ := trustedCatalog(t)
	mustDecide(t, s, alice, signing.KindApprove, "alpha", "sum", pendingSum(t))
	db, id := rawDB(t, path), s.identity
	dave := newOperator(t, "dave")
	other := strings.Repeat("00", identityBytes)
	unlisted, _ := forgeDecision(t, db, id, dave, dave.actor(), signing.KindApprove, "alpha", "echo", digestOf(t, "echo", "v1"))
	foreign, _ := forgeDecision(t, db, other, alice, alice.actor(), signing.KindDisable, "alpha", "echo", "")
	accepted, _ := forgeDecision(t, db, id, alice, alice.actor(), signing.KindDisable, "alpha", "echo", "")

	f := forensicOpen(t, path, "")
	if _, err := f.VerifyAudit(bg); err != nil {
		t.Errorf("VerifyAudit = %v; every forged entry is correctly sealed", err)
	}
	rep := mustIntegrity(t, f)
	if rep.SignedRecordsInvalid != 2 || rep.TrustListsInvalid != 0 || rep.ChainBreaks != 0 {
		t.Errorf("Integrity = %+v; want exactly the two refused records", rep)
	}
	first := unlistedSentence(unlisted, dave, 2)
	second := fmt.Sprintf("signed record of entry %d names catalog %s, not this one", foreign, other)
	problemMentioning(t, rep, first, second)
	if i, j := problemIndex(rep, first), problemIndex(rep, second); i < 0 || j < 0 || i > j {
		t.Errorf("the refusals of entries %d and %d are problem lines %d and %d; Integrity reports them in seq order", unlisted, foreign, i, j)
	}
	for _, p := range rep.Problems {
		if containsEntry(p, accepted) {
			t.Errorf("the accepted record at %d, after two refused ones, was reported: %q", accepted, p)
		}
	}
}
