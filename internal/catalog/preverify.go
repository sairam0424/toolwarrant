package catalog

import (
	"context"
	"runtime"
	"sync"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/signing"
)

// The parallel half of the signed-record walk (D23 (a); the v0.5 plan, PR
// 8.1). Everything the walk requires of a signed entry before the stateful
// rules is pure in the entry, its row and the catalog identity: the record
// binding, the signature, the parse by kind and the payload binding
// (checkSignedEntryCrypto, trustwalk.go). A page's signed entries therefore go
// through a pool of goroutines that fill one slot per signed entry, in page
// order, and the serial loop of verifySignedEntries then consumes the slots in
// seq order and applies the rules exactly as before (checkSignedEntryRules):
// the trust fold, the authorisation against the list in force, the decision
// outcomes, the signed= binding and the continuity memory. A slot that holds a
// refusal is surfaced when the serial loop reaches its entry, so the first
// refusal in seq order is the one reported whatever the goroutines' timing,
// the walk stops there, the pin stays below it and nothing of the page is
// recorded (chainMemory.recordPage). The workers touch neither the page's
// outcome nor the memory: the closures over them stay in the serial loop. The
// context is read before every index is handed out and once more when the pool
// has ended, so a cancelled one stops the pool, no slot is written under a
// context cancelled before the pool started, and the walk returns the
// context's error, never a refusal.

// preverified is what the pure half produced for one signed entry: the parsed
// trust list or decision the rules consume, or the refusal, which the serial
// loop reports in seq order. Exactly one of the three is set.
type preverified struct {
	list     *signing.TrustList
	decision *signing.Decision
	err      error
}

// verifyWorkers is how many goroutines preverifyPage runs for n signed
// entries: one per entry up to the scheduler's parallelism, at least one.
func verifyWorkers(n int) int {
	return max(1, min(n, runtime.GOMAXPROCS(0)))
}

// preverifyPage runs checkSignedEntryCrypto over the signed entries of page in
// workers goroutines and returns one slot per signed entry, in page order. An
// entry without a row at its seq gets errNoSignedRecord in its slot. The
// goroutines read page, rows and identity and each write their own slots only,
// so the result does not depend on the order the entries were served in. Once
// ctx ends the pool stops between entries and the context's error is returned
// with no slots (fillSlots).
func preverifyPage(ctx context.Context, page []audit.Entry, rows map[int64]signing.Record, identity string, workers int) ([]preverified, error) {
	var signed []audit.Entry
	for _, e := range page {
		if isSignedEvent(e.Event) {
			signed = append(signed, e)
		}
	}
	slots := make([]preverified, len(signed))
	if len(signed) == 0 {
		return slots, nil
	}
	if err := fillSlots(ctx, slots, signed, rows, identity, workers); err != nil {
		return nil, err
	}
	return slots, nil
}

// fillSlots is the pool: workers goroutines, at most one per entry and at
// least one, take the indexes of signed from an unbuffered channel and each
// write their own slots, slots[i] for signed[i]. The feeder reads the context
// before every index (feedIndexes) and fillSlots reads it once more when every
// goroutine has ended, so under a context cancelled before the pool started no
// slot is written, and a cancellation that lands during the last send is still
// reported: the context's error comes back whenever ctx ended before the pool
// did, and the caller drops the slots.
func fillSlots(ctx context.Context, slots []preverified, signed []audit.Entry, rows map[int64]signing.Record, identity string, workers int) error {
	indexes := make(chan int)
	var wg sync.WaitGroup
	for range max(1, min(workers, len(signed))) {
		wg.Go(func() {
			for i := range indexes {
				slots[i] = preverifyEntry(signed[i], rows, identity)
			}
		})
	}
	err := feedIndexes(ctx, indexes, len(signed))
	wg.Wait()
	if err == nil {
		err = ctx.Err()
	}
	return err
}

// feedIndexes hands the indexes 0 to n-1 to the pool and closes the channel so
// that every worker ends. It reads the context before every send and stops at
// the first index it finds the context ended for, returning the context's
// error. The read comes first because a select alone between the send and
// ctx.Done() picks at random among the ready cases, so a worker parked on the
// channel could still be handed an index under a context that had ended.
func feedIndexes(ctx context.Context, indexes chan<- int, n int) error {
	defer close(indexes)
	for i := range n {
		if err := ctx.Err(); err != nil {
			return err
		}
		select {
		case indexes <- i:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// preverifyEntry is one slot's work: the row at the entry's seq, then the
// pure half of the check.
func preverifyEntry(e audit.Entry, rows map[int64]signing.Record, identity string) preverified {
	rec, ok := rows[e.Seq]
	if !ok {
		return preverified{err: errNoSignedRecord(e)}
	}
	return checkSignedEntryCrypto(e, rec, identity)
}

// checkSignedEntryCrypto is the pure half of a signed entry's check, the part
// the pool runs: rule 1 without cryptography (checkRecordBinding), the
// signature under the kind's namespace, the parse of the payload as the kind's
// canonical type and the payload binding (checkPayloadBinding), in that order,
// each refusal keeping the serial walk's sentence. It reads nothing but e, rec
// and identity. Until signing.Verify has pinned rec.Signer to the fingerprint
// of the key that signed, the signer is whatever the row holds, so the
// sentences before that point (checkRecordBinding's and the signature's) print
// it through quote; the sentences after it print a fingerprint the signature
// proved.
func checkSignedEntryCrypto(e audit.Entry, rec signing.Record, identity string) preverified {
	if err := checkRecordBinding(e, rec); err != nil {
		return preverified{err: err}
	}
	if _, err := signing.Verify(rec.Payload, rec.Signature, namespaceOf(e.Event), rec.Signer); err != nil {
		return preverified{err: problemf(ruleBinding, err, "signed record of entry %d: the signature by %s does not verify over the stored payload; the record was rewritten: %v", e.Seq, quote(rec.Signer), err)}
	}
	switch e.Event {
	case evTrustBootstrap, evTrustRotated:
		list, err := signing.ParseTrustList(rec.Payload)
		if err != nil {
			return preverified{err: problemf(ruleBinding, err, "signed record of entry %d is not a canonical trust list: %v", e.Seq, err)}
		}
		if err := checkPayloadBinding(e, rec.Signer, list.Signer, list.Catalog, list.PrevHead, identity); err != nil {
			return preverified{err: err}
		}
		return preverified{list: &list}
	case evDecisionSigned:
		d, err := signing.ParseDecision(rec.Payload)
		if err != nil {
			return preverified{err: problemf(ruleBinding, err, "signed record of entry %d is not a canonical decision: %v", e.Seq, err)}
		}
		if err := checkPayloadBinding(e, rec.Signer, d.Signer, d.Catalog, d.PrevHead, identity); err != nil {
			return preverified{err: err}
		}
		return preverified{decision: &d}
	}
	return preverified{err: problemf(ruleBinding, nil, "audit entry %d is a %s, which carries no signed record", e.Seq, e.Event)}
}

// signedResult is what checkSignedEntryRules returns for one accepted entry:
// the trust memory after it (changed by a trust record, carried by a decision)
// and the outcome of a decision record.
type signedResult struct {
	trust    trustMemory
	decision *signedOutcome
}

// checkSignedEntryRules is the stateful half of a signed entry's check, run in
// seq order by the one loop that owns the memory: a refusal the pure half
// recorded is reported first, as it would have been in the serial walk; then
// rule 3 for a trust list (checkTrustRecord, trustwalk.go) or rules 2 and 4
// for a decision (checkDecisionRecord, decisionwalk.go) against the trust
// memory in force at the entry. On refusal the returned memory is tm
// unchanged, so Integrity keeps the list in force past a refused record. The
// writers run the two halves on the entry they are about to store (Decide,
// SetTrust), so the reader, the writer and Integrity cannot drift apart.
func checkSignedEntryRules(e audit.Entry, rec signing.Record, pv preverified, tm trustMemory, pinnedRoot string) (signedResult, error) {
	switch {
	case pv.err != nil:
		return signedResult{trust: tm}, pv.err
	case pv.list != nil:
		next, err := checkTrustRecord(e, rec, *pv.list, tm, pinnedRoot)
		return signedResult{trust: next}, err
	case pv.decision != nil:
		outcome, err := checkDecisionRecord(e, rec, *pv.decision, tm.state)
		return signedResult{trust: tm, decision: outcome}, err
	}
	return signedResult{trust: tm}, problemf(ruleBinding, nil, "audit entry %d is a %s whose signed record was not verified", e.Seq, e.Event)
}
