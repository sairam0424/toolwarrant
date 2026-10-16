package catalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// The verified chain (D15, D17). A Store verifies the whole audit chain once,
// when it opens (audit.VerifyFrom over a streamed read, from the genesis), and
// remembers two things about it: the head, the seq and hash of the newest
// entry it verified (the pin of D14 b), and the hash of every decision entry
// it walked (version.proposed, version.superseded, version.rejected,
// version.approved, version.rolled_back, tool.budget_reset, server.added,
// server.processor_set, server.paused, server.resumed, and every lifecycle
// event about a tool, tool.discovered to tool.unusable, whose newest entry
// anchors the tool's state), as the walk computed it from the entry's fields.
// Every later read verifies only the suffix appended after the head and
// extends the memory. Since D22 (c) the walk also verifies every signed entry
// of the pages it walks (trustwalk.go: the trust records once at open and the
// new ones on each reload, none on a crawl-only reload, O-15) and carries the
// trust list in force and the outcome of every verified decision record in
// the same memory; since D22 (b) and (d) it holds every entry after the
// bootstrap to the signed= binding and the crawl-transition guard
// (decisionwalk.go), and the anchor pass asks the memory whether an anchored
// human decision names a verified record (requireSigned). An audit entry is
// trusted on the serving path and on the
// decision path only when the hash computed from the fields read now equals
// the hash recorded for its seq in that walk (chainMemory.verify): the stored
// hash column is never consulted for trust, since whoever can write the file
// writes it too, and never keys a memory. A forger who rewrites one entry in
// place, however well it re-seals from its predecessor, is therefore refused
// as soon as the entry is read, by the Store that walked the original and by
// every Store that opens later and walks the chain the rewrite broke; to
// pass, the forger must rewrite every entry from the forged one to the head,
// which changes the head a running Store pinned and the head the operator
// recorded.
//
// The limit of the pin, stated as the code has it (D17 k): the pin protects
// only while a Store holds it. The processor's pin protects while a processor
// runs; the CLI opens a Store per command and is never protected by a pin.
// Any rewrite from the forged entry to the head made while no Store holds a
// pin, the whole chain or a suffix of it, verifies clean when the next Store
// opens and walks it, and is caught by the recorded head alone (audit verify
// with the recorded head), which is why operators record the head after every
// verify and compare it before every decision made after the processors were
// stopped. The fifth review showed why the previous rule (the newest approval
// entry re-sealed from its predecessor only, remembered by the stored hash
// column for ten minutes) was not enough: an entry below the head rewritten in
// place was served, and an after_hash edited with the hash column kept was
// served for ten minutes. The seventh review showed that a walk bounded by
// seq > 0 never read a row at seq 0 or below (D17 d, firstPossibleSeq) and that
// a reader whose snapshot predated the pin was told the log was truncated
// (D17 f, checkFile).

// chainPin is the newest audit entry a Store has verified: its seq and the
// hash computed from its fields. seq 0 means nothing verified yet, or an
// empty log.
type chainPin struct {
	seq  int64
	hash string
}

// entryHash is a verified entry's hash as bytes: a long-lived processor keeps
// one per decision entry of the log, so it is stored decoded.
type entryHash [sha256.Size]byte

// chainMemory is what a Store knows about the chain it verified; see the file
// comment. walkMu serialises the walks and the first statement of every
// checked read (checkFile), so two readers cannot verify one suffix with
// different contents and both record it, and no read compares its snapshot
// with a pin that a later snapshot set; mu guards the memory.
type chainMemory struct {
	walkMu sync.Mutex
	mu     sync.RWMutex
	head   chainPin
	hashes map[int64]entryHash
	// hashed counts the entries verify has hashed since the Store opened: the
	// anchor pass of every checked read, which is the only hashing that grows
	// with the tool count since D21 (d). The pin check and the suffix walk
	// hash through audit.HashOf and audit.VerifyFrom directly and are not
	// counted, so the hashes/op of the reload benchmarks and the count
	// TestBenchmarkSnapshotHashesOnlyAuditEntries pins are the anchor pass
	// alone.
	hashed atomic.Int64
	// trust is what the walk knows about the operator trust list, signed
	// what it recorded about every verified decision.signed entry, open the
	// decision transaction the head entry belongs to (seq 0 when none) and
	// states what the newest entry about each tool left it (trustwalk.go,
	// decisionwalk.go, decisioncontinuity.go); all four advance with the
	// walk, under mu. states holds one value per tool subject, never one per
	// entry, so a long-lived processor keeps it beside hashes.
	trust  trustMemory
	signed map[int64]signedOutcome
	open   openTxn
	states map[string]toolLast
	// verified counts the signatures the walks have verified since the Store
	// opened: every signed entry once at open, the new ones on each reload,
	// none on a crawl-only reload (O-15;
	// TestReload_ANewTrustListEntersTheStateOnTheSuffixWalk).
	verified atomic.Int64
}

func newChainMemory() *chainMemory {
	return &chainMemory{hashes: map[int64]entryHash{}, signed: map[int64]signedOutcome{}, states: map[string]toolLast{}}
}

// pin returns the head of the verified chain.
func (c *chainMemory) pin() chainPin {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.head
}

// recordPage extends the memory with one page of entries that walkChain has
// just verified in order. audit.VerifyFrom accepted the page, so each entry's
// Hash field equals the hash it computed from the entry's fields; that
// computed value is what is kept, for every decision entry and for the head.
// The page is walked first (verifySignedPage): the signed entries against the
// trust list in force as the memory holds it after the pages before, the
// others against the bootstrap, the decision outcomes and the tool states
// known at their point (rules 5 and 6), and nothing of the page is recorded
// when one entry is refused: the walk stops there, the pin stays below the
// refused entry,
// and the refusal is the ErrCorrupt the caller returns.
func (c *chainMemory) recordPage(ctx context.Context, q queryer, page []audit.Entry, identity, pinnedRoot string) error {
	if len(page) == 0 {
		return nil
	}
	c.mu.RLock()
	in := pageInput{trust: c.trust, open: c.open, identity: identity, pinnedRoot: pinnedRoot, lookup: c.lookupSigned, lastState: c.lookupState}
	c.mu.RUnlock()
	out, err := verifySignedPage(ctx, q, page, in)
	if err != nil {
		return err
	}
	c.verified.Add(int64(out.verified))
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range page {
		if !isChainRecordedEvent(e.Event) {
			continue
		}
		if h, ok := decodeEntryHash(e.Hash); ok {
			c.hashes[e.Seq] = h
		}
	}
	c.trust = out.trust
	c.open = out.open
	for seq, o := range out.signed {
		c.signed[seq] = o
	}
	for subject, l := range out.states {
		c.states[subject] = l
	}
	last := page[len(page)-1]
	c.head = chainPin{seq: last.Seq, hash: last.Hash}
	return nil
}

// decisions is how many decision entries the memory holds; tests read it.
func (c *chainMemory) decisions() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.hashes)
}

// drop forgets the chain. Close calls it, so a closed Store vouches for nothing.
func (c *chainMemory) drop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.head = chainPin{}
	c.hashes = map[int64]entryHash{}
	c.trust = trustMemory{}
	c.signed = map[int64]signedOutcome{}
	c.open = openTxn{}
	c.states = map[string]toolLast{}
}

// hashCount is the number of entries verify has hashed so far.
func (c *chainMemory) hashCount() int64 { return c.hashed.Load() }

// verify requires e, as read now, to be an entry of the verified chain: the
// hash computed from its fields must be the one the walk recorded for its
// seq. The Hash field of e is not looked at.
func (c *chainMemory) verify(e audit.Entry) error {
	c.hashed.Add(1)
	local, err := audit.HashOf(e)
	if err != nil {
		return fmt.Errorf("%w: audit entry %d about %s cannot be hashed: %v", ErrCorrupt, e.Seq, quote(e.Subject), err)
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	var want string
	switch {
	case e.Seq > c.head.seq:
		return fmt.Errorf("%w: audit entry %d about %s lies after the chain this store verified (head %d)", ErrCorrupt, e.Seq, quote(e.Subject), c.head.seq)
	case e.Seq == c.head.seq:
		want = c.head.hash
	default:
		h, ok := c.hashes[e.Seq]
		if !ok {
			return fmt.Errorf("%w: audit entry %d about %s is not a decision entry of the chain this store verified", ErrCorrupt, e.Seq, quote(e.Subject))
		}
		want = hex.EncodeToString(h[:])
	}
	if want != local {
		return errEntryRewritten(e.Seq, e.Subject)
	}
	return nil
}

// errEntryRewritten is the ErrCorrupt for an audit entry whose fields no longer
// hash to the value the Store verified in the chain: the log was rewritten.
func errEntryRewritten(seq int64, subject string) error {
	return fmt.Errorf("%w: audit entry %d about %s is not the entry this store verified in the chain (its fields hash to another value); the log was rewritten in place", ErrCorrupt, seq, quote(subject))
}

// isChainRecordedEvent reports whether the walk keeps an entry's hash: the
// events the serving and decision paths and the server views read back as
// evidence (server.added anchors a server's URL and allow_private flag,
// server.processor_set its processor address, server.paused and
// server.resumed its paused flag, and the newest lifecycle event about a tool
// its state column, D17 c), and the three signed events, whose entries the
// signed-record reads verify through the memory (D22 c).
func isChainRecordedEvent(event string) bool {
	switch event {
	case string(lifecycle.EvProposed), string(lifecycle.EvSuperseded), string(lifecycle.EvRejected),
		string(lifecycle.EvApproved), string(lifecycle.EvRolledBack), evBudgetReset, evServerAdded, evServerProcessorSet,
		evServerPaused, evServerResumed,
		string(lifecycle.EvDiscovered), string(lifecycle.EvDrifted), string(lifecycle.EvReverted), string(lifecycle.EvDisabled),
		string(lifecycle.EvEnabled), string(lifecycle.EvMissing), string(lifecycle.EvDeprecated), string(lifecycle.EvReappeared),
		string(lifecycle.EvReturned), string(lifecycle.EvUnusable),
		evDecisionSigned, evTrustBootstrap, evTrustRotated:
		return true
	}
	return false
}

// decodeEntryHash decodes a verified entry's hex hash; a value that is not 64
// hex characters cannot have passed audit.VerifyFrom and is not kept.
func decodeEntryHash(s string) (entryHash, bool) {
	var h entryHash
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(h) {
		return entryHash{}, false
	}
	copy(h[:], b)
	return h, true
}

// walkChain reads the entries after from.seq in pages, requires each page to
// continue the chain (audit.VerifyFrom; from the genesis when from is the zero
// pin) and hands every verified page to visit, which may be nil; an error
// from visit ends the walk and is returned as is, so a signed record the
// rules refuse stops the walk at its page. It returns the new head and the
// number of entries walked. A break is returned as audit.VerifyFrom reports
// it, unwrapped, so VerifyAudit can hand it on as is. A walk from the genesis
// starts at the smallest seq SQLite can store, bound included, so a row at
// seq 0 or below, which the catalog never writes, is read and refused as a
// break (expected seq 1) instead of skipped (D17 d).
func walkChain(ctx context.Context, q queryer, from chainPin, visit func([]audit.Entry) error) (chainPin, int, error) {
	prev := audit.Entry{Seq: from.seq, Hash: from.hash}
	next := prev.Seq + 1
	if from.seq == 0 {
		next = firstPossibleSeq
	}
	walked := 0
	for {
		page, err := queryAudit(ctx, q, next, auditPage)
		if err != nil {
			return chainPin{}, 0, err
		}
		if err := audit.VerifyFrom(prev, page); err != nil {
			return chainPin{}, 0, err
		}
		if visit != nil {
			if err := visit(page); err != nil {
				return chainPin{}, 0, err
			}
		}
		walked += len(page)
		if len(page) > 0 {
			prev = page[len(page)-1]
			next = prev.Seq + 1
		}
		if len(page) < auditPage {
			return chainPin{seq: prev.Seq, hash: prev.Hash}, walked, nil
		}
	}
}
