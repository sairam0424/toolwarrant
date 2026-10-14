package catalog

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
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
// extends the memory. An audit entry is trusted on the serving path and on the
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
	// hashed counts the entries verify has hashed since the Store opened. It
	// is the only SHA-256 a reload computes since D21 (d), so the reload
	// benchmarks report it as hashes/op and
	// TestBenchmarkSnapshotHashesOnlyAuditEntries pins the count.
	hashed atomic.Int64
}

func newChainMemory() *chainMemory { return &chainMemory{hashes: map[int64]entryHash{}} }

// pin returns the head of the verified chain.
func (c *chainMemory) pin() chainPin {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.head
}

// record extends the memory with one page of entries that walkChain has just
// verified in order. audit.VerifyFrom accepted the page, so each entry's Hash
// field equals the hash it computed from the entry's fields; that computed
// value is what is kept, for every decision entry and for the head.
func (c *chainMemory) record(page []audit.Entry) {
	if len(page) == 0 {
		return
	}
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
	last := page[len(page)-1]
	c.head = chainPin{seq: last.Seq, hash: last.Hash}
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
// its state column, D17 c).
func isChainRecordedEvent(event string) bool {
	switch event {
	case string(lifecycle.EvProposed), string(lifecycle.EvSuperseded), string(lifecycle.EvRejected),
		string(lifecycle.EvApproved), string(lifecycle.EvRolledBack), evBudgetReset, evServerAdded, evServerProcessorSet,
		evServerPaused, evServerResumed,
		string(lifecycle.EvDiscovered), string(lifecycle.EvDrifted), string(lifecycle.EvReverted), string(lifecycle.EvDisabled),
		string(lifecycle.EvEnabled), string(lifecycle.EvMissing), string(lifecycle.EvDeprecated), string(lifecycle.EvReappeared),
		string(lifecycle.EvReturned), string(lifecycle.EvUnusable):
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
// pin) and hands every verified page to visit, which may be nil. It returns
// the new head and the number of entries walked. A break is returned as
// audit.VerifyFrom reports it, unwrapped, so VerifyAudit can hand it on as is.
// A walk from the genesis starts at the smallest seq SQLite can store, bound
// included, so a row at seq 0 or below, which the catalog never writes, is
// read and refused as a break (expected seq 1) instead of skipped (D17 d).
func walkChain(ctx context.Context, q queryer, from chainPin, visit func([]audit.Entry)) (chainPin, int, error) {
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
			visit(page)
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

// loadPin reads the head of the verified chain; tests compare it with the log.
func (s *Store) loadPin() chainPin { return s.chain.pin() }

// checkFile is what every serving-path and view read requires of the file
// before it trusts a row: the file at the path still the one this Store opened
// and still carrying the catalog identity it read at open (identity.go, D14
// e), no row below id 1 in the history tables (checkGhostRows, D17 b) and the
// guard objects and tables as the schema defines them (both skipped by a
// forensic open, as at Open, so that the views can inspect a file whose
// guards are gone or that holds a planted row, which Integrity and the
// listing then report), and the audit chain unchanged since this Store last looked, with the
// memory of it extended to the head (verifyChain). It must be the first thing
// a read transaction runs: the whole check holds walkMu, so the transaction's
// first statement, which fixes its snapshot, runs under the same lock as the
// read of the pin it is compared with. A snapshot fixed before the lock could
// predate a pin another handle of this Store advanced in between, and the
// pinned entry, absent from that older snapshot, read as a truncation (D17 f;
// the seventh review measured one in five Snapshot calls under six readers
// and one writer failing that way on an untouched file).
func (s *Store) checkFile(ctx context.Context, q queryer) error {
	_, err := s.checkFilePinned(ctx, q)
	return err
}

// checkFilePinned is checkFile returning the head of the verified chain as
// this read verified it: the pin after the walk, read under the same hold of
// walkMu as the walk, so it is the head of this transaction's snapshot, never
// one that another handle of this Store advanced after the lock was released
// (a pin read after checkFile returned could be newer than the rows this read
// goes on to return). Callers that record the head beside what they read in
// the same transaction (ApprovedWithHead, AuditHead) use it.
func (s *Store) checkFilePinned(ctx context.Context, q queryer) (chainPin, error) {
	if err := s.checkFileIdentity(); err != nil {
		return chainPin{}, err
	}
	s.chain.walkMu.Lock()
	defer s.chain.walkMu.Unlock()
	if err := s.checkStoredIdentity(ctx, q); err != nil {
		return chainPin{}, err
	}
	if !s.forensic {
		if err := checkGhostRows(ctx, q); err != nil {
			return chainPin{}, err
		}
		if err := verifyGuards(ctx, q); err != nil {
			return chainPin{}, err
		}
	}
	if err := s.verifyChainLocked(ctx, q); err != nil {
		return chainPin{}, err
	}
	return s.chain.pin(), nil
}

// verifyChain brings the Store's memory of the chain up to the log as this
// transaction sees it, under walkMu. Open and every write transaction call
// it: at Open it is the transaction's first statement, and a write transaction
// (BEGIN IMMEDIATE) always sees the newest commit, so neither can hold a
// snapshot older than the pin. Reads go through checkFile, which takes the
// lock before their first statement.
func (s *Store) verifyChain(ctx context.Context, q queryer) error {
	s.chain.walkMu.Lock()
	defer s.chain.walkMu.Unlock()
	return s.verifyChainLocked(ctx, q)
}

// verifyChainLocked is verifyChain with walkMu held: the pinned entry must
// still hash, from its fields as stored now, to the recorded hash, every entry
// after it must continue the chain, and the memory is extended to the new
// head. Nothing before the pin is read again; with no pin yet (a fresh Store,
// or an empty log so far) the walk starts at the genesis.
func (s *Store) verifyChainLocked(ctx context.Context, q queryer) error {
	pin := s.chain.pin()
	if pin.seq != 0 {
		if err := checkPinnedEntry(ctx, q, pin); err != nil {
			return err
		}
	}
	_, _, err := walkChain(ctx, q, pin, s.chain.record)
	var broken *audit.BrokenError
	switch {
	case err == nil:
		return nil
	case !errors.As(err, &broken):
		return err
	case pin.seq == 0:
		return fmt.Errorf("%w: the audit log does not form one chain from its first entry: %w; run audit verify", ErrCorrupt, err)
	}
	return fmt.Errorf("%w: the audit entries appended after entry %d do not continue its chain: %w", ErrCorrupt, pin.seq, err)
}

// checkPinnedEntry requires the pinned entry to exist and its fields, as
// stored now, to hash to the recorded hash. The hash column is not compared:
// the fifth review edited a pinned entry's fields and kept the column. An
// absent pinned entry is a truncation and nothing else, because the snapshot
// of every caller is fixed under walkMu and so never predates the pin (see
// checkFile and verifyChain).
func checkPinnedEntry(ctx context.Context, q queryer, pin chainPin) error {
	e, err := scanAudit(q.QueryRowContext(ctx, `SELECT `+auditCols+` FROM audit_log WHERE seq = ?`, pin.seq))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("%w: audit entry %d, which this store verified, is gone; the log was truncated or the file replaced under a running reader", ErrCorrupt, pin.seq)
	case err != nil:
		return fmt.Errorf("catalog: read pinned audit entry: %w", err)
	}
	if local, err := audit.HashOf(e); err != nil || local != pin.hash {
		return fmt.Errorf("%w: audit entry %d, which this store verified, was rewritten; the log was edited or re-chained under a running reader", ErrCorrupt, pin.seq)
	}
	return nil
}
