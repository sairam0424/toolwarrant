package catalog

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/sairam0424/toolwarrant/internal/audit"
)

// The chain pin (D14 b). A Store remembers the newest audit entry it has
// verified, by seq and hash. On every Snapshot, Approved and view load it reads
// that entry again and requires the same hash, then verifies that every entry
// appended since continues the chain from it (audit.VerifyFrom), and moves the
// pin to the newest of them. Whoever rewrites an entry at or before the pin
// must re-chain every later entry, which changes the pinned hash; whoever
// truncates the log removes it. So history up to the pin cannot change under a
// running reader, whatever the file's triggers say. What the pin cannot see is
// a correctly chained append (the D14 limit) and a rewrite before the Store
// opened: the first pin is the head as found, verified to re-seal from its
// predecessor only, because verifying the whole chain on every start of a
// processor or a canary would cost a full read of the log; that prefix is what
// audit verify with the recorded head is for.

// chainPin is the newest audit entry a Store has verified; seq 0 means none yet.
type chainPin struct {
	seq  int64
	hash string
}

// loadPin reads the pin under its lock.
func (s *Store) loadPin() chainPin {
	s.pinMu.Lock()
	defer s.pinMu.Unlock()
	return s.pin
}

// advancePin moves the pin forward, never back: two concurrent reads may each
// verify a suffix, and the one that saw more wins.
func (s *Store) advancePin(to chainPin) {
	s.pinMu.Lock()
	defer s.pinMu.Unlock()
	if to.seq > s.pin.seq {
		s.pin = to
	}
}

// checkFile is what every serving-path and view read requires of the file
// before it trusts a row: the file at the path still the one this Store opened
// (identity.go), the guard objects as the schema defines them (skipped by a
// forensic open, as at Open, so that the views can inspect a file whose
// guards are gone) and the audit chain unchanged since this Store last looked.
func (s *Store) checkFile(ctx context.Context, q queryer) error {
	if err := s.checkFileIdentity(); err != nil {
		return err
	}
	if !s.forensic {
		if err := verifyGuards(ctx, q); err != nil {
			return err
		}
	}
	return s.verifyChain(ctx, q)
}

// verifyChain checks the pinned entry and the suffix after it, then advances
// the pin; see the file comment. An empty log pins nothing.
func (s *Store) verifyChain(ctx context.Context, q queryer) error {
	pin := s.loadPin()
	if pin.seq == 0 {
		head, err := s.verifyHead(ctx, q)
		if err != nil || head.seq == 0 {
			return err
		}
		s.advancePin(head)
		return nil
	}
	if err := checkPinnedEntry(ctx, q, pin); err != nil {
		return err
	}
	prev := audit.Entry{Seq: pin.seq, Hash: pin.hash}
	for {
		page, err := queryAudit(ctx, q, prev.Seq, auditPage)
		if err != nil {
			return err
		}
		if err := audit.VerifyFrom(prev, page); err != nil {
			return fmt.Errorf("%w: the audit entries appended after entry %d do not continue its chain: %w", ErrCorrupt, pin.seq, err)
		}
		if len(page) > 0 {
			prev = page[len(page)-1]
		}
		if len(page) < auditPage {
			break
		}
	}
	s.advancePin(chainPin{seq: prev.Seq, hash: prev.Hash})
	return nil
}

// verifyHead reads the newest entry of the log and requires it to re-seal from
// its predecessor. It returns the zero pin for an empty log.
func (s *Store) verifyHead(ctx context.Context, q queryer) (chainPin, error) {
	var a anchoredEntry
	err := q.QueryRowContext(ctx, `SELECT `+auditCols+`, COALESCE((SELECT p.hash FROM audit_log p WHERE p.seq = audit_log.seq - 1), '')
		FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(
		&a.entry.Seq, &a.entry.TS, &a.entry.Actor, &a.entry.ActorType, &a.entry.Event, &a.entry.Subject,
		&a.entry.BeforeHash, &a.entry.AfterHash, &a.entry.Detail, &a.entry.PrevHash, &a.entry.Hash, &a.prevHash)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return chainPin{}, nil
	case err != nil:
		return chainPin{}, fmt.Errorf("catalog: read audit head: %w", err)
	}
	if !s.sealed.verifySeal(a.entry, a.prevHash) {
		return chainPin{}, errEntryRewritten(a.entry.Seq, a.entry.Subject)
	}
	return chainPin{seq: a.entry.Seq, hash: a.entry.Hash}, nil
}

// checkPinnedEntry requires the pinned entry to exist with the pinned hash.
func checkPinnedEntry(ctx context.Context, q queryer, pin chainPin) error {
	var hash string
	err := q.QueryRowContext(ctx, `SELECT hash FROM audit_log WHERE seq = ?`, pin.seq).Scan(&hash)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("%w: audit entry %d, which this store verified, is gone; the log was truncated or the file replaced under a running reader", ErrCorrupt, pin.seq)
	case err != nil:
		return fmt.Errorf("catalog: read pinned audit entry: %w", err)
	case hash != pin.hash:
		return fmt.Errorf("%w: audit entry %d, which this store verified, was rewritten; the log was re-chained under a running reader", ErrCorrupt, pin.seq)
	}
	return nil
}
