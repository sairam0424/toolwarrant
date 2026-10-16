package catalog

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/sairam0424/toolwarrant/internal/audit"
)

// The checked read and the chain verification every transaction starts with
// (chain.go has the memory they extend). Split out of chain.go at the size
// rule (orchestrator decision 13 for PR 7.5): nothing here changed in the
// move.

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
	cs, err := s.checkFileState(ctx, q)
	return cs.pin, err
}

// checkFileState is checkFilePinned returning, beside the pin, the trust
// memory of the same walk and its decision count, taken under the same hold
// of walkMu, so SigningState hands out a head and the list in force of one
// snapshot (D22 c, as ApprovedWithHead pairs the head with the approvals).
func (s *Store) checkFileState(ctx context.Context, q queryer) (chainState, error) {
	if err := s.checkFileIdentity(); err != nil {
		return chainState{}, err
	}
	s.chain.walkMu.Lock()
	defer s.chain.walkMu.Unlock()
	if err := s.checkStoredIdentity(ctx, q); err != nil {
		return chainState{}, err
	}
	if !s.forensic {
		if err := checkGhostRows(ctx, q); err != nil {
			return chainState{}, err
		}
		if err := verifyGuards(ctx, q); err != nil {
			return chainState{}, err
		}
	}
	if err := s.verifyChainLocked(ctx, q); err != nil {
		return chainState{}, err
	}
	return s.chain.state(), nil
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
// after it must continue the chain, every signed entry after it must pass the
// rules of trustwalk.go against this catalog's identity and the pinned trust
// root, the memory is extended to the new head, and with a root pinned a list
// must then be in force (requireTrustRoot). Nothing before the pin is read
// again; with no pin yet (a fresh Store, or an empty log so far) the walk
// starts at the genesis.
func (s *Store) verifyChainLocked(ctx context.Context, q queryer) error {
	pin := s.chain.pin()
	if pin.seq != 0 {
		if err := checkPinnedEntry(ctx, q, pin); err != nil {
			return err
		}
	}
	visit := func(page []audit.Entry) error { return s.chain.recordPage(ctx, q, page, s.identity, s.trustRoot) }
	_, _, err := walkChain(ctx, q, pin, visit)
	var broken *audit.BrokenError
	switch {
	case err == nil:
		return s.requireTrustRoot()
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
