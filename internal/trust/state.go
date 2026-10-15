package trust

import (
	"errors"
	"fmt"
	"strconv"
)

// Kind is the audit event a trust record arrives under; the catalog writes
// these two event names and folds each into State.Apply.
type Kind string

const (
	// KindBootstrap is the first list of a catalog, version 1, self-signed.
	KindBootstrap Kind = "trust.bootstrap"
	// KindRotated is every later list, version N+1, signed by a key of both.
	KindRotated Kind = "trust.rotated"
)

var (
	// ErrSecondBootstrap is returned when a bootstrap arrives while a list is
	// in force: the trust list cannot start twice, so a writer cannot replace
	// the operators by appending a fresh first list.
	ErrSecondBootstrap = errors.New("trust: a second bootstrap; the trust list cannot start twice")
	// ErrNoList is returned when a rotation arrives before any bootstrap.
	ErrNoList = errors.New("trust: a rotation before any bootstrap; no list is in force")
	// ErrKind is returned for an event that is neither of the two kinds.
	ErrKind = errors.New("trust: not a trust event")
	// ErrSeqOrder is returned when a record is folded out of order: at a seq
	// below 1 (the chain's own rule: seq 0 or below is a chain break) or not
	// above the seq of the list in force.
	ErrSeqOrder = errors.New("trust: trust records must be folded in increasing seq order from 1")
)

// State is the trust list in force after folding every trust record up to a
// point of the chain: the current list, the seq of the bootstrap and the seq
// of the record that put Current in force. A zero State has no list; Current
// is nil and both seqs are 0. Apply returns the new State when it accepts a
// record and the receiver, unchanged, when it refuses one, so a caller that
// writes s, err = s.Apply(...) and records the problem keeps the list in force.
type State struct {
	Current      *Record
	BootstrapSeq int64
	ListSeq      int64
}

// Apply folds one trust record, found at seq under kind and signed by the key
// with fingerprint signer, into the state: a bootstrap when no list is in
// force (CheckBootstrap against pinnedRoot), a rotation when one is
// (CheckRotation against Current). Records must arrive in increasing seq
// order from 1. Whether the entry's actor is the name the new list gives
// signer is Record.Authorize on the returned Current, which the catalog calls
// next.
func (s State) Apply(seq int64, kind Kind, next Record, signer, pinnedRoot string) (State, error) {
	if seq < 1 || seq <= s.ListSeq {
		return s, fmt.Errorf("%w: seq %d after seq %d", ErrSeqOrder, seq, s.ListSeq)
	}
	if err := next.check(); err != nil {
		return s, err
	}
	switch kind {
	case KindBootstrap:
		if s.Current != nil {
			return s, fmt.Errorf("%w: the list in force started at seq %d", ErrSecondBootstrap, s.BootstrapSeq)
		}
		if err := CheckBootstrap(next, signer, pinnedRoot); err != nil {
			return s, err
		}
		return State{Current: &next, BootstrapSeq: seq, ListSeq: seq}, nil
	case KindRotated:
		if s.Current == nil {
			return s, ErrNoList
		}
		if err := CheckRotation(*s.Current, next, signer); err != nil {
			return s, err
		}
		return State{Current: &next, BootstrapSeq: s.BootstrapSeq, ListSeq: seq}, nil
	}
	return s, fmt.Errorf("%w: %s", ErrKind, strconv.Quote(string(kind)))
}
