package catalog

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/sairam0424/toolwarrant/internal/signing"
	"github.com/sairam0424/toolwarrant/internal/trust"
)

// The operator trust list in the chain (D22 (c); owner decisions O-11, O-12,
// O-14, O-15, O-17). SetTrust writes a trust.bootstrap (version 1, signed by
// one of its own keys) or a trust.rotated entry (exactly one version above the
// list in force, signed by a key of both lists) about the trust subject, with
// the record in signed_records at the entry's seq and bound to it by the
// sigref token. The compare-and-set is the heart of it (research finding 12):
// the payload names the audit head the signer saw as prev_head, and inside
// the write transaction, after the chain was verified to its head, SetTrust
// refuses the record unless that head is the pin (ErrHeadMoved), and only
// then appends the entry, whose prev_hash is that same pin by construction.
// So a stored prev_head always equals its entry's prev_hash, the check and
// the persistence are one atomic step, and a signature made over a head the
// log has left behind is never stored. The catalog never calls a signer: the
// signature is made before the transaction, by the CLI, and the write lock is
// never held on a person or an agent (O-17).

// Receipt is what a signed write returns: the seq of the entry that carries
// the record and the head of the chain after it, which is that entry's hash.
// The operator records the head, and the next signed payload names it as its
// prev_head.
type Receipt struct {
	Seq  int64
	Head string
}

// TrustView is the operator trust list in force as this Store's walk verified
// it: the version, the seq of the bootstrap and of the record that put this
// list in force, the fingerprint that signed the bootstrap (the root
// --trust-root pins), the operators in list order with their canonical names,
// key lines and fingerprints, and how many signed decisions and trust lists
// the walk has verified. A zero Version means the catalog has no trust list.
type TrustView struct {
	Version         int
	BootstrapSeq    int64
	ListSeq         int64
	Root            string
	Signers         []trust.Operator
	SignedDecisions int
	Lists           int
}

// InForce reports whether a trust list is in force: the catalog was
// bootstrapped, so decisions after that entry must be signed.
func (v TrustView) InForce() bool { return v.Version > 0 }

// SigningState is what a signer needs before it signs (O-17): the catalog
// identity the payload names, the audit head it extends and the trust list
// it must be signed under, all from one read transaction and one hold of the
// walk lock, so a head is never paired with the list of another snapshot
// (TestSigningState_IdentityHeadAndTrustComeFromOneSnapshot).
type SigningState struct {
	Identity string
	Head     string
	Trust    TrustView
}

// SetTrust records a signed trust list: the first one as trust.bootstrap, every
// later one as trust.rotated. The record is signing.Sign's output over the
// bytes signing.MarshalTrustList produced; it is verified and parsed before
// the transaction, then checked inside it exactly as every walk will check it
// (checkTrustRecord on the sealed entry), so the writer and the reader apply
// one rule. Refusals: a system actor is ErrHumanRequired; a record that does
// not verify, is not a trust list, names another catalog or is not a valid
// list is ErrInvalid; a prev_head that is not the audit head is ErrHeadMoved
// and nothing is written; a signer the rotation rule does not admit (not a
// key of both lists, or a bootstrap not signed by its own list) is
// ErrNotASigner; a second bootstrap, a skipped version, a bootstrap under
// another pinned root and an actor the new list names another key for are
// ErrInvalid wrapping the internal/trust error. The receipt names the entry
// and the new head.
func (s *Store) SetTrust(ctx context.Context, rec signing.Record, by Actor) (Receipt, error) {
	actor, err := requireHuman(by)
	if err != nil {
		return Receipt{}, err
	}
	list, err := s.prepareTrustRecord(rec)
	if err != nil {
		return Receipt{}, err
	}
	kind := trust.KindRotated
	if list.Version == trust.MinVersion {
		kind = trust.KindBootstrap
	}
	var receipt Receipt
	err = s.inTx(ctx, func(t *txn) error {
		pin := s.chain.pin()
		if head := headOf(pin); list.PrevHead != head {
			return fmt.Errorf("%w: the trust list names %s as prev_head but the audit head is %s; the log grew since it was signed", ErrHeadMoved, list.PrevHead, head)
		}
		detail := fmt.Sprintf("%s=%d %s=%d", fieldVersion, list.Version, fieldSigners, len(list.Signers))
		e, err := t.sealSigned(actor, string(kind), trustSubject, detail, rec)
		if err != nil {
			return err
		}
		tm, _ := s.chain.signedState()
		if _, err := checkTrustRecord(e, rec, tm, s.identity, s.trustRoot); err != nil {
			return trustWriteError(err)
		}
		if err := t.storeSigned(ctx, e, rec); err != nil {
			return err
		}
		receipt = Receipt{Seq: e.Seq, Head: e.Hash}
		return nil
	})
	if err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

// prepareTrustRecord verifies and parses a record before any lock is taken:
// the signature under the trust namespace with the signer the record names,
// the payload as a canonical trust list naming that signer and this catalog,
// and the list as internal/trust accepts it. Every refusal is ErrInvalid
// wrapping the deciding error.
func (s *Store) prepareTrustRecord(rec signing.Record) (signing.TrustList, error) {
	if _, err := signing.Verify(rec.Payload, rec.Signature, signing.NamespaceTrust, rec.Signer); err != nil {
		return signing.TrustList{}, fmt.Errorf("%w: trust list: %w", ErrInvalid, err)
	}
	list, err := signing.ParseTrustList(rec.Payload)
	if err != nil {
		return signing.TrustList{}, fmt.Errorf("%w: trust list: %w", ErrInvalid, err)
	}
	if list.Signer != rec.Signer {
		return signing.TrustList{}, invalidf("trust list names signer %s inside the payload but %s signed it", list.Signer, rec.Signer)
	}
	if list.Catalog != s.identity {
		return signing.TrustList{}, invalidf("trust list names catalog %s but this catalog is %s; the payload was signed for another catalog", list.Catalog, s.identity)
	}
	if _, err := trust.Validate(list); err != nil {
		return signing.TrustList{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return list, nil
}

// trustWriteError maps a refusal of the walk's check, run on the entry
// SetTrust is about to write, to the error SetTrust returns: a signer the
// rotation rule does not admit is ErrNotASigner, everything else ErrInvalid,
// each wrapping the deciding internal/trust error.
func trustWriteError(err error) error {
	switch {
	case errors.Is(err, trust.ErrSignerNotInBothLists), errors.Is(err, trust.ErrNotSelfSigned), errors.Is(err, trust.ErrUnauthorizedSigner):
		return fmt.Errorf("%w: %w", ErrNotASigner, err)
	}
	return fmt.Errorf("%w: %w", ErrInvalid, err)
}

// TrustList returns the trust list in force as this Store's walk verified it,
// after the file check of every view; a catalog without one returns a view
// whose InForce is false and no error.
func (s *Store) TrustList(ctx context.Context) (TrustView, error) {
	st, err := s.SigningState(ctx)
	if err != nil {
		return TrustView{}, err
	}
	return st.Trust, nil
}

// SigningState returns the identity, the verified head and the trust list in
// force from one read transaction: the file check fixes the snapshot and
// walks the chain to the head under the walk lock, and the pin and the trust
// memory are taken under that same hold (checkFileState), as ApprovedWithHead
// takes the head beside the approvals.
func (s *Store) SigningState(ctx context.Context) (SigningState, error) {
	var st SigningState
	err := s.inRead(ctx, func(q queryer) error {
		cs, err := s.checkFileState(ctx, q)
		if err != nil {
			return err
		}
		st = SigningState{Identity: s.identity, Head: headOf(cs.pin), Trust: trustViewOf(cs.trust, cs.decisions)}
		return nil
	})
	if err != nil {
		return SigningState{}, err
	}
	return st, nil
}

// trustViewOf renders the walk's trust memory as a TrustView.
func trustViewOf(tm trustMemory, decisions int) TrustView {
	cur := tm.state.Current
	if cur == nil {
		return TrustView{}
	}
	return TrustView{
		Version: cur.Version, BootstrapSeq: tm.state.BootstrapSeq, ListSeq: tm.state.ListSeq, Root: tm.root,
		Signers: slices.Clone(cur.Signers), SignedDecisions: decisions, Lists: tm.lists,
	}
}

// chainState is what a checked read takes under one hold of the walk lock:
// the pin and the trust memory of the same walk, and how many decision
// records the memory holds.
type chainState struct {
	pin       chainPin
	trust     trustMemory
	decisions int
}

// state returns the pin, the trust memory and the decision count together.
func (c *chainMemory) state() chainState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return chainState{pin: c.head, trust: c.trust, decisions: len(c.signed)}
}

// signedState returns the trust memory and the decision count; SetTrust reads
// it inside its write transaction, after verifyChain brought it to the head.
func (c *chainMemory) signedState() (trustMemory, int) {
	cs := c.state()
	return cs.trust, cs.decisions
}

// verifiedSignatures is how many signatures the walks have verified since the
// Store opened; tests read it.
func (c *chainMemory) verifiedSignatures() int64 { return c.verified.Load() }
