package catalog

import (
	"context"
	"errors"
	"fmt"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
	"github.com/sairam0424/toolwarrant/internal/signing"
	"github.com/sairam0424/toolwarrant/internal/trust"
)

// Signed decisions (D22 (b); owner decisions O-13, O-16 and O-17). Every human
// decision, approve, reject, rollback, disable, enable, pause, resume and the
// budget reset, goes through Decide. Once a trust list is in force the
// decision must carry a signed record: the exact RFC 8785 bytes of a
// toolwarrant/decision/v1 payload naming this catalog, the decision and the
// audit head it extends, signed under the decision namespace by a key the
// list names for the deciding person. The signature is made before the
// transaction, by the CLI, over the head SigningState handed out, so the
// catalog never calls a signer and the write lock is never held on a person
// or an agent (O-17). Inside the transaction, after the chain was verified to
// its head, the payload's prev_head must be the pin (ErrHeadMoved, nothing
// written: the compare-and-set of research finding 12), the decision.signed
// entry is sealed from that pin, so its prev_hash is the head the payload
// names by construction, checked with the walk's own checkDecisionRecord, and
// stored first; the lifecycle, budget or server entries of the decision follow
// in the same transaction, each carrying signed=N, the seq of that entry,
// which rule 5 of the walk and the anchor pass bind to it. Before the
// bootstrap nothing changes: an unsigned Decision writes exactly what v0.3
// wrote (O-12). --as is a label: the payload's actor must be the deciding
// actor, and the key must be the one the list names for that person
// (ErrNotASigner, "the key belongs to ..."; O-13).

// Decision is one human decision as Decide takes it: the kind, the server, the
// tool (empty for pause and resume), the digest the kind names (approve,
// reject and rollback; empty for the others), the person deciding and, when
// a trust list is in force, the signed record over the matching payload.
type Decision struct {
	Kind   signing.Kind
	Server string
	Tool   string
	Digest string
	By     Actor
	// Signed is the record signing.Sign returned over the bytes
	// signing.MarshalDecision produced for this decision, or nil for an
	// unsigned decision, which only a catalog without a trust list accepts.
	Signed *signing.Record
}

// decisionRequest is a Decision validated and, when signed, verified before
// any lock is taken: the actor canonical, the digest lower-case, the subject
// of its entries, and the parsed payload (nil when unsigned).
type decisionRequest struct {
	d       Decision
	actor   Actor
	subject string
	payload *signing.Decision
}

// Decide records one human decision and returns the seq of its
// decision.signed entry (0 for an unsigned decision before the bootstrap) and
// the audit head after it. Refusals: a system actor is ErrHumanRequired; a
// kind, digest or tool that does not fit is ErrInvalid; an unsigned decision
// while a trust list is in force is ErrSignatureRequired; a record that does
// not verify, is not a decision, names another catalog, another actor or
// another decision than the one made is ErrInvalid; a signed decision on a
// catalog without a trust list is ErrNoTrustList; a prev_head that is not the
// audit head is ErrHeadMoved and nothing is written; a key the list in force
// does not name, or names for another person, is ErrNotASigner. What the
// lifecycle refuses (lifecycle.ErrStaleVersion and friends) is wrapped as the
// five decision methods always wrapped it, and nothing is written then either.
func (s *Store) Decide(ctx context.Context, d Decision) (Receipt, error) {
	req, err := s.prepareDecision(d)
	if err != nil {
		return Receipt{}, err
	}
	var receipt Receipt
	err = s.inTx(ctx, func(t *txn) error {
		seq, err := s.recordSigned(ctx, t, req)
		if err != nil {
			return err
		}
		if err := s.applyDecision(ctx, t, req, signedNote(seq)); err != nil {
			return err
		}
		receipt = Receipt{Seq: seq, Head: t.last.Hash}
		return nil
	})
	if err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

// prepareDecision validates a Decision before any lock is taken: the kind,
// the actor (a person), the digest for the kinds that name one and its
// absence for the others, the tool for the kinds that name one and its
// absence for pause and resume, and the signed record when there is one.
func (s *Store) prepareDecision(d Decision) (decisionRequest, error) {
	if !d.Kind.Valid() {
		return decisionRequest{}, invalidf("decision kind %s is not one of approve, reject, rollback, disable, enable, pause, resume, budget_reset", quote(string(d.Kind)))
	}
	actor, err := requireHuman(d.By)
	if err != nil {
		return decisionRequest{}, err
	}
	switch {
	case d.Kind.NamesVersion():
		if d.Digest, err = normalizeDigest(d.Digest); err != nil {
			return decisionRequest{}, err
		}
	case d.Digest != "":
		return decisionRequest{}, invalidf("a %s names no digest", d.Kind)
	}
	switch {
	case d.Kind.NamesTool() && d.Tool == "":
		return decisionRequest{}, invalidf("a %s names a tool", d.Kind)
	case !d.Kind.NamesTool() && d.Tool != "":
		return decisionRequest{}, invalidf("a %s acts on a server and names no tool", d.Kind)
	}
	req := decisionRequest{d: d, actor: actor, subject: decisionSubject(d.Kind, d.Server, d.Tool)}
	if d.Signed != nil {
		if req.payload, err = s.prepareDecisionRecord(*d.Signed, d, actor); err != nil {
			return decisionRequest{}, err
		}
	}
	return req, nil
}

// prepareDecisionRecord verifies and parses a signed record before any lock
// is taken: the signature under the decision namespace with the signer the
// record names, the payload as a canonical decision naming that signer, this
// catalog, the deciding actor and exactly the decision being made. Every
// refusal is ErrInvalid wrapping the deciding error.
func (s *Store) prepareDecisionRecord(rec signing.Record, d Decision, actor Actor) (*signing.Decision, error) {
	if _, err := signing.Verify(rec.Payload, rec.Signature, signing.NamespaceDecision, rec.Signer); err != nil {
		return nil, fmt.Errorf("%w: decision: %w", ErrInvalid, err)
	}
	p, err := signing.ParseDecision(rec.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: decision: %w", ErrInvalid, err)
	}
	switch {
	case p.Signer != rec.Signer:
		return nil, invalidf("the decision names signer %s inside the payload but %s signed it", p.Signer, rec.Signer)
	case p.Catalog != s.identity:
		return nil, invalidf("the decision names catalog %s but this catalog is %s; the payload was signed for another catalog", p.Catalog, s.identity)
	case p.Actor != actor.Name:
		return nil, invalidf("the decision was signed for actor %s but is made as %s; --as must name the person whose key signed", quote(p.Actor), quote(actor.Name))
	case p.Kind != d.Kind || p.Server != d.Server || p.Tool != d.Tool || p.Digest != d.Digest:
		return nil, invalidf("the signed decision (%s on %s digest %s) is not the decision being made (%s on %s digest %s)",
			p.Kind, quote(decisionSubject(p.Kind, p.Server, p.Tool)), orNoDigest(p.Digest), d.Kind, quote(decisionSubject(d.Kind, d.Server, d.Tool)), orNoDigest(d.Digest))
	}
	return &p, nil
}

// recordSigned is the signed half of a decision, inside the transaction after
// the chain was verified to its head: an unsigned decision while a list is in
// force is ErrSignatureRequired; a payload over another head than the pin is
// ErrHeadMoved; the decision.signed entry is sealed from the pin, checked
// with the walk's own rules (checkDecisionRecord) and stored with its record.
// It returns the entry's seq, 0 for an unsigned decision.
func (s *Store) recordSigned(ctx context.Context, t *txn, req decisionRequest) (int64, error) {
	pin := s.chain.pin()
	tm, _ := s.chain.signedState()
	if req.payload == nil {
		if cur := tm.state.Current; cur != nil {
			return 0, fmt.Errorf("%w: trust list version %d has been in force since entry %d; sign the %s with a key the list names", ErrSignatureRequired, cur.Version, tm.state.BootstrapSeq, req.d.Kind)
		}
		return 0, nil
	}
	if head := headOf(pin); req.payload.PrevHead != head {
		return 0, fmt.Errorf("%w: the decision names %s as prev_head but the audit head is %s; the log grew since it was signed", ErrHeadMoved, req.payload.PrevHead, head)
	}
	rec := *req.d.Signed
	e, err := t.sealSigned(req.actor, evDecisionSigned, req.subject, decisionDetail(req.d.Kind, req.d.Digest), rec)
	if err != nil {
		return 0, err
	}
	if _, err := checkDecisionRecord(e, rec, tm.state, s.identity); err != nil {
		return 0, decisionWriteError(err, rec, tm.state, req.actor)
	}
	if err := t.storeSigned(ctx, e, rec); err != nil {
		return 0, err
	}
	return e.Seq, nil
}

// decisionWriteError maps a refusal of the walk's check, run on the entry
// Decide is about to write, to the error Decide returns: a key the list names
// for another person is ErrNotASigner naming that person (O-13: the label
// must be the key's operator), a key the list does not name is ErrNotASigner,
// no list in force is ErrNoTrustList, everything else ErrInvalid, each
// wrapping the deciding error.
func decisionWriteError(err error, rec signing.Record, state trust.State, actor Actor) error {
	switch {
	case errors.Is(err, trust.ErrAnotherOperatorsKey):
		name, _ := state.Current.Lookup(rec.Signer)
		return fmt.Errorf("%w: the key belongs to %s, not to %s, whom the decision names; --as must name the key's operator: %w", ErrNotASigner, name, actor.Name, err)
	case errors.Is(err, trust.ErrUnauthorizedSigner):
		return fmt.Errorf("%w: %w", ErrNotASigner, err)
	case errors.Is(err, trust.ErrNoList):
		return fmt.Errorf("%w: a signed decision needs a trust list in force; bootstrap the list first: %w", ErrNoTrustList, err)
	}
	return fmt.Errorf("%w: %w", ErrInvalid, err)
}

// applyDecision runs the decision itself, after the signed entry, with note
// (" signed=N", or nothing before the bootstrap) on every entry it writes.
func (s *Store) applyDecision(ctx context.Context, t *txn, req decisionRequest, note string) error {
	switch req.d.Kind {
	case signing.KindPause, signing.KindResume:
		return s.setPausedTx(ctx, t, req.d.Server, req.actor, req.d.Kind == signing.KindPause, note)
	case signing.KindBudgetReset:
		return s.resetBudgetTx(ctx, t, req.d.Server, req.d.Tool, req.actor, note)
	}
	return s.transitionTx(ctx, t, req.d.Server, req.d.Tool, changeFor(req.d, req.actor), req.actor, note)
}

// changeFor is the lifecycle command and the approvals row of a decision that
// moves a tool: approve, reject and rollback record a decision, disable and
// enable do not.
func changeFor(d Decision, actor Actor) change {
	switch d.Kind {
	case signing.KindApprove:
		return change{op: "approve", cmd: lifecycle.Approve{Digest: d.Digest, Actor: actor.Name}, decision: decisionApprove, digest: d.Digest}
	case signing.KindReject:
		return change{op: "reject", cmd: lifecycle.Reject{Digest: d.Digest, Actor: actor.Name}, decision: decisionReject, digest: d.Digest}
	case signing.KindRollback:
		return change{op: "rollback", cmd: lifecycle.Rollback{To: d.Digest, Actor: actor.Name}, decision: decisionRollback, digest: d.Digest}
	case signing.KindDisable:
		return change{op: "disable", cmd: lifecycle.Disable{Actor: actor.Name}}
	}
	return change{op: "enable", cmd: lifecycle.Enable{Actor: actor.Name}}
}
