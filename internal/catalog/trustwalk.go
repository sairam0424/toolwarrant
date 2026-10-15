package catalog

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/signing"
	"github.com/sairam0424/toolwarrant/internal/trust"
)

// What every chain walk requires of a signed entry (D22 (c); the v0.4 plan,
// section 1, rules 1, 3 and 4). Rule 1, the record binding: the entry has a
// signed_records row at its seq whose digest is the entry's sigref token and
// whose signer is the entry's signer token, the signature verifies under the
// kind's namespace, the payload is the canonical form of the kind's type and
// names this catalog, the entry's own prev_hash as its prev_head and the
// record's signer, and the entry is a person's. Rule 3, the trust list: a
// bootstrap once and only before any rotation, the version exactly one above
// the list in force, the signer in both lists (the bootstrap signed by a key
// of its own list and by the pinned root when one is given), the entry's
// actor the name the new list gives the signing key, and the version and
// signer-count tokens what the payload says. Rule 4, authorisation: a
// decision record's signer is in the list in force at that seq and listed for
// the entry's actor (rules 2 and 5, the decision's own fields and the signed=
// binding of the lifecycle entries, arrive with Decide). Every failure is
// ErrCorrupt with a fixed sentence naming the entry; the walk stops at the
// first and records nothing of its page, so the pin stays below the refused
// record. The writer runs the same functions on the entry it is about to
// store (SetTrust), so the reader and the writer cannot drift apart.

// signedRule says which rule a signed entry broke, so that Integrity counts
// the refusal under the right counter while the walk names it.
type signedRule int

const (
	// ruleBinding is rule 1: the record and the entry disagree, or the
	// record does not verify or parse.
	ruleBinding signedRule = iota
	// ruleTrust is rule 3: a trust list the rotation rule refuses.
	ruleTrust
	// ruleDecision is rule 4: a decision record whose signer the list in
	// force does not authorise.
	ruleDecision
)

// signedProblem is one refusal of a signed entry: the fixed sentence the walk
// reports, the rule it broke and, beneath it, the internal/trust or
// internal/signing error that decided it when one did, so that errors.Is sees
// through the sentence to the rule (SetTrust maps them to its own errors).
type signedProblem struct {
	rule  signedRule
	text  string
	cause error
}

// Error is the fixed sentence.
func (p *signedProblem) Error() string { return p.text }

// Unwrap exposes the deciding error, nil when the sentence stands alone.
func (p *signedProblem) Unwrap() error { return p.cause }

// problemf builds a signedProblem.
func problemf(rule signedRule, cause error, format string, args ...any) error {
	return &signedProblem{rule: rule, text: fmt.Sprintf(format, args...), cause: cause}
}

// errNoSignedRecord is the refusal of a signed entry without a row at its seq.
func errNoSignedRecord(e audit.Entry) error {
	return problemf(ruleBinding, nil, "audit entry %d is a %s with no signed record at its seq; the row was deleted or the entry was appended without one", e.Seq, e.Event)
}

// signedOutcome is what the walk recorded about one verified decision.signed
// entry: the fields the signed= binding of the lifecycle entries compares
// (the next round's rule 5).
type signedOutcome struct {
	kind    signing.Kind
	subject string
	actor   string
	ts      string
	digest  string
}

// trustMemory is what a walk knows about the operator trust list: the state
// after folding every trust record it verified, the fingerprint that signed
// the bootstrap (the root --trust-root pins) and how many trust records it
// verified.
type trustMemory struct {
	state trust.State
	root  string
	lists int
}

// pageOutcome is what verifySignedPage hands back for one page: the trust
// memory after the page, the decision outcomes of the page and how many
// signatures it verified.
type pageOutcome struct {
	trust    trustMemory
	signed   map[int64]signedOutcome
	verified int
}

// verifySignedPage verifies every signed entry of one page in seq order
// against the trust list in force as tm holds it, reading the rows by primary
// key once for the page, and returns the memory after the page. The first
// refusal ends the page as ErrCorrupt with its sentence.
func verifySignedPage(ctx context.Context, q queryer, page []audit.Entry, tm trustMemory, identity, pinnedRoot string) (pageOutcome, error) {
	out := pageOutcome{trust: tm}
	seqs := signedSeqs(page)
	if len(seqs) == 0 {
		return out, nil
	}
	rows, err := readSignedRecords(ctx, q, seqs)
	if err != nil {
		return pageOutcome{}, err
	}
	out.signed = make(map[int64]signedOutcome)
	for _, e := range page {
		if !isSignedEvent(e.Event) {
			continue
		}
		rec, ok := rows[e.Seq]
		if !ok {
			return pageOutcome{}, fmt.Errorf("%w: %w", ErrCorrupt, errNoSignedRecord(e))
		}
		res, err := checkSignedEntry(e, rec, out.trust, identity, pinnedRoot)
		if err != nil {
			return pageOutcome{}, fmt.Errorf("%w: %w", ErrCorrupt, err)
		}
		out.verified++
		out.trust = res.trust
		if res.decision != nil {
			out.signed[e.Seq] = *res.decision
		}
	}
	return out, nil
}

// signedResult is what checkSignedEntry returns for one accepted entry: the
// trust memory after it (changed by a trust record, carried by a decision)
// and the outcome of a decision record.
type signedResult struct {
	trust    trustMemory
	decision *signedOutcome
}

// checkSignedEntry applies rule 1 to one signed entry and its row, verifies
// the signature under the kind's namespace, then rule 3 or rule 4 by kind.
// On refusal the returned memory is tm unchanged, so Integrity keeps the list
// in force past a refused record.
func checkSignedEntry(e audit.Entry, rec signing.Record, tm trustMemory, identity, pinnedRoot string) (signedResult, error) {
	if err := checkRecordBinding(e, rec); err != nil {
		return signedResult{trust: tm}, err
	}
	if _, err := signing.Verify(rec.Payload, rec.Signature, namespaceOf(e.Event), rec.Signer); err != nil {
		return signedResult{trust: tm}, problemf(ruleBinding, err, "signed record of entry %d: the signature by %s does not verify over the stored payload; the record was rewritten: %v", e.Seq, rec.Signer, err)
	}
	switch e.Event {
	case evTrustBootstrap, evTrustRotated:
		next, err := checkTrustRecord(e, rec, tm, identity, pinnedRoot)
		return signedResult{trust: next}, err
	case evDecisionSigned:
		outcome, err := checkDecisionBinding(e, rec, tm.state, identity)
		return signedResult{trust: tm, decision: outcome}, err
	}
	return signedResult{trust: tm}, problemf(ruleBinding, nil, "audit entry %d is a %s, which carries no signed record", e.Seq, e.Event)
}

// checkRecordBinding is the part of rule 1 that needs no cryptography: the
// entry's sigref token is the digest of the row, its signer token is the
// row's signer, and the entry is a person's.
func checkRecordBinding(e audit.Entry, rec signing.Record) error {
	token, ok := detailField(e.Detail, fieldSigref)
	if !ok {
		return problemf(ruleBinding, nil, "audit entry %d is a %s whose detail carries no %s token", e.Seq, e.Event, fieldSigref)
	}
	if token != signing.RecordDigest(rec) {
		return problemf(ruleBinding, nil, "the signed record of audit entry %d was replaced: its digest is not the %s token the entry carries", e.Seq, fieldSigref)
	}
	if signer, ok := detailField(e.Detail, fieldSigner); !ok || signer != rec.Signer {
		return problemf(ruleBinding, nil, "audit entry %d names signer %s but its signed record was made with %s", e.Seq, quote(signer), rec.Signer)
	}
	if e.ActorType != string(ActorHuman) {
		return problemf(ruleBinding, nil, "audit entry %d is a %s by %s, a %s actor; only a person signs", e.Seq, e.Event, quote(e.Actor), quote(e.ActorType))
	}
	return nil
}

// checkPayloadBinding is the part of rule 1 every parsed payload obeys: it
// names the record's signer, this catalog and the entry's own prev_hash.
func checkPayloadBinding(e audit.Entry, recSigner, payloadSigner, catalog, prevHead, identity string) error {
	if payloadSigner != recSigner {
		return problemf(ruleBinding, nil, "signed record of entry %d names signer %s inside the payload but %s signed it", e.Seq, payloadSigner, recSigner)
	}
	if catalog != identity {
		return problemf(ruleBinding, nil, "signed record of entry %d names catalog %s, not this one (%s); the record was copied from another catalog", e.Seq, catalog, quote(identity))
	}
	if prevHead != e.PrevHash {
		return problemf(ruleBinding, nil, "signed record of entry %d names %s as prev_head but the entry's prev_hash is %s; the record was made over another head", e.Seq, prevHead, e.PrevHash)
	}
	return nil
}

// checkTrustRecord is rule 3 for one trust entry whose signature verified:
// the payload is a canonical trust list bound to the entry, the entry's
// tokens say what the payload says, the list is valid, the rotation rule
// accepts it after the list in force, and the entry's actor is the name the
// new list gives the signing key. It returns the memory after the record, or
// tm unchanged with the refusal.
func checkTrustRecord(e audit.Entry, rec signing.Record, tm trustMemory, identity, pinnedRoot string) (trustMemory, error) {
	list, err := signing.ParseTrustList(rec.Payload)
	if err != nil {
		return tm, problemf(ruleBinding, err, "signed record of entry %d is not a canonical trust list: %v", e.Seq, err)
	}
	if err := checkPayloadBinding(e, rec.Signer, list.Signer, list.Catalog, list.PrevHead, identity); err != nil {
		return tm, err
	}
	if err := checkTrustTokens(e, list); err != nil {
		return tm, err
	}
	record, err := trust.Validate(list)
	if err != nil {
		return tm, problemf(ruleTrust, err, "the trust list at entry %d is not a valid list: %v", e.Seq, err)
	}
	next, err := tm.state.Apply(e.Seq, trust.Kind(e.Event), record, rec.Signer, pinnedRoot)
	if err != nil {
		return tm, trustRuleProblem(e, list, tm.state, rec.Signer, pinnedRoot, err)
	}
	if err := next.Current.Authorize(rec.Signer, e.Actor); err != nil {
		name, _ := next.Current.Lookup(rec.Signer)
		return tm, problemf(ruleTrust, err, "the trust list at entry %d is signed by %s, which it names for %s, but the entry's actor is %s", e.Seq, rec.Signer, quote(name), quote(e.Actor))
	}
	root := tm.root
	if e.Event == evTrustBootstrap {
		root = rec.Signer
	}
	return trustMemory{state: next, root: root, lists: tm.lists + 1}, nil
}

// checkTrustTokens requires a trust entry to be about the trust subject and
// its version and signers tokens to say what the signed payload says.
func checkTrustTokens(e audit.Entry, list signing.TrustList) error {
	if e.Subject != trustSubject {
		return problemf(ruleBinding, nil, "audit entry %d is a %s about %s, not %s", e.Seq, e.Event, quote(e.Subject), trustSubject)
	}
	if v, ok := detailField(e.Detail, fieldVersion); !ok || v != strconv.Itoa(list.Version) {
		return problemf(ruleBinding, nil, "audit entry %d says %s=%s but its signed trust list is version %d", e.Seq, fieldVersion, quote(v), list.Version)
	}
	if n, ok := detailField(e.Detail, fieldSigners); !ok || n != strconv.Itoa(len(list.Signers)) {
		return problemf(ruleBinding, nil, "audit entry %d says %s=%s but its signed trust list names %d", e.Seq, fieldSigners, quote(n), len(list.Signers))
	}
	return nil
}

// trustRuleProblem turns a refusal of trust.State.Apply into the fixed
// sentence for that rule, with the trust error beneath it.
func trustRuleProblem(e audit.Entry, list signing.TrustList, state trust.State, signer, pinnedRoot string, err error) error {
	want := trust.MinVersion
	if state.Current != nil {
		want = state.Current.Version + 1
	}
	switch {
	case errors.Is(err, trust.ErrSecondBootstrap):
		return problemf(ruleTrust, err, "a second trust bootstrap at entry %d; the trust list cannot start twice (the list in force started at entry %d)", e.Seq, state.BootstrapSeq)
	case errors.Is(err, trust.ErrNoList):
		return problemf(ruleTrust, err, "a trust rotation at entry %d before any bootstrap; no list is in force", e.Seq)
	case errors.Is(err, trust.ErrBootstrapVersion):
		return problemf(ruleTrust, err, "the trust bootstrap at entry %d has version %d, expected %d", e.Seq, list.Version, trust.MinVersion)
	case errors.Is(err, trust.ErrRollback):
		return problemf(ruleTrust, err, "trust list at entry %d has version %d, expected %d (exactly one above the list in force)", e.Seq, list.Version, want)
	case errors.Is(err, trust.ErrNotThePinnedRoot):
		return problemf(ruleTrust, err, "the trust bootstrap at entry %d was signed by %s, not the pinned trust root %s; the catalog was re-bootstrapped or replaced", e.Seq, signer, pinnedRoot)
	case errors.Is(err, trust.ErrNotSelfSigned):
		return problemf(ruleTrust, err, "the trust bootstrap at entry %d is not signed by a key of its own list (signed by %s)", e.Seq, signer)
	case errors.Is(err, trust.ErrSignerNotInBothLists):
		return problemf(ruleTrust, err, "the trust list at entry %d is not signed by a key of both the list in force and the new list (signed by %s)", e.Seq, signer)
	}
	return problemf(ruleTrust, err, "the trust list at entry %d is refused: %v", e.Seq, err)
}

// checkDecisionBinding is rule 1 and rule 4 for one decision.signed entry
// whose signature verified: the payload is a canonical decision bound to the
// entry and its actor, the kind token says what the payload says, a list is
// in force and it names the signing key for the entry's actor. The decision's
// own fields against the entry's subject and digest (rule 2) and the signed=
// binding of the lifecycle entries (rule 5) arrive with Decide.
func checkDecisionBinding(e audit.Entry, rec signing.Record, state trust.State, identity string) (*signedOutcome, error) {
	d, err := signing.ParseDecision(rec.Payload)
	if err != nil {
		return nil, problemf(ruleBinding, err, "signed record of entry %d is not a canonical decision: %v", e.Seq, err)
	}
	if err := checkPayloadBinding(e, rec.Signer, d.Signer, d.Catalog, d.PrevHead, identity); err != nil {
		return nil, err
	}
	if d.Actor != e.Actor {
		return nil, problemf(ruleBinding, nil, "signed record of entry %d names actor %s but the entry's actor is %s", e.Seq, quote(d.Actor), quote(e.Actor))
	}
	if k, ok := detailField(e.Detail, fieldKind); !ok || k != string(d.Kind) {
		return nil, problemf(ruleBinding, nil, "audit entry %d says %s=%s but its signed decision is a %s", e.Seq, fieldKind, quote(k), d.Kind)
	}
	if state.Current == nil {
		return nil, problemf(ruleDecision, trust.ErrNoList, "audit entry %d is a %s but no trust list is in force at that entry; a signed record has no list to be verified against", e.Seq, e.Event)
	}
	if err := state.Current.Authorize(rec.Signer, e.Actor); err != nil {
		if name, ok := state.Current.Lookup(rec.Signer); ok {
			return nil, problemf(ruleDecision, err, "signed record of entry %d: signer %s belongs to %s but the entry and payload name %s", e.Seq, rec.Signer, quote(name), quote(e.Actor))
		}
		return nil, problemf(ruleDecision, err, "signed record of entry %d: signer %s is not in trust list v%d in force at that entry", e.Seq, rec.Signer, state.Current.Version)
	}
	return &signedOutcome{kind: d.Kind, subject: e.Subject, actor: e.Actor, ts: e.TS, digest: d.Digest}, nil
}
