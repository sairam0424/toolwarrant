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
// record's signer, the entry is a person's, and no row sits at the seq of an
// entry that carries no record (checkOrphanRows). Rule 3, the trust list: a
// bootstrap once and only before any rotation, the version exactly one above
// the list in force, the signer in both lists (the bootstrap signed by a key
// of its own list and by the pinned root when one is given), the entry's
// actor the name the new list gives the signing key, letter for letter, and
// the version and signer-count tokens what the payload says. Rules 2 and 4
// (the decision's own tokens and subject, and the authorisation of its
// signer by the list in force), rule 5 (the signed= binding of the entries
// of a decision) and rule 6 (the crawl-transition guard) are decisionwalk.go;
// verifySignedPage below applies all of them to one page in seq order. Every
// failure is ErrCorrupt with a fixed sentence naming the entry; the walk
// stops at the first and records nothing of its page, so the pin stays below
// the refused record. The writer runs the same functions on the entry it is
// about to store (SetTrust, Decide), so the reader and the writer cannot
// drift apart.

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
	// ruleSignedBinding is rule 5: an entry after the bootstrap whose event
	// only a human command writes names no verified decision.signed entry of
	// its own transaction (decisionwalk.go).
	ruleSignedBinding
	// ruleCrawl is rule 6: an entry after the bootstrap that no decision
	// signed moves a tool along a transition no crawl can make.
	ruleCrawl
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

// errNoTrustList is the second rule of the pinned root: a walk that reaches
// the head with no trust list in force while a root was pinned refuses the
// file, since the pin says the operator bootstrapped this catalog, so a file
// without a bootstrap is another file, or one whose history was cut back
// below the bootstrap. Every walk applies it (verifyChainLocked), so a
// forensic open, which does not walk at open, meets it on its first view,
// and Integrity prints it for a log that holds no trust entry at all.
func errNoTrustList(root string) error {
	return problemf(ruleTrust, ErrNoTrustList, "the catalog has no trust list and a trust root %s was given; the catalog was never bootstrapped, or this is another file", root)
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

// pageInput is what verifySignedPage starts one page from: the trust memory
// and the open decision transaction after the pages before, the catalog
// identity and the pinned root, how to find the outcome of a decision.signed
// entry of an earlier page, what an earlier page left each tool, and how many
// goroutines verify the page's signatures (preverify.go; the rules run in seq
// order whatever the count).
type pageInput struct {
	trust      trustMemory
	open       openTxn
	identity   string
	pinnedRoot string
	lookup     func(seq int64) (signedOutcome, bool)
	lastState  func(subject string) (toolLast, bool)
	workers    int
}

// pageOutcome is what verifySignedPage hands back for one page: the trust
// memory after the page, the decision outcomes of the page, the decision
// transaction open at its end (decisionwalk.go), what the page's entries left
// each tool they are about (decisioncontinuity.go) and how many signatures it
// verified.
type pageOutcome struct {
	trust    trustMemory
	signed   map[int64]signedOutcome
	open     openTxn
	states   map[string]toolLast
	verified int
}

// verifySignedPage walks one page in seq order: every signed entry is
// verified against the trust list in force as the memory holds it, the rows
// read by primary key once for the page, and every other entry is held to
// rules 5 and 6 (checkLifecycleEntry) against the bootstrap and the decision
// outcomes known at that point; then every row within the page's seq range
// must belong to one of the signed entries (checkOrphanRows). It returns the
// memory after the page. The first refusal ends the page as ErrCorrupt with
// its sentence.
func verifySignedPage(ctx context.Context, q queryer, page []audit.Entry, in pageInput) (pageOutcome, error) {
	out, err := verifySignedEntries(ctx, q, page, in)
	if err != nil {
		return pageOutcome{}, err
	}
	if err := checkOrphanRows(ctx, q, page); err != nil {
		return pageOutcome{}, fmt.Errorf("%w: %w", ErrCorrupt, err)
	}
	return out, nil
}

// verifySignedEntries is the per-entry half of verifySignedPage: the rows
// read once, the pure half of every signed entry's check in parallel
// (preverifyPage), then one loop in seq order that applies rule 3 or rules 2
// and 4 to each signed entry from its slot, and rules 5 and 6 to each entry
// that carries no record. The loop alone touches out and the memory.
func verifySignedEntries(ctx context.Context, q queryer, page []audit.Entry, in pageInput) (pageOutcome, error) {
	out := pageOutcome{trust: in.trust, open: in.open, signed: make(map[int64]signedOutcome), states: make(map[string]toolLast)}
	rows, err := readSignedRecords(ctx, q, signedSeqs(page))
	if err != nil {
		return pageOutcome{}, err
	}
	slots, err := preverifyPage(ctx, page, rows, in.identity, in.workers)
	if err != nil {
		return pageOutcome{}, err
	}
	w := decisionWalk{lookup: func(seq int64) (signedOutcome, bool) {
		if o, ok := out.signed[seq]; ok {
			return o, true
		}
		return in.lookup(seq)
	}, lastState: func(subject string) (toolLast, bool) {
		if l, ok := out.states[subject]; ok {
			return l, true
		}
		return in.lastState(subject)
	}}
	next := 0
	for _, e := range page {
		if !isSignedEvent(e.Event) {
			if err := stepLifecycle(e, &w, &out); err != nil {
				return pageOutcome{}, fmt.Errorf("%w: %w", ErrCorrupt, err)
			}
			continue
		}
		pv := slots[next]
		next++
		res, err := checkSignedEntryRules(e, rows[e.Seq], pv, out.trust, in.pinnedRoot)
		if err != nil {
			return pageOutcome{}, fmt.Errorf("%w: %w", ErrCorrupt, err)
		}
		out.verified++
		out.trust = res.trust
		out.open = openTxn{}
		if res.decision != nil {
			out.signed[e.Seq] = *res.decision
			out.open = openTxn{seq: e.Seq}
		}
	}
	return out, nil
}

// stepLifecycle is the serial loop's work for one entry that carries no
// record: rules 5 and 6 against the bootstrap, the transaction and the tool
// states known at that point, then what the entry left recorded in out.
func stepLifecycle(e audit.Entry, w *decisionWalk, out *pageOutcome) error {
	w.bootstrap, w.open = out.trust.state.BootstrapSeq, out.open
	step, err := checkLifecycleEntry(e, *w)
	if err != nil {
		return err
	}
	out.open = step.open
	if step.tool {
		out.states[e.Subject] = step.left
	}
	return nil
}

// checkRecordBinding is the part of rule 1 that needs no cryptography: the
// entry's sigref token is the digest of the row, its signer token is the
// row's signer, and the entry is a person's. It runs before the signature is
// verified, so both signers it prints are bytes the file holds and go through
// quote.
func checkRecordBinding(e audit.Entry, rec signing.Record) error {
	token, ok := detailField(e.Detail, fieldSigref)
	if !ok {
		return problemf(ruleBinding, nil, "audit entry %d is a %s whose detail carries no %s token", e.Seq, e.Event, fieldSigref)
	}
	if token != signing.RecordDigest(rec) {
		return problemf(ruleBinding, nil, "the signed record of audit entry %d was replaced: its digest is not the %s token the entry carries", e.Seq, fieldSigref)
	}
	if signer, ok := detailField(e.Detail, fieldSigner); !ok || signer != rec.Signer {
		return problemf(ruleBinding, nil, "audit entry %d names signer %s but its signed record was made with %s", e.Seq, quote(signer), quote(rec.Signer))
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

// checkTrustRecord is rule 3 for one trust entry whose signature verified and
// whose payload checkSignedEntryCrypto parsed as list and bound to the entry:
// the entry's tokens say what the payload says, the list is valid, the
// rotation rule accepts it after the list in force, and the entry's actor is
// the name the new list gives the signing key. It returns the memory after the
// record, or tm unchanged with the refusal.
func checkTrustRecord(e audit.Entry, rec signing.Record, list signing.TrustList, tm trustMemory, pinnedRoot string) (trustMemory, error) {
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
	if err := checkTrustActor(e, rec.Signer, next.Current); err != nil {
		return tm, err
	}
	root := tm.root
	if e.Event == evTrustBootstrap {
		root = rec.Signer
	}
	return trustMemory{state: next, root: root, lists: tm.lists + 1}, nil
}

// checkTrustActor is the last part of rule 3: the entry's actor is the name
// the new list gives the signing key, letter for letter. Authorize compares
// after normalisation, which admits any spelling that folds to the name; the
// Store writes only the canonical name (requireHuman), so a spelling that
// merely folds to it is one a forger wrote and is refused with the same
// sentence (TestWalk_RefusesATrustListWithTheWrongVersionOrSigner, the
// non-canonical actor).
func checkTrustActor(e audit.Entry, signer string, list *trust.Record) error {
	err := list.Authorize(signer, e.Actor)
	name, _ := list.Lookup(signer)
	if err == nil && name != e.Actor {
		err = fmt.Errorf("%w: the list names the key for %s and the entry spells its actor %s", trust.ErrAnotherOperatorsKey, quote(name), quote(e.Actor))
	}
	if err != nil {
		return problemf(ruleTrust, err, "the trust list at entry %d is signed by %s, which it names for %s, but the entry's actor is %s", e.Seq, signer, quote(name), quote(e.Actor))
	}
	return nil
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
