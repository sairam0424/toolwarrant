package main

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	"github.com/sairam0424/toolwarrant/internal/signing"
)

// The signed decision flow (D22 (b) and (h); owner decisions O-13 and O-17).
// Once a trust list is in force every decision must be signed, so a decision
// command resolves the operator's key before it reads anything about the
// tool, reads the catalog identity, the audit head and the list in one
// SigningState, derives the person from the key, reviews the decision as
// before, and only then signs: the payload names this catalog, the decision
// and the head, the signature is made outside the catalog's write lock, and
// Decide compares that head with the head inside its transaction. A head that
// moved while the person signed (a scheduled crawl landing in the signing
// window) is signed again once, then refused; with --expect-head the operator
// named the head themselves and nothing is signed over another.

// decisionFlow is one decision command's state after its flags were parsed
// and the catalog opened: the store, the signer (nil before the bootstrap),
// the person acting, the head the operator expects (or "") and the head the
// signature was made over, for the line printed afterwards.
type decisionFlow struct {
	store      *catalog.Store
	signer     *cliSigner
	actor      catalog.Actor
	expectHead string
	signedOver string
}

// beginSigned opens the catalog for a decision and settles who decides and
// whether the decision is signed. label is the actor the unsigned path would
// use (--as, --by, TOOLWARRANT_ACTOR or the OS user) and source where the
// operator named one, labelNone when they did not. With a trust list in force
// a key is required (exit 2 with the fix) and the person is the key's
// operator; without one a key is a usage error naming trust init, since a
// signed decision needs a list to be verified against. The signer is resolved
// before the catalog is opened, so a refused key touches nothing.
func (a *app) beginSigned(c *command, expectHead string, label catalog.Actor, source labelSource) (f *decisionFlow, err error) {
	signer, err := a.optionalSigner(c)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			signer.close()
		}
	}()
	store, err := a.openStore(openWrite)
	if err != nil {
		return nil, err
	}
	f = &decisionFlow{store: store, signer: signer, actor: label, expectHead: expectHead}
	if err := f.settle(a, c, source); err != nil {
		closeStore(store, &err)
		return nil, err
	}
	return f, nil
}

// settle applies the rules of the trust list to the key the operator gave or
// did not give, and derives the actor from the key when one signs, holding
// the label (from source) to it.
func (f *decisionFlow) settle(a *app, c *command, source labelSource) error {
	st, err := f.store.SigningState(a.ctx)
	if err != nil {
		return err
	}
	switch {
	case st.Trust.InForce() && f.signer == nil:
		return &usageError{msg: fmt.Sprintf("signing is required since the trust bootstrap at entry %d; pass --%s PATH (or set %s) naming a key the trust list holds", st.Trust.BootstrapSeq, flagSSHKey, envSSHKey), cmd: c}
	case !st.Trust.InForce() && f.signer != nil:
		return &usageError{msg: fmt.Sprintf("the catalog has no trust list; run \"%s trust init\" first: a signed decision needs a list to be verified against", programName), cmd: c}
	case !st.Trust.InForce() && f.expectHead != "":
		return &usageError{msg: fmt.Sprintf("--%s compares the head inside a signed write and the catalog has no trust list; run \"%s trust init\" first", flagExpect, programName), cmd: c}
	case f.signer == nil:
		return nil
	}
	actor, err := a.signedActor(c, st.Trust, f.signer.fp, f.actor, source)
	if err != nil {
		return err
	}
	f.actor = actor
	return nil
}

// close releases the signer and the store; the store's close error is kept
// only when the command itself succeeded.
func (f *decisionFlow) close(err *error) {
	f.signer.close()
	closeStore(f.store, err)
}

// decide records the decision: unsigned before the bootstrap, as v0.3 did;
// signed otherwise, over the head read just before signing, with one retry
// when that head moved under the signature (signedWrite).
func (f *decisionFlow) decide(a *app, kind signing.Kind, server, tool, digest string) (catalog.Receipt, error) {
	d := catalog.Decision{Kind: kind, Server: server, Tool: tool, Digest: digest, By: f.actor}
	if f.signer == nil {
		return f.store.Decide(a.ctx, d)
	}
	return a.signedWrite(f.expectHead, func() (catalog.Receipt, error) {
		st, err := f.store.SigningState(a.ctx)
		if err != nil {
			return catalog.Receipt{}, err
		}
		if err := checkExpectedHead(f.expectHead, st.Head); err != nil {
			return catalog.Receipt{}, err
		}
		payload, err := signing.MarshalDecision(signing.Decision{
			Actor: f.actor.Name, Catalog: st.Identity, Digest: digest, Kind: kind, PrevHead: st.Head,
			Server: server, SignedAt: time.Now(), Signer: f.signer.fp, Tool: tool,
		})
		if err != nil {
			return catalog.Receipt{}, fmt.Errorf("build the decision to sign: %w", err)
		}
		rec, err := f.signer.sign(a.ctx, payload, signing.NamespaceDecision)
		if err != nil {
			return catalog.Receipt{}, err
		}
		f.signedOver = st.Head
		a.afterSigning()
		d.Signed = &rec
		return f.store.Decide(a.ctx, d)
	})
}

// report follows the command's own line: the signature and the new head for
// a signed decision, the L13 warning for an unsigned one.
func (f *decisionFlow) report(a *app, r catalog.Receipt) {
	if f.signer == nil {
		a.stderr.printf("warning: this decision is not signed: the catalog has no trust list (L13); run \"%s trust init\"\n", programName)
		return
	}
	a.stdout.printf("signed as %s with %s over head %s; audit head now %s\n", cell(f.actor.Name), f.signer.fp, f.signedOver, r.Head)
}

// signedWrite runs attempt, which reads the head, signs over it and writes
// with the catalog's compare-and-set. When the head moved under the signature
// and the operator named no head, the log grew (a scheduled crawl landed in
// the signing window, O-17) and the attempt is made once more; a second move
// is refused with the advice to stop the crawl. With --expect-head there is
// no retry: the operator named the head and nothing is signed over another.
func (a *app) signedWrite(expectHead string, attempt func() (catalog.Receipt, error)) (catalog.Receipt, error) {
	r, err := attempt()
	if err == nil || expectHead != "" || !errors.Is(err, catalog.ErrHeadMoved) {
		return r, err
	}
	a.stderr.printf("the log grew while you signed; signing again\n")
	r, err = attempt()
	if errors.Is(err, catalog.ErrHeadMoved) {
		return r, fmt.Errorf("the log moved twice while you signed; stop the scheduled crawl and try again (%w)", err)
	}
	return r, err
}

// checkExpectedHead is the operator's compare-and-set before anything is
// signed: with --expect-head the head read for signing must be the one they
// recorded, case-insensitively as audit verify compares it. The value in the
// refusal is raw; describe escapes it once.
func checkExpectedHead(expect, head string) error {
	if expect == "" || strings.EqualFold(expect, head) {
		return nil
	}
	return fmt.Errorf("%w: expected %s, found %s; the log grew since you recorded the head or it was rewritten, and nothing was signed", catalog.ErrHeadMoved, expect, head)
}

// afterSigning runs the test hook, when one is set, between a signature and
// the write it precedes: the tests of the retry inject a crawl there.
func (a *app) afterSigning() {
	if a.afterSign != nil {
		a.afterSign()
	}
}
