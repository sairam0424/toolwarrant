package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/catalog"
	"github.com/sairam0424/toolwarrant/internal/emit"
	"github.com/sairam0424/toolwarrant/internal/fetch"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
	"github.com/sairam0424/toolwarrant/internal/textdiff"
)

// Advice for the refusals an operator meets most often. The sentinel text
// alone ("approver must differ from every proposer") does not say what to do
// next; these do. Each is one sentence.
const (
	adviceSelfApproval = "your crawl proposed this version; another person must approve it, or pass --allow-self-approval"
	adviceStale        = "the proposal changed since you looked; run diff again"
	adviceAmbiguous    = "give more characters of the hash"
	adviceReadOnly     = "the database was opened read-only, so nothing can be changed through it"
	advicePaused       = "the server is paused; run \"" + programName + " server resume NAME\" before crawling it again"
	adviceHuman        = "only a named person decides; pass --as with your own name"
	adviceSchema       = "the file was written by another schema version; the message says whether it came from an unreleased build (delete it and run init again) or from a release (migrate it in place with this build as the message says, or read it with a build of that schema; never delete it)"
	adviceCorrupt      = "do not serve from this database, restore it from a backup"
	adviceInterrupted  = "interrupted"
	adviceSignature    = "pass --ssh-key PATH naming a key the trust list holds (run \"" + programName + " trust show\" to see them)"
	adviceNotASigner   = "run \"" + programName + " trust show\" to see whose keys the trust list names; a key is added with \"" + programName + " trust add\""
	adviceNoTrustList  = "run \"" + programName + " trust init\" first"
	// adviceNoTrustListPinned is for a catalog that was never bootstrapped
	// and was opened under a trust root: there is no backup to restore, the
	// pin names a catalog this is not (or not yet).
	adviceNoTrustListPinned = "this catalog has no trust list: run \"" + programName + " trust init\" without --" + flagTrustRoot + " (or " + envTrustRoot + "), or name the root of the catalog you meant"
)

// describe turns an error into the one sentence the operator reads on stderr.
// Known sentinels get advice; everything else is the error text, escaped
// because upstream-controlled strings can end up inside it.
func describe(err error) string {
	msg := textdiff.Escape(err.Error())
	var broken *audit.BrokenError
	switch {
	case errors.Is(err, lifecycle.ErrSelfApproval):
		return adviceSelfApproval
	case errors.Is(err, lifecycle.ErrStaleVersion):
		return adviceStale
	case errors.Is(err, lifecycle.ErrInvalidTransition):
		return msg + "; run show to see the tool's state"
	case errors.Is(err, lifecycle.ErrNotRollbackTarget):
		return msg + "; only a version that was approved before can be rolled back to"
	case errors.As(err, &broken):
		s := fmt.Sprintf("the audit log is broken at entry %d (%s); the database was changed outside toolwarrant", broken.Seq, textdiff.Escape(broken.Reason))
		if integrity, ok := joinedCorrupt(err); ok {
			s += "; " + integrity
		}
		return s
	case errors.Is(err, emit.ErrInvalidInput):
		return msg + "; fix the catalog or the flags and run emit again"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return adviceInterrupted
	}
	if advice, ok := describeCatalog(err); ok {
		return msg + "; " + advice
	}
	return describeFetch(err, msg)
}

// joinedCorrupt finds the integrity failure that audit verify joins to a
// broken chain (D14 i: the report runs even when the chain is broken) and
// renders it with its advice, so the one line on stderr names both findings
// instead of the broken entry alone.
func joinedCorrupt(err error) (string, bool) {
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		return "", false
	}
	for _, e := range joined.Unwrap() {
		if errors.Is(e, catalog.ErrCorrupt) {
			return textdiff.Escape(e.Error()) + "; " + adviceCorrupt, true
		}
	}
	return "", false
}

// describeCatalog adds advice for the catalog's own refusals. The order
// matters only where one error wraps another: the walk's refusal of a catalog
// without a trust list under a pinned root wraps ErrNoTrustList in ErrCorrupt,
// and its advice (drop the pin or name the right root) comes before the
// corrupt advice (restore a backup), which a never-bootstrapped catalog has no
// use for.
func describeCatalog(err error) (string, bool) {
	switch {
	case errors.Is(err, catalog.ErrCorrupt) && errors.Is(err, catalog.ErrNoTrustList):
		return adviceNoTrustListPinned, true
	case errors.Is(err, catalog.ErrAmbiguous):
		return adviceAmbiguous, true
	case errors.Is(err, catalog.ErrReadOnly):
		return adviceReadOnly, true
	case errors.Is(err, catalog.ErrPaused):
		return advicePaused, true
	case errors.Is(err, catalog.ErrHumanRequired):
		return adviceHuman, true
	case errors.Is(err, catalog.ErrSchema):
		return adviceSchema, true
	case errors.Is(err, catalog.ErrCorrupt):
		return adviceCorrupt, true
	case errors.Is(err, catalog.ErrSignatureRequired):
		return adviceSignature, true
	case errors.Is(err, catalog.ErrNotASigner):
		return adviceNotASigner, true
	case errors.Is(err, catalog.ErrNoTrustList):
		return adviceNoTrustList, true
	}
	return "", false
}

// describeFetch adds advice for the egress policy refusals.
func describeFetch(err error, msg string) string {
	switch {
	case errors.Is(err, fetch.ErrBlockedAddress):
		return msg + "; the egress policy forbids loopback, private and link-local addresses unless the server was added with --allow-private (lab use only)"
	case errors.Is(err, fetch.ErrBlockedHost):
		return msg + "; the url must have a plain host and no user info"
	case errors.Is(err, fetch.ErrBlockedScheme):
		return msg + "; only http and https are crawled"
	case errors.Is(err, fetch.ErrRedirect):
		return msg + "; register the final url instead of following redirects"
	case errors.Is(err, fetch.ErrTooLarge):
		return msg + "; the response exceeded the size cap"
	}
	return msg
}
