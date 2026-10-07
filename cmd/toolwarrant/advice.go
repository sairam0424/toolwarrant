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
	adviceSchema       = "the file was written by another schema version and there is no migration: for a database from an unreleased build, delete the file and run init again"
	adviceCorrupt      = "do not serve from this database, restore it from a backup"
	adviceInterrupted  = "interrupted"
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
		return fmt.Sprintf("the audit log is broken at entry %d (%s); the database was changed outside toolwarrant", broken.Seq, textdiff.Escape(broken.Reason))
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

// describeCatalog adds advice for the catalog's own refusals. The order
// matters only where one error can wrap another, which these do not.
func describeCatalog(err error) (string, bool) {
	switch {
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
