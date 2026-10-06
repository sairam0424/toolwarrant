package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"text/tabwriter"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/catalog"
	"github.com/sairam0424/toolwarrant/internal/emit"
	"github.com/sairam0424/toolwarrant/internal/fetch"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
	"github.com/sairam0424/toolwarrant/internal/textdiff"
)

const (
	// shortDigestLen is how much of a digest a table shows. Twelve hex digits
	// are unique in any real catalog and enough for ResolveDigest.
	shortDigestLen = 12
	emptyCell      = "-"
	// escapedNewline is how a line break inside a table cell is shown, in the
	// same \u{HEX} style textdiff.Escape uses for everything else invisible.
	escapedNewline = `\u{000A}`
	invalidURL     = "(invalid url)"
)

// Advice for the lifecycle refusals an operator meets most often. The sentinel
// text alone ("approver must differ from the proposer") does not say what to
// do next; these do.
const (
	adviceSelfApproval = "you proposed this version; another person must approve it, or pass --allow-self-approval"
	adviceStale        = "the proposal changed since you looked; run diff again"
	adviceAmbiguous    = "give more characters of the hash"
)

// shellWordPattern matches arguments that need no quoting in a POSIX shell.
var shellWordPattern = regexp.MustCompile(`^[A-Za-z0-9_./:@%+=,-]+$`)

// cell renders untrusted text (tool names, actor names, server error text) for
// one line of terminal output. Every such string goes through textdiff.Escape,
// and a line break becomes visible too, so a row cannot forge another row.
func cell(s string) string {
	if s == "" {
		return emptyCell
	}
	return strings.ReplaceAll(textdiff.Escape(s), "\n", escapedNewline)
}

// shortDigest shows the first shortDigestLen hex digits of a digest.
func shortDigest(d string) string {
	if d == "" {
		return emptyCell
	}
	if len(d) > shortDigestLen {
		return d[:shortDigestLen]
	}
	return d
}

// safeURL reduces a URL to scheme://host[:port]/path. Query, fragment and user
// info are dropped because that is where credentials live.
func safeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return invalidURL
	}
	clean := url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}
	return clean.String()
}

// displayURL is safeURL escaped for the terminal.
func displayURL(raw string) string { return textdiff.Escape(safeURL(raw)) }

// shellWord quotes s for copy-paste into a POSIX shell when it needs it.
func shellWord(s string) string {
	if shellWordPattern.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// table aligns rows of already-escaped cells.
type table struct{ w *tabwriter.Writer }

func newTable(w io.Writer) *table {
	return &table{w: tabwriter.NewWriter(w, 0, 0, tabPadding, ' ', 0)}
}

func (t *table) row(cells ...string) {
	fmt.Fprintln(t.w, strings.Join(cells, "\t"))
}

func (t *table) flush() error {
	if err := t.w.Flush(); err != nil {
		return fmt.Errorf("write table: %w", err)
	}
	return nil
}

// writeJSON prints v indented. JSON mode is for machines, so strings are not
// escaped beyond what the JSON encoding requires.
func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("write json: %w", err)
	}
	return nil
}

// writeCompactJSON prints v as one line, for the one-object-per-line output of
// a scheduled crawl.
func writeCompactJSON(w io.Writer, v any) error {
	if err := json.NewEncoder(w).Encode(v); err != nil {
		return fmt.Errorf("write json: %w", err)
	}
	return nil
}

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
	case errors.Is(err, catalog.ErrAmbiguous):
		return msg + "; " + adviceAmbiguous
	case errors.Is(err, catalog.ErrNotFound), errors.Is(err, catalog.ErrExists), errors.Is(err, catalog.ErrInvalid):
		return msg
	case errors.Is(err, catalog.ErrSchema):
		return msg + "; upgrade toolwarrant or point --db at a toolwarrant database"
	case errors.Is(err, catalog.ErrCorrupt):
		return msg + "; do not serve from this database, restore it from a backup"
	case errors.As(err, &broken):
		return fmt.Sprintf("the audit log is broken at entry %d (%s); the database was changed outside toolwarrant", broken.Seq, textdiff.Escape(broken.Reason))
	case errors.Is(err, emit.ErrInvalidInput):
		return msg + "; fix the catalog or the flags and run emit again"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "interrupted"
	}
	return describeFetch(err, msg)
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
