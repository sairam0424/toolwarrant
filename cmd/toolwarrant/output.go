package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"text/tabwriter"

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
	// nameWithheld stands for a tool name the catalog refused to keep (it
	// broke the shared tool-name rule), so that no look-alike is ever shown.
	nameWithheld = "(name withheld)"
)

// shellWordPattern matches arguments that need no quoting in a POSIX shell.
var shellWordPattern = regexp.MustCompile(`^[A-Za-z0-9_./:@%+=,-]+$`)

// stream is one of the program's two output streams. It remembers the first
// write error instead of returning one from every print site, so that output
// code stays one line per message while run can still turn a broken stdout or
// stderr into exit 1: a closed pipe must not look like success, and an error
// must never be dropped on the floor just because printing it is tedious.
type stream struct {
	w   io.Writer
	err error
}

// Write implements io.Writer for the table writer and the JSON encoder. After
// the first failure nothing more is written and that error is returned.
func (s *stream) Write(p []byte) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	n, err := s.w.Write(p)
	if err != nil {
		s.err = err
	}
	return n, err
}

// printf formats one message onto the stream.
func (s *stream) printf(format string, args ...any) {
	if s.err != nil {
		return
	}
	if _, err := fmt.Fprintf(s.w, format, args...); err != nil {
		s.err = err
	}
}

// print writes text as it is.
func (s *stream) print(text string) {
	if s.err != nil {
		return
	}
	if _, err := io.WriteString(s.w, text); err != nil {
		s.err = err
	}
}

// broken returns the first write error, or nil if every write succeeded.
func (s *stream) broken() error { return s.err }

// cell renders untrusted text (tool names, actor names, server error text) for
// one line of terminal output. Every such string goes through textdiff.Escape,
// and a line break becomes visible too, so a row cannot forge another row.
func cell(s string) string {
	if s == "" {
		return emptyCell
	}
	return strings.ReplaceAll(textdiff.Escape(s), "\n", escapedNewline)
}

// cells renders a list of untrusted names as one comma-separated cell.
func cells(names []string) string {
	return joinCells(names, ",")
}

// cellsProse renders a list of untrusted names for a sentence: comma and
// space separated, as the guide shows the list audit verify prints after the
// unsigned approvals in service (post-v0.4.0 verification, orchestrator
// decision 45 (f)); the bare comma of a table cell would read as one name.
func cellsProse(names []string) string {
	return joinCells(names, ", ")
}

// joinCells escapes every name as a cell and joins them with sep.
func joinCells(names []string, sep string) string {
	if len(names) == 0 {
		return emptyCell
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, cell(n))
	}
	return strings.Join(out, sep)
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

// table aligns rows of already-escaped cells. The first write error is kept
// and returned from flush, so a table printed to a closed pipe is reported
// once instead of once per row.
type table struct {
	w   *tabwriter.Writer
	err error
}

func newTable(w io.Writer) *table {
	return &table{w: tabwriter.NewWriter(w, 0, 0, tabPadding, ' ', 0)}
}

func (t *table) row(cells ...string) {
	if t.err != nil {
		return
	}
	if _, err := fmt.Fprintln(t.w, strings.Join(cells, "\t")); err != nil {
		t.err = err
	}
}

func (t *table) flush() error {
	if t.err != nil {
		return fmt.Errorf("write table: %w", t.err)
	}
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
// a scheduled crawl or check.
func writeCompactJSON(w io.Writer, v any) error {
	if err := json.NewEncoder(w).Encode(v); err != nil {
		return fmt.Errorf("write json: %w", err)
	}
	return nil
}
