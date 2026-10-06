package textdiff

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const (
	sectionSuspicious = "Suspicious characters"
	sectionChanged    = "Changed text"
	// maxFindingLines caps the detail lines printed per document. The counts
	// per category are always complete, and the diff above shows every
	// character as an escape anyway, so a megabyte of zero-width spaces
	// cannot bury the rest of the report.
	maxFindingLines = 100
)

// Tool renders what an approver reads before approving a changed tool.
// fromCanonical and toCanonical are tool definitions as canonical JSON (RFC
// 8785). Each is pretty-printed with sorted keys and two-space indentation and
// the two are compared with Unified, so every line is escaped.
//
// Two sections follow the diff:
//
//   - "Suspicious characters" lists every suspicious rune in the decoded string
//     values and object keys of each document, with the path and byte offset.
//     The decoded text is scanned, not the raw JSON, because a JSON escape
//     hides the character in the source text.
//   - "Changed text" lists, for every string value that differs, the words that
//     were removed and added, both escaped.
//
// It returns an error, without echoing the input, if either document is not
// exactly one valid JSON value.
func Tool(fromLabel, toLabel string, fromCanonical, toCanonical []byte) (string, error) {
	fromDoc, err := decodeJSON(fromCanonical)
	if err != nil {
		return "", fmt.Errorf("textdiff: from document: %w", err)
	}
	toDoc, err := decodeJSON(toCanonical)
	if err != nil {
		return "", fmt.Errorf("textdiff: to document: %w", err)
	}
	fromPretty, err := prettyJSON(fromDoc)
	if err != nil {
		return "", fmt.Errorf("textdiff: from document: %w", err)
	}
	toPretty, err := prettyJSON(toDoc)
	if err != nil {
		return "", fmt.Errorf("textdiff: to document: %w", err)
	}

	fromStrings, toStrings := collectStrings(fromDoc), collectStrings(toDoc)
	var sb strings.Builder
	sb.WriteString(Unified(fromLabel, toLabel, fromPretty, toPretty))
	sb.WriteString("\n" + sectionSuspicious + "\n")
	writeDocFindings(&sb, "from", fromStrings)
	writeDocFindings(&sb, "to", toStrings)
	sb.WriteString("\n" + sectionChanged + "\n")
	writeChangedText(&sb, stringValues(fromStrings), stringValues(toStrings))
	return sb.String(), nil
}

// writeDocFindings prints the suspicious characters of one document: a count
// line with the per-category totals, then up to maxFindingLines detail lines.
func writeDocFindings(sb *strings.Builder, label string, entries []stringEntry) {
	type located struct {
		entry stringEntry
		f     Finding
	}
	var all []located
	counts := map[string]int{}
	for _, e := range entries {
		for _, f := range Findings(e.value) {
			all = append(all, located{e, f})
			counts[f.Category]++
		}
	}
	if len(all) == 0 {
		sb.WriteString("  " + label + ": none\n")
		return
	}
	sb.WriteString("  " + label + ": " + strconv.Itoa(len(all)) + " (" + categoryTotals(counts) + ")\n")
	for i, l := range all {
		if i == maxFindingLines {
			sb.WriteString("    ... " + strconv.Itoa(len(all)-maxFindingLines) + " more not listed\n")
			break
		}
		where := l.entry.path
		if l.entry.isKey {
			where += " (key)"
		}
		fmt.Fprintf(sb, "    %s byte %d: %s %s (%s)\n",
			where, l.f.Offset, codePoint(l.f.Rune), l.f.Name, l.f.Category)
	}
}

// categoryTotals formats "category: n" pairs sorted by category.
func categoryTotals(counts map[string]int) string {
	names := make([]string, 0, len(counts))
	for c := range counts {
		names = append(names, c)
	}
	sort.Strings(names)
	parts := make([]string, len(names))
	for i, c := range names {
		parts[i] = c + ": " + strconv.Itoa(counts[c])
	}
	return strings.Join(parts, ", ")
}

// writeChangedText prints, for each string value that differs between the
// documents, the removed and added words. A value that exists on one side only
// counts as changed from or to the empty string.
func writeChangedText(sb *strings.Builder, from, to map[string]string) {
	paths := make([]string, 0, len(from)+len(to))
	seen := make(map[string]bool, len(from)+len(to))
	for _, m := range []map[string]string{from, to} {
		for p := range m {
			if !seen[p] {
				seen[p] = true
				paths = append(paths, p)
			}
		}
	}
	sort.Strings(paths)

	wrote := false
	for _, p := range paths {
		changes := wordChanges(from[p], to[p])
		if len(changes) == 0 {
			continue
		}
		wrote = true
		sb.WriteString("  " + p + "\n")
		for _, c := range changes {
			writeQuoted(sb, '-', c.removed)
			writeQuoted(sb, '+', c.added)
		}
	}
	if !wrote {
		sb.WriteString("  none\n")
	}
}

// writeQuoted prints one removed or added span on its own line, escaped and in
// quotes so leading and trailing spaces are visible. An empty span is skipped.
func writeQuoted(sb *strings.Builder, sign byte, text string) {
	if text == "" {
		return
	}
	sb.WriteString("    ")
	sb.WriteByte(sign)
	sb.WriteString(` "`)
	sb.WriteString(escapeInline(text))
	sb.WriteString("\"\n")
}
