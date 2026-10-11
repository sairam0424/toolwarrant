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
	// maxChangedValues caps the string values listed under "Changed text" in
	// the same way: the total is always printed, so two thousand renamed
	// schema properties cannot hide one changed description in the noise.
	maxChangedValues = 100
)

// Tool renders what an approver reads before approving a changed tool.
// fromCanonical and toCanonical are tool definitions as canonical JSON (RFC
// 8785). Each is pretty-printed with sorted keys and two-space indentation
// (capped at maxIndentDepth levels) and the two are compared with Unified, so
// every line is escaped.
//
// Two sections follow the diff:
//
//   - "Suspicious characters" lists every suspicious rune in the decoded string
//     values and object keys of each document, with the path and byte offset.
//     The decoded text is scanned, not the raw JSON, because a JSON escape
//     hides the character in the source text.
//   - "Changed text" lists, for every string value that differs, the words that
//     were removed and added, both escaped, in document order. A change inside
//     a long run of text without spaces is narrowed to the bytes that differ,
//     with a line saying where they sit.
//
// The whole report is capped at maxReportBytes; past that it ends with one
// line that gives the full size and says the definition should be refused.
//
// It returns an error, without echoing the input, if either document is not
// exactly one valid JSON value in valid UTF-8.
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

	r := &report{limit: maxReportBytes}
	writeUnified(r, fromLabel, toLabel, fromPretty, toPretty)
	r.writeString("\n" + sectionSuspicious + "\n")
	writeDocFindings(r, "from", fromDoc)
	writeDocFindings(r, "to", toDoc)
	r.writeString("\n" + sectionChanged + "\n")
	writeChangedText(r, compareDocs(fromDoc, toDoc))
	return r.String(), nil
}

// located is a suspicious rune together with the string it was found in.
type located struct {
	entry stringEntry
	f     rawFinding
}

// writeDocFindings prints the suspicious characters of one document: a count
// line with the per-category totals, then up to maxFindingLines detail lines.
// Every string is scanned, but only the listed findings get a name and a path.
func writeDocFindings(r *report, label string, doc any) {
	var kept []located
	counts := map[string]int{}
	total := 0
	walkStrings(doc, rootNode(), func(e stringEntry) {
		scanSuspicious(e.value, func(f rawFinding) {
			total++
			counts[f.Category]++
			if len(kept) < maxFindingLines {
				kept = append(kept, located{e, f})
			}
		})
	})
	if total == 0 {
		r.writeString("  " + label + ": none\n")
		return
	}
	r.writeString("  " + label + ": " + strconv.Itoa(total) + " (" + categoryTotals(counts) + ")\n")
	for _, l := range kept {
		where := l.entry.node.String()
		if l.entry.isKey {
			where += " (key)"
		}
		f := l.f.named(l.entry.value)
		r.writeString("    " + where + " byte " + strconv.Itoa(f.Offset) + ": " +
			codePoint(f.Rune) + " " + f.Name + " (" + f.Category + ")\n")
	}
	if total > maxFindingLines {
		r.writeString("    ... " + strconv.Itoa(total-maxFindingLines) + " more not listed\n")
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
// documents, the removed and added words, up to maxChangedValues values
// followed by a count of the rest and the total. It also stops early once the
// report is full, because the word diffs are the expensive part.
func writeChangedText(r *report, changes []changedValue) {
	if len(changes) == 0 {
		r.writeString("  none\n")
		return
	}
	for i, c := range changes {
		if i == maxChangedValues || r.truncated() {
			r.writeString("    ... " + strconv.Itoa(len(changes)-i) + " more changed values not listed (" +
				strconv.Itoa(len(changes)) + " in total)\n")
			return
		}
		r.writeString("  " + c.path.String() + "\n")
		for _, g := range wordChanges(c.from, c.to) {
			writeSpan(r, g)
		}
	}
}

// writeSpan prints one change group. A group whose two sides are both long is
// narrowed to the text that differs, with a line saying where it sits.
func writeSpan(r *report, g wordChange) {
	n := narrow(g)
	if n.before+n.after > 0 {
		r.writeString("    (differs at old byte " + strconv.Itoa(g.fromOffset+n.before) +
			" / new byte " + strconv.Itoa(g.toOffset+n.before) + "; " + strconv.Itoa(n.before) +
			" identical bytes before and " + strconv.Itoa(n.after) + " after are not shown)\n")
	}
	writeQuoted(r, '-', n.removed)
	writeQuoted(r, '+', n.added)
}

// writeQuoted prints one removed or added span on its own line, escaped and in
// quotes so leading and trailing spaces are visible. A quotation mark inside
// the span is written \" (escapeInline doubles every real backslash, so the
// form is unambiguous, as in keySegment): a span can end only at the
// renderer's own closing quote, and hostile text cannot forge a second span on
// the line. An empty span is skipped.
func writeQuoted(r *report, sign byte, text string) {
	if text == "" {
		return
	}
	r.writeString("    ")
	r.writeByte(sign)
	r.writeString(` "`)
	r.writeString(strings.ReplaceAll(escapeInline(text), `"`, `\"`))
	r.writeString("\"\n")
}
