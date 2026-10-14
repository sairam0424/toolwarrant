package textdiff

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	sectionLookAlike = "Look-alike changes"
	// maxLookAlikeLines caps the detail lines of the section, as
	// maxFindingLines caps the suspicious characters: the counts stay complete.
	maxLookAlikeLines = 100
	// maxSwapsListed caps the swaps printed for one value; a value with more
	// is a rewrite, and the count says how many.
	maxSwapsListed = 10
)

// LookAlikeChange is one string value or object key of the new document that
// differs from the old document at the same path but reads the same (equal
// skeletons, see Skeleton). Path is the escaped display path, safe to print;
// IsKey says the text is an object key, a parameter name for example, that
// replaced a key of the same appearance; Swaps are the code points that
// changed, in the new text's order.
type LookAlikeChange struct {
	Path  string
	IsKey bool
	Swaps []Swap
}

// Where renders the path with the key marker, as the report prints it.
func (c LookAlikeChange) Where() string {
	if c.IsKey {
		return c.Path + " (key)"
	}
	return c.Path
}

// Detail renders the swaps, at most maxSwapsListed of them, then a count.
func (c LookAlikeChange) Detail() string {
	parts := make([]string, 0, len(c.Swaps))
	for i, s := range c.Swaps {
		if i == maxSwapsListed {
			parts = append(parts, "+"+strconv.Itoa(len(c.Swaps)-i)+" more")
			break
		}
		parts = append(parts, s.String())
	}
	return strings.Join(parts, ", ")
}

// LookAlikeChanges decodes two canonical documents and lists every string
// value that changed to a look-alike of itself and every object key that was
// replaced by a look-alike of a key that vanished from the same object. A
// changed value the diff shows as a visible change is not listed; the point
// of the list is what the diff cannot show. It returns an error, without
// echoing the input, if either document is not exactly one valid JSON value
// in valid UTF-8.
func LookAlikeChanges(fromCanonical, toCanonical []byte) ([]LookAlikeChange, error) {
	fromDoc, err := decodeJSON(fromCanonical)
	if err != nil {
		return nil, fmt.Errorf("textdiff: from document: %w", err)
	}
	toDoc, err := decodeJSON(toCanonical)
	if err != nil {
		return nil, fmt.Errorf("textdiff: to document: %w", err)
	}
	values, keys := compareAll(fromDoc, toDoc)
	return lookAlikesOf(values, keys), nil
}

// lookAlikesOf keeps the changed values whose two sides share a skeleton and
// every key swap the comparer already paired by skeleton.
func lookAlikesOf(values, keySwaps []changedValue) []LookAlikeChange {
	var out []LookAlikeChange
	for _, v := range values {
		if v.from != "" && v.to != "" && LookAlike(v.from, v.to) {
			out = append(out, LookAlikeChange{Path: v.path.String(), Swaps: swapsBetween(v.from, v.to)})
		}
	}
	for _, k := range keySwaps {
		out = append(out, LookAlikeChange{Path: k.path.String(), IsKey: true, Swaps: swapsBetween(k.from, k.to)})
	}
	return out
}

// lookAlikeLine is one detail line of the section with its category.
type lookAlikeLine struct {
	text     string
	category string
}

// writeLookAlikes prints the section: a count line with the per-category
// totals, then up to maxLookAlikeLines detail lines. The look-alike changes
// are between the two documents; the mixed-script words are those of the new
// document, since the old one was reviewed when it was approved.
func writeLookAlikes(r *report, changes []LookAlikeChange, toDoc any) {
	var lines []lookAlikeLine
	counts := map[string]int{}
	total := 0
	keep := func(l lookAlikeLine) {
		total++
		counts[l.category]++
		if len(lines) < maxLookAlikeLines {
			lines = append(lines, l)
		}
	}
	for _, c := range changes {
		keep(lookAlikeLine{c.Where() + ": " + c.Detail(), catLookAlike})
	}
	walkStrings(toDoc, rootNode(), func(e stringEntry) {
		where := e.node.String()
		if e.isKey {
			where += " (key)"
		}
		for _, w := range MixedScriptWords(e.value) {
			keep(lookAlikeLine{where + " byte " + strconv.Itoa(w.Offset) + ": " + w.Detail(), catMixedScript})
		}
	})
	if total == 0 {
		r.writeString("  none\n")
		return
	}
	r.writeString("  " + strconv.Itoa(total) + " (" + categoryTotals(counts) + ")\n")
	for _, l := range lines {
		r.writeString("    " + l.text + " (" + l.category + ")\n")
	}
	if total > maxLookAlikeLines {
		r.writeString("    ... " + strconv.Itoa(total-maxLookAlikeLines) + " more not listed\n")
	}
}
