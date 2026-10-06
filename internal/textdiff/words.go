package textdiff

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// longSpanBytes is the size from which a changed span is narrowed to the bytes
// that actually differ. A 50 KB description with no spaces is a single token,
// so a 28-byte insertion in the middle used to print the whole token twice
// with nothing to say where the difference was.
const longSpanBytes = 256

// wordChange is one group of adjacent differences between two strings: the
// text that was removed and the text that was added in its place. Either side
// may be empty. fromOffset and toOffset are the byte offsets of the group in
// the two strings.
type wordChange struct {
	removed    string
	added      string
	fromOffset int
	toOffset   int
}

// tokenize splits s into alternating runs of whitespace and non-whitespace.
// Joining the tokens gives s back, so whitespace changes are not lost.
func tokenize(s string) []string {
	var out []string
	start := 0
	prevSpace := false
	for i, r := range s {
		isSpace := unicode.IsSpace(r)
		if i > 0 && isSpace != prevSpace {
			out = append(out, s[start:i])
			start = i
		}
		prevSpace = isSpace
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// wordChanges diffs two strings word by word and returns the groups of
// removed and added text in order. Equal strings give no groups. Bytes that
// are not valid UTF-8 are kept as they are inside the tokens.
func wordChanges(from, to string) []wordChange {
	a, b := tokenize(from), tokenize(to)
	edits := diffSeq(a, b)
	var out []wordChange
	fromPos, toPos := 0, 0
	for i := 0; i < len(edits); {
		if edits[i].kind == kindEqual {
			fromPos += len(a[edits[i].aIdx])
			toPos += len(b[edits[i].bIdx])
			i++
			continue
		}
		group := wordChange{fromOffset: fromPos, toOffset: toPos}
		var removed, added strings.Builder
		for ; i < len(edits) && edits[i].kind != kindEqual; i++ {
			switch edits[i].kind {
			case kindDelete:
				removed.WriteString(a[edits[i].aIdx])
			case kindInsert:
				added.WriteString(b[edits[i].bIdx])
			}
		}
		group.removed, group.added = removed.String(), added.String()
		fromPos += len(group.removed)
		toPos += len(group.added)
		out = append(out, group)
	}
	return out
}

// narrowed is a change group reduced to the text that differs, with the
// number of identical bytes cut from its front and back.
type narrowed struct {
	removed string
	added   string
	before  int
	after   int
}

// narrow trims the common start and end of a group whose two sides are both
// long, so a small edit inside a huge token shows up as that edit. Short spans
// are returned whole: printing them costs nothing and keeps the context. Cuts
// fall on rune boundaries so no character is split into byte escapes.
func narrow(c wordChange) narrowed {
	if len(c.removed) <= longSpanBytes || len(c.added) <= longSpanBytes {
		return narrowed{removed: c.removed, added: c.added}
	}
	before := commonPrefixRunes(c.removed, c.added)
	after := commonSuffixRunes(c.removed[before:], c.added[before:])
	return narrowed{
		removed: c.removed[before : len(c.removed)-after],
		added:   c.added[before : len(c.added)-after],
		before:  before,
		after:   after,
	}
}

// commonPrefixRunes returns the length in bytes of the longest common prefix
// of a and b that ends on a rune boundary.
func commonPrefixRunes(a, b string) int {
	n := 0
	for n < len(a) && n < len(b) && a[n] == b[n] {
		n++
	}
	for n > 0 && n < len(a) && !utf8.RuneStart(a[n]) {
		n--
	}
	return n
}

// commonSuffixRunes returns the length in bytes of the longest common suffix
// of a and b that starts on a rune boundary.
func commonSuffixRunes(a, b string) int {
	n := 0
	for n < len(a) && n < len(b) && a[len(a)-1-n] == b[len(b)-1-n] {
		n++
	}
	for n > 0 && !utf8.RuneStart(a[len(a)-n]) {
		n--
	}
	return n
}
