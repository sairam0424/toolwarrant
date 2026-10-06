package textdiff

import (
	"strings"
	"unicode"
)

// wordChange is one group of adjacent differences between two strings: the
// text that was removed and the text that was added in its place. Either side
// may be empty.
type wordChange struct {
	removed string
	added   string
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
	for i := 0; i < len(edits); {
		if edits[i].kind == kindEqual {
			i++
			continue
		}
		var removed, added strings.Builder
		for ; i < len(edits) && edits[i].kind != kindEqual; i++ {
			switch edits[i].kind {
			case kindDelete:
				removed.WriteString(a[edits[i].aIdx])
			case kindInsert:
				added.WriteString(b[edits[i].bIdx])
			}
		}
		out = append(out, wordChange{removed: removed.String(), added: added.String()})
	}
	return out
}
