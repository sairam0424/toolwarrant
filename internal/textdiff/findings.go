package textdiff

import (
	"fmt"
	"unicode/utf8"
)

// Finding describes one suspicious rune found in a string.
//
// Offset is the byte offset of the rune in the string that was scanned (not a
// rune index), so a caller can slice the original. For a byte that is not
// valid UTF-8, Rune is utf8.RuneError, Category is "invalid-utf8" and the name
// says which byte it was.
type Finding struct {
	Offset   int
	Rune     rune
	Name     string
	Category string
}

// rawFinding is a Finding before its name is looked up. The renderer counts
// every suspicious rune but prints only the first few, so it must not pay for
// a name per rune: a megabyte of unassigned runes is 350,000 names.
type rawFinding struct {
	Offset   int
	Rune     rune
	Category string
}

// named completes the finding with its name; s is the string that was scanned.
func (f rawFinding) named(s string) Finding {
	name := runeName(f.Rune)
	if f.Category == catInvalidUTF8 {
		name = fmt.Sprintf("INVALID UTF-8 BYTE 0x%02X", s[f.Offset])
	}
	return Finding{Offset: f.Offset, Rune: f.Rune, Name: name, Category: f.Category}
}

// Findings returns every suspicious rune in s, in order, for a warning banner.
// It reports exactly the characters that Escape writes as \u{...} or \x{..}.
// It does not report a tab, a newline, or ordinary printable text. Nil means
// nothing suspicious was found.
func Findings(s string) []Finding {
	var out []Finding
	scanSuspicious(s, func(f rawFinding) {
		out = append(out, f.named(s))
	})
	return out
}

// scanSuspicious calls visit, in order, for every rune of s that Escape would
// not write raw. It allocates nothing itself, so callers that only count can
// scan megabytes cheaply.
func scanSuspicious(s string, visit func(rawFinding)) {
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			if cat, bad := asciiCategory(c); bad {
				visit(rawFinding{Offset: i, Rune: rune(c), Category: cat})
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			visit(rawFinding{Offset: i, Rune: utf8.RuneError, Category: catInvalidUTF8})
		} else if cat, bad := classify(r); bad {
			visit(rawFinding{Offset: i, Rune: r, Category: cat})
		}
		i += size
	}
}

// asciiCategory classifies a byte below 0x80. Printable ASCII, tab and newline
// are not findings.
func asciiCategory(c byte) (string, bool) {
	if c == '\t' || c == '\n' || (c >= asciiPrintable && c <= asciiLastPrint) {
		return "", false
	}
	return classify(rune(c))
}
