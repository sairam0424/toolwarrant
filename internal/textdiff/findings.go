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

// Findings returns every suspicious rune in s, in order, for a warning banner.
// It reports exactly the characters that Escape writes as \u{...} or \x{..}.
// It does not report a tab, a newline, or ordinary printable text. Nil means
// nothing suspicious was found.
func Findings(s string) []Finding {
	var out []Finding
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			if f, ok := asciiFinding(i, c); ok {
				out = append(out, f)
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			out = append(out, invalidByteFinding(i, c))
		} else if cat, bad := classify(r); bad {
			out = append(out, Finding{Offset: i, Rune: r, Name: runeName(r), Category: cat})
		}
		i += size
	}
	return out
}

// asciiFinding reports a control byte below 0x80. Printable ASCII, tab and
// newline are not findings.
func asciiFinding(offset int, c byte) (Finding, bool) {
	if c == '\t' || c == '\n' || (c >= asciiPrintable && c <= asciiLastPrint) {
		return Finding{}, false
	}
	r := rune(c)
	cat, _ := classify(r)
	return Finding{Offset: offset, Rune: r, Name: runeName(r), Category: cat}, true
}

// invalidByteFinding reports a byte that is not part of valid UTF-8.
func invalidByteFinding(offset int, c byte) Finding {
	return Finding{
		Offset:   offset,
		Rune:     utf8.RuneError,
		Name:     fmt.Sprintf("INVALID UTF-8 BYTE 0x%02X", c),
		Category: catInvalidUTF8,
	}
}
