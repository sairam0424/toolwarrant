package emit

import (
	"fmt"
	"strings"
)

// Printable ASCII bounds. Anything outside [firstPrintable, lastPrintable] is
// either a control character or not ASCII, and is never written raw into the
// generated file.
const (
	firstPrintable = 0x20
	lastPrintable  = 0x7e
	maxBMP         = 0xFFFF
)

// isPrintableASCII reports whether every byte of s is a printable ASCII
// character. The emitter only accepts such strings for identifiers that end up
// inside the generated file, which keeps the output reviewable byte by byte and
// closes off encoding tricks (bidi overrides, homoglyphs, line separators).
func isPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < firstPrintable || s[i] > lastPrintable {
			return false
		}
	}
	return true
}

// quote returns s as a double-quoted string literal that is valid both as a
// YAML scalar and as a CEL string literal. Both grammars accept the same
// escapes (backslash, double quote, \uXXXX and \UXXXXXXXX), so one function
// serves both and a value can never break out of its quotes or add a line.
// Backslash, double quote, control characters and every non-ASCII rune are
// escaped; invalid UTF-8 becomes U+FFFD rather than raw bytes.
func quote(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case r == '"':
			b.WriteString(`\"`)
		case r >= firstPrintable && r <= lastPrintable:
			b.WriteRune(r)
		case r <= maxBMP:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			fmt.Fprintf(&b, `\U%08x`, r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
