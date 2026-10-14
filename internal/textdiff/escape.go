package textdiff

import (
	"strings"
	"unicode/utf8"
)

const (
	hexDigits      = "0123456789ABCDEF"
	minUnicodeHex  = 4 // \u{0041}: at least four digits, like U+0041
	byteHexDigits  = 2 // \x{FF}
	nibbleBits     = 4
	nibbleMask     = 0xF
	asciiLastPrint = 0x7E
)

// Escape returns a visible, unambiguous rendering of s that is safe to print
// to a terminal.
//
// Printable characters, a plain space and newline pass through. A backslash is
// doubled and a tab becomes \t, so the escapes below can never be confused with
// text that was already there. Everything a person cannot see or a terminal
// would act on becomes \u{HEX} (upper-case, at least four digits): control
// characters including ESC, DEL and the C1 range; format characters such as
// zero-width and bidi controls and the whole Tags block; line and paragraph
// separators; every space except the plain space; private use, surrogates,
// unassigned code points and non-characters; variation selectors; and a short
// list of invisible fillers. Bytes that are not valid UTF-8 become \x{HH}.
//
// Why it is unambiguous: the output has no raw backslash except as the start
// of an escape, so the original can always be recovered. Applying Escape to its
// own output therefore changes nothing except doubling the backslashes.
//
// Escape does not try to spot look-alikes; a printable character that draws
// the same glyph as another passes through unchanged, since an escape would
// have nothing to make visible. LookAlikeChanges and MixedScriptWords report
// them by code point instead.
func Escape(s string) string {
	return escapeString(s, true)
}

// escapeInline is Escape for text that must stay on one output line, such as a
// label or a value shown inside quotes: a newline becomes \n instead of
// passing through, so hostile text cannot start a fake line.
func escapeInline(s string) string {
	return escapeString(s, false)
}

func escapeString(s string, keepNewline bool) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			writeASCII(&b, c, keepNewline)
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			writeByteEscape(&b, c)
		case isSuspicious(r):
			writeRuneEscape(&b, r)
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

// isSuspicious reports whether r must be escaped (and reported by Findings).
func isSuspicious(r rune) bool {
	_, bad := classify(r)
	return bad
}

// writeASCII handles the bytes below 0x80, where the rules are fixed.
func writeASCII(b *strings.Builder, c byte, keepNewline bool) {
	switch {
	case c == '\\':
		b.WriteString(`\\`)
	case c == '\t':
		b.WriteString(`\t`)
	case c == '\n' && keepNewline:
		b.WriteByte('\n')
	case c == '\n':
		b.WriteString(`\n`)
	case c >= asciiPrintable && c <= asciiLastPrint:
		b.WriteByte(c)
	default:
		writeRuneEscape(b, rune(c))
	}
}

// writeRuneEscape writes \u{HEX} with upper-case digits, at least four.
func writeRuneEscape(b *strings.Builder, r rune) {
	b.WriteString(`\u{`)
	writeHex(b, uint32(r), minUnicodeHex)
	b.WriteByte('}')
}

// writeByteEscape writes \x{HH} for a byte that is not valid UTF-8.
func writeByteEscape(b *strings.Builder, c byte) {
	b.WriteString(`\x{`)
	writeHex(b, uint32(c), byteHexDigits)
	b.WriteByte('}')
}

// writeHex writes v in upper-case hex, left-padded with zeros to minDigits.
func writeHex(b *strings.Builder, v uint32, minDigits int) {
	var buf [8]byte
	n := len(buf)
	for v != 0 || len(buf)-n < minDigits {
		n--
		buf[n] = hexDigits[v&nibbleMask]
		v >>= nibbleBits
	}
	b.Write(buf[n:])
}
