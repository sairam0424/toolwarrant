// Package toolname is the single rule for what an upstream tool name may look
// like. The crawler, the catalog, the processor and the config emitter must all
// agree on it: the review found three different rules, which let a name pass
// one component and poison another (a name the catalog refused froze the whole
// crawl, and a name the emitter could not express stayed hidden with no signal).
//
// A tool name is an identifier that an AI agent reads and a gateway matches
// byte for byte, so the rule is strict: visible characters only, no invisible
// or default-ignorable code points that could hide a second name inside the
// first, one canonical Unicode form so that look-alike spellings cannot be two
// different tools, and a hard length cap because the name becomes a store key.
package toolname

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// MaxBytes is the longest accepted name. It matches the catalog's store key cap.
const MaxBytes = 256

// ErrInvalid is wrapped by every error this package returns.
var ErrInvalid = errors.New("toolname: invalid tool name")

// defaultIgnorable lists the Unicode Default_Ignorable_Code_Point ranges that
// are classified as graphic (marks, letters or symbols) and so would pass a
// plain category check although they render as nothing: the combining grapheme
// joiner, Hangul and Khitan fillers, Mongolian and generic variation selectors,
// the invisible musical and shorthand controls, the braille blank and the
// object replacement character. Format characters (Cf) are rejected separately.
var defaultIgnorable = &unicode.RangeTable{
	R16: []unicode.Range16{
		{Lo: 0x034F, Hi: 0x034F, Stride: 1},
		{Lo: 0x115F, Hi: 0x1160, Stride: 1},
		{Lo: 0x17B4, Hi: 0x17B5, Stride: 1},
		{Lo: 0x180B, Hi: 0x180F, Stride: 1},
		{Lo: 0x2800, Hi: 0x2800, Stride: 1},
		{Lo: 0x3164, Hi: 0x3164, Stride: 1},
		{Lo: 0xFE00, Hi: 0xFE0F, Stride: 1},
		{Lo: 0xFFA0, Hi: 0xFFA0, Stride: 1},
		{Lo: 0xFFFC, Hi: 0xFFFC, Stride: 1},
	},
	R32: []unicode.Range32{
		{Lo: 0x16FE4, Hi: 0x16FE4, Stride: 1},
		{Lo: 0x1BCA0, Hi: 0x1BCA3, Stride: 1},
		{Lo: 0x1D173, Hi: 0x1D17A, Stride: 1},
		{Lo: 0xE0100, Hi: 0xE01EF, Stride: 1},
	},
}

// Forbidden reports whether a single rune may not appear in a tool name: any
// non-graphic rune (controls, format characters, surrogates, private use,
// unassigned, line and paragraph separators), any space other than U+0020, and
// the default-ignorable code points above.
func Forbidden(r rune) bool {
	if r == ' ' {
		return false
	}
	if !unicode.IsGraphic(r) || unicode.Is(unicode.Zs, r) {
		return true
	}
	return unicode.Is(defaultIgnorable, r)
}

// Validate returns nil if name is acceptable, else an error wrapping ErrInvalid
// whose text names the reason but never echoes the name itself (the caller
// quotes it if it must be shown).
func Validate(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("%w: empty", ErrInvalid)
	case len(name) > MaxBytes:
		return fmt.Errorf("%w: longer than %d bytes", ErrInvalid, MaxBytes)
	case !utf8.ValidString(name):
		return fmt.Errorf("%w: not valid UTF-8", ErrInvalid)
	case !norm.NFC.IsNormalString(name):
		return fmt.Errorf("%w: not in Unicode normalization form C", ErrInvalid)
	case name[0] == ' ' || name[len(name)-1] == ' ':
		return fmt.Errorf("%w: leading or trailing space", ErrInvalid)
	case strings.Contains(name, "  "):
		return fmt.Errorf("%w: consecutive spaces", ErrInvalid)
	}
	for _, r := range name {
		if Forbidden(r) {
			return fmt.Errorf("%w: contains a control, invisible or non-printing character (U+%04X)", ErrInvalid, r)
		}
	}
	return nil
}
