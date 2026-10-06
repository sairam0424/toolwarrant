// Package textdiff renders the difference between two versions of an MCP tool
// definition for the person who has to approve it.
//
// Tool descriptions are read by AI agents, so the attack is a hidden
// instruction: zero-width characters between letters, Unicode "tag" characters
// that spell a sentence no human can see, bidi overrides that reverse text,
// or terminal escape sequences that rewrite what the approver's screen shows.
// Everything in this package therefore works from one rule: a character that a
// person cannot see, or that a terminal would act on, is never written out
// raw. It is replaced by a visible escape such as \u{200B}.
//
// The package does not detect homoglyphs (a Cyrillic "a" that looks like a
// Latin one). Those are ordinary printable characters and pass through
// unchanged; a reader is not warned about them.
//
// Nothing here uses colour. The CLI adds that later.
package textdiff

import (
	"unicode"
	"unicode/utf8"
)

// Categories reported by Findings. They are short and stable so a CLI can
// group or colour by them.
const (
	catControl           = "control"
	catTerminalEscape    = "terminal-escape"
	catZeroWidth         = "zero-width"
	catBidi              = "bidi-control"
	catTag               = "tag-character"
	catFiller            = "invisible-filler"
	catInvisibleOperator = "invisible-operator"
	catVariationSelector = "variation-selector"
	catGraphemeJoiner    = "grapheme-joiner"
	catSoftHyphen        = "soft-hyphen"
	catDeprecatedFormat  = "deprecated-format"
	catFormat            = "format"
	catLineSeparator     = "line-separator"
	catSpace             = "unusual-space"
	catPrivateUse        = "private-use"
	catSurrogate         = "surrogate"
	catNoncharacter      = "noncharacter"
	catUnassigned        = "unassigned"
	catObject            = "object-replacement"
	catInvalidRune       = "invalid-rune"
	catInvalidUTF8       = "invalid-utf8"
)

// Code point boundaries used by the classifier.
const (
	c1Start        = 0x7F // DEL, then the C1 range up to c1End
	c1End          = 0x9F
	asciiPrintable = 0x20 // first printable ASCII rune
	tagBlockStart  = 0xE0000
	tagBlockEnd    = 0xE007F
	noncharLow     = 0xFDD0
	noncharHigh    = 0xFDEF
	noncharMask    = 0xFFFE // U+xFFFE and U+xFFFF of every plane
	surrogateStart = 0xD800
	surrogateEnd   = 0xDFFF
)

// classify reports why r must not be written raw. The second result is false
// for an ordinary printable rune, including a plain space. Tab and newline are
// classified as controls here; Escape and Findings give them their own
// handling before they ask.
func classify(r rune) (string, bool) {
	if !utf8.ValidRune(r) {
		if r >= surrogateStart && r <= surrogateEnd {
			return catSurrogate, true
		}
		return catInvalidRune, true
	}
	if r < asciiPrintable || (r >= c1Start && r <= c1End) {
		return controlCategory(r), true
	}
	if r < utf8.RuneSelf {
		return "", false
	}
	if cat, ok := classifyExplicit(r); ok {
		return cat, true
	}
	return classifyByTable(r)
}

// controlCategory separates the controls a terminal acts on (ESC and the C1
// introducers) from the rest, because those are the ones that can repaint the
// approver's screen.
func controlCategory(r rune) string {
	switch r {
	case 0x1B, 0x90, 0x98, 0x9B, 0x9D, 0x9E, 0x9F:
		return catTerminalEscape
	}
	return catControl
}

// classifyExplicit covers the characters that are named one by one in the
// threat model. They are matched by code point, not by Unicode category, so a
// future table update cannot quietly let one through.
func classifyExplicit(r rune) (string, bool) {
	switch {
	case r == 0x00AD:
		return catSoftHyphen, true
	case r == 0x034F:
		return catGraphemeJoiner, true
	case r == 0x061C, r == 0x200E, r == 0x200F,
		r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
		return catBidi, true
	case r >= 0x200B && r <= 0x200D, r == 0x2060, r == 0xFEFF:
		return catZeroWidth, true
	case r >= 0x2061 && r <= 0x2064:
		return catInvisibleOperator, true
	case r >= 0x206A && r <= 0x206F:
		return catDeprecatedFormat, true
	case r == 0x115F, r == 0x1160, r == 0x3164, r == 0xFFA0,
		r == 0x2800, r == 0x17B4, r == 0x17B5:
		return catFiller, true
	case isVariationSelector(r):
		return catVariationSelector, true
	case r >= tagBlockStart && r <= tagBlockEnd:
		return catTag, true
	case r == 0xFFFC:
		return catObject, true
	case r == 0x2028, r == 0x2029:
		return catLineSeparator, true
	}
	return "", false
}

// isVariationSelector reports the standard and supplementary variation
// selectors and the Mongolian free variation selectors. They change how the
// previous character is drawn and are invisible on their own.
func isVariationSelector(r rune) bool {
	return (r >= 0x180B && r <= 0x180D) || r == 0x180F ||
		(r >= 0xFE00 && r <= 0xFE0F) || (r >= 0xE0100 && r <= 0xE01EF)
}

// classifyByTable handles everything the explicit list does not: any other
// format character, any space that is not a plain space, private use, and
// code points that are not assigned to a character at all.
func classifyByTable(r rune) (string, bool) {
	switch {
	case (r >= noncharLow && r <= noncharHigh) || r&noncharMask == noncharMask:
		return catNoncharacter, true
	case unicode.Is(unicode.Cf, r):
		return catFormat, true
	case unicode.Is(unicode.Zs, r):
		return catSpace, true
	case unicode.Is(unicode.Co, r):
		return catPrivateUse, true
	case !isAssigned(r):
		return catUnassigned, true
	}
	return "", false
}

// isAssigned reports whether r has a general category other than Cn
// (unassigned). It lists Cc, Cf, Co and Cs one by one because unicode.C, the
// whole "Other" group, also contains the unassigned code points.
func isAssigned(r rune) bool {
	return unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S,
		unicode.Z, unicode.Cc, unicode.Cf, unicode.Co, unicode.Cs)
}
