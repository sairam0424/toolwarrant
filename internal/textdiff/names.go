package textdiff

import (
	"strconv"
	"strings"
	"sync"
)

// c0Names holds the Unicode names of U+0000..U+001F in order, joined by '|'.
const c0Names = "NULL|START OF HEADING|START OF TEXT|END OF TEXT|END OF TRANSMISSION|" +
	"ENQUIRY|ACKNOWLEDGE|BELL|BACKSPACE|CHARACTER TABULATION|LINE FEED|" +
	"LINE TABULATION|FORM FEED|CARRIAGE RETURN|SHIFT OUT|SHIFT IN|" +
	"DATA LINK ESCAPE|DEVICE CONTROL ONE|DEVICE CONTROL TWO|DEVICE CONTROL THREE|" +
	"DEVICE CONTROL FOUR|NEGATIVE ACKNOWLEDGE|SYNCHRONOUS IDLE|" +
	"END OF TRANSMISSION BLOCK|CANCEL|END OF MEDIUM|SUBSTITUTE|ESCAPE|" +
	"INFORMATION SEPARATOR FOUR|INFORMATION SEPARATOR THREE|" +
	"INFORMATION SEPARATOR TWO|INFORMATION SEPARATOR ONE"

// digitNames are the Unicode names of the ASCII digits, in order.
const digitNames = "ZERO|ONE|TWO|THREE|FOUR|FIVE|SIX|SEVEN|EIGHT|NINE"

// asciiPunctuationNames lists ASCII space and punctuation, each entry being
// the character followed by its name. The vertical line is the separator, so
// it is handled in code.
const asciiPunctuationNames = " SPACE|!EXCLAMATION MARK|\"QUOTATION MARK|#NUMBER SIGN|$DOLLAR SIGN|" +
	"%PERCENT SIGN|&AMPERSAND|'APOSTROPHE|(LEFT PARENTHESIS|)RIGHT PARENTHESIS|" +
	"*ASTERISK|+PLUS SIGN|,COMMA|-HYPHEN-MINUS|.FULL STOP|/SOLIDUS|:COLON|" +
	";SEMICOLON|<LESS-THAN SIGN|=EQUALS SIGN|>GREATER-THAN SIGN|?QUESTION MARK|" +
	"@COMMERCIAL AT|[LEFT SQUARE BRACKET|\\REVERSE SOLIDUS|]RIGHT SQUARE BRACKET|" +
	"^CIRCUMFLEX ACCENT|_LOW LINE|`GRAVE ACCENT|{LEFT CURLY BRACKET|" +
	"}RIGHT CURLY BRACKET|~TILDE"

// nameTables holds every hand-written name. It is built exactly once and never
// written again, so it is shared immutable data rather than mutable global
// state. Building the maps on every call, as the first version did, cost a
// gigabyte of allocation on a one-megabyte run of unassigned runes.
type nameTables struct {
	c0        []string
	digits    []string
	punct     map[byte]string
	format    map[rune]string
	space     map[rune]string
	invisible map[rune]string
}

var (
	tablesOnce sync.Once
	tables     nameTables
)

// names returns the shared tables, building them on first use.
func names() *nameTables {
	tablesOnce.Do(func() {
		tables = nameTables{
			c0:        strings.Split(c0Names, "|"),
			digits:    strings.Split(digitNames, "|"),
			punct:     punctuationTable(),
			format:    formatTable(),
			space:     spaceTable(),
			invisible: invisibleTable(),
		}
	})
	return &tables
}

// runeName returns a human-readable name for a suspicious rune, in the style
// of the Unicode character names. Runes without a hand-written name get the
// upper-cased category and the code point, so the name is never empty.
func runeName(r rune) string {
	if r < asciiPrintable || (r >= c1Start && r <= c1End) {
		return controlName(r)
	}
	if r >= tagBlockStart && r <= tagBlockEnd {
		return tagName(r)
	}
	if n := knownName(r); n != "" {
		return n
	}
	cat, _ := classify(r)
	return strings.ToUpper(strings.ReplaceAll(cat, "-", " ")) + " " + codePoint(r)
}

// codePoint formats r as U+XXXX with at least four upper-case hex digits.
func codePoint(r rune) string {
	hex := strings.ToUpper(strconv.FormatInt(int64(r), 16))
	if len(hex) < 4 {
		hex = strings.Repeat("0", 4-len(hex)) + hex
	}
	return "U+" + hex
}

// controlName names a C0 control, DEL or a C1 control.
func controlName(r rune) string {
	switch {
	case r < asciiPrintable:
		return names().c0[r]
	case r == c1Start:
		return "DELETE"
	}
	if n := c1Name(r); n != "" {
		return n
	}
	return "C1 CONTROL " + codePoint(r)
}

// c1Name names the C1 controls a terminal is most likely to act on.
func c1Name(r rune) string {
	switch r {
	case 0x85:
		return "NEXT LINE"
	case 0x8E:
		return "SINGLE SHIFT TWO"
	case 0x8F:
		return "SINGLE SHIFT THREE"
	case 0x90:
		return "DEVICE CONTROL STRING"
	case 0x98:
		return "START OF STRING"
	case 0x9B:
		return "CONTROL SEQUENCE INTRODUCER"
	case 0x9C:
		return "STRING TERMINATOR"
	case 0x9D:
		return "OPERATING SYSTEM COMMAND"
	case 0x9E:
		return "PRIVACY MESSAGE"
	case 0x9F:
		return "APPLICATION PROGRAM COMMAND"
	}
	return ""
}

// tagName names a character of the Tags block. Each tag character mirrors an
// ASCII character, so "TAG LATIN SMALL LETTER A" tells the reader which letter
// of a hidden sentence it is.
func tagName(r rune) string {
	base := r - tagBlockStart
	switch {
	case base == 0x01:
		return "LANGUAGE TAG"
	case base == 0x7F:
		return "CANCEL TAG"
	case base >= asciiPrintable && base <= 0x7E:
		return "TAG " + asciiName(byte(base))
	}
	return "TAG CHARACTER " + codePoint(r)
}

// asciiName names a printable ASCII character.
func asciiName(c byte) string {
	switch {
	case c >= 'A' && c <= 'Z':
		return "LATIN CAPITAL LETTER " + string(c)
	case c >= 'a' && c <= 'z':
		return "LATIN SMALL LETTER " + string(c-'a'+'A')
	case c >= '0' && c <= '9':
		return "DIGIT " + names().digits[c-'0']
	case c == '|':
		return "VERTICAL LINE"
	}
	if n, ok := names().punct[c]; ok {
		return n
	}
	return "ASCII CHARACTER " + codePoint(rune(c))
}

// punctuationTable parses asciiPunctuationNames into a lookup table.
func punctuationTable() map[byte]string {
	out := make(map[byte]string)
	for _, entry := range strings.Split(asciiPunctuationNames, "|") {
		if entry != "" {
			out[entry[0]] = entry[1:]
		}
	}
	return out
}

// knownName returns the Unicode name of the suspicious characters that are
// listed in the threat model, or "" for any other rune.
func knownName(r rune) string {
	t := names()
	if n := t.format[r]; n != "" {
		return n
	}
	if n := t.space[r]; n != "" {
		return n
	}
	if n := t.invisible[r]; n != "" {
		return n
	}
	return variationName(r)
}

// formatTable names the format (Cf) characters used to hide text.
func formatTable() map[rune]string {
	return map[rune]string{
		0x00AD: "SOFT HYPHEN", 0x034F: "COMBINING GRAPHEME JOINER",
		0x061C: "ARABIC LETTER MARK", 0x180E: "MONGOLIAN VOWEL SEPARATOR",
		0x200B: "ZERO WIDTH SPACE", 0x200C: "ZERO WIDTH NON-JOINER",
		0x200D: "ZERO WIDTH JOINER", 0x200E: "LEFT-TO-RIGHT MARK",
		0x200F: "RIGHT-TO-LEFT MARK", 0x202A: "LEFT-TO-RIGHT EMBEDDING",
		0x202B: "RIGHT-TO-LEFT EMBEDDING", 0x202C: "POP DIRECTIONAL FORMATTING",
		0x202D: "LEFT-TO-RIGHT OVERRIDE", 0x202E: "RIGHT-TO-LEFT OVERRIDE",
		0x2060: "WORD JOINER", 0x2061: "FUNCTION APPLICATION",
		0x2062: "INVISIBLE TIMES", 0x2063: "INVISIBLE SEPARATOR",
		0x2064: "INVISIBLE PLUS", 0x2066: "LEFT-TO-RIGHT ISOLATE",
		0x2067: "RIGHT-TO-LEFT ISOLATE", 0x2068: "FIRST STRONG ISOLATE",
		0x2069: "POP DIRECTIONAL ISOLATE", 0x206A: "INHIBIT SYMMETRIC SWAPPING",
		0x206B: "ACTIVATE SYMMETRIC SWAPPING", 0x206C: "INHIBIT ARABIC FORM SHAPING",
		0x206D: "ACTIVATE ARABIC FORM SHAPING", 0x206E: "NATIONAL DIGIT SHAPES",
		0x206F: "NOMINAL DIGIT SHAPES", 0xFEFF: "ZERO WIDTH NO-BREAK SPACE",
		0xFFF9: "INTERLINEAR ANNOTATION ANCHOR", 0xFFFA: "INTERLINEAR ANNOTATION SEPARATOR",
		0xFFFB: "INTERLINEAR ANNOTATION TERMINATOR", 0xFFFC: "OBJECT REPLACEMENT CHARACTER",
		0x2028: "LINE SEPARATOR", 0x2029: "PARAGRAPH SEPARATOR",
	}
}

// spaceTable names the spaces that are not a plain space.
func spaceTable() map[rune]string {
	return map[rune]string{
		0x00A0: "NO-BREAK SPACE", 0x1680: "OGHAM SPACE MARK", 0x2000: "EN QUAD",
		0x2001: "EM QUAD", 0x2002: "EN SPACE", 0x2003: "EM SPACE",
		0x2004: "THREE-PER-EM SPACE", 0x2005: "FOUR-PER-EM SPACE",
		0x2006: "SIX-PER-EM SPACE", 0x2007: "FIGURE SPACE", 0x2008: "PUNCTUATION SPACE",
		0x2009: "THIN SPACE", 0x200A: "HAIR SPACE", 0x202F: "NARROW NO-BREAK SPACE",
		0x205F: "MEDIUM MATHEMATICAL SPACE", 0x3000: "IDEOGRAPHIC SPACE",
	}
}

// invisibleTable names the characters that draw nothing but are letters or
// marks to a text engine: the fillers and the script-specific joiners.
func invisibleTable() map[rune]string {
	return map[rune]string{
		hangulChoseongFiller: "HANGUL CHOSEONG FILLER", hangulJungseongFiller: "HANGUL JUNGSEONG FILLER",
		hangulFiller: "HANGUL FILLER", halfwidthHangulFiller: "HALFWIDTH HANGUL FILLER",
		brailleBlank: "BRAILLE PATTERN BLANK", khmerVowelInherentAQ: "KHMER VOWEL INHERENT AQ",
		khmerVowelInherentAA: "KHMER VOWEL INHERENT AA", khitanFiller: "KHITAN SMALL SCRIPT FILLER",
		tifinaghConsonantJoiner: "TIFINAGH CONSONANT JOINER", brahmiNumberJoiner: "BRAHMI NUMBER JOINER",
		zanabazarSubjoiner: "ZANABAZAR SQUARE SUBJOINER", soyomboSubjoiner: "SOYOMBO SUBJOINER",
		duployanThickSelector: "DUPLOYAN THICK LETTER SELECTOR",
	}
}

// variationName names the variation selectors.
func variationName(r rune) string {
	switch {
	case r >= 0xFE00 && r <= 0xFE0F:
		return "VARIATION SELECTOR-" + strconv.Itoa(int(r-0xFE00)+1)
	case r >= 0xE0100 && r <= 0xE01EF:
		return "VARIATION SELECTOR-" + strconv.Itoa(int(r-0xE0100)+17)
	case r >= 0x180B && r <= 0x180D:
		return "MONGOLIAN FREE VARIATION SELECTOR " + names().digits[r-0x180B+1]
	case r == 0x180F:
		return "MONGOLIAN FREE VARIATION SELECTOR FOUR"
	}
	return ""
}
