package textdiff

import (
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestFindings_none(t *testing.T) {
	for _, s := range []string{"", "plain text", "tab\tand\nnewline", "é 日本 😀", `back\slash`} {
		if fs := Findings(s); fs != nil {
			t.Errorf("Findings(%q) = %+v, want nil", s, fs)
		}
	}
}

func TestFindings_namesCategoriesAndOffsets(t *testing.T) {
	cases := []struct {
		in   string
		want Finding
	}{
		{"a\u200b", Finding{1, 0x200B, "ZERO WIDTH SPACE", "zero-width"}},
		{"\u202e", Finding{0, 0x202E, "RIGHT-TO-LEFT OVERRIDE", "bidi-control"}},
		{"\u200f", Finding{0, 0x200F, "RIGHT-TO-LEFT MARK", "bidi-control"}},
		{"é\U000E0061", Finding{2, 0xE0061, "TAG LATIN SMALL LETTER A", "tag-character"}},
		{"\x1b", Finding{0, 0x1B, "ESCAPE", "terminal-escape"}},
		{"\x00", Finding{0, 0, "NULL", "control"}},
		{"\r", Finding{0, '\r', "CARRIAGE RETURN", "control"}},
		{"\x7f", Finding{0, 0x7F, "DELETE", "control"}},
		{"\u009b", Finding{0, 0x9B, "CONTROL SEQUENCE INTRODUCER", "terminal-escape"}},
		{"\u0081", Finding{0, 0x81, "C1 CONTROL U+0081", "control"}},
		{"\u3164", Finding{0, 0x3164, "HANGUL FILLER", "invisible-filler"}},
		{"\u2800", Finding{0, 0x2800, "BRAILLE PATTERN BLANK", "invisible-filler"}},
		{"\u2062", Finding{0, 0x2062, "INVISIBLE TIMES", "invisible-operator"}},
		{"\ufe0f", Finding{0, 0xFE0F, "VARIATION SELECTOR-16", "variation-selector"}},
		{"\U000E0100", Finding{0, 0xE0100, "VARIATION SELECTOR-17", "variation-selector"}},
		{"\u034f", Finding{0, 0x34F, "COMBINING GRAPHEME JOINER", "grapheme-joiner"}},
		{"\u00ad", Finding{0, 0xAD, "SOFT HYPHEN", "soft-hyphen"}},
		{"\u00a0", Finding{0, 0xA0, "NO-BREAK SPACE", "unusual-space"}},
		{"\u2028", Finding{0, 0x2028, "LINE SEPARATOR", "line-separator"}},
		{"\ufffc", Finding{0, 0xFFFC, "OBJECT REPLACEMENT CHARACTER", "object-replacement"}},
		{"\ue000", Finding{0, 0xE000, "PRIVATE USE U+E000", "private-use"}},
		{"\u0378", Finding{0, 0x378, "UNASSIGNED U+0378", "unassigned"}},
		{"\ufdd0", Finding{0, 0xFDD0, "NONCHARACTER U+FDD0", "noncharacter"}},
		{"\xff", Finding{0, utf8.RuneError, "INVALID UTF-8 BYTE 0xFF", "invalid-utf8"}},
		{"ab\xc3", Finding{2, utf8.RuneError, "INVALID UTF-8 BYTE 0xC3", "invalid-utf8"}},
	}
	for _, tc := range cases {
		got := Findings(tc.in)
		if !reflect.DeepEqual(got, []Finding{tc.want}) {
			t.Errorf("Findings(%q) = %+v, want %+v", tc.in, got, tc.want)
		}
	}
}

func TestFindings_orderAndMultiple(t *testing.T) {
	fs := Findings("a\u200bb\u202ec\x1b")
	wantOffsets := []int{1, 5, 9}
	if len(fs) != 3 {
		t.Fatalf("got %+v", fs)
	}
	for i, f := range fs {
		if f.Offset != wantOffsets[i] {
			t.Errorf("finding %d offset = %d, want %d", i, f.Offset, wantOffsets[i])
		}
	}
}

func TestFindings_offsetsPointAtTheRune(t *testing.T) {
	s := "héllo\u200b wörld\U000E0041\x00"
	for _, f := range Findings(s) {
		r, _ := utf8.DecodeRuneInString(s[f.Offset:])
		if r != f.Rune {
			t.Errorf("offset %d holds %U, finding says %U", f.Offset, r, f.Rune)
		}
	}
}

func TestNames_tagBlockMirrorsAscii(t *testing.T) {
	cases := map[rune]string{
		0xE0020: "TAG SPACE",
		0xE0031: "TAG DIGIT ONE",
		0xE005A: "TAG LATIN CAPITAL LETTER Z",
		0xE0001: "LANGUAGE TAG",
		0xE007F: "CANCEL TAG",
		0xE002D: "TAG HYPHEN-MINUS",
		0xE007C: "TAG VERTICAL LINE",
		0xE0005: "TAG CHARACTER U+E0005",
	}
	for r, want := range cases {
		if got := runeName(r); got != want {
			t.Errorf("runeName(%U) = %q, want %q", r, got, want)
		}
	}
}

func TestNames_everyPrintableAsciiHasARealName(t *testing.T) {
	seen := map[string]byte{}
	for c := byte(0x20); c <= 0x7E; c++ {
		n := asciiName(c)
		if n == "" || strings.HasPrefix(n, "ASCII CHARACTER") {
			t.Errorf("asciiName(%q) = %q", c, n)
		}
		if prev, dup := seen[n]; dup {
			t.Errorf("asciiName(%q) and asciiName(%q) are both %q", c, prev, n)
		}
		seen[n] = c
	}
}

func TestNames_noSuspiciousRuneHasAnEmptyName(t *testing.T) {
	for r := rune(0); r <= 0x10FFFF; r += 1 {
		if r >= surrogateStart && r <= surrogateEnd {
			continue
		}
		if _, bad := classify(r); bad && runeName(r) == "" {
			t.Fatalf("U+%04X has no name", r)
		}
	}
}

func TestNames_c0AndVariationSelectors(t *testing.T) {
	if got := controlName(0x09); got != "CHARACTER TABULATION" {
		t.Errorf("tab = %q", got)
	}
	if got := controlName(0x1F); got != "INFORMATION SEPARATOR ONE" {
		t.Errorf("US = %q", got)
	}
	if got := variationName(0x180B); got != "MONGOLIAN FREE VARIATION SELECTOR ONE" {
		t.Errorf("0x180B = %q", got)
	}
	if got := variationName(0x180F); got != "MONGOLIAN FREE VARIATION SELECTOR FOUR" {
		t.Errorf("0x180F = %q", got)
	}
	if got := variationName(0x41); got != "" {
		t.Errorf("A = %q", got)
	}
}

func TestClassify_invalidRunes(t *testing.T) {
	if cat, bad := classify(0xD800); !bad || cat != "surrogate" {
		t.Errorf("surrogate = %q %v", cat, bad)
	}
	if cat, bad := classify(0x110000); !bad || cat != "invalid-rune" {
		t.Errorf("beyond max = %q %v", cat, bad)
	}
	if cat, bad := classify(-1); !bad || cat != "invalid-rune" {
		t.Errorf("negative = %q %v", cat, bad)
	}
	if n := runeName(0xD800); n != "SURROGATE U+D800" {
		t.Errorf("surrogate name = %q", n)
	}
}
