// Three tests in this package walk every Unicode code point and dominate the
// suite under the race detector (hundreds of seconds on a loaded machine):
// TestEscape_everyRune and TestEscape_coversEveryRuneTheToolNameRuleForbids in
// this file and TestNames_noSuspiciousRuneHasAnEmptyName in findings_test.go.
// They skip under -short so the default suite stays fast. The full run is
//
//	go test ./internal/textdiff
//
// without -short. No assertion is weakened: the skip is the only gate.

package textdiff

import (
	"strconv"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/sairam0424/toolwarrant/internal/toolname"
)

func TestEscape_table(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"empty", "", ""},
		{"ascii passes", "Add two numbers.", "Add two numbers."},
		{"unicode text passes", "héllo wörld 日本語 😀", "héllo wörld 日本語 😀"},
		{"plain space passes", "a b  c", "a b  c"},
		{"newline passes", "a\nb", "a\nb"},
		{"backslash doubled", `a\b`, `a\\b`},
		{"tab", "a\tb", `a\tb`},
		{"nul", "a\x00b", `a\u{0000}b`},
		{"esc", "\x1b[2J", `\u{001B}[2J`},
		{"del", "a\x7fb", `a\u{007F}b`},
		{"c1 csi", "\u009b2J", `\u{009B}2J`},
		{"carriage return", "ok\rbad", `ok\u{000D}bad`},
		{"backspace", "a\bb", `a\u{0008}b`},
		{"zero width space", "ig\u200bnore", `ig\u{200B}nore`},
		{"rlo and pdf", "\u202eevil\u202c", `\u{202E}evil\u{202C}`},
		{"bom", "\ufeffx", `\u{FEFF}x`},
		{"soft hyphen", "a\u00adb", `a\u{00AD}b`},
		{"nbsp", "a\u00a0b", `a\u{00A0}b`},
		{"ideographic space", "a\u3000b", `a\u{3000}b`},
		{"line separator", "a\u2028b", `a\u{2028}b`},
		{"tag a (five digits)", "\U000E0061", `\u{E0061}`},
		{"private use", "\ue000", `\u{E000}`},
		{"unassigned", "\u0378", `\u{0378}`},
		{"noncharacter", "\U0010FFFF", `\u{10FFFF}`},
		{"variation selector", "a\ufe0f", `a\u{FE0F}`},
		{"supplementary variation selector", "a\U000E0100", `a\u{E0100}`},
		{"grapheme joiner", "a\u034fb", `a\u{034F}b`},
		{"braille blank", "\u2800", `\u{2800}`},
		{"hangul filler", "a\u3164b", `a\u{3164}b`},
		{"khitan filler", "a\U00016FE4b", `a\u{16FE4}b`},
		{"tifinagh consonant joiner", "a\u2d7fb", `a\u{2D7F}b`},
		{"object replacement", "\ufffc", `\u{FFFC}`},
		{"real replacement char passes", "\ufffd", "\ufffd"},
		{"invalid byte", "a\xffb", `a\x{FF}b`},
		{"encoded surrogate is invalid utf-8", "\xed\xa0\x80", `\x{ED}\x{A0}\x{80}`},
		{"truncated sequence", "\xe2\x82", `\x{E2}\x{82}`},
		{"literal escape text stays unambiguous", `\u{200B}`, `\\u{200B}`},
		{"literal hex escape text", `\x{41}`, `\\x{41}`},
		{"literal backslash t", `\t`, `\\t`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Escape(tc.in); got != tc.want {
				t.Fatalf("Escape(%q) = %q, want %q", tc.in, got, tc.want)
			}
			assertSafe(t, Escape(tc.in))
			back, err := unescape(Escape(tc.in), false)
			if err != nil || back != tc.in {
				t.Fatalf("round trip = %q, %v; want %q", back, err, tc.in)
			}
		})
	}
}

func TestEscape_literalEscapeDiffersFromRealCharacter(t *testing.T) {
	real := Escape("\u200b")
	literal := Escape(`\u{200B}`)
	if real == literal {
		t.Fatalf("a real ZWSP and the text \\u{200B} must render differently, both gave %q", real)
	}
}

func TestEscape_inlineEscapesNewline(t *testing.T) {
	if got := escapeInline("a\nb"); got != `a\nb` {
		t.Fatalf("escapeInline = %q", got)
	}
	back, err := unescape(escapeInline("a\nb\\n"), true)
	if err != nil || back != "a\nb\\n" {
		t.Fatalf("inline round trip = %q, %v", back, err)
	}
}

// requiredEscapes is the list from the task: every one of these must be shown
// as \u{HEX}.
func requiredEscapes() []rune {
	var rs []rune
	add := func(lo, hi rune) {
		for r := lo; r <= hi; r++ {
			rs = append(rs, r)
		}
	}
	add(0x00, 0x08)
	add(0x0B, 0x1F) // controls except tab (0x09) and newline (0x0A)
	add(0x7F, 0x9F) // DEL and C1
	add(0x200B, 0x200F)
	add(0x202A, 0x202E)
	add(0x2066, 0x2069)
	add(0x2060, 0x2064)
	add(0xE0000, 0xE007F)
	add(0xFE00, 0xFE0F)
	add(0xE0100, 0xE01EF)
	add(0x2000, 0x200A)
	rs = append(rs, 0xFEFF, 0x00AD, 0x2028, 0x2029, 0x00A0, 0x1680, 0x202F, 0x205F,
		0x3000, 0xE000, 0xF8FF, 0x0378, 0xFDD0, 0xFFFE, 0xFFFF, 0x1FFFE,
		0x034F, 0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800, 0xFFFC)
	return rs
}

func TestEscape_requiredCharactersAreAllEscaped(t *testing.T) {
	for _, r := range requiredEscapes() {
		got := Escape("x" + string(r) + "y")
		digits := strings.ToUpper(strconv.FormatInt(int64(r), 16))
		for len(digits) < 4 {
			digits = "0" + digits
		}
		want := `x\u{` + digits + `}y`
		if got != want {
			t.Errorf("U+%04X: Escape = %q, want %q", r, got, want)
		}
		fs := Findings("x" + string(r) + "y")
		if len(fs) != 1 || fs[0].Rune != r || fs[0].Name == "" || fs[0].Category == "" || fs[0].Offset != 1 {
			t.Errorf("U+%04X: Findings = %+v", r, fs)
		}
	}
}

// TestEscape_everyRune walks all of Unicode. The safety invariant: a rune
// that is written raw must be an ordinary printable character.
func TestEscape_everyRune(t *testing.T) {
	if testing.Short() {
		t.Skip("walks all of Unicode; run without -short")
	}
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if r >= surrogateStart && r <= surrogateEnd {
			continue
		}
		s := string(r)
		out := Escape(s)
		raw := out == s
		if raw && r != '\n' && !unicode.IsPrint(r) {
			t.Fatalf("U+%04X is written raw but is not printable", r)
		}
		special := r == '\\' || r == '\t' || r == '\n'
		if !raw && !special && !strings.HasPrefix(out, `\u{`) {
			t.Fatalf("U+%04X escaped as %q", r, out)
		}
		if n := len(Findings(s)); (n == 1) != (!raw && !special) || n > 1 {
			t.Fatalf("U+%04X: raw=%v special=%v but %d findings", r, raw, special, n)
		}
	}
}

// Every rune the shared tool-name rule forbids (controls, format characters,
// unusual spaces, the default-ignorable code points that Unicode files as
// letters or marks) must also be invisible to no one here: Escape writes it
// as an escape. Tab and newline are the two exceptions by design.
func TestEscape_coversEveryRuneTheToolNameRuleForbids(t *testing.T) {
	if testing.Short() {
		t.Skip("walks all of Unicode; run without -short")
	}
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if (r >= surrogateStart && r <= surrogateEnd) || r == '\n' || r == '\t' {
			continue
		}
		if !toolname.Forbidden(r) {
			continue
		}
		if s := string(r); Escape(s) == s {
			t.Fatalf("U+%04X is forbidden in a tool name but Escape writes it raw", r)
		}
	}
}

// defaultIgnorableRanges is the Default_Ignorable_Code_Point property from
// DerivedCoreProperties.txt (Unicode 15 and later). None of these draws
// anything, so none may ever be written raw; the review found U+16FE4, the
// one entry whose general category is Mn, slipping through.
func defaultIgnorableRanges() [][2]rune {
	return [][2]rune{
		{0x00AD, 0x00AD}, {0x034F, 0x034F}, {0x061C, 0x061C}, {0x115F, 0x1160},
		{0x17B4, 0x17B5}, {0x180B, 0x180F}, {0x200B, 0x200F}, {0x202A, 0x202E},
		{0x2060, 0x206F}, {0x3164, 0x3164}, {0xFE00, 0xFE0F}, {0xFEFF, 0xFEFF},
		{0xFFA0, 0xFFA0}, {0xFFF0, 0xFFF8}, {0x16FE4, 0x16FE4}, {0x1BCA0, 0x1BCA3},
		{0x1D173, 0x1D17A}, {0xE0000, 0xE0FFF},
	}
}

func TestEscape_defaultIgnorableCodePointsAreNeverRaw(t *testing.T) {
	for _, rg := range defaultIgnorableRanges() {
		for r := rg[0]; r <= rg[1]; r++ {
			if s := string(r); Escape(s) == s || len(Findings(s)) != 1 {
				t.Errorf("default-ignorable U+%04X is written raw or not reported", r)
			}
		}
	}
}

// The invisible fillers and joiners that Unicode files as marks or letters
// are escaped, reported and named like every other hidden character.
func TestEscape_invisibleJoinersAndFillersAreNamed(t *testing.T) {
	cases := map[rune][2]string{
		0x16FE4: {"KHITAN SMALL SCRIPT FILLER", "invisible-filler"},
		0x2D7F:  {"TIFINAGH CONSONANT JOINER", "invisible-joiner"},
		0x1107F: {"BRAHMI NUMBER JOINER", "invisible-joiner"},
		0x1BC9D: {"DUPLOYAN THICK LETTER SELECTOR", "invisible-joiner"},
		0x11A47: {"ZANABAZAR SQUARE SUBJOINER", "invisible-joiner"},
		0x11A99: {"SOYOMBO SUBJOINER", "invisible-joiner"},
	}
	for r, want := range cases {
		s := "del" + string(r) + "ete"
		if Escape(s) == s {
			t.Errorf("U+%05X written raw", r)
		}
		fs := Findings(s)
		if len(fs) != 1 || fs[0].Offset != 3 || fs[0].Rune != r || fs[0].Name != want[0] || fs[0].Category != want[1] {
			t.Errorf("U+%05X: Findings = %+v, want name %q category %q", r, fs, want[0], want[1])
		}
	}
}

func TestEscape_variationSelectorsAndTagsNeverRaw(t *testing.T) {
	for r := rune(0xE0000); r <= 0xE007F; r++ {
		if strings.ContainsRune(Escape(string(r)), r) {
			t.Fatalf("tag U+%04X written raw", r)
		}
	}
	for r := rune(0xE0100); r <= 0xE01EF; r++ {
		if strings.ContainsRune(Escape(string(r)), r) {
			t.Fatalf("variation selector U+%04X written raw", r)
		}
	}
}

func TestEscape_outputIsValidUTF8ForAnyBytes(t *testing.T) {
	var all strings.Builder
	for i := 0; i < 256; i++ {
		all.WriteByte(byte(i))
	}
	out := Escape(all.String())
	assertSafe(t, out)
	back, err := unescape(out, false)
	if err != nil || back != all.String() {
		t.Fatalf("round trip of all bytes failed: %v", err)
	}
	if !utf8.ValidString(out) {
		t.Fatal("not valid UTF-8")
	}
}

func TestWriteHex_padding(t *testing.T) {
	var b strings.Builder
	writeHex(&b, 0, 4)
	b.WriteByte(' ')
	writeHex(&b, 0xABCDE, 4)
	b.WriteByte(' ')
	writeHex(&b, 0x7, 2)
	if got := b.String(); got != "0000 ABCDE 07" {
		t.Fatalf("writeHex = %q", got)
	}
}
