package toolname

import (
	"errors"
	"strings"
	"testing"
)

func TestValidate_Accepts(t *testing.T) {
	ok := []string{
		"echo", "wipe_database", "get-user.v2", "Tool Name", "\u65E5\u672C\u8A9E", "\u00E9mail", "a",
		strings.Repeat("x", MaxBytes),
		"\u00FCber", // NFC form of u with diaeresis
	}
	for _, n := range ok {
		if err := Validate(n); err != nil {
			t.Errorf("Validate(%q) = %v, want nil", n, err)
		}
	}
}

func TestValidate_Rejects(t *testing.T) {
	bad := map[string]string{
		"empty":                     "",
		"too long":                  strings.Repeat("x", MaxBytes+1),
		"invalid utf-8":             "a\xffb",
		"nfd form":                  "u\u0308ber", // u + combining diaeresis
		"leading space":             " echo",
		"trailing space":            "echo ",
		"double space":              "wipe  database",
		"nul":                       "a\x00b",
		"tab":                       "a\tb",
		"newline":                   "a\nb",
		"escape":                    "a\x1b[2Jb",
		"c1 control":                "a\u0085b",
		"zero width space":          "list\u200Bfiles",
		"zero width joiner":         "a\u200Db",
		"rtl override":              "a\u202Eb",
		"bom":                       "\uFEFFecho",
		"soft hyphen":               "ec\u00ADho",
		"nbsp":                      "a\u00A0b",
		"ideographic space":         "a\u3000b",
		"line separator":            "a\u2028b",
		"word joiner":               "a\u2060b",
		"tag character":             "echo\U000E0041",
		"private use":               "a\uE000b",
		"unassigned":                "a\u0378b",
		"combining grapheme joiner": "a\u034Fb",
		"hangul filler":             "a\u3164b",
		"hangul choseong filler":    "a\u115Fb",
		"khmer vowel inherent":      "a\u17B4b",
		"mongolian vowel separator": "a\u180Eb",
		"mongolian fvs":             "a\u180Bb",
		"variation selector":        "a\uFE0Fb",
		"supplementary vs":          "a\U000E0100b",
		"braille blank":             "a\u2800b",
		"object replacement":        "a\uFFFCb",
		"khitan filler":             "a\U00016FE4b",
		"musical invisible":         "a\U0001D173b",
		"shorthand format":          "a\U0001BCA0b",
		"halfwidth hangul filler":   "a\uFFA0b",
		"interlinear annotation":    "a\uFFF9b",
		"surrogate escape as rune":  string([]byte{0xed, 0xa0, 0x80}), // encoded lone surrogate, invalid UTF-8
		"noncharacter":              "a\uFFFEb",
		"paragraph separator":       "a\u2029b",
		"narrow no-break space":     "a\u202Fb",
		"medium mathematical space": "a\u205Fb",
		"ogham space mark":          "a\u1680b",
		"arabic letter mark":        "a\u061Cb",
		"invisible times":           "a\u2062b",
	}
	for label, n := range bad {
		err := Validate(n)
		if err == nil {
			t.Errorf("%s: Validate(%q) accepted", label, n)
			continue
		}
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: error %v does not wrap ErrInvalid", label, err)
		}
		if strings.Contains(err.Error(), n) && n != "" {
			t.Errorf("%s: error text echoes the name: %q", label, err)
		}
	}
}

func TestForbidden_PlainSpaceAllowed(t *testing.T) {
	if Forbidden(' ') {
		t.Fatal("U+0020 must be allowed")
	}
	if !Forbidden('\u00A0') || !Forbidden('\u200B') || !Forbidden('\x00') {
		t.Fatal("invisible characters must be forbidden")
	}
}

func FuzzValidate(f *testing.F) {
	for _, s := range []string{"echo", "", " a", "a\u200Bb", strings.Repeat("y", 300)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		err := Validate(s) // must never panic
		if err == nil {
			for _, r := range s {
				if Forbidden(r) {
					t.Fatalf("accepted %q with forbidden rune U+%04X", s, r)
				}
			}
		}
	})
}
