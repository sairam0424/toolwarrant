package textdiff

import (
	"strconv"
	"strings"
	"testing"
	"unicode"
)

// The UTS #39 Highly Restrictive profile: one script, or Latin with the
// scripts of Japanese, Korean or Chinese; Common and Inherited never count;
// a code point in no script table is the script Unknown and mixes with
// everything.
func TestMixedScriptWords_highlyRestrictiveProfile(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want []string // "offset: detail" per flagged word
	}{
		{"latin", "path", nil},
		{"cyrillic a inside latin", "p" + cyrillicA + "th", []string{"0: Cyrillic (U+0430) with Latin (U+0070 U+0074 U+0068)"}},
		{"han with latin", hanTokyo + "Tokyo", nil},
		{"japanese with latin and the prolonged sound mark", hanTokyo + hiraganaA + katakanaA + "\u30FCAPI", nil},
		{"hangul with latin", hangulKR + "Korea", nil},
		{"bopomofo with latin", bopomofoBP + "Bopomofo", nil},
		{"han with hiragana only", "\u4E00" + hiraganaA, nil},
		{"han with hangul only", "\u4E00" + hangulKR, nil},
		{"han with bopomofo only", "\u4E00" + bopomofoBP, nil},
		{"cyrillic with han (equal counts sort by name)", "\u0422" + cyrillicO + hanTokyo, []string{"0: Cyrillic (U+0422 U+043E) with Han (U+6771 U+4EAC)"}},
		{"greek inside latin", greekOmega + "mega", []string{"0: Greek (U+03A9) with Latin (U+006D U+0065 U+0067 U+0061)"}},
		{"hangul with hiragana", hangulKR + hiraganaA, []string{"0: Hiragana (U+3042) with Hangul (U+D55C U+AD6D)"}},
		{"digits and punctuation are common", "abc123!?", nil},
		{"greek alone", "\u03B1\u03B2\u03B3", nil},
		{"combining mark is inherited", "e\u0301t\u00E9", nil},
		{"unknown code point with latin", unassigned + "x", []string{"0: Latin (U+0078) with Unknown (U+0378)"}},
		{"unknown code points alone", unassigned + unassigned, nil},
		{"offsets count bytes", " two  w" + cyrillicO + "rds here", []string{"6: Cyrillic (U+043E) with Latin (U+0077 U+0072 U+0064 U+0073)"}},
		{"two words flagged", "p" + cyrillicA + "th t" + cyrillicO, []string{
			"0: Cyrillic (U+0430) with Latin (U+0070 U+0074 U+0068)",
			"6: Cyrillic (U+043E) with Latin (U+0074)",
		}},
		{"whitespace only", " \t\n", nil},
		{"empty", "", nil},
	}
	for _, tc := range cases {
		words := MixedScriptWords(tc.in)
		var got []string
		for _, w := range words {
			got = append(got, strconv.Itoa(w.Offset)+": "+w.Detail())
			assertSafe(t, w.Detail())
		}
		if strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("%s: MixedScriptWords(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}

// The script with the fewest code points is listed first, since it is usually
// the intruder, and the list per script is capped with a count.
func TestMixedWord_listsTheRarestScriptFirstAndCapsEachList(t *testing.T) {
	t.Parallel()
	word := strings.Repeat(cyrillicA, maxScriptRunes+4) + "x"
	words := MixedScriptWords(word)
	if len(words) != 1 {
		t.Fatalf("got %d words, want 1", len(words))
	}
	got := words[0].Detail()
	want := "Latin (U+0078) with Cyrillic (" + strings.TrimSpace(strings.Repeat("U+0430 ", maxScriptRunes)) + " +4 more)"
	if got != want {
		t.Fatalf("Detail = %q, want %q", got, want)
	}
}

// scriptOf answers exactly what a walk over every table of unicode.Scripts
// answers, at every range boundary of the index and on a sample of the whole
// code space; a code point in no table is Unknown.
func TestScriptOf_agreesWithTheStdlibTables(t *testing.T) {
	t.Parallel()
	slow := func(r rune) string {
		for name, table := range unicode.Scripts {
			if unicode.Is(table, r) {
				return name
			}
		}
		return scriptUnknown
	}
	check := func(r rune) {
		if r < 0 || r > unicode.MaxRune {
			return
		}
		if got, want := scriptOf(r), slow(r); got != want {
			t.Errorf("scriptOf(%U) = %q, want %q", r, got, want)
		}
	}
	for _, rg := range scriptTable().ranges {
		check(rg.lo - 1)
		check(rg.lo)
		check(rg.hi)
		check(rg.hi + 1)
	}
	const sampleStride = 97
	for r := rune(0); r <= unicode.MaxRune; r += sampleStride {
		check(r)
	}
	for _, r := range []rune{'a', '1', 0x0430, 0x0378, 0xE000, 0x3042, 0x30FC, 0x0301, 0x1F600, unicode.MaxRune} {
		check(r)
	}
	ranges := scriptTable().ranges
	for i := 1; i < len(ranges); i++ {
		if ranges[i].lo <= ranges[i-1].hi {
			t.Fatalf("index ranges overlap or are unsorted at %d: %+v %+v", i, ranges[i-1], ranges[i])
		}
	}
}

func TestHighlyRestrictive_combinations(t *testing.T) {
	t.Parallel()
	set := func(names ...string) []ScriptRunes {
		out := make([]ScriptRunes, 0, len(names))
		for _, n := range names {
			out = append(out, ScriptRunes{Script: n, Runes: []rune{'x'}})
		}
		return out
	}
	cases := []struct {
		names []string
		want  bool
	}{
		{nil, true},
		{[]string{scriptLatin}, true},
		{[]string{scriptLatin, scriptHan, scriptHiragana, scriptKatakana}, true},
		{[]string{scriptLatin, scriptHan, scriptHangul}, true},
		{[]string{scriptLatin, scriptHan, scriptBopomofo}, true},
		{[]string{scriptHiragana, scriptKatakana}, true},
		{[]string{scriptHangul, scriptHiragana}, false},
		{[]string{scriptLatin, "Cyrillic"}, false},
		{[]string{scriptLatin, "Greek"}, false},
		{[]string{scriptHan, scriptHangul, scriptBopomofo}, false},
		{[]string{scriptUnknown, scriptLatin}, false},
	}
	for _, tc := range cases {
		if got := highlyRestrictive(set(tc.names...)); got != tc.want {
			t.Errorf("highlyRestrictive(%v) = %v, want %v", tc.names, got, tc.want)
		}
	}
}
