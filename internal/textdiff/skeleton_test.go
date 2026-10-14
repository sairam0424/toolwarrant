package textdiff

import (
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

// Every look-alike in this file is written as a \u escape: the source holds no
// character that reads as another (checked with grep -P in review, as the
// invisible characters are).
const (
	cyrillicA  = "\u0430" // CYRILLIC SMALL LETTER A, reads as a
	cyrillicO  = "\u043E" // CYRILLIC SMALL LETTER O, reads as o
	cyrillicER = "\u0440" // CYRILLIC SMALL LETTER ER, reads as p
	greekOmega = "\u03A9" // GREEK CAPITAL LETTER OMEGA
	fiLigature = "\uFB01" // LATIN SMALL LIGATURE FI
	scriptL    = "\u2113" // SCRIPT SMALL L
	hanTokyo   = "\u6771\u4EAC"
	hangulKR   = "\uD55C\uAD6D"
	bopomofoBP = "\u3105\u3106"
	hiraganaA  = "\u3042"
	katakanaA  = "\u30A2"
	unassigned = "\u0378" // in no script table of go1.27's unicode package
)

// The UTS #39 examples: a code point maps to its prototype, a ligature to its
// letters, the letter m to rn, and the decomposition is applied first.
func TestSkeleton_matchesUTS39Examples(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"ascii letters stay", "path", "path"},
		{"cyrillic a", "p" + cyrillicA + "ypal", "paypal"},
		{"cyrillic er and o", cyrillicER + cyrillicO + "p", "pop"},
		{"m is rn", "m", "rn"},
		{"fi ligature", fiLigature + "le", "file"},
		{"one, capital i and vertical line are l", "1I|", "lll"},
		{"digit zero is capital o", "0", "O"},
		{"script small l", scriptL, "l"},
		{"precomposed is decomposed", "\u00E9", "e\u0301"},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		if got := Skeleton(tc.in); got != tc.want {
			t.Errorf("%s: Skeleton(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}

// The table is transitively closed, so a second pass changes nothing: every
// source, every example and every hostile corpus entry is a fixed point of the
// second application.
func TestSkeleton_isIdempotent(t *testing.T) {
	inputs := []string{"path", "p" + cyrillicA + "th", "m", fiLigature, "1I|0", "\u00E9", ""}
	for _, c := range injectionCorpus() {
		inputs = append(inputs, c.input)
	}
	for _, c := range confusables {
		inputs = append(inputs, string(c.src), "x"+string(c.src)+"y")
		for _, r := range c.dst {
			if _, isSource := confusableOf(r); isSource {
				t.Errorf("%U maps to %q, which holds the source %U: the table is not transitively closed", c.src, c.dst, r)
			}
		}
	}
	for _, s := range inputs {
		once := Skeleton(s)
		if again := Skeleton(once); again != once {
			t.Errorf("Skeleton(Skeleton(%q)) = %q, want %q", s, again, once)
		}
	}
}

// Bytes that are not valid UTF-8 are kept, so the skeleton never invents a
// character and a byte-exact input stays comparable.
func TestSkeleton_keepsBytesThatAreNotUTF8(t *testing.T) {
	in := "a\xffb\xc0\xaf" + cyrillicA
	got := Skeleton(in)
	if !strings.HasPrefix(got, "a\xffb\xc0\xaf") || !strings.HasSuffix(got, "a") {
		t.Fatalf("Skeleton(%q) = %q", in, got)
	}
	if utf8.ValidString(got) {
		t.Fatalf("the invalid bytes were replaced: %q", got)
	}
}

func TestLookAlike_onlyWhenSkeletonsAgreeAndBytesDiffer(t *testing.T) {
	cases := []struct {
		from, to string
		want     bool
	}{
		{"path", "path", false},
		{"path", "p" + cyrillicA + "th", true},
		{"p" + cyrillicA + "th", "path", true},
		{"path", "bath", false},
		{"m", "rn", true},
		{"file", fiLigature + "le", true},
		{"", "", false},
		{"", "a", false},
		{"a", "", false},
		{"ignore", "ig\u200Bnore", false},
		{"\u00E9", "e\u0301", true},
	}
	for _, tc := range cases {
		if got := LookAlike(tc.from, tc.to); got != tc.want {
			t.Errorf("LookAlike(%q, %q) = %v, want %v", tc.from, tc.to, got, tc.want)
		}
	}
}

// The swaps between two look-alikes name the code points on both sides with
// their scripts and the byte offset in the new text; the characters are never
// written, since they would read as the text they replaced.
func TestSwapsBetween_listCodePointsAndScripts(t *testing.T) {
	cases := []struct {
		from, to string
		want     []string
	}{
		{"path", "p" + cyrillicA + "th", []string{"U+0430 (Cyrillic) for U+0061 (Latin) at byte 1"}},
		{"m", "rn", []string{"U+0072 U+006E (Latin) for U+006D (Latin) at byte 0"}},
		{fiLigature + "le", "file", []string{"U+0066 U+0069 (Latin) for U+FB01 (Latin) at byte 0"}},
		{"path to", "p" + cyrillicA + "th t" + cyrillicO, []string{
			"U+0430 (Cyrillic) for U+0061 (Latin) at byte 1",
			"U+043E (Cyrillic) for U+006F (Latin) at byte 7",
		}},
		{"same", "same", nil},
	}
	for _, tc := range cases {
		swaps := swapsBetween(tc.from, tc.to)
		got := make([]string, 0, len(swaps))
		for _, s := range swaps {
			got = append(got, s.String())
		}
		if len(got) == 0 {
			got = nil
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("swapsBetween(%q, %q) = %q, want %q", tc.from, tc.to, got, tc.want)
		}
	}
}

func TestSwap_capsTheCodePointsItLists(t *testing.T) {
	from := strings.Repeat("a", maxSwapRunes+5)
	to := strings.Repeat(cyrillicA, maxSwapRunes+5)
	swaps := swapsBetween(from, to)
	if len(swaps) != 1 {
		t.Fatalf("got %d swaps, want one block", len(swaps))
	}
	got := swaps[0].String()
	if strings.Count(got, "U+0430") != maxSwapRunes || !strings.Contains(got, "+5 more (Cyrillic) for") {
		t.Fatalf("swap = %q", got)
	}
	if strings.Contains(got, cyrillicA) {
		t.Fatalf("the swap holds the raw look-alike: %q", got)
	}
	assertSafe(t, got)
}

func TestCodePoints(t *testing.T) {
	if got := codePoints([]rune{'a', 0x1F600}, 8); got != "U+0061 U+1F600" {
		t.Fatalf("codePoints = %q", got)
	}
	if got := codePoints([]rune{'a', 'b', 'c'}, 2); got != "U+0061 U+0062 +1 more" {
		t.Fatalf("codePoints capped = %q", got)
	}
	if got := codePoints(nil, 2); got != "" {
		t.Fatalf("codePoints(nil) = %q", got)
	}
}
