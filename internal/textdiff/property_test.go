package textdiff

import (
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// hostileRunes is a small alphabet heavy on the characters that matter.
var hostileRunes = []rune{
	'a', 'b', ' ', '\\', '\t', '\n', '\r', '\x1b', '\x00', '\x7f', '{', '}', 'u', 'x', '0', 'F',
	'\u0085', '\u00a0', 'é', '\u0301', '\u200b', '\u202e', '\u2028', '\ufeff', '\ufffd',
	0xE0041, 0xE0100, 0xE000, 0x378, 0x1F600, '\u3164', '\u2800',
}

func hostileString() *rapid.Generator[string] {
	return rapid.OneOf(
		rapid.String(),
		rapid.StringOf(rapid.SampledFrom(hostileRunes)),
		rapid.Map(rapid.SliceOf(rapid.Byte()), func(b []byte) string { return string(b) }),
	)
}

// lineText builds multi-line text from a tiny vocabulary so that two
// independently drawn texts share many lines and produce dense diffs.
func lineText() *rapid.Generator[string] {
	vocabulary := []string{"a", "b", "c", "d", "", "x y", "e\u200bf", "g\\h"}
	return rapid.Map(rapid.SliceOfN(rapid.SampledFrom(vocabulary), 0, 30),
		func(ls []string) string { return strings.Join(ls, "\n") })
}

func TestProperty_escapeIsIdempotentExceptForBackslashDoubling(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		s := hostileString().Draw(t, "s")
		e := Escape(s)
		// What is true: a second pass changes nothing except doubling every
		// backslash, because the first pass left no character that needs
		// escaping other than the backslash itself.
		if again, want := Escape(e), strings.ReplaceAll(e, `\`, `\\`); again != want {
			t.Fatalf("Escape(Escape(s)) = %q, want %q", again, want)
		}
	})
}

func TestProperty_escapeIsReversibleAndSafe(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		s := hostileString().Draw(t, "s")
		e := Escape(s)
		assertSafe(t, e)
		back, err := unescape(e, false)
		if err != nil || back != s {
			t.Fatalf("round trip = %q, %v; want %q", back, err, s)
		}
		if n := countNumericEscapes(e); n != len(Findings(s)) {
			t.Fatalf("%d numeric escapes but %d findings", n, len(Findings(s)))
		}
	})
}

func TestProperty_escapeKeepsOrdinaryTextVerbatim(t *testing.T) {
	ordinary := rapid.StringOf(rapid.RuneFrom([]rune("abc XYZ 019 .,;:!?é日本語😀\n")))
	rapid.Check(t, func(t *rapid.T) {
		s := ordinary.Draw(t, "s")
		if Escape(s) != s || Findings(s) != nil {
			t.Fatalf("ordinary text %q changed", s)
		}
	})
}

func TestProperty_escapeInlineHasNoNewline(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		s := hostileString().Draw(t, "s")
		e := escapeInline(s)
		if strings.Contains(e, "\n") {
			t.Fatalf("escapeInline left a newline: %q", e)
		}
		back, err := unescape(e, true)
		if err != nil || back != s {
			t.Fatalf("inline round trip = %q, %v", back, err)
		}
	})
}

func TestProperty_findingOffsetsAreOrderedAndInRange(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		s := hostileString().Draw(t, "s")
		prev := -1
		for _, f := range Findings(s) {
			if f.Offset <= prev || f.Offset >= len(s) || f.Name == "" || f.Category == "" {
				t.Fatalf("bad finding %+v in %q (prev %d)", f, s, prev)
			}
			prev = f.Offset
		}
	})
}

func TestProperty_unifiedOfEqualInputsHasNoChangeLines(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		x := rapid.OneOf(lineText(), hostileString()).Draw(t, "x")
		out := Unified("a", "b", x, x)
		if n := len(changeLines(out)); n != 0 {
			t.Fatalf("Unified(x, x) has %d change lines:\n%s", n, out)
		}
		if out != "--- a\n+++ b\n" {
			t.Fatalf("Unified(x, x) = %q", out)
		}
	})
}

func TestProperty_unifiedAppliesCleanlyAndIsSafe(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		gen := rapid.OneOf(lineText(), hostileString())
		from, to := gen.Draw(t, "from"), gen.Draw(t, "to")
		label := hostileString().Draw(t, "label")
		out := Unified(label, label, from, to)
		assertSafe(t, out)
		checkApply(t, from, to, out)
		if again := Unified(label, label, from, to); again != out {
			t.Fatal("not deterministic")
		}
	})
}

func TestProperty_diffEngineIsMinimal(t *testing.T) {
	seq := rapid.SliceOfN(rapid.IntRange(0, 3), 0, 16)
	rapid.Check(t, func(t *rapid.T) {
		a, b := seq.Draw(t, "a"), seq.Draw(t, "b")
		edits := diffSeq(a, b)
		if got, want := checkEdits(t, a, b, edits), lcsLength(a, b); got != want {
			t.Fatalf("equal steps = %d, LCS = %d", got, want)
		}
	})
}

func TestProperty_toolNeverPanicsAndIsSafe(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		gen := hostileString()
		doc := func(label string) []byte {
			b, err := jsonObject(gen.Draw(t, label+"Key"), gen.Draw(t, label+"Val"))
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
		out, err := Tool(gen.Draw(t, "l1"), gen.Draw(t, "l2"), doc("from"), doc("to"))
		if err != nil {
			t.Fatalf("Tool: %v", err)
		}
		assertSafe(t, out)
	})
}
