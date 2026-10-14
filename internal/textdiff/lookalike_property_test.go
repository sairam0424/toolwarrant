package textdiff

import (
	"encoding/json"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// plainLetters is the alphabet of the look-alike targets the property tests
// build on: ASCII letters and digits, some of which are themselves table
// sources (m, 0, 1, I), so the base text is not a fixed point of Skeleton.
const plainLetters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "

// confusableSlot is one table entry; a string is built by choosing, per slot,
// the source or its prototype.
func confusableSlot() *rapid.Generator[confusable] {
	return rapid.Custom(func(t *rapid.T) confusable {
		return confusables[rapid.IntRange(0, len(confusables)-1).Draw(t, "entry")]
	})
}

// twoSpellings builds two strings from the same slots, each slot spelt as the
// source on one side or the other at random, with the same plain letters
// between slots.
func twoSpellings(t *rapid.T) (string, string) {
	slots := rapid.SliceOfN(confusableSlot(), 1, 12).Draw(t, "slots")
	var a, b strings.Builder
	for _, c := range slots {
		filler := rapid.StringOfN(rapid.RuneFrom([]rune(plainLetters)), 0, 4, -1).Draw(t, "filler")
		a.WriteString(filler)
		b.WriteString(filler)
		if rapid.Bool().Draw(t, "swap") {
			a.WriteRune(c.src)
			b.WriteString(c.dst)
		} else {
			a.WriteString(c.dst)
			b.WriteRune(c.src)
		}
	}
	return a.String(), b.String()
}

// Replacing any code point by its confusable prototype, or the prototype by
// the code point, anywhere in a text, leaves the skeleton unchanged; the two
// spellings are therefore look-alikes whenever their bytes differ, and the
// skeleton of either is a fixed point.
func TestProperty_skeletonIsInvariantUnderConfusableSubstitution(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a, b := twoSpellings(t)
		sa, sb := Skeleton(a), Skeleton(b)
		if sa != sb {
			t.Fatalf("Skeleton(%q) = %q but Skeleton(%q) = %q", a, sa, b, sb)
		}
		if LookAlike(a, b) != (a != b) {
			t.Fatalf("LookAlike(%q, %q) = %v", a, b, LookAlike(a, b))
		}
		if Skeleton(sa) != sa {
			t.Fatalf("Skeleton is not idempotent on %q", sa)
		}
	})
}

// lookAlikeDoc builds a tool-like document from hostile text and look-alike
// spellings in both keys and values, so the section has swaps, mixed-script
// words and suspicious characters to render at once.
func lookAlikeDoc(t *rapid.T, label string, spell func(string, string) string) []byte {
	a, b := twoSpellings(t)
	hostile := hostileString().Draw(t, label+"Hostile")
	doc := map[string]any{
		"description": spell(a, b) + " " + hostile,
		"inputSchema": map[string]any{
			"properties": map[string]any{
				spell(a, b):           map[string]any{"type": "string", "description": hostile},
				spell(hostile, b):     map[string]any{"type": "string"},
				hostile + spell(a, b): 1,
			},
		},
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Whatever the documents hold, the Look-alike changes section is safe to print:
// it carries no raw suspicious rune (a look-alike key with a zero-width space
// in it is written with the escape, as every path is) and no control byte,
// and the whole report stays safe.
func TestProperty_lookAlikeSectionNeverHoldsRawSuspiciousRunes(t *testing.T) {
	first := func(a, _ string) string { return a }
	second := func(_, b string) string { return b }
	rapid.Check(t, func(t *rapid.T) {
		from := lookAlikeDoc(t, "from", first)
		to := lookAlikeDoc(t, "to", second)
		out, err := Tool("from", "to", from, to)
		if err != nil {
			t.Fatalf("Tool: %v", err)
		}
		assertSafe(t, out)
		parts := strings.SplitN(out, "\n"+sectionLookAlike+"\n", 2)
		if len(parts) != 2 {
			t.Fatalf("no section:\n%s", out)
		}
		assertSafe(t, parts[1])
		changes, err := LookAlikeChanges(from, to)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range changes {
			assertSafe(t, c.Where()+": "+c.Detail())
			if len(c.Swaps) == 0 {
				t.Fatalf("a look-alike change without swaps: %+v", c)
			}
		}
	})
}
