package textdiff

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestUnified_golden(t *testing.T) {
	twentyLines := numberedLines("l", 20)
	changedTwice := strings.Replace(strings.Replace(twentyLines, "l2\n", "X2\n", 1), "l18\n", "X18\n", 1)

	cases := []struct {
		name     string
		from, to string
		want     string
	}{
		{
			name: "one changed line",
			from: "one\ntwo\nthree", to: "one\n2\nthree",
			want: "--- old\n+++ new\n@@ -1,3 +1,3 @@\n  one\n- two\n+ 2\n  three\n",
		},
		{
			name: "two hunks with three lines of context",
			from: twentyLines, to: changedTwice,
			want: "--- old\n+++ new\n" +
				"@@ -1,5 +1,5 @@\n  l1\n- l2\n+ X2\n  l3\n  l4\n  l5\n" +
				"@@ -15,6 +15,6 @@\n  l15\n  l16\n  l17\n- l18\n+ X18\n  l19\n  l20\n",
		},
		{
			name: "nearby changes share a hunk",
			from: "a\nb\nc\nd\ne\nf\ng", to: "A\nb\nc\nd\ne\nf\nG",
			want: "--- old\n+++ new\n@@ -1,7 +1,7 @@\n- a\n+ A\n  b\n  c\n  d\n  e\n  f\n- g\n+ G\n",
		},
		{
			name: "hidden zero-width space is made visible",
			from: "say hello", to: "say he\u200bllo",
			want: "--- old\n+++ new\n@@ -1,1 +1,1 @@\n- say hello\n+ say he\\u{200B}llo\n",
		},
		{
			name: "backslash and tab are escaped",
			from: "a\\b", to: "a\tb",
			want: "--- old\n+++ new\n@@ -1,1 +1,1 @@\n- a\\\\b\n+ a\\tb\n",
		},
		{
			name: "insert into empty",
			from: "", to: "x",
			want: "--- old\n+++ new\n@@ -0,0 +1,1 @@\n+ x\n",
		},
		{
			name: "delete everything",
			from: "x\ny", to: "",
			want: "--- old\n+++ new\n@@ -1,2 +0,0 @@\n- x\n- y\n",
		},
		{
			name: "missing trailing newline is a visible change",
			from: "a", to: "a\n",
			want: "--- old\n+++ new\n@@ -1,1 +1,2 @@\n  a\n+ \n",
		},
		{
			name: "carriage return is not a line break",
			from: "a\r\nb", to: "a\nb",
			want: "--- old\n+++ new\n@@ -1,2 +1,2 @@\n- a\\u{000D}\n+ a\n  b\n",
		},
		{
			name: "identical input has headers only",
			from: "same\ntext", to: "same\ntext",
			want: "--- old\n+++ new\n",
		},
		{
			name: "both empty",
			from: "", to: "",
			want: "--- old\n+++ new\n",
		},
		{
			name: "deletes come before inserts",
			from: "a\nb\nc\nd", to: "a\nX\nY\nd",
			want: "--- old\n+++ new\n@@ -1,4 +1,4 @@\n  a\n- b\n- c\n+ X\n+ Y\n  d\n",
		},
		{
			name: "leading marker-like characters are escaped",
			from: "-x\n+y\n@z", to: "-x\n+y\n@@ -1,1 +1,1 @@",
			want: "--- old\n+++ new\n@@ -1,3 +1,3 @@\n  \\u{002D}x\n  \\u{002B}y\n- \\u{0040}z\n+ \\u{0040}@ -1,1 +1,1 @@\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Unified("old", "new", tc.from, tc.to)
			if got != tc.want {
				t.Fatalf("Unified mismatch\n got: %q\nwant: %q", got, tc.want)
			}
			if again := Unified("old", "new", tc.from, tc.to); again != got {
				t.Fatal("output is not stable for the same input")
			}
			assertSafe(t, got)
			checkApply(t, tc.from, tc.to, got)
		})
	}
}

func TestUnified_hugeInputsStayBounded(t *testing.T) {
	from := numberedLines("a", 3*maxDiffItems)
	to := numberedLines("b", 3*maxDiffItems)
	out := Unified("old", "new", from, to)
	if n := len(changeLines(out)); n != 6*maxDiffItems {
		t.Fatalf("change lines = %d, want whole-block replace of %d", n, 6*maxDiffItems)
	}
	checkApply(t, from, to, out)
}

// A deleted line that starts with COMBINING LONG VERTICAL LINE OVERLAY used to
// render as "-" plus the overlay, which displays as a plus sign: a removal that
// reads as an addition. The mark is now written as an escape.
func TestUnified_leadingCombiningMarkCannotAttachToTheMarker(t *testing.T) {
	out := Unified("a", "b", "\u20d2removed", "kept")
	if !strings.Contains(out, "\n- \\u{20D2}removed\n") || strings.ContainsRune(out, 0x20d2) {
		t.Fatalf("combining mark not escaped at the start of a line:\n%s", out)
	}
	if got := Unified("a", "b", "x", "a\u20d2b"); !strings.Contains(got, "\n+ a\u20d2b\n") {
		t.Fatalf("a combining mark inside a line is ordinary text:\n%s", got)
	}
	checkApply(t, "\u20d2removed", "kept", out)
}

// Content that starts with "++ " used to render as "+++ forged header" and a
// line starting with "@@" as a hunk header. Every content line now carries the
// marker, a space and an escaped first character, so neither can be forged.
func TestUnified_contentCannotForgeHeaders(t *testing.T) {
	to := "++ forged header\n@@ -1,1 +1,1 @@ fake\n-- also\n+plain\n--- old"
	out := Unified("old", "new", "x", to)
	assertSafe(t, out)
	checkApply(t, "x", to, out)
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if lines[0] != "--- old" || lines[1] != "+++ new" {
		t.Fatalf("headers = %q", lines[:2])
	}
	hunkHeader := regexp.MustCompile(`^@@ -\d+,\d+ \+\d+,\d+ @@$`)
	for _, l := range lines[2:] {
		if hunkHeader.MatchString(l) {
			continue
		}
		if len(l) < 2 || l[1] != ' ' || !strings.ContainsRune("-+ ", rune(l[0])) {
			t.Fatalf("line %q is neither a hunk header nor marker-space-text", l)
		}
	}
	for _, want := range []string{
		"\n+ \\u{002B}+ forged header\n",
		"\n+ \\u{0040}@ -1,1 +1,1 @@ fake\n",
		"\n+ \\u{002D}- also\n",
		"\n+ \\u{002B}plain\n",
		"\n+ \\u{002D}-- old\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestSplitLines(t *testing.T) {
	if got := splitLines(""); got != nil {
		t.Errorf(`splitLines("") = %#v`, got)
	}
	if got := splitLines("\n"); !reflect.DeepEqual(got, []string{"", ""}) {
		t.Errorf(`splitLines("\n") = %#v`, got)
	}
	if got := splitLines("a\nb"); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf(`splitLines("a\nb") = %#v`, got)
	}
}

// checkApply parses a Unified result and applies it to from: the result must
// reproduce to exactly (compared as escaped lines), every hunk header must
// match its body, and there must be no change lines when from equals to.
func checkApply(t failer, from, to, out string) {
	t.Helper()
	got, err := applyUnified(from, out)
	if err != nil {
		t.Fatalf("bad diff: %v\n%s", err, out)
	}
	var want []string
	for _, l := range splitLines(to) {
		want = append(want, escapeLine(l))
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("applying the diff gave %q, want %q\n%s", got, want, out)
	}
	if noChanges := len(changeLines(out)) == 0; noChanges != (from == to) {
		t.Fatalf("change lines present=%v but from==to is %v", !noChanges, from == to)
	}
}

// applyUnified applies the hunks of a Unified result to from and returns the
// escaped lines of the result.
func applyUnified(from, out string) ([]string, error) {
	var src []string
	for _, l := range splitLines(from) {
		src = append(src, escapeLine(l))
	}
	all := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(all) < 2 {
		return nil, fmt.Errorf("missing headers")
	}
	var result []string
	pos := 0
	for i := 2; i < len(all); {
		var aStart, aCount, bStart, bCount int
		if _, err := fmt.Sscanf(all[i], "@@ -%d,%d +%d,%d @@", &aStart, &aCount, &bStart, &bCount); err != nil {
			return nil, fmt.Errorf("bad hunk header %q: %w", all[i], err)
		}
		j := i + 1
		for j < len(all) && !strings.HasPrefix(all[j], "@@ -") {
			j++
		}
		first := aStart - 1
		if aCount == 0 {
			first = aStart
		}
		if first < pos || first > len(src) {
			return nil, fmt.Errorf("hunk starts at %d, already at %d of %d", first, pos, len(src))
		}
		result = append(result, src[pos:first]...)
		next, added, err := applyHunk(src, first, all[i+1:j], &result)
		if err != nil {
			return nil, err
		}
		if next-first != aCount || added != bCount {
			return nil, fmt.Errorf("header says %d/%d lines, body has %d/%d", aCount, bCount, next-first, added)
		}
		pos, i = next, j
	}
	return append(result, src[pos:]...), nil
}

// applyHunk walks one hunk body, checking it against src from index first,
// appends the resulting lines to result and returns the next source index and
// the number of lines on the new side. Every body line is the marker, one
// space, then the text.
func applyHunk(src []string, first int, body []string, result *[]string) (next, newSide int, err error) {
	next = first
	for _, l := range body {
		if len(l) < 2 || l[1] != ' ' {
			return 0, 0, fmt.Errorf("hunk line %q lacks the marker and space", l)
		}
		text := l[2:]
		switch l[0] {
		case ' ', '-':
			if next >= len(src) || src[next] != text {
				return 0, 0, fmt.Errorf("line %q does not match source", l)
			}
			next++
			if l[0] == ' ' {
				*result = append(*result, text)
				newSide++
			}
		case '+':
			*result = append(*result, text)
			newSide++
		default:
			return 0, 0, fmt.Errorf("bad hunk line %q", l)
		}
	}
	return next, newSide, nil
}
