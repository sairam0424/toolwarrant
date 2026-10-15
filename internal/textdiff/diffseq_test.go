package textdiff

import (
	"strconv"
	"testing"
)

// lcsLength is a plain dynamic-programming oracle for the engine.
func lcsLength[T comparable](a, b []T) int {
	prev := make([]int, len(b)+1)
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		for j := 1; j <= len(b); j++ {
			switch {
			case a[i-1] == b[j-1]:
				cur[j] = prev[j-1] + 1
			case prev[j] >= cur[j-1]:
				cur[j] = prev[j]
			default:
				cur[j] = cur[j-1]
			}
		}
		prev = cur
	}
	return prev[len(b)]
}

// checkEdits verifies that edits turn a into b, consuming every item exactly
// once and in order, with deletes before inserts inside each run. It returns
// the number of equal steps.
func checkEdits[T comparable](t failer, a, b []T, edits []edit) int {
	t.Helper()
	ai, bi, equal := 0, 0, 0
	var rebuilt []T
	prevKind := kindEqual
	for n, e := range edits {
		switch e.kind {
		case kindEqual:
			if e.aIdx != ai || e.bIdx != bi || a[ai] != b[bi] {
				t.Fatalf("step %d: bad equal %+v (ai=%d bi=%d)", n, e, ai, bi)
			}
			rebuilt = append(rebuilt, a[ai])
			ai++
			bi++
			equal++
		case kindDelete:
			if e.aIdx != ai {
				t.Fatalf("step %d: bad delete %+v (ai=%d)", n, e, ai)
			}
			if prevKind == kindInsert {
				t.Fatalf("step %d: delete after insert inside one change run", n)
			}
			ai++
		case kindInsert:
			if e.bIdx != bi {
				t.Fatalf("step %d: bad insert %+v (bi=%d)", n, e, bi)
			}
			rebuilt = append(rebuilt, b[bi])
			bi++
		}
		prevKind = e.kind
	}
	if ai != len(a) || bi != len(b) || len(rebuilt) != len(b) {
		t.Fatalf("edits consumed a=%d/%d b=%d/%d", ai, len(a), bi, len(b))
	}
	for i := range b {
		if rebuilt[i] != b[i] {
			t.Fatalf("rebuilt[%d] != b[%d]", i, i)
		}
	}
	return equal
}

func TestDiffSeq_smallCasesAreMinimal(t *testing.T) {
	t.Parallel()
	cases := []struct{ a, b string }{
		{"", ""}, {"abc", "abc"}, {"", "abc"}, {"abc", ""}, {"abc", "abd"},
		{"abcabba", "cbabac"}, {"xaxbx", "ab"}, {"ab", "xaxbx"}, {"aaaa", "aa"},
		{"abcdef", "fedcba"}, {"a", "b"}, {"kitten", "sitting"},
	}
	for _, tc := range cases {
		a, b := []byte(tc.a), []byte(tc.b)
		edits := diffSeq(a, b)
		if got, want := checkEdits(t, a, b, edits), lcsLength(a, b); got != want {
			t.Errorf("%q -> %q: %d equal steps, LCS is %d", tc.a, tc.b, got, want)
		}
	}
}

func TestDiffSeq_isDeterministic(t *testing.T) {
	t.Parallel()
	a, b := []byte("abcabbaabcabba"), []byte("cbabaccbabac")
	first := diffSeq(a, b)
	for i := 0; i < 5; i++ {
		again := diffSeq(a, b)
		if len(again) != len(first) {
			t.Fatal("length changed between runs")
		}
		for j := range first {
			if again[j] != first[j] {
				t.Fatal("edit script changed between runs")
			}
		}
	}
}

func lines(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = prefix + strconv.Itoa(i)
	}
	return out
}

func countKinds(edits []edit) (equal, del, ins int) {
	for _, e := range edits {
		switch e.kind {
		case kindEqual:
			equal++
		case kindDelete:
			del++
		case kindInsert:
			ins++
		}
	}
	return equal, del, ins
}

func TestDiffSeq_hugeUnrelatedInputFallsBackToBlockReplace(t *testing.T) {
	t.Parallel()
	a, b := lines("a", maxDiffItems+5), lines("b", maxDiffItems+5)
	edits := diffSeq(a, b)
	equal, del, ins := countKinds(edits)
	if equal != 0 || del != len(a) || ins != len(b) {
		t.Fatalf("equal=%d del=%d ins=%d", equal, del, ins)
	}
	checkEdits(t, a, b, edits)
}

func TestDiffSeq_tooFarApartFallsBackToBlockReplace(t *testing.T) {
	t.Parallel()
	a, b := lines("a", 3000), lines("b", 3000)
	if _, ok := myers(a, b); ok {
		t.Fatal("myers should give up beyond maxEditDistance")
	}
	equal, del, ins := countKinds(diffSeq(a, b))
	if equal != 0 || del != 3000 || ins != 3000 {
		t.Fatalf("equal=%d del=%d ins=%d", equal, del, ins)
	}
}

func TestDiffSeq_hugeInputWithSmallChangeIsStillExact(t *testing.T) {
	t.Parallel()
	a := lines("line", 3*maxDiffItems)
	b := append([]string(nil), a...)
	b[len(b)/2] = "changed"
	edits := diffSeq(a, b)
	equal, del, ins := countKinds(edits)
	if equal != len(a)-1 || del != 1 || ins != 1 {
		t.Fatalf("equal=%d del=%d ins=%d", equal, del, ins)
	}
	checkEdits(t, a, b, edits)
}

func TestDiffSeq_manyScatteredChangesWithinLimit(t *testing.T) {
	t.Parallel()
	a := lines("line", 1500)
	b := append([]string(nil), a...)
	for i := 0; i < len(b); i += 3 {
		b[i] = "changed" + strconv.Itoa(i)
	}
	edits := diffSeq(a, b)
	if got, want := checkEdits(t, a, b, edits), lcsLength(a, b); got != want {
		t.Fatalf("equal=%d, LCS=%d", got, want)
	}
}

func TestReplaceBlock(t *testing.T) {
	t.Parallel()
	edits := replaceBlock(2, 3)
	equal, del, ins := countKinds(edits)
	if equal != 0 || del != 2 || ins != 3 {
		t.Fatalf("equal=%d del=%d ins=%d", equal, del, ins)
	}
}
