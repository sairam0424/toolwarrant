package lifecycle_test

// The Proposers value type (D4): an append-only, duplicate-free, ordered list
// of principals that compares with == so Version stays comparable.

import (
	"slices"
	"strings"
	"testing"

	lc "github.com/sairam0424/toolwarrant/internal/lifecycle"
	"pgregory.net/rapid"
)

// hostileNames are principals that would break a separator-based encoding:
// separators, NUL, whitespace of several kinds, non-ASCII, invalid UTF-8, an
// encoded surrogate, a long name, quotes and backslashes.
func hostileNames() []string {
	return []string{
		"alice", "a,b", ",", "\x00", "nul\x00inside", "\n", " ", "\xc2\xa0", string(rune(0x540d)) + string(rune(0x5b57)),
		"\xff\xfe", strings.Repeat("x", 300), `"quoted"`, "a\\b", "\xed\xa0\x80",
	}
}

func TestProposers_ZeroValueIsEmpty(t *testing.T) {
	var p lc.Proposers
	if p.Len() != 0 || p.First() != "" || p.All() != nil || p.String() != "" || p.Contains("") {
		t.Errorf("zero Proposers is not empty: len=%d first=%q all=%v str=%q", p.Len(), p.First(), p.All(), p.String())
	}
	if lc.ProposersOf() != p || lc.ProposersOf("") != p {
		t.Error("ProposersOf with no names must equal the zero value")
	}
}

func TestProposers_AddKeepsOrderSkipsDuplicatesAndEmptyNames(t *testing.T) {
	p := lc.ProposersOf(alice, "", bob, alice, carol, bob)
	if got := p.All(); !slices.Equal(got, []string{alice, bob, carol}) {
		t.Fatalf("All() = %v", got)
	}
	if p.First() != alice || p.Len() != 3 || p.String() != "alice,bob,carol" {
		t.Errorf("First=%q Len=%d String=%q", p.First(), p.Len(), p.String())
	}
	for _, n := range []string{alice, bob, carol} {
		if !p.Contains(n) {
			t.Errorf("Contains(%q) = false", n)
		}
	}
	if p.Contains("") || p.Contains("dave") || p.Contains("alice,bob") {
		t.Error("Contains matched a name that was never added")
	}
	if q := p.Add(alice); q != p {
		t.Errorf("adding a known name changed the value: %v -> %v", p, q)
	}
	if q := p.Add(""); q != p {
		t.Errorf("adding an empty name changed the value: %v -> %v", p, q)
	}
}

// Add returns a new value and never changes its receiver, so a clone of a
// Version cannot be edited behind the original's back.
func TestProposers_AddDoesNotMutateTheReceiver(t *testing.T) {
	p := lc.ProposersOf(alice)
	q := p.Add(bob)
	if p.Len() != 1 || p.Contains(bob) {
		t.Errorf("receiver changed: %v", p)
	}
	if q.Len() != 2 || !q.Contains(bob) || q.First() != alice {
		t.Errorf("result wrong: %v", q)
	}
	all := q.All()
	all[0] = "mallory"
	if q.First() != alice {
		t.Error("All() returned a slice that aliases the list")
	}
}

// Two lists with the same names in the same order are equal with ==, and any
// difference in names or order makes them differ, whatever the names contain.
func TestProposers_EqualityFollowsTheNames(t *testing.T) {
	names := hostileNames()
	for i, a := range names {
		for j, b := range names {
			first, second := lc.ProposersOf(a, b), lc.ProposersOf(a, b)
			if first != second {
				t.Errorf("ProposersOf(%q,%q) built twice differs", a, b)
			}
			if cross := first == lc.ProposersOf(b, a); cross != (i == j) {
				t.Errorf("ProposersOf(%q,%q) == ProposersOf(%q,%q) = %v", a, b, b, a, cross)
			}
		}
	}
	if lc.ProposersOf("a,b") == lc.ProposersOf("a", "b") || lc.ProposersOf("ab") == lc.ProposersOf("a", "b") {
		t.Error("a joined name must not equal two names")
	}
}

func TestProposers_HostileNamesRoundTrip(t *testing.T) {
	var p lc.Proposers
	for _, n := range hostileNames() {
		p = p.Add(n)
	}
	if got := p.All(); !slices.Equal(got, hostileNames()) {
		t.Errorf("All() = %q, want %q", got, hostileNames())
	}
	for _, n := range hostileNames() {
		if !p.Contains(n) {
			t.Errorf("Contains(%q) = false after Add", n)
		}
	}
}

// Property: for any sequence of names, All() is the sequence with empty names
// dropped and repeats removed (first occurrence kept); Add never shrinks the
// list or moves its head.
func TestProposers_PropertyAddIsAppendOnlyDedup(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		names := rapid.SliceOfN(rapid.SampledFrom(append(hostileNames(), "", bob, carol)), 0, 12).Draw(rt, "names")
		var p lc.Proposers
		var want []string
		for _, n := range names {
			before := p.All()
			p = p.Add(n)
			after := p.All()
			if len(after) < len(before) || !slices.Equal(after[:len(before)], before) {
				rt.Fatalf("Add(%q) shrank or reordered %v -> %v", n, before, after)
			}
			if n != "" && !slices.Contains(want, n) {
				want = append(want, n)
			}
		}
		if got := p.All(); !slices.Equal(got, want) {
			rt.Fatalf("All() = %q, want %q", got, want)
		}
		if p.Len() != len(want) || (len(want) > 0 && p.First() != want[0]) {
			rt.Fatalf("Len=%d First=%q, want %d %q", p.Len(), p.First(), len(want), want)
		}
		if lc.ProposersOf(names...) != p {
			rt.Fatalf("ProposersOf differs from repeated Add")
		}
	})
}
