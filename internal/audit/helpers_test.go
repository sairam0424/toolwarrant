package audit_test

// Shared fixtures for the audit tests. The tests use only the exported API and
// derive every expectation from the written specification.

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/audit"
)

const (
	hexLength = 64
	// chainLength is the chain used by the tamper tests: long enough to have
	// a first, middle and last entry, short enough to try every position.
	chainLength = 6
)

// isLowerHex64 reports whether s is exactly 64 lower-case hex digits.
func isLowerHex64(s string) bool {
	if len(s) != hexLength {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// sampleEntry returns a deterministic entry with every content field set, so a
// test can blank or change any of them.
func sampleEntry(seq int64) audit.Entry {
	actors := []string{"alice", "bob", "system"}
	actor := actors[((int(seq)%len(actors))+len(actors))%len(actors)] // seq may be negative in gap tests
	actorType := "human"
	if actor == "system" {
		actorType = "system"
	}
	return audit.Entry{
		Seq:        seq,
		TS:         fmt.Sprintf("2026-10-06T12:00:%02d.%09dZ", seq%60, seq),
		Actor:      actor,
		ActorType:  actorType,
		Event:      "version.proposed",
		Subject:    fmt.Sprintf("server-%d/tool-%d", seq, seq),
		BeforeHash: strings.Repeat("b", hexLength-1) + fmt.Sprint(seq%10),
		AfterHash:  strings.Repeat("a", hexLength-1) + fmt.Sprint(seq%10),
		Detail:     fmt.Sprintf("entry number %d", seq),
	}
}

// sealOn seals e after prev and fails the test if Seal errors.
func sealOn(tb testing.TB, prev, e audit.Entry) audit.Entry {
	tb.Helper()
	sealed, err := audit.Seal(prev, e)
	if err != nil {
		tb.Fatalf("Seal(seq %d): %v", e.Seq, err)
	}
	return sealed
}

// buildChain seals n sample entries with Seq 1..n.
func buildChain(tb testing.TB, n int) []audit.Entry {
	tb.Helper()
	chain := make([]audit.Entry, 0, n)
	prev := audit.Entry{}
	for i := 1; i <= n; i++ {
		prev = sealOn(tb, prev, sampleEntry(int64(i)))
		chain = append(chain, prev)
	}
	return chain
}

// prevOf returns the entry that precedes position i (0-based) in chain, or the
// zero Entry for the first position.
func prevOf(chain []audit.Entry, i int) audit.Entry {
	if i == 0 {
		return audit.Entry{}
	}
	return chain[i-1]
}

// fieldRef names one string field of an Entry and how to reach it.
type fieldRef struct {
	name string
	ptr  func(e *audit.Entry) *string
}

// contentFields are the fields a caller supplies; Seal computes PrevHash and
// Hash from them.
func contentFields() []fieldRef {
	return []fieldRef{
		{"ts", func(e *audit.Entry) *string { return &e.TS }},
		{"actor", func(e *audit.Entry) *string { return &e.Actor }},
		{"actor_type", func(e *audit.Entry) *string { return &e.ActorType }},
		{"event", func(e *audit.Entry) *string { return &e.Event }},
		{"subject", func(e *audit.Entry) *string { return &e.Subject }},
		{"before_hash", func(e *audit.Entry) *string { return &e.BeforeHash }},
		{"after_hash", func(e *audit.Entry) *string { return &e.AfterHash }},
		{"detail", func(e *audit.Entry) *string { return &e.Detail }},
	}
}

// chainFields are the two fields Seal fills in.
func chainFields() []fieldRef {
	return []fieldRef{
		{"prev_hash", func(e *audit.Entry) *string { return &e.PrevHash }},
		{"hash", func(e *audit.Entry) *string { return &e.Hash }},
	}
}

// stringVariants are the ways a string field is damaged. Each returns a value
// different from the input for every non-degenerate input.
func stringVariants() map[string]func(string) string {
	return map[string]func(string) string{
		"append":  func(s string) string { return s + "x" },
		"prepend": func(s string) string { return " " + s },
		"blank": func(s string) string {
			if s == "" {
				return "x"
			}
			return ""
		},
		"flip-last": func(s string) string {
			if s == "" {
				return "x"
			}
			runes := []rune(s)
			last := len(runes) - 1
			if runes[last] == 'z' {
				runes[last] = 'y'
			} else {
				runes[last] = 'z'
			}
			return string(runes)
		},
	}
}

// mutation is one damaged copy of an entry.
type mutation struct {
	name    string
	entry   audit.Entry
	seqOnly bool // the Seq field itself was changed
}

// mutationsOf lists every single-field change of e: each string field under
// each variant, plus the hash-specific damage (upper-casing, truncation) and
// two Seq changes. Changes that leave the entry identical are dropped.
func mutationsOf(e audit.Entry) []mutation {
	var out []mutation
	add := func(name string, m audit.Entry, seqOnly bool) {
		if m != e {
			out = append(out, mutation{name: name, entry: m, seqOnly: seqOnly})
		}
	}
	for _, f := range append(contentFields(), chainFields()...) {
		for vname, variant := range stringVariants() {
			m := e
			*f.ptr(&m) = variant(*f.ptr(&m))
			add(f.name+"/"+vname, m, false)
		}
	}
	upper, short := e, e
	upper.Hash = strings.ToUpper(e.Hash)
	short.Hash = e.Hash[:len(e.Hash)-1]
	add("hash/upper-case", upper, false)
	add("hash/truncated", short, false)
	plus, zero := e, e
	plus.Seq = e.Seq + 1000
	zero.Seq = 0
	add("seq/plus-1000", plus, true)
	add("seq/zero", zero, true)
	return out
}

// requireBroken asserts err is a *audit.BrokenError whose Seq is one of
// allowed. The specification says Verify returns "the Seq of the first bad
// entry"; when a tampered entry's own Seq differs from its position the text
// does not say which of the two is meant, so callers list both.
func requireBroken(t *testing.T, err error, allowed ...int64) {
	t.Helper()
	if err == nil {
		t.Fatalf("Verify succeeded, want *BrokenError at seq %v", allowed)
	}
	var broken *audit.BrokenError
	if !errors.As(err, &broken) {
		t.Fatalf("Verify error is %T (%v), want *audit.BrokenError", err, err)
	}
	if !slices.Contains(allowed, broken.Seq) {
		t.Errorf("BrokenError.Seq = %d (%s), want one of %v", broken.Seq, broken.Reason, allowed)
	}
	if broken.Reason == "" || broken.Error() == "" {
		t.Errorf("BrokenError without a reason: %+v / %q", broken, broken.Error())
	}
}

// seqsAt returns the two readings of "the Seq of the first bad entry" for the
// entry at position pos (0-based): its own Seq field and its expected Seq.
func seqsAt(entries []audit.Entry, pos int) []int64 {
	return []int64{entries[pos].Seq, int64(pos + 1)}
}

// cloneEntries copies a slice of entries.
func cloneEntries(in []audit.Entry) []audit.Entry { return slices.Clone(in) }
