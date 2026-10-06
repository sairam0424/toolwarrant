package audit_test

// Verify and Head tests, derived from the specification:
//
//	Verify(entries) requires Seq to run 1..n without gaps, every PrevHash to
//	equal the previous Hash (Genesis for the first), and every Hash to match;
//	on failure it returns *BrokenError with the Seq of the first bad entry.
//	Head returns the last Hash or Genesis.

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/audit"
)

func TestVerify_EmptyLogVerifiesAndHeadIsGenesis(t *testing.T) {
	for name, log := range map[string][]audit.Entry{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			if err := audit.Verify(log); err != nil {
				t.Errorf("Verify(empty) = %v, want nil", err)
			}
			if got := audit.Head(log); got != audit.Genesis {
				t.Errorf("Head(empty) = %q, want Genesis", got)
			}
		})
	}
}

func TestVerify_AcceptsValidChainsOfEveryShortLength(t *testing.T) {
	for n := 1; n <= 12; n++ {
		chain := buildChain(t, n)
		if err := audit.Verify(chain); err != nil {
			t.Fatalf("Verify(chain of %d) = %v", n, err)
		}
		if got := audit.Head(chain); got != chain[n-1].Hash {
			t.Errorf("Head(chain of %d) = %q, want the last Hash %q", n, got, chain[n-1].Hash)
		}
	}
}

// Spec: "changing ANY single field of ANY entry breaks verification at
// exactly that seq".
func TestVerify_AnySingleFieldChangeBreaksTheChainAtThatEntry(t *testing.T) {
	for _, n := range []int{1, 2, chainLength} {
		chain := buildChain(t, n)
		for k := range chain {
			for _, m := range mutationsOf(chain[k]) {
				t.Run(fmt.Sprintf("n%d/entry%d/%s", n, k+1, m.name), func(t *testing.T) {
					log := cloneEntries(chain)
					log[k] = m.entry
					err := audit.Verify(log)
					if m.seqOnly {
						// The tampered Seq is the entry's own claim; the position is where it sits.
						requireBroken(t, err, seqsAt(log, k)...)
						return
					}
					requireBroken(t, err, int64(k+1))
				})
			}
		}
	}
}

// Spec (package doc): "Changing, deleting, reordering or inserting any row
// therefore breaks verification from that row on." A forger who re-seals only
// the row they changed still breaks the link to the next row.
func TestVerify_ResealingOnlyTheChangedEntryBreaksTheNextLink(t *testing.T) {
	chain := buildChain(t, chainLength)
	fullHead := audit.Head(chain)
	for k := range chain {
		for _, f := range contentFields() {
			log := cloneEntries(chain)
			forged := log[k]
			*f.ptr(&forged) += "x"
			log[k] = sealOn(t, prevOf(log, k), forged)
			err := audit.Verify(log)
			if k == len(chain)-1 {
				// Nothing follows the last row, so the chain is still internally
				// consistent; only Head gives the rewrite away.
				if err != nil {
					t.Errorf("entry %d field %s: rewriting the last row should still verify, got %v", k+1, f.name, err)
				}
				if audit.Head(log) == fullHead {
					t.Errorf("entry %d field %s: Head did not change", k+1, f.name)
				}
				continue
			}
			requireBroken(t, err, int64(k+2))
		}
	}
}

func TestVerify_DeletedEntryIsDetected(t *testing.T) {
	chain := buildChain(t, chainLength)
	for k := 0; k < len(chain)-1; k++ {
		log := slices.Delete(cloneEntries(chain), k, k+1)
		requireBroken(t, audit.Verify(log), seqsAt(log, k)...)
	}
}

// Spec: "truncating the tail (truncation stays valid, but Head changes)".
func TestVerify_TruncatedTailStaysValidButHeadChanges(t *testing.T) {
	chain := buildChain(t, chainLength)
	fullHead := audit.Head(chain)
	for keep := 0; keep < len(chain); keep++ {
		prefix := cloneEntries(chain[:keep])
		if err := audit.Verify(prefix); err != nil {
			t.Errorf("Verify(first %d entries) = %v, a truncated log must stay valid", keep, err)
		}
		want := audit.Genesis
		if keep > 0 {
			want = chain[keep-1].Hash
		}
		head := audit.Head(prefix)
		if head != want {
			t.Errorf("Head(first %d entries) = %q, want %q", keep, head, want)
		}
		if head == fullHead {
			t.Errorf("Head did not change after truncating to %d entries", keep)
		}
	}
	// Deleting only the last entry is the same thing.
	last := slices.Delete(cloneEntries(chain), len(chain)-1, len(chain))
	if err := audit.Verify(last); err != nil || audit.Head(last) == fullHead {
		t.Errorf("dropping the last entry: err=%v, head unchanged=%v", err, audit.Head(last) == fullHead)
	}
}

func TestVerify_InsertedEntryIsDetected(t *testing.T) {
	chain := buildChain(t, chainLength)
	for k := 0; k < len(chain); k++ {
		forged := sampleEntry(int64(k + 1))
		forged.Detail = "forged"

		// A forgery sealed correctly on top of its predecessor is itself valid;
		// the entry that used to follow the gap is where the chain breaks.
		sealed := sealOn(t, prevOf(chain, k), forged)
		log := slices.Insert(cloneEntries(chain), k, sealed)
		requireBroken(t, audit.Verify(log), seqsAt(log, k+1)...)

		// A forgery with a made-up hash is bad at its own position.
		bogus := sealed
		bogus.Hash = strings.Repeat("d", hexLength)
		log = slices.Insert(cloneEntries(chain), k, bogus)
		requireBroken(t, audit.Verify(log), seqsAt(log, k)...)
	}
}

// Appending a correctly sealed entry is how the log grows, not tampering.
func TestVerify_AppendingASealedEntryKeepsTheChainValid(t *testing.T) {
	chain := buildChain(t, chainLength)
	next := sealOn(t, chain[len(chain)-1], sampleEntry(int64(len(chain)+1)))
	grown := append(cloneEntries(chain), next)
	if err := audit.Verify(grown); err != nil {
		t.Fatalf("Verify(grown) = %v", err)
	}
	if audit.Head(grown) != next.Hash || audit.Head(grown) == audit.Head(chain) {
		t.Errorf("Head after append = %q", audit.Head(grown))
	}
}

func TestVerify_SwappedEntriesAreDetected(t *testing.T) {
	chain := buildChain(t, chainLength)
	for i := 0; i < len(chain); i++ {
		for j := i + 1; j < len(chain); j++ {
			log := cloneEntries(chain)
			log[i], log[j] = log[j], log[i]
			requireBroken(t, audit.Verify(log), seqsAt(log, i)...)
		}
	}
}

func TestVerify_DuplicatedEntryIsDetected(t *testing.T) {
	chain := buildChain(t, chainLength)
	for k := range chain {
		log := slices.Insert(cloneEntries(chain), k+1, chain[k])
		requireBroken(t, audit.Verify(log), seqsAt(log, k+1)...)
	}
}

// Spec: "Verify requires Seq to run 1..n without gaps". The entries below are
// sealed correctly, so the sequence rule is the only thing that can fail.
func TestVerify_SeqMustRunFromOneWithoutGaps(t *testing.T) {
	tests := []struct {
		name string
		seqs []int64
	}{
		{"starts at zero", []int64{0, 1, 2}},
		{"starts at two", []int64{2, 3, 4}},
		{"gap in the middle", []int64{1, 2, 4, 5}},
		{"skips the second", []int64{1, 3}},
		{"repeats a number", []int64{1, 2, 2, 3}},
		{"descending", []int64{3, 2, 1}},
		{"negative start", []int64{-1, 0, 1}},
		{"single entry with seq two", []int64{2}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var log []audit.Entry
			prev := audit.Entry{}
			for _, seq := range tc.seqs {
				prev = sealOn(t, prev, sampleEntry(seq))
				log = append(log, prev)
			}
			firstBad := -1
			for i, seq := range tc.seqs {
				if seq != int64(i+1) {
					firstBad = i
					break
				}
			}
			requireBroken(t, audit.Verify(log), seqsAt(log, firstBad)...)
		})
	}
}

// Spec: "every PrevHash to equal the previous Hash (Genesis for the first)".
func TestVerify_FirstEntryMustChainToGenesis(t *testing.T) {
	notGenesis := audit.Entry{Hash: strings.Repeat("a", hexLength)}
	first := sealOn(t, notGenesis, sampleEntry(1)) // its own hash is right for this prev_hash
	second := sealOn(t, first, sampleEntry(2))
	requireBroken(t, audit.Verify([]audit.Entry{first}), 1)
	requireBroken(t, audit.Verify([]audit.Entry{first, second}), 1)
}

func TestVerify_UnsealedEntriesAreRejected(t *testing.T) {
	log := []audit.Entry{sampleEntry(1), sampleEntry(2)}
	requireBroken(t, audit.Verify(log), 1)
}

// Entries sealed on two different logs cannot be joined.
func TestVerify_SplicingTwoLogsIsDetected(t *testing.T) {
	a := buildChain(t, 5)
	b := make([]audit.Entry, 0, 5)
	prev := audit.Entry{}
	for i := 1; i <= 5; i++ {
		e := sampleEntry(int64(i))
		e.Detail = "the other log"
		prev = sealOn(t, prev, e)
		b = append(b, prev)
	}
	spliced := append(cloneEntries(a[:2]), b[2:]...)
	requireBroken(t, audit.Verify(spliced), 3)
}

// Spec (package doc): "The chain alone cannot prove the log is complete:
// whoever can rewrite the whole file can rebuild a valid chain. Record Head()
// somewhere outside the database to detect that."
func TestVerify_RebuildingTheWholeSuffixVerifiesButHeadBetraysIt(t *testing.T) {
	chain := buildChain(t, chainLength)
	original := audit.Head(chain)
	rebuilt := cloneEntries(chain)
	rebuilt[1].Detail = "rewritten history"
	for i := 1; i < len(rebuilt); i++ {
		rebuilt[i] = sealOn(t, rebuilt[i-1], rebuilt[i])
	}
	if err := audit.Verify(rebuilt); err != nil {
		t.Fatalf("a fully rebuilt chain must verify (that is the documented limit), got %v", err)
	}
	if audit.Head(rebuilt) == original {
		t.Error("Head is unchanged after rewriting history, so it cannot detect the rewrite")
	}
}

func TestVerifyAndHead_DoNotMutateTheirInput(t *testing.T) {
	good := buildChain(t, chainLength)
	bad := cloneEntries(good)
	bad[2].Detail = "tampered"
	for name, log := range map[string][]audit.Entry{"good": good, "bad": bad} {
		snapshot := cloneEntries(log)
		_ = audit.Verify(log)
		_ = audit.Head(log)
		if !slices.Equal(log, snapshot) {
			t.Errorf("%s: Verify or Head modified the entries", name)
		}
	}
}

func TestBrokenError_DescribesTheFailure(t *testing.T) {
	chain := buildChain(t, 3)
	chain[1].Detail = "tampered"
	err := audit.Verify(chain)
	requireBroken(t, err, 2)
	if !strings.Contains(err.Error(), "2") {
		t.Errorf("error text %q does not mention the failing seq", err.Error())
	}
}
