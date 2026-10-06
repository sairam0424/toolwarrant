package audit_test

// Property tests over random logs (pgregory.net/rapid). Unlike the table tests
// they use arbitrary Unicode text in every field.

import (
	"errors"
	"slices"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"pgregory.net/rapid"
)

const (
	propertyRounds = 6
	maxRandomChain = 10
)

func checkRounds(t *testing.T, prop func(*rapid.T)) {
	t.Helper()
	for i := 0; i < propertyRounds; i++ {
		rapid.Check(t, prop)
	}
}

// drawEntry draws an entry whose content fields are arbitrary valid UTF-8.
func drawEntry(rt *rapid.T, seq int64, label string) audit.Entry {
	text := func(name string) string { return rapid.String().Draw(rt, label+"."+name) }
	return audit.Entry{
		Seq:        seq,
		TS:         text("ts"),
		Actor:      text("actor"),
		ActorType:  text("actor_type"),
		Event:      text("event"),
		Subject:    text("subject"),
		BeforeHash: text("before_hash"),
		AfterHash:  text("after_hash"),
		Detail:     text("detail"),
	}
}

// drawChain seals between minLen and maxLen random entries.
func drawChain(rt *rapid.T, minLen, maxLen int) []audit.Entry {
	n := rapid.IntRange(minLen, maxLen).Draw(rt, "length")
	chain := make([]audit.Entry, 0, n)
	prev := audit.Entry{}
	for i := 1; i <= n; i++ {
		sealed, err := audit.Seal(prev, drawEntry(rt, int64(i), "entry"))
		if err != nil {
			rt.Fatalf("Seal rejected valid UTF-8 text: %v", err)
		}
		chain = append(chain, sealed)
		prev = sealed
	}
	return chain
}

// brokenSeq extracts the Seq of a *BrokenError, or reports that err is not one.
func brokenSeq(err error) (int64, bool) {
	var broken *audit.BrokenError
	if !errors.As(err, &broken) {
		return 0, false
	}
	return broken.Seq, true
}

func TestProperty_RandomChainsVerifyAndLink(t *testing.T) {
	checkRounds(t, func(rt *rapid.T) {
		chain := drawChain(rt, 0, maxRandomChain)
		if err := audit.Verify(chain); err != nil {
			rt.Fatalf("Verify(valid chain) = %v", err)
		}
		wantHead := audit.Genesis
		if len(chain) > 0 {
			wantHead = chain[len(chain)-1].Hash
		}
		if got := audit.Head(chain); got != wantHead {
			rt.Fatalf("Head = %q, want %q", got, wantHead)
		}
		prevHash := audit.Genesis
		for i, e := range chain {
			if !isLowerHex64(e.Hash) || e.PrevHash != prevHash || e.Seq != int64(i+1) {
				rt.Fatalf("entry %d: seq=%d prev=%q hash=%q", i, e.Seq, e.PrevHash, e.Hash)
			}
			prevHash = e.Hash
		}
	})
}

// Any single-field change to any entry breaks verification at that entry.
func TestProperty_AnySingleFieldChangeIsDetectedAtThatEntry(t *testing.T) {
	checkRounds(t, func(rt *rapid.T) {
		chain := drawChain(rt, 1, maxRandomChain)
		k := rapid.IntRange(0, len(chain)-1).Draw(rt, "index")
		mutations := mutationsOf(chain[k])
		m := rapid.SampledFrom(mutations).Draw(rt, "mutation")
		log := cloneEntries(chain)
		log[k] = m.entry
		seq, ok := brokenSeq(audit.Verify(log))
		if !ok {
			rt.Fatalf("mutation %s of entry %d went undetected", m.name, k+1)
		}
		allowed := []int64{int64(k + 1)}
		if m.seqOnly {
			allowed = seqsAt(log, k)
		}
		if !slices.Contains(allowed, seq) {
			rt.Fatalf("mutation %s of entry %d reported at seq %d, want one of %v", m.name, k+1, seq, allowed)
		}
	})
}

// Replacing a content field with a different random string is detected too.
func TestProperty_RandomReplacementOfAContentFieldIsDetected(t *testing.T) {
	checkRounds(t, func(rt *rapid.T) {
		chain := drawChain(rt, 1, maxRandomChain)
		k := rapid.IntRange(0, len(chain)-1).Draw(rt, "index")
		field := rapid.SampledFrom(contentFields()).Draw(rt, "field")
		log := cloneEntries(chain)
		target := field.ptr(&log[k])
		replacement := rapid.String().Filter(func(s string) bool { return s != *target }).Draw(rt, "replacement")
		*target = replacement
		seq, ok := brokenSeq(audit.Verify(log))
		if !ok || seq != int64(k+1) {
			rt.Fatalf("replacing %s of entry %d: broken=%v seq=%d", field.name, k+1, ok, seq)
		}
	})
}

func TestProperty_TruncationStaysValidAndMovesHead(t *testing.T) {
	checkRounds(t, func(rt *rapid.T) {
		chain := drawChain(rt, 1, maxRandomChain)
		keep := rapid.IntRange(0, len(chain)-1).Draw(rt, "keep")
		prefix := cloneEntries(chain[:keep])
		if err := audit.Verify(prefix); err != nil {
			rt.Fatalf("Verify(prefix of %d) = %v", keep, err)
		}
		if audit.Head(prefix) == audit.Head(chain) {
			rt.Fatalf("Head unchanged after truncating %d entries to %d", len(chain), keep)
		}
	})
}

// Deleting, swapping, duplicating or inserting entries is always detected,
// except deleting the last entry, which is a truncation.
func TestProperty_StructuralTamperingIsDetected(t *testing.T) {
	checkRounds(t, func(rt *rapid.T) {
		chain := drawChain(rt, 2, maxRandomChain)
		n := len(chain)
		log := cloneEntries(chain)
		switch op := rapid.IntRange(0, 3).Draw(rt, "op"); op {
		case 0:
			k := rapid.IntRange(0, n-2).Draw(rt, "deleted")
			log = slices.Delete(log, k, k+1)
		case 1:
			i := rapid.IntRange(0, n-2).Draw(rt, "i")
			j := rapid.IntRange(i+1, n-1).Draw(rt, "j")
			log[i], log[j] = log[j], log[i]
		case 2:
			k := rapid.IntRange(0, n-1).Draw(rt, "duplicated")
			log = slices.Insert(log, k+1, chain[k])
		default:
			k := rapid.IntRange(0, n-1).Draw(rt, "insertedBefore")
			forged, err := audit.Seal(prevOf(chain, k), drawEntry(rt, int64(k+1), "forged"))
			if err != nil {
				rt.Fatalf("Seal: %v", err)
			}
			if forged == chain[k] {
				rt.Skip("the forged entry equals the original")
			}
			log = slices.Insert(log, k, forged)
		}
		if _, ok := brokenSeq(audit.Verify(log)); !ok {
			rt.Fatalf("structural tampering went undetected: %d entries -> %d", n, len(log))
		}
	})
}

// Seal is a function of (prev, entry) and the hash distinguishes entries.
func TestProperty_SealIsDeterministicAndDistinguishesEntries(t *testing.T) {
	checkRounds(t, func(rt *rapid.T) {
		prev := audit.Entry{}
		if rapid.Bool().Draw(rt, "hasPrev") {
			prev = sealOn(t, audit.Entry{}, drawEntry(rt, 1, "prev"))
		}
		a := drawEntry(rt, 2, "a")
		first, second := sealOn(t, prev, a), sealOn(t, prev, a)
		if first != second {
			rt.Fatalf("Seal is not deterministic: %+v vs %+v", first, second)
		}
		b := drawEntry(rt, 2, "b")
		if a == b {
			rt.Skip("identical entries")
		}
		if sealOn(t, prev, b).Hash == first.Hash {
			rt.Fatalf("different entries share a hash: %+v and %+v", a, b)
		}
	})
}
