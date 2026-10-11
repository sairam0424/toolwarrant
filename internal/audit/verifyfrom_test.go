package audit_test

// VerifyFrom tests, derived from its specification:
//
//	VerifyFrom(prev, entries) accepts entries that continue the chain after
//	prev (prev.Seq+1 onwards, PrevHash equal to prev.Hash, every Hash correct)
//	and returns *BrokenError at the first entry that does not; the zero prev
//	means the start of the log, so VerifyFrom(Entry{}, log) is Verify(log).

import (
	"errors"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/audit"
)

// Every suffix of a valid chain verifies from the entry before it, and the
// empty suffix verifies from any entry at all.
func TestVerifyFrom_AcceptsEverySuffixOfAValidChain(t *testing.T) {
	chain := buildChain(t, chainLength)
	for k := 0; k <= len(chain); k++ {
		if err := audit.VerifyFrom(prevOf(chain, k), chain[k:]); err != nil {
			t.Errorf("VerifyFrom(entry %d, suffix of %d) = %v", k, len(chain)-k, err)
		}
	}
	if err := audit.VerifyFrom(chain[len(chain)-1], nil); err != nil {
		t.Errorf("VerifyFrom(head, nothing) = %v, want nil", err)
	}
}

// The zero prev is the start of the log: VerifyFrom agrees with Verify on
// valid chains and on the first broken entry of tampered ones.
func TestVerifyFrom_ZeroPrevIsVerify(t *testing.T) {
	chain := buildChain(t, chainLength)
	if err := audit.VerifyFrom(audit.Entry{}, chain); err != nil {
		t.Fatalf("VerifyFrom(zero, chain) = %v", err)
	}
	for k := range chain {
		log := cloneEntries(chain)
		log[k].Detail += "x"
		want, got := audit.Verify(log), audit.VerifyFrom(audit.Entry{}, log)
		var wantBroken, gotBroken *audit.BrokenError
		if !errors.As(want, &wantBroken) || !errors.As(got, &gotBroken) || wantBroken.Seq != gotBroken.Seq {
			t.Errorf("entry %d: Verify = %v, VerifyFrom(zero) = %v; want the same broken seq", k+1, want, got)
		}
	}
}

// A suffix that was re-chained from the wrong predecessor is refused at its
// first entry: the reader that pinned prev sees that the entries after it do
// not continue from the hash it remembers.
func TestVerifyFrom_RefusesASuffixThatDoesNotContinueFromPrev(t *testing.T) {
	chain := buildChain(t, chainLength)
	const k = 3
	t.Run("wrong prev hash", func(t *testing.T) {
		forged := prevOf(chain, k)
		forged.Hash = "f" + forged.Hash[1:]
		requireBroken(t, audit.VerifyFrom(forged, chain[k:]), chain[k].Seq)
	})
	t.Run("wrong prev seq", func(t *testing.T) {
		forged := prevOf(chain, k)
		forged.Seq++
		requireBroken(t, audit.VerifyFrom(forged, chain[k:]), chain[k].Seq)
	})
	t.Run("suffix re-sealed from another predecessor", func(t *testing.T) {
		log := cloneEntries(chain)
		other := log[k-1]
		other.Detail += " rewritten"
		other = sealOn(t, prevOf(log, k-1), other)
		for i := k; i < len(log); i++ {
			log[i] = sealOn(t, func() audit.Entry {
				if i == k {
					return other
				}
				return log[i-1]
			}(), log[i])
		}
		requireBroken(t, audit.VerifyFrom(chain[k-1], log[k:]), chain[k].Seq)
	})
	t.Run("edited entry inside the suffix", func(t *testing.T) {
		log := cloneEntries(chain)
		log[k+1].Actor = "mallory"
		requireBroken(t, audit.VerifyFrom(prevOf(log, k), log[k:]), log[k+1].Seq)
	})
	t.Run("gap inside the suffix", func(t *testing.T) {
		log := cloneEntries(chain)
		cut := append(log[k:k+1:k+1], log[k+2:]...)
		requireBroken(t, audit.VerifyFrom(prevOf(log, k), cut), log[k+2].Seq)
	})
}
