package trust

import (
	"errors"
	"reflect"
	"testing"

	"pgregory.net/rapid"

	"github.com/sairam0424/toolwarrant/internal/signing"
	"github.com/sairam0424/toolwarrant/internal/signing/sigtest"
)

// poolNames are the operators the property tests draw lists from; each has
// one key for the whole test.
var poolNames = []string{"alice", "bob", "carol", "dave", "erin"}

// keyPool generates one key per pool name.
func keyPool(t testing.TB) []sigtest.Key {
	t.Helper()
	keys := make([]sigtest.Key, len(poolNames))
	for i := range keys {
		keys[i] = sigtest.GenerateEd25519(t)
	}
	return keys
}

// drawList draws a validated list of version v over a non-empty subset of the
// pool.
func drawList(rt *rapid.T, label string, v int, keys []sigtest.Key) Record {
	members := rapid.SliceOfNDistinct(rapid.IntRange(0, len(keys)-1), 1, len(keys), rapid.ID[int]).Draw(rt, label+"Members")
	ops := make([]named, 0, len(members))
	for _, i := range members {
		ops = append(ops, named{poolNames[i], keys[i]})
	}
	r, err := Validate(listOf(v, ops...))
	if err != nil {
		rt.Fatalf("%s: Validate: %v", label, err)
	}
	return r
}

// Folding a random sequence of trust records, some acceptable and some not,
// through State.Apply leaves Current equal to the last record Apply accepted,
// ListSeq at that record's seq, BootstrapSeq at the first accepted seq, and
// the accepted versions are 1, 2, 3, ... with no gap; a refused record leaves
// the state as it was.
func TestProperty_stateAfterFoldingEqualsTheLastAcceptedRecord(t *testing.T) {
	t.Parallel()
	keys := keyPool(t)
	kinds := []Kind{KindBootstrap, KindRotated, Kind("other")}
	rapid.Check(t, func(rt *rapid.T) {
		var s State
		var last *Record
		var firstSeq, lastSeq int64
		accepted := 0
		seq := int64(0)
		for i, n := 0, rapid.IntRange(1, 12).Draw(rt, "records"); i < n; i++ {
			seq += rapid.Int64Range(1, 3).Draw(rt, "gap")
			v := rapid.IntRange(1, 5).Draw(rt, "version")
			next := drawList(rt, "next", v, keys)
			signer := fp(keys[rapid.IntRange(0, len(keys)-1).Draw(rt, "signer")])
			kind := kinds[rapid.IntRange(0, len(kinds)-1).Draw(rt, "kind")]
			after, err := s.Apply(seq, kind, next, signer, "")
			if err != nil {
				if after != (State{}) {
					rt.Fatalf("a refused record returned a state: %+v", after)
				}
				continue
			}
			accepted++
			if next.Version != accepted {
				rt.Fatalf("accepted version %d as the %dth list", next.Version, accepted)
			}
			if accepted == 1 {
				firstSeq = seq
			}
			last, lastSeq, s = &next, seq, after
		}
		if (last == nil) != (s.Current == nil) || (last != nil && !reflect.DeepEqual(*s.Current, *last)) {
			rt.Fatalf("Current = %+v, last accepted %+v", s.Current, last)
		}
		if s.ListSeq != lastSeq || s.BootstrapSeq != firstSeq {
			rt.Fatalf("seqs %d/%d, want %d/%d", s.BootstrapSeq, s.ListSeq, firstSeq, lastSeq)
		}
	})
}

// For every version V of a list in force and every candidate version W,
// CheckRotation accepts exactly when W is V+1 and the signer is in both
// lists, so a sequence of accepted rotations never lowers or skips a version
// and a signer in one list only is refused at every version.
func TestProperty_rotationNeverLowersTheVersion(t *testing.T) {
	t.Parallel()
	keys := keyPool(t)
	rapid.Check(t, func(rt *rapid.T) {
		v := rapid.IntRange(1, 1_000_000).Draw(rt, "V")
		w := rapid.IntRange(1, 1_000_004).Draw(rt, "W")
		prev := drawList(rt, "prev", v, keys)
		next := drawList(rt, "next", w, keys)
		signer := fp(keys[rapid.IntRange(0, len(keys)-1).Draw(rt, "signer")])
		_, inPrev := prev.Lookup(signer)
		_, inNext := next.Lookup(signer)
		err := CheckRotation(prev, next, signer)
		switch {
		case w != v+1 && !errors.Is(err, ErrRollback):
			rt.Fatalf("V=%d W=%d: %v, want ErrRollback", v, w, err)
		case w == v+1 && (!inPrev || !inNext) && !errors.Is(err, ErrSignerNotInBothLists):
			rt.Fatalf("V=%d W=%d signer in %t/%t: %v, want ErrSignerNotInBothLists", v, w, inPrev, inNext, err)
		case w == v+1 && inPrev && inNext && err != nil:
			rt.Fatalf("V=%d W=%d signer in both: %v", v, w, err)
		}
	})
}

// NormalizeName is a fixed point on its own output, and the identity on every
// name that already matches the pattern, so a stored actor compares as itself.
func TestProperty_normalizeNameIsIdentityOnCanonicalNames(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		name := rapid.StringMatching(`[a-z0-9][a-z0-9._@-]{0,63}`).Draw(rt, "name")
		got, err := NormalizeName(name)
		if err != nil || got != name {
			rt.Fatalf("NormalizeName(%q) = %q, %v", name, got, err)
		}
	})
	rapid.Check(t, func(rt *rapid.T) {
		name := rapid.String().Draw(rt, "any")
		got, err := NormalizeName(name)
		if err != nil {
			return
		}
		again, err := NormalizeName(got)
		if err != nil || again != got {
			rt.Fatalf("NormalizeName(%q) = %q, then %q, %v", name, got, again, err)
		}
		if _, err := signing.ParseAuthorizedKey("ssh-ed25519 " + got); err == nil {
			rt.Fatalf("a name parsed as a key: %q", got)
		}
	})
}
