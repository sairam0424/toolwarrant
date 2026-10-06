package audit_test

// Seal tests, derived from the specification:
//
//	Seal(prev, e) sets e.PrevHash to prev.Hash (or the Genesis constant, 64
//	zeros, when prev.Hash is empty) and e.Hash to the lower-case hex SHA-256 of
//	the RFC 8785 canonical JSON of the entry WITHOUT the hash field, with keys
//	seq, ts, actor, actor_type, event, subject, before_hash, after_hash,
//	detail, prev_hash. Seq must lie in [-2^53, 2^53-1].

import (
	"math"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/audit"
)

func TestGenesis_IsSixtyFourZeros(t *testing.T) {
	if audit.Genesis != strings.Repeat("0", hexLength) {
		t.Errorf("Genesis = %q, want 64 zeros", audit.Genesis)
	}
}

func TestSeal_FirstEntryChainsToGenesis(t *testing.T) {
	got := sealOn(t, audit.Entry{}, sampleEntry(1))
	if got.PrevHash != audit.Genesis {
		t.Errorf("PrevHash = %q, want Genesis", got.PrevHash)
	}
	if !isLowerHex64(got.Hash) {
		t.Errorf("Hash = %q, want 64 lower-case hex digits", got.Hash)
	}
}

func TestSeal_EmptyPrevHashMeansGenesisEvenWithOtherFieldsSet(t *testing.T) {
	prev := sampleEntry(41) // Hash is empty: it was never sealed
	got := sealOn(t, prev, sampleEntry(1))
	if got.PrevHash != audit.Genesis {
		t.Errorf("PrevHash = %q, want Genesis when prev.Hash is empty", got.PrevHash)
	}
}

func TestSeal_LinksToThePreviousHash(t *testing.T) {
	first := sealOn(t, audit.Entry{}, sampleEntry(1))
	second := sealOn(t, first, sampleEntry(2))
	if second.PrevHash != first.Hash {
		t.Errorf("PrevHash = %q, want the previous Hash %q", second.PrevHash, first.Hash)
	}
	if second.Hash == first.Hash || !isLowerHex64(second.Hash) {
		t.Errorf("Hash = %q", second.Hash)
	}
}

func TestSeal_CopiesAnyNonEmptyPrevHashVerbatim(t *testing.T) {
	for _, h := range []string{strings.Repeat("a", hexLength), "not-hex", "ABC"} {
		got := sealOn(t, audit.Entry{Hash: h}, sampleEntry(1))
		if got.PrevHash != h {
			t.Errorf("PrevHash = %q, want %q", got.PrevHash, h)
		}
	}
}

func TestSeal_KeepsEveryOtherFieldAndIsDeterministic(t *testing.T) {
	in := sampleEntry(7)
	a := sealOn(t, audit.Entry{}, in)
	b := sealOn(t, audit.Entry{}, in)
	if a != b {
		t.Fatalf("Seal is not deterministic: %+v vs %+v", a, b)
	}
	want := in
	want.PrevHash, want.Hash = a.PrevHash, a.Hash
	if a != want {
		t.Errorf("Seal changed a caller-supplied field:\n got %+v\nwant %+v", a, want)
	}
}

func TestSeal_IgnoresStaleHashAndPrevHashInTheInput(t *testing.T) {
	clean := sealOn(t, audit.Entry{}, sampleEntry(3))
	stale := sampleEntry(3)
	stale.PrevHash = strings.Repeat("f", hexLength)
	stale.Hash = strings.Repeat("e", hexLength)
	if got := sealOn(t, audit.Entry{}, stale); got != clean {
		t.Errorf("stale PrevHash/Hash leaked into the result:\n got %+v\nwant %+v", got, clean)
	}
}

// Spec: the hash covers seq, ts, actor, actor_type, event, subject,
// before_hash, after_hash, detail and prev_hash: changing any one changes it.
func TestSeal_HashCoversEveryField(t *testing.T) {
	base := sealOn(t, audit.Entry{}, sampleEntry(5))
	for _, f := range contentFields() {
		for vname, variant := range stringVariants() {
			e := sampleEntry(5)
			*f.ptr(&e) = variant(*f.ptr(&e))
			if got := sealOn(t, audit.Entry{}, e); got.Hash == base.Hash {
				t.Errorf("changing %s (%s) did not change the hash", f.name, vname)
			}
		}
	}
	changedSeq := sampleEntry(5)
	changedSeq.Seq = 6
	if got := sealOn(t, audit.Entry{}, changedSeq); got.Hash == base.Hash {
		t.Error("changing seq did not change the hash")
	}
	otherPrev := sealOn(t, audit.Entry{Hash: strings.Repeat("c", hexLength)}, sampleEntry(5))
	if otherPrev.Hash == base.Hash {
		t.Error("changing the previous hash did not change the hash")
	}
}

// A hash that ignored field boundaries would let an attacker move text from
// one field into its neighbour. The canonical JSON quotes every value, so
// shifting one character across any pair of neighbouring fields must change
// the hash.
func TestSeal_ShiftingTextBetweenNeighbouringFieldsChangesTheHash(t *testing.T) {
	pairs := [][2]func(*audit.Entry) *string{
		{func(e *audit.Entry) *string { return &e.TS }, func(e *audit.Entry) *string { return &e.Actor }},
		{func(e *audit.Entry) *string { return &e.Actor }, func(e *audit.Entry) *string { return &e.ActorType }},
		{func(e *audit.Entry) *string { return &e.ActorType }, func(e *audit.Entry) *string { return &e.Event }},
		{func(e *audit.Entry) *string { return &e.Event }, func(e *audit.Entry) *string { return &e.Subject }},
		{func(e *audit.Entry) *string { return &e.Subject }, func(e *audit.Entry) *string { return &e.BeforeHash }},
		{func(e *audit.Entry) *string { return &e.BeforeHash }, func(e *audit.Entry) *string { return &e.AfterHash }},
		{func(e *audit.Entry) *string { return &e.AfterHash }, func(e *audit.Entry) *string { return &e.Detail }},
	}
	for i, pair := range pairs {
		left := audit.Entry{}
		right := audit.Entry{}
		*pair[0](&left), *pair[1](&left) = "ab", "c"
		*pair[0](&right), *pair[1](&right) = "a", "bc"
		if a, b := sealOn(t, audit.Entry{}, left), sealOn(t, audit.Entry{}, right); a.Hash == b.Hash {
			t.Errorf("pair %d: moving a character between neighbouring fields left the hash unchanged", i)
		}
	}
}

// The canonical form escapes strings but must not confuse different strings:
// quotes, backslashes and JSON-looking text in a value cannot forge another
// entry's hash.
func TestSeal_InjectionLookingValuesStayDistinct(t *testing.T) {
	a := sampleEntry(1)
	a.Detail = `x","prev_hash":"` + audit.Genesis
	b := sampleEntry(1)
	b.Detail = "x"
	ha, hb := sealOn(t, audit.Entry{}, a).Hash, sealOn(t, audit.Entry{}, b).Hash
	if ha == hb {
		t.Error("a detail that mimics JSON syntax hashed like the plain one")
	}
}

// Spec: "Changing ANY single field of ANY entry breaks verification." Strings
// that differ only in bytes that are not valid UTF-8 are different strings. An
// implementation that re-encodes through a lossy JSON step would hash
// "\xff" and "\xfe" (and U+FFFD) alike. Rejecting such input with an error is
// acceptable; silently aliasing distinct values is not.
func TestSeal_DistinctInvalidUTF8ValuesDoNotCollide(t *testing.T) {
	values := []string{"a\xffb", "a\xfeb", "a" + string(rune(0xfffd)) + "b", "a?b"}
	seen := map[string]string{}
	for _, v := range values {
		e := sampleEntry(1)
		e.Detail = v
		sealed, err := audit.Seal(audit.Entry{}, e)
		if err != nil {
			continue
		}
		if other, dup := seen[sealed.Hash]; dup {
			t.Errorf("details %q and %q produced the same hash %s", other, v, sealed.Hash)
		}
		seen[sealed.Hash] = v
	}
}

// Spec (RFC 8785): numbers are IEEE 754 doubles, so integers above 2^53 lose
// precision when canonicalised. Two entries whose Seq differ only above 2^53
// must not silently share a hash; refusing to seal them is acceptable. (The
// catalog never produces such a Seq, and Verify would reject it, so this is a
// defence-in-depth check.)
func TestSeal_SeqsBeyondDoublePrecisionDoNotCollide(t *testing.T) {
	const twoTo53 = int64(1) << 53
	a, b := sampleEntry(1), sampleEntry(1)
	a.Seq, b.Seq = twoTo53, twoTo53+1
	sealedA, errA := audit.Seal(audit.Entry{}, a)
	sealedB, errB := audit.Seal(audit.Entry{}, b)
	if errA != nil || errB != nil {
		return
	}
	if sealedA.Hash == sealedB.Hash {
		t.Errorf("seq %d and seq %d produce the same hash %s", a.Seq, b.Seq, sealedA.Hash)
	}
}

// Spec: "Seq must lie in [-2^53, 2^53-1]". Both ends are accepted, one beyond
// each end is refused, and the accepted extremes hash differently from their
// neighbours. A mutant that moved either bound by one survived the earlier
// tests; this pins them.
func TestSeal_SeqBoundaries(t *testing.T) {
	const twoTo53 = int64(1) << 53
	accepted := []int64{-twoTo53, -twoTo53 + 1, -1, 0, 1, twoTo53 - 2, twoTo53 - 1}
	hashes := map[string]int64{}
	for _, seq := range accepted {
		e := sampleEntry(1)
		e.Seq = seq
		sealed, err := audit.Seal(audit.Entry{}, e)
		if err != nil {
			t.Errorf("Seal(seq %d) = %v, want accepted", seq, err)
			continue
		}
		if other, dup := hashes[sealed.Hash]; dup {
			t.Errorf("seq %d and seq %d share hash %s", other, seq, sealed.Hash)
		}
		hashes[sealed.Hash] = seq
	}
	refused := []int64{-twoTo53 - 1, twoTo53, math.MinInt64, math.MaxInt64}
	for _, seq := range refused {
		e := sampleEntry(1)
		e.Seq = seq
		if sealed, err := audit.Seal(audit.Entry{}, e); err == nil {
			t.Errorf("Seal(seq %d) accepted with hash %s, want a refusal", seq, sealed.Hash)
		} else if sealed != (audit.Entry{}) {
			t.Errorf("Seal(seq %d) returned a non-zero entry alongside the error", seq)
		}
	}
}

// Verify applies the same bound: an entry sealed by other means with a Seq the
// canonical form cannot hold is reported as broken at that entry.
func TestVerify_RefusesSeqBeyondTheBound(t *testing.T) {
	const twoTo53 = int64(1) << 53
	chain := buildChain(t, 2)
	chain[1].Seq = twoTo53
	err := audit.Verify(chain)
	if err == nil {
		t.Fatal("Verify accepted a chain whose second entry has seq 2^53")
	}
}

// The hash is a function of the entry, not of the slice it lives in.
func TestSeal_DoesNotDependOnCallOrder(t *testing.T) {
	first := sealOn(t, audit.Entry{}, sampleEntry(1))
	_ = sealOn(t, first, sampleEntry(2)) // an unrelated Seal in between
	again := sealOn(t, audit.Entry{}, sampleEntry(1))
	if first != again {
		t.Errorf("Seal depends on earlier calls: %+v vs %+v", first, again)
	}
}
