package trust

import (
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/signing"
	"github.com/sairam0424/toolwarrant/internal/signing/sigtest"
)

// Validate returns the names in canonical form ("Bob" becomes "bob", a
// full-width spelling becomes ASCII) and in list order with each key's
// fingerprint; two entries whose names agree after normalisation are a
// duplicate name, and two entries holding one key under two names are a
// duplicate key, each refused naming both positions (finding 9).
func TestRecord_ValidateNormalisesNamesAndRefusesDuplicateNamesAndKeys(t *testing.T) {
	t.Parallel()
	a, b, c := sigtest.GenerateEd25519(t), sigtest.GenerateEd25519(t), sigtest.GenerateEd25519(t)
	r := mustValidate(t, listOf(1, named{"alice", a}, named{"Bob", b}, named{cp(0xFF23) + "arol", c}))
	want := []Operator{
		{Name: "alice", Key: signing.MarshalKey(a.Public), Fingerprint: fp(a)},
		{Name: "bob", Key: signing.MarshalKey(b.Public), Fingerprint: fp(b)},
		{Name: "carol", Key: signing.MarshalKey(c.Public), Fingerprint: fp(c)},
	}
	if !reflect.DeepEqual(r.Signers, want) || r.Version != 1 || r.Threshold != 1 {
		t.Errorf("Validate = %+v, want signers %+v at version 1, threshold 1", r, want)
	}
	for label, dup := range map[string]signing.TrustList{
		"same spelling":         listOf(1, named{"alice", a}, named{"alice", b}),
		"case":                  listOf(1, named{"alice", a}, named{"Alice", b}),
		"full-width":            listOf(1, named{"alice", a}, named{cp(fullA) + "lice", b}),
		"ligature":              listOf(1, named{"fiona", a}, named{cp(fiLigat) + "ona", b}),
		"one key two names":     listOf(1, named{"alice", a}, named{"bob", a}),
		"one key two names far": listOf(1, named{"alice", a}, named{"bob", b}, named{"carol", a}),
	} {
		_, err := Validate(dup)
		wantErrIs(t, label, err, ErrList, "signers[")
		if !strings.Contains(err.Error(), "both") {
			t.Errorf("%s: error %v does not name both positions", label, err)
		}
	}
	_, err := Validate(listOf(1, named{"alice", a}, named{"al" + cp(zwsp) + "ice", b}))
	wantErrIs(t, "an invisible character in a name", err, ErrName, "signers[1].name")
	_, err = Validate(listOf(1, named{"alice", a}, named{"", b}))
	wantErrIs(t, "an empty name", err, ErrList, "empty")
}

// A list names one to signing.MaxSigners operators: none and one over the
// bound are refused, one and exactly the bound accepted; a version below one
// is refused as well.
func TestRecord_RefusesAnEmptyListAndOneOverMaxSigners(t *testing.T) {
	t.Parallel()
	ops := make([]named, signing.MaxSigners+1)
	for i := range ops {
		ops[i] = named{"op" + strings.Repeat("x", i/26) + string(rune('a'+i%26)), sigtest.GenerateEd25519(t)}
	}
	_, err := Validate(listOf(1))
	wantErrIs(t, "no signers", err, ErrList, "1 to 64")
	_, err = Validate(listOf(1, ops...))
	wantErrIs(t, "65 signers", err, ErrList, "not 65")
	if r := mustValidate(t, listOf(1, ops[:signing.MaxSigners]...)); len(r.Signers) != signing.MaxSigners {
		t.Errorf("%d signers validated to %d", signing.MaxSigners, len(r.Signers))
	}
	if r := mustValidate(t, listOf(7, ops[0])); len(r.Signers) != 1 || r.Version != 7 {
		t.Errorf("one signer at version 7 validated to %+v", r)
	}
	_, err = Validate(listOf(0, ops[0]))
	wantErrIs(t, "version 0", err, ErrList, "below 1")
	_, err = Validate(listOf(-1, ops[0]))
	wantErrIs(t, "version -1", err, ErrList, "below 1")
}

// The threshold is one and nothing else (O-14): zero, two of two and a value
// above the list are each ErrUnsupportedThreshold, so no record of this
// release can claim a rule its verifier does not apply.
func TestRecord_RefusesAThresholdOtherThanOne(t *testing.T) {
	t.Parallel()
	a, b := sigtest.GenerateEd25519(t), sigtest.GenerateEd25519(t)
	for _, n := range []int{0, 2, 3, -1} {
		l := listOf(1, named{"alice", a}, named{"bob", b})
		l.Threshold = n
		_, err := Validate(l)
		wantErrIs(t, "threshold "+strconv.Itoa(n), err, ErrUnsupportedThreshold, "got "+strconv.Itoa(n))
	}
	if r := mustValidate(t, listOf(1, named{"alice", a}, named{"bob", b})); r.Threshold != 1 {
		t.Errorf("Threshold = %d", r.Threshold)
	}
}

// Every key must be its one canonical line and within the policy: an RSA key
// below MinRSABits is refused wrapping signing.ErrKeyPolicy, a line with a
// comment wrapping signing.ErrKeyLine; RSA at the bound and the accepted
// curves pass.
func TestRecord_RefusesAKeyOutsideThePolicyAndANonCanonicalKeyLine(t *testing.T) {
	t.Parallel()
	a := sigtest.GenerateEd25519(t)
	weak := sigtest.GenerateRSA(t, 2048)
	_, err := Validate(listOf(1, named{"alice", a}, named{"bob", weak}))
	wantErrIs(t, "RSA 2048", err, ErrList, "signers[1].key")
	if !errors.Is(err, signing.ErrKeyPolicy) {
		t.Errorf("RSA 2048: error %v does not wrap signing.ErrKeyPolicy", err)
	}
	l := listOf(1, named{"alice", a})
	l.Signers[0].Key += " alice@example"
	_, err = Validate(l)
	wantErrIs(t, "a comment on the key line", err, ErrList, "signers[0].key")
	if !errors.Is(err, signing.ErrKeyLine) {
		t.Errorf("comment: error %v does not wrap signing.ErrKeyLine", err)
	}
	strong := sigtest.GenerateRSA(t, signing.MinRSABits)
	if r := mustValidate(t, listOf(1, named{"alice", a}, named{"bob", strong})); r.Signers[1].Fingerprint != fp(strong) {
		t.Errorf("RSA %d: %+v", signing.MinRSABits, r.Signers[1])
	}
}

// A Record that Validate did not produce (the zero value, or one built by
// hand with the exported fields) is refused by every rule: it names nobody,
// authorises nothing, cannot bootstrap, rotate or be rotated, folds into no
// state and renders no file.
func TestRecord_RulesRefuseARecordValidateDidNotProduce(t *testing.T) {
	t.Parallel()
	a := sigtest.GenerateEd25519(t)
	good := mustValidate(t, listOf(1, named{"alice", a}))
	forged := Record{Version: 1, Threshold: 1, Signers: []Operator{{Name: "alice", Key: signing.MarshalKey(a.Public), Fingerprint: fp(a)}}}
	for label, r := range map[string]Record{"zero": {}, "hand-built": forged} {
		if name, ok := r.Lookup(fp(a)); ok || name != "" {
			t.Errorf("%s: Lookup = %q, %t", label, name, ok)
		}
		wantErrIs(t, label+" Authorize", r.Authorize(fp(a), "alice"), ErrList, "not produced by Validate")
		wantErrIs(t, label+" CheckBootstrap", CheckBootstrap(r, fp(a), ""), ErrList, "")
		wantErrIs(t, label+" CheckRotation as prev", CheckRotation(r, good, fp(a)), ErrList, "list in force")
		two := mustValidate(t, listOf(2, named{"alice", a}))
		wantErrIs(t, label+" CheckRotation as next", CheckRotation(two, r, fp(a)), ErrList, "new list")
		_, err := State{}.Apply(1, KindBootstrap, r, fp(a), "")
		wantErrIs(t, label+" Apply", err, ErrList, "")
		if out, err := AllowedSigners(r); err == nil || out != nil {
			t.Errorf("%s: AllowedSigners = %q, %v", label, out, err)
		}
	}
}
