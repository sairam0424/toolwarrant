package trust

import (
	"testing"

	"github.com/sairam0424/toolwarrant/internal/signing/sigtest"
)

// A bootstrap is version 1 signed by one of its own keys; with a pinned root
// the signer must be that fingerprint. Version 2 as a first list, a signer the
// list does not hold and a signer other than the pinned root are each refused,
// the root refusal naming both fingerprints; an empty root is trust on first
// use.
func TestCheckBootstrap_IsSelfSignedByAListedKeyAndMatchesAPinnedRoot(t *testing.T) {
	t.Parallel()
	a, b, x := sigtest.GenerateEd25519(t), sigtest.GenerateEd25519(t), sigtest.GenerateEd25519(t)
	one := mustValidate(t, listOf(1, named{"alice", a}, named{"bob", b}))
	if err := CheckBootstrap(one, fp(a), ""); err != nil {
		t.Errorf("self-signed by alice, no root: %v", err)
	}
	if err := CheckBootstrap(one, fp(b), ""); err != nil {
		t.Errorf("self-signed by bob, no root: %v", err)
	}
	if err := CheckBootstrap(one, fp(b), fp(b)); err != nil {
		t.Errorf("self-signed by bob, root bob: %v", err)
	}
	wantErrIs(t, "signed by an unlisted key", CheckBootstrap(one, fp(x), ""), ErrNotSelfSigned, fp(x))
	wantErrIs(t, "signed by an unlisted key that is the pinned root", CheckBootstrap(one, fp(x), fp(x)), ErrNotSelfSigned, "")
	wantErrIs(t, "signed by alice under root bob", CheckBootstrap(one, fp(a), fp(b)), ErrNotThePinnedRoot, fp(a))
	wantErrIs(t, "signed by alice under root bob names the root", CheckBootstrap(one, fp(a), fp(b)), ErrNotThePinnedRoot, fp(b))
	wantErrIs(t, "a root that is not a fingerprint", CheckBootstrap(one, fp(a), "not a fingerprint"), ErrNotThePinnedRoot, "")
	wantErrIs(t, "an empty signer", CheckBootstrap(one, "", ""), ErrNotSelfSigned, "")
	two := mustValidate(t, listOf(2, named{"alice", a}))
	wantErrIs(t, "version 2 as a first list", CheckBootstrap(two, fp(a), ""), ErrBootstrapVersion, "version 2")
}

// A rotation is exactly version N+1 signed by a key of both lists: N+2 and N
// are refused as rollback (TUF 5.3.5), a signer only in the old list and one
// only in the new list are refused (TUF 5.3.4 at threshold one), a signer in
// both is accepted whether it adds, removes or renames, and the last signer
// cannot remove itself since no key would be in both lists.
func TestCheckRotation_MustBeExactlyNextVersionAndSignedByAKeyOfBothLists(t *testing.T) {
	t.Parallel()
	a, b, c := sigtest.GenerateEd25519(t), sigtest.GenerateEd25519(t), sigtest.GenerateEd25519(t)
	v1 := mustValidate(t, listOf(1, named{"alice", a}, named{"bob", b}))
	add := mustValidate(t, listOf(2, named{"alice", a}, named{"bob", b}, named{"carol", c}))
	if err := CheckRotation(v1, add, fp(a)); err != nil {
		t.Errorf("alice adds carol: %v", err)
	}
	if err := CheckRotation(v1, add, fp(b)); err != nil {
		t.Errorf("bob adds carol: %v", err)
	}
	wantErrIs(t, "carol vouches for herself (only in the new list)", CheckRotation(v1, add, fp(c)), ErrSignerNotInBothLists, "in the list in force: false, in the new list: true")

	skipped := mustValidate(t, listOf(3, named{"alice", a}, named{"bob", b}, named{"carol", c}))
	wantErrIs(t, "N+2", CheckRotation(v1, skipped, fp(a)), ErrRollback, "got version 3, the list in force is version 1")
	same := mustValidate(t, listOf(1, named{"alice", a}, named{"bob", b}, named{"carol", c}))
	wantErrIs(t, "N", CheckRotation(v1, same, fp(a)), ErrRollback, "got version 1")
	v3 := mustValidate(t, listOf(3, named{"alice", a}))
	wantErrIs(t, "N-1 (a later list rotated back)", CheckRotation(v3, add, fp(a)), ErrRollback, "")

	remove := mustValidate(t, listOf(2, named{"alice", a}))
	if err := CheckRotation(v1, remove, fp(a)); err != nil {
		t.Errorf("alice removes bob with her own key, which stays: %v", err)
	}
	wantErrIs(t, "bob removes himself (only in the old list)", CheckRotation(v1, remove, fp(b)), ErrSignerNotInBothLists, "in the list in force: true, in the new list: false")
	wantErrIs(t, "an unlisted key removes bob", CheckRotation(v1, remove, fp(c)), ErrSignerNotInBothLists, "false, in the new list: false")

	last := mustValidate(t, listOf(1, named{"alice", a}))
	handover := mustValidate(t, listOf(2, named{"bob", b}))
	wantErrIs(t, "the last signer replaces itself, signed by the leaving key", CheckRotation(last, handover, fp(a)), ErrSignerNotInBothLists, "")
	wantErrIs(t, "the last signer replaces itself, signed by the arriving key", CheckRotation(last, handover, fp(b)), ErrSignerNotInBothLists, "")
	renamed := mustValidate(t, listOf(2, named{"alicia", a}))
	if err := CheckRotation(last, renamed, fp(a)); err != nil {
		t.Errorf("a rename keeps the key in both lists: %v", err)
	}
	wantErrIs(t, "an empty signer", CheckRotation(v1, add, ""), ErrSignerNotInBothLists, "")
}
