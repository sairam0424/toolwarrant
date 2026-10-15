package trust

import (
	"testing"

	"github.com/sairam0424/toolwarrant/internal/signing"
	"github.com/sairam0424/toolwarrant/internal/signing/sigtest"
)

// A signature that verifies is not authorisation (finding 6): carol's key
// signs a decision that signing.Verify accepts, and the list that names alice
// and bob gives it no name, so Lookup finds nobody and Authorize is
// ErrUnauthorizedSigner for carol as for any actor; a listed key is authorised
// for its own name only.
func TestAuthorize_ValidKeyNotInTheListIsNotAuthorization(t *testing.T) {
	t.Parallel()
	a, b, c := sigtest.GenerateEd25519(t), sigtest.GenerateEd25519(t), sigtest.GenerateEd25519(t)
	r := mustValidate(t, listOf(1, named{"alice", a}, named{"bob", b}))
	d := signing.Decision{
		Actor: "carol", Catalog: sampleCatalog, Digest: sampleDigest, Kind: signing.KindApprove,
		PrevHead: samplePrevHead, Server: "mock", SignedAt: sampleTime(), Signer: fp(c), Tool: "echo",
	}
	payload, err := signing.MarshalDecision(d)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := signing.Sign(t.Context(), payload, c.Signer, signing.NamespaceDecision)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := signing.Verify(rec.Payload, rec.Signature, signing.NamespaceDecision, rec.Signer)
	if err != nil {
		t.Fatalf("the signature is valid by construction: %v", err)
	}
	signer := signing.Fingerprint(pub)
	if name, ok := r.Lookup(signer); ok || name != "" {
		t.Errorf("Lookup of the unlisted key = %q, %t", name, ok)
	}
	for _, actor := range []string{"carol", "alice", "bob"} {
		wantErrIs(t, "unlisted key as "+actor, r.Authorize(signer, actor), ErrUnauthorizedSigner, signer)
	}
	if err := r.Authorize(fp(a), "alice"); err != nil {
		t.Errorf("alice's key as alice: %v", err)
	}
	if err := r.Authorize(fp(b), "bob"); err != nil {
		t.Errorf("bob's key as bob: %v", err)
	}
	if name, ok := r.Lookup(fp(b)); !ok || name != "bob" {
		t.Errorf("Lookup(bob's key) = %q, %t", name, ok)
	}
}

// A listed key used under another operator's name is refused naming both
// people, so the audit never carries a name the key does not back (O-13); the
// actor is normalised as the stored actor was, and a spelling D7 refuses is
// ErrName before any lookup.
func TestAuthorize_AnotherOperatorsKeyIsNamed(t *testing.T) {
	t.Parallel()
	a, b := sigtest.GenerateEd25519(t), sigtest.GenerateEd25519(t)
	r := mustValidate(t, listOf(1, named{"alice", a}, named{"bob", b}))
	err := r.Authorize(fp(b), "alice")
	wantErrIs(t, "bob's key as alice", err, ErrAnotherOperatorsKey, `"bob"`)
	wantErrIs(t, "bob's key as alice names alice", err, ErrAnotherOperatorsKey, `"alice"`)
	wantErrIs(t, "bob's key as alice names the key", err, ErrAnotherOperatorsKey, fp(b))
	wantErrIs(t, "alice's key as bob", r.Authorize(fp(a), "bob"), ErrAnotherOperatorsKey, "")
	if err := r.Authorize(fp(a), "Alice"); err != nil {
		t.Errorf("a case spelling of the same identity: %v", err)
	}
	if err := r.Authorize(fp(a), cp(fullA)+"lice"); err != nil {
		t.Errorf("a full-width spelling of the same identity: %v", err)
	}
	wantErrIs(t, "a name with an invisible character", r.Authorize(fp(a), "al"+cp(zwsp)+"ice"), ErrName, "")
	wantErrIs(t, "an empty actor", r.Authorize(fp(a), ""), ErrName, "")
	wantErrIs(t, "an empty fingerprint", r.Authorize("", "alice"), ErrUnauthorizedSigner, "")
}
