package signing

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/sairam0424/toolwarrant/internal/gate"
	"github.com/sairam0424/toolwarrant/internal/signing/sigtest"
)

// For every accepted key type, a random payload under a random namespace signs
// and verifies, and every mutation fails: a payload byte, a signature byte,
// another namespace, another key's fingerprint.
func TestProperty_signThenVerifyHoldsForEveryKeyTypeAndRandomPayloadAndFailsForEveryMutation(t *testing.T) {
	t.Parallel()
	keys := []sigtest.Key{
		sigtest.GenerateEd25519(t),
		sigtest.GenerateECDSA(t, elliptic.P256()),
		sigtest.GenerateECDSA(t, elliptic.P384()),
		sigtest.GenerateECDSA(t, elliptic.P521()),
		sigtest.GenerateRSA(t, MinRSABits),
	}
	namespaces := []Namespace{NamespaceDecision, NamespaceTrust, NamespaceHead}
	rapid.Check(t, func(rt *rapid.T) {
		k := keys[rapid.IntRange(0, len(keys)-1).Draw(rt, "key")]
		other := keys[rapid.IntRange(0, len(keys)-1).Draw(rt, "otherKey")]
		ns := namespaces[rapid.IntRange(0, len(namespaces)-1).Draw(rt, "namespace")]
		payload := rapid.SliceOfN(rapid.Byte(), 1, 2048).Draw(rt, "payload")
		r, err := Sign(t.Context(), payload, k.Signer, ns)
		if err != nil {
			rt.Fatalf("Sign: %v", err)
		}
		if _, err := Verify(r.Payload, r.Signature, ns, r.Signer); err != nil {
			rt.Fatalf("Verify: %v", err)
		}
		if _, err := Verify(flipByte(payload, rapid.IntRange(0, len(payload)-1).Draw(rt, "payloadByte")), r.Signature, ns, r.Signer); !errors.Is(err, ErrSignature) {
			rt.Fatalf("a flipped payload byte verified or failed otherwise: %v", err)
		}
		if _, err := Verify(payload, flipByte(r.Signature, rapid.IntRange(0, len(r.Signature)-1).Draw(rt, "signatureByte")), ns, r.Signer); err == nil {
			rt.Fatal("a flipped signature byte verified")
		}
		for _, o := range namespaces {
			if o == ns {
				continue
			}
			if _, err := Verify(payload, r.Signature, o, r.Signer); !errors.Is(err, ErrNamespaceMismatch) {
				rt.Fatalf("under %s: %v", o, err)
			}
		}
		if Fingerprint(other.Public) != r.Signer {
			if _, err := Verify(payload, r.Signature, ns, Fingerprint(other.Public)); !errors.Is(err, ErrNotTheExpectedKey) {
				rt.Fatalf("under another key: %v", err)
			}
		}
	})
}

// RecordDigest is the hex SHA-256 of the canonical document of the encoded
// triple: it agrees with an independent computation, and two triples that
// differ anywhere never collide across a run.
func TestProperty_recordDigestIsInjectiveOnTheEncodedTriple(t *testing.T) {
	t.Parallel()
	seen := map[string]Record{}
	rapid.Check(t, func(rt *rapid.T) {
		r := Record{
			Payload:   rapid.SliceOfN(rapid.Byte(), 0, 64).Draw(rt, "payload"),
			Signature: rapid.SliceOfN(rapid.Byte(), 0, 64).Draw(rt, "signature"),
			Signer:    rapid.StringMatching(`SHA256:[A-Za-z0-9+/]{0,43}`).Draw(rt, "signer"),
		}
		doc, err := gate.Canonical([]byte(`{"signer":` + jsonString(r.Signer) + `,"signature":"` +
			base64.StdEncoding.EncodeToString(r.Signature) + `","payload":"` + base64.StdEncoding.EncodeToString(r.Payload) + `"}`))
		if err != nil {
			rt.Fatal(err)
		}
		sum := sha256.Sum256(doc)
		got := RecordDigest(r)
		if got != hex.EncodeToString(sum[:]) {
			rt.Fatalf("RecordDigest = %s, independent computation %x", got, sum)
		}
		if prev, ok := seen[got]; ok && (!bytes.Equal(prev.Payload, r.Payload) || !bytes.Equal(prev.Signature, r.Signature) || prev.Signer != r.Signer) {
			rt.Fatalf("collision: %+v and %+v", prev, r)
		}
		seen[got] = r
	})
}

// jsonString quotes s as a JSON string the canonicaliser accepts.
func jsonString(s string) string {
	b, _ := gate.Canonical([]byte(`"` + s + `"`))
	return string(b)
}

// Every valid decision marshals to bytes that parse back to the same
// decision, and the bytes are their own canonical form.
func TestProperty_decisionMarshalParseRoundTripForEveryValidShape(t *testing.T) {
	t.Parallel()
	fp := Fingerprint(sigtest.GenerateEd25519(t).Public)
	kinds := []Kind{KindApprove, KindReject, KindRollback, KindDisable, KindEnable, KindPause, KindResume, KindBudgetReset}
	rapid.Check(t, func(rt *rapid.T) {
		d := Decision{
			Actor:    rapid.StringMatching(`[a-z0-9][a-z0-9._@-]{0,63}`).Draw(rt, "actor"),
			Catalog:  rapid.StringMatching(`[0-9a-f]{32}`).Draw(rt, "catalog"),
			Kind:     kinds[rapid.IntRange(0, len(kinds)-1).Draw(rt, "kind")],
			PrevHead: rapid.StringMatching(`[0-9a-f]{64}`).Draw(rt, "prevHead"),
			Server:   rapid.StringMatching(`[a-z0-9]([a-z0-9-]{0,10}[a-z0-9])?`).Draw(rt, "server"),
			SignedAt: time.Unix(rapid.Int64Range(0, 4_000_000_000).Draw(rt, "signedAt"), 0).UTC(),
			Signer:   fp,
		}
		if d.Kind.NamesVersion() {
			d.Digest = rapid.StringMatching(`[0-9a-f]{64}`).Draw(rt, "digest")
		}
		if d.Kind.NamesTool() {
			d.Tool = rapid.StringMatching(`[a-z][a-z0-9_-]{0,30}`).Draw(rt, "tool")
		}
		b, err := MarshalDecision(d)
		if err != nil {
			rt.Fatalf("MarshalDecision(%+v): %v", d, err)
		}
		canon, err := gate.Canonical(b)
		if err != nil || !bytes.Equal(canon, b) {
			rt.Fatalf("not canonical: %v", err)
		}
		got, err := ParseDecision(b)
		if err != nil || got != d {
			rt.Fatalf("ParseDecision = %+v, %v; want %+v", got, err, d)
		}
	})
}
