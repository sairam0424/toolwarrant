package signing

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/sairam0424/toolwarrant/internal/signing/sigtest"
)

// The constants are the contract every later PR and every operator document
// reuses; a change to one is a format change and must be deliberate.
func TestConstants_PinTheNamespacesTypesAndBounds(t *testing.T) {
	t.Parallel()
	pins := map[string]struct{ got, want any }{
		"NamespaceDecision":        {string(NamespaceDecision), "decision@toolwarrant.invalid"},
		"NamespaceTrust":           {string(NamespaceTrust), "trust@toolwarrant.invalid"},
		"NamespaceHead":            {string(NamespaceHead), "head@toolwarrant.invalid"},
		"TypeDecision":             {TypeDecision, "toolwarrant/decision/v1"},
		"TypeTrustList":            {TypeTrustList, "toolwarrant/trust-list/v1"},
		"TypeHead":                 {TypeHead, "toolwarrant/head/v1"},
		"HashAlgorithm":            {HashAlgorithm, sshsig.HashSHA512},
		"RSASignatureAlgorithm":    {RSASignatureAlgorithm, "rsa-sha2-512"},
		"MaxPayloadBytes":          {MaxPayloadBytes, 64 << 10},
		"MaxSignatureBytes":        {MaxSignatureBytes, 4 << 10},
		"MaxArmoredSignatureBytes": {MaxArmoredSignatureBytes, 8 << 10},
		"MaxKeyFileBytes":          {MaxKeyFileBytes, 16 << 10},
		"MaxKeyLineBytes":          {MaxKeyLineBytes, 4 << 10},
		"MinRSABits":               {MinRSABits, 3072},
		"MaxSigners":               {MaxSigners, 64},
		"MaxSocketPathBytes":       {MaxSocketPathBytes, 104},
		"AgentTimeout":             {AgentTimeout, 5 * time.Second},
	}
	for name, p := range pins {
		if p.got != p.want {
			t.Errorf("%s = %v, want %v", name, p.got, p.want)
		}
	}
}

// A signature made under one namespace fails under the other, and neither
// Sign nor Verify takes a namespace outside the closed set: an empty one, which
// the library's Verify would accept, or git's.
func TestVerify_RefusesAnotherNamespace(t *testing.T) {
	t.Parallel()
	k := sigtest.GenerateEd25519(t)
	payload := mustMarshalDecision(t, sampleDecision(Fingerprint(k.Public)))
	r := mustSign(t, payload, k, NamespaceDecision)
	if _, err := Verify(r.Payload, r.Signature, NamespaceDecision, r.Signer); err != nil {
		t.Fatalf("Verify under the signing namespace: %v", err)
	}
	_, err := Verify(r.Payload, r.Signature, NamespaceTrust, r.Signer)
	wantErrIs(t, "trust namespace", err, ErrNamespaceMismatch, `"decision@toolwarrant.invalid", verifying under trust@toolwarrant.invalid`)
	_, err = Verify(r.Payload, r.Signature, NamespaceHead, r.Signer)
	wantErrIs(t, "head namespace", err, ErrNamespaceMismatch, "")
	for _, ns := range []Namespace{"", "git", "file", "decision@toolwarrant.invalid "} {
		_, err := Verify(r.Payload, r.Signature, ns, r.Signer)
		wantErrIs(t, "verify under "+string(ns), err, ErrNamespace, "")
		_, err = Sign(t.Context(), payload, k.Signer, ns)
		wantErrIs(t, "sign under "+string(ns), err, ErrNamespace, "")
	}
}

// The fingerprint of the embedded key is compared with the one the record
// names before the signature is looked at: a blob with another key and garbage
// for a signature is ErrNotTheExpectedKey, the same blob under its own key is
// ErrSignature.
func TestVerify_RefusesAnotherKeyBeforeLookingAtTheSignature(t *testing.T) {
	t.Parallel()
	a, b := sigtest.GenerateEd25519(t), sigtest.GenerateEd25519(t)
	payload := mustMarshalDecision(t, sampleDecision(Fingerprint(a.Public)))
	ra := mustSign(t, payload, a, NamespaceDecision)
	_, err := Verify(ra.Payload, ra.Signature, NamespaceDecision, Fingerprint(b.Public))
	wantErrIs(t, "a's signature under b's fingerprint", err, ErrNotTheExpectedKey, "made with "+Fingerprint(a.Public)+", record names \""+Fingerprint(b.Public)+"\"")
	garbage := sshsig.Signature{
		Version: 1, PublicKey: b.Public, Namespace: string(NamespaceDecision), HashAlgorithm: HashAlgorithm,
		Signature: &ssh.Signature{Format: ssh.KeyAlgoED25519, Blob: make([]byte, 64)},
	}
	blob := garbage.Marshal()
	_, err = Verify(payload, blob, NamespaceDecision, Fingerprint(a.Public))
	wantErrIs(t, "garbage from b under a's fingerprint", err, ErrNotTheExpectedKey, "")
	if errors.Is(err, ErrSignature) {
		t.Errorf("the key check did not come first: %v", err)
	}
	_, err = Verify(payload, blob, NamespaceDecision, Fingerprint(b.Public))
	wantErrIs(t, "garbage from b under b's fingerprint", err, ErrSignature, "")
	_, err = Verify(payload, blob, NamespaceDecision, "")
	wantErrIs(t, "empty expected fingerprint", err, ErrNotTheExpectedKey, "")
}

// A signature over the sha256 of the message is refused by name; passing
// sha512 to the library makes it fail cryptographically as well.
func TestVerify_RefusesASHA256Signature(t *testing.T) {
	t.Parallel()
	k := sigtest.GenerateEd25519(t)
	payload := mustMarshalDecision(t, sampleDecision(Fingerprint(k.Public)))
	sig, err := sshsig.Sign(bytes.NewReader(payload), k.Signer, sshsig.HashSHA256, string(NamespaceDecision))
	if err != nil {
		t.Fatal(err)
	}
	_, err = Verify(payload, sig.Marshal(), NamespaceDecision, Fingerprint(k.Public))
	wantErrIs(t, "sha256 signature", err, ErrHashAlgorithm, `"sha256"`)
	if err := sshsig.Verify(bytes.NewReader(payload), sig, k.Public, HashAlgorithm, string(NamespaceDecision)); err == nil {
		t.Error("the library verified a sha256 signature under sha512")
	}
}

// An ssh-rsa signature whose inner algorithm is rsa-sha2-256 is refused by
// name although the message hash is sha512: PROTOCOL.sshsig admits both RSA
// algorithms and so does the library, whose Verify accepts the very blob; the
// trust root of section 1 of the plan is rsa-sha2-512 only, and Sign writes
// nothing else. The same key signing rsa-sha2-512 by hand verifies.
func TestVerify_RefusesAnRsaSha2256Signature(t *testing.T) {
	t.Parallel()
	k := sigtest.GenerateRSA(t, MinRSABits)
	payload := mustMarshalDecision(t, sampleDecision(Fingerprint(k.Public)))
	sha256Blob := wireBlob(t, payload, k, NamespaceDecision, "", ssh.KeyAlgoRSASHA256)
	_, err := Verify(payload, sha256Blob, NamespaceDecision, Fingerprint(k.Public))
	wantErrIs(t, "rsa-sha2-256 signature", err, ErrSignatureAlgorithm, `"rsa-sha2-256", want rsa-sha2-512`)
	parsed, err := sshsig.ParseSignature(sha256Blob)
	if err != nil {
		t.Fatal(err)
	}
	if err := sshsig.Verify(bytes.NewReader(payload), parsed, k.Public, HashAlgorithm, string(NamespaceDecision)); err != nil {
		t.Errorf("the library refused the rsa-sha2-256 signature itself (%v); the pin above would then be redundant", err)
	}
	sha512Blob := wireBlob(t, payload, k, NamespaceDecision, "", ssh.KeyAlgoRSASHA512)
	if _, err := Verify(payload, sha512Blob, NamespaceDecision, Fingerprint(k.Public)); err != nil {
		t.Errorf("rsa-sha2-512 signature by hand: %v", err)
	}
}

// A blob is accepted only as the exact bytes its parse re-marshals to. The
// wire reserved string, which ssh-keygen and the library write empty and the
// library's Signature type drops without a check, is the one field that could
// vary: a blob with reserved set verifies under the library and has another
// RecordDigest, so one signature would have unboundedly many byte forms; here
// it is ErrSignatureFormat, from Verify and from Armor alike.
func TestVerify_RefusesANonCanonicalSignatureEncoding(t *testing.T) {
	t.Parallel()
	k := sigtest.GenerateEd25519(t)
	fp := Fingerprint(k.Public)
	payload := mustMarshalDecision(t, sampleDecision(fp))
	canonical := wireBlob(t, payload, k, NamespaceDecision, "", ssh.KeyAlgoED25519)
	if _, err := Verify(payload, canonical, NamespaceDecision, fp); err != nil {
		t.Fatalf("the hand-built canonical blob: %v", err)
	}
	variant := wireBlob(t, payload, k, NamespaceDecision, "anything-at-all", ssh.KeyAlgoED25519)
	_, err := Verify(payload, variant, NamespaceDecision, fp)
	wantErrIs(t, "non-empty reserved", err, ErrSignatureFormat, "canonical encoding")
	if _, err := Armor(variant); !errors.Is(err, ErrSignatureFormat) {
		t.Errorf("Armor of the variant: %v", err)
	}
	parsed, err := sshsig.ParseSignature(variant)
	if err != nil {
		t.Fatal(err)
	}
	if err := sshsig.Verify(bytes.NewReader(payload), parsed, k.Public, HashAlgorithm, string(NamespaceDecision)); err != nil {
		t.Errorf("the library refused the variant itself (%v); the check above would then be redundant", err)
	}
	if RecordDigest(Record{Payload: payload, Signature: canonical, Signer: fp}) == RecordDigest(Record{Payload: payload, Signature: variant, Signer: fp}) {
		t.Error("the two byte forms of one signature share a digest")
	}
}

// Every single-bit change to the payload fails the cryptographic check, and
// every single-bit change to the signature blob fails somewhere: the shape,
// the key, the namespace, the hash name or the cryptography.
func TestVerify_RefusesAFlippedPayloadByteAndAFlippedSignatureByte(t *testing.T) {
	t.Parallel()
	k := sigtest.GenerateEd25519(t)
	payload := mustMarshalDecision(t, sampleDecision(Fingerprint(k.Public)))
	r := mustSign(t, payload, k, NamespaceDecision)
	for i := range r.Payload {
		if _, err := Verify(flipByte(r.Payload, i), r.Signature, NamespaceDecision, r.Signer); !errors.Is(err, ErrSignature) {
			t.Fatalf("payload byte %d flipped: error %v, want ErrSignature", i, err)
		}
	}
	for i := range r.Signature {
		if _, err := Verify(r.Payload, flipByte(r.Signature, i), NamespaceDecision, r.Signer); err == nil {
			t.Fatalf("signature byte %d flipped: verified", i)
		}
	}
	if _, err := Verify(r.Payload, r.Signature, NamespaceDecision, r.Signer); err != nil {
		t.Fatalf("the unflipped record: %v", err)
	}
}

// garbageAgent lists a key and answers every Sign with zeros, as a faulty or
// hostile agent would.
type garbageAgent struct {
	agent.Agent
	key sigtest.Key
}

func (g garbageAgent) List() ([]*agent.Key, error) {
	return []*agent.Key{{Format: g.key.Public.Type(), Blob: g.key.Public.Marshal()}}, nil
}

func (g garbageAgent) Sign(ssh.PublicKey, []byte) (*ssh.Signature, error) {
	return &ssh.Signature{Format: g.key.Public.Type(), Blob: make([]byte, 64)}, nil
}

// Sign verifies the agent's answer under the key's own public half before
// returning it: an agent that answers with garbage yields ErrSignerOutput and
// no record.
func TestSign_VerifiesTheAgentsSignatureBeforeReturningIt(t *testing.T) {
	t.Parallel()
	k := sigtest.GenerateEd25519(t)
	sock := sigtest.Serve(t, garbageAgent{key: k})
	a, err := OpenAgent(t.Context(), sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	key, err := a.SignerFor(k.Public)
	if err != nil {
		t.Fatal(err)
	}
	payload := mustMarshalDecision(t, sampleDecision(Fingerprint(k.Public)))
	r, err := Sign(t.Context(), payload, key, NamespaceDecision)
	wantErrIs(t, "garbage agent", err, ErrSignerOutput, "nothing stored")
	if !errors.Is(err, ErrSignature) {
		t.Errorf("the refusal does not name the failed check: %v", err)
	}
	if r.Signature != nil || r.Payload != nil || r.Signer != "" {
		t.Errorf("a record was returned: %+v", r)
	}
}

// The sigref is the hex SHA-256 of the canonical {"payload","signature",
// "signer"} document with base64 fields; equal records agree, a change to
// any of the three changes it.
func TestRecordDigest_ChangesWithPayloadSignatureOrSigner(t *testing.T) {
	t.Parallel()
	k := sigtest.GenerateEd25519(t)
	payload := mustMarshalDecision(t, sampleDecision(Fingerprint(k.Public)))
	r := mustSign(t, payload, k, NamespaceDecision)
	doc := `{"payload":"` + base64.StdEncoding.EncodeToString(r.Payload) +
		`","signature":"` + base64.StdEncoding.EncodeToString(r.Signature) +
		`","signer":"` + r.Signer + `"}`
	sum := sha256.Sum256([]byte(doc))
	if got := RecordDigest(r); got != hex.EncodeToString(sum[:]) || len(got) != 64 {
		t.Errorf("RecordDigest = %s, want the hex SHA-256 of %s", got, doc)
	}
	if RecordDigest(r) != RecordDigest(Record{Payload: bytes.Clone(r.Payload), Signature: bytes.Clone(r.Signature), Signer: r.Signer}) {
		t.Error("equal records have different digests")
	}
	base := RecordDigest(r)
	variants := map[string]Record{
		"payload":   {Payload: flipByte(r.Payload, 0), Signature: r.Signature, Signer: r.Signer},
		"signature": {Payload: r.Payload, Signature: flipByte(r.Signature, 0), Signer: r.Signer},
		"signer":    {Payload: r.Payload, Signature: r.Signature, Signer: strings.Replace(r.Signer, "SHA256:", "SHA256;", 1)},
		"empty":     {},
	}
	for label, v := range variants {
		if RecordDigest(v) == base {
			t.Errorf("%s changed and the digest did not", label)
		}
	}
}

// Armor frames a valid blob as the PEM block ssh-keygen reads and Unarmor
// takes back exactly that. Text before the block (a junk line, a bare newline,
// one space: ssh-keygen's dearmor compares the header at offset 0 and says
// "Couldn't parse signature: missing header"), headers, trailing text, another
// PEM type, a second block, an invalid blob and an oversized input are refused.
func TestUnarmor_RefusesWhatSshKeygenWouldNotWrite(t *testing.T) {
	t.Parallel()
	k := sigtest.GenerateEd25519(t)
	r := mustSign(t, mustMarshalDecision(t, sampleDecision(Fingerprint(k.Public))), k, NamespaceDecision)
	armored, err := Armor(r.Signature)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(armored, []byte("-----BEGIN SSH SIGNATURE-----\n")) {
		t.Errorf("armored form begins %q", armored[:30])
	}
	back, err := Unarmor(armored)
	if err != nil || !bytes.Equal(back, r.Signature) {
		t.Fatalf("Unarmor(Armor(sig)) = %x, %v", back, err)
	}
	if _, err := Armor([]byte("not a signature")); !errors.Is(err, ErrSignatureFormat) {
		t.Errorf("Armor of garbage: %v", err)
	}
	cases := map[string][]byte{
		"headers":         bytes.Replace(armored, []byte("-----\n"), []byte("-----\nComment: x\n\n"), 1),
		"trailing text":   append(bytes.Clone(armored), []byte("trailing\n")...),
		"second block":    append(bytes.Clone(armored), armored...),
		"other type":      bytes.ReplaceAll(armored, []byte("SSH SIGNATURE"), []byte("PUBLIC KEY")),
		"no block":        []byte("plain text"),
		"invalid blob":    []byte("-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n"),
		"oversized":       append(bytes.Clone(armored), bytes.Repeat([]byte("x"), MaxArmoredSignatureBytes)...),
		"garbage prefix":  append([]byte("junk\n"), armored...),
		"leading newline": append([]byte("\n"), armored...),
		"leading space":   append([]byte(" "), armored...),
	}
	for label, in := range cases {
		if _, err := Unarmor(in); !errors.Is(err, ErrSignatureFormat) {
			t.Errorf("%s: error %v, want ErrSignatureFormat", label, err)
		}
	}
}

// Sign and Verify refuse an empty or oversized payload and an empty or
// oversized signature before anything is hashed.
func TestSignAndVerify_RefuseOutOfBoundsInputs(t *testing.T) {
	t.Parallel()
	k := sigtest.GenerateEd25519(t)
	big := bytes.Repeat([]byte("x"), MaxPayloadBytes+1)
	_, err := Sign(t.Context(), nil, k.Signer, NamespaceDecision)
	wantErrIs(t, "sign empty", err, ErrPayload, "empty")
	_, err = Sign(t.Context(), big, k.Signer, NamespaceDecision)
	wantErrIs(t, "sign oversized", err, ErrPayload, "more than")
	_, err = Sign(t.Context(), []byte("x"), nil, NamespaceDecision)
	if err == nil {
		t.Error("sign with no key: no error")
	}
	r := mustSign(t, []byte(`{"any":"bytes"}`), k, NamespaceHead)
	_, err = Verify(nil, r.Signature, NamespaceHead, r.Signer)
	wantErrIs(t, "verify empty payload", err, ErrPayload, "")
	_, err = Verify(r.Payload, nil, NamespaceHead, r.Signer)
	wantErrIs(t, "verify empty signature", err, ErrSignatureFormat, "empty")
	_, err = Verify(r.Payload, bytes.Repeat([]byte("x"), MaxSignatureBytes+1), NamespaceHead, r.Signer)
	wantErrIs(t, "verify oversized signature", err, ErrSignatureFormat, "more than")
}
