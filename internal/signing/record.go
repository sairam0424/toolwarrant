package signing

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"

	"github.com/sairam0424/toolwarrant/internal/gate"
)

// Namespace is the sshsig namespace a record is signed under. Only the
// constants below are accepted by Sign and Verify; a caller cannot pass a
// string, so no record can be verified under an empty or borrowed namespace.
type Namespace string

const (
	// NamespaceDecision signs a TypeDecision payload.
	NamespaceDecision Namespace = "decision@toolwarrant.invalid"
	// NamespaceTrust signs a TypeTrustList payload.
	NamespaceTrust Namespace = "trust@toolwarrant.invalid"
	// NamespaceHead is reserved for the head log of a later release; nothing
	// in v0.4 writes it. It is in the closed set so the records of v0.4 need
	// no change when it arrives.
	NamespaceHead Namespace = "head@toolwarrant.invalid"

	// TypeDecision is the `type` inside a decision payload.
	TypeDecision = "toolwarrant/decision/v1"
	// TypeTrustList is the `type` inside a trust-list payload.
	TypeTrustList = "toolwarrant/trust-list/v1"
	// TypeHead is reserved with NamespaceHead; no parser exists for it yet.
	TypeHead = "toolwarrant/head/v1"

	// HashAlgorithm is the only message hash accepted: OpenSSH's default.
	// Verify passes it explicitly, so a signature made over sha256 fails
	// cryptographically as well as by name.
	HashAlgorithm = sshsig.HashSHA512
	// RSASignatureAlgorithm is the only inner signature algorithm accepted
	// from an ssh-rsa key: OpenSSH's default for sshsig. PROTOCOL.sshsig and
	// the library admit rsa-sha2-256 as well; Verify refuses it by name. The
	// other key types have one algorithm each, which x/crypto enforces.
	RSASignatureAlgorithm = ssh.KeyAlgoRSASHA512

	// MaxPayloadBytes bounds a signed payload: a 64-signer list of RSA-4096
	// keys is about 50 KiB.
	MaxPayloadBytes = 64 << 10
	// MaxSignatureBytes bounds the sshsig wire blob; an RSA-4096 signature
	// with its embedded key is about 1.1 KiB.
	MaxSignatureBytes = 4 << 10
	// MaxArmoredSignatureBytes bounds the PEM form Unarmor reads: the blob
	// bound at four thirds plus the PEM frame, rounded up.
	MaxArmoredSignatureBytes = 8 << 10
	// MaxKeyFileBytes bounds a private or public key file this package opens.
	// It is this package's own bound; export.MaxKeyFileBytes stays 8 KiB.
	MaxKeyFileBytes = 16 << 10
	// MinRSABits is the smallest ssh-rsa modulus accepted.
	MinRSABits = 3072
	// MaxSigners bounds the operators one trust list may name.
	MaxSigners = 64
	// MaxSocketPathBytes is the shortest sun_path of the release platforms
	// (104 on darwin, including the terminating byte); an agent socket path
	// must be shorter than it.
	MaxSocketPathBytes = 104
	// AgentTimeout bounds the dial of ssh-agent and the listing of its keys;
	// a Sign call takes the caller's context instead.
	AgentTimeout = 5 * time.Second

	// fingerprintPrefix and fingerprintLen pin the one form of key identity
	// this package prints: `SHA256:` and 43 unpadded base64 characters, as
	// `ssh-keygen -l` prints it.
	fingerprintPrefix = "SHA256:"
	fingerprintLen    = len(fingerprintPrefix) + 43
	hexDigestLen      = sha256.Size * 2
)

var (
	// ErrNamespace is returned when a namespace is not one of the constants.
	ErrNamespace = errors.New("signing: namespace is not one this package signs under")
	// ErrNamespaceMismatch is returned when a signature was made under another
	// namespace than the one it is verified under (cross-protocol replay).
	ErrNamespaceMismatch = errors.New("signing: signature was made under another namespace")
	// ErrNotTheExpectedKey is returned when the key inside a signature is not
	// the one the record names; it is checked before the cryptography.
	ErrNotTheExpectedKey = errors.New("signing: signature was made with another key than the record names")
	// ErrHashAlgorithm is returned when a signature hashes with anything but
	// HashAlgorithm.
	ErrHashAlgorithm = errors.New("signing: signature hashes the message with another algorithm than sha512")
	// ErrSignatureAlgorithm is returned when an ssh-rsa signature was made with
	// another algorithm than RSASignatureAlgorithm.
	ErrSignatureAlgorithm = errors.New("signing: ssh-rsa signature was made with another algorithm than rsa-sha2-512")
	// ErrSignatureFormat is returned when the blob is not an sshsig signature.
	ErrSignatureFormat = errors.New("signing: not an sshsig signature")
	// ErrSignature is returned when the cryptographic check fails.
	ErrSignature = errors.New("signing: signature does not verify")
	// ErrSignerOutput is returned by Sign when the signer handed back a
	// signature that does not verify under its own key, so a faulty or hostile
	// agent cannot make the caller store it.
	ErrSignerOutput = errors.New("signing: the signer returned a signature that does not verify; nothing stored")
	// ErrPayload is returned when a payload is empty, oversized, not UTF-8, not
	// canonical or not the object shape of its type.
	ErrPayload = errors.New("signing: payload is not a canonical record")
)

// Record is one signed payload as the catalog stores it: the exact bytes that
// were signed, the sshsig wire blob, and the SHA256: fingerprint of the key
// that signed, which the trust list resolves to a person.
type Record struct {
	Payload   []byte
	Signature []byte
	Signer    string
}

// check refuses any namespace that is not one of the constants.
func (n Namespace) check() error {
	switch n {
	case NamespaceDecision, NamespaceTrust, NamespaceHead:
		return nil
	}
	return fmt.Errorf("%w: %s", ErrNamespace, strconv.Quote(string(n)))
}

// contextBinder is implemented by a signer whose I/O can be bounded by a
// context: Sign binds the caller's context for the duration of the call and
// releases it after.
type contextBinder interface {
	bindContext(ctx context.Context) (release func())
}

// Sign signs payload under ns with key and returns the record, after checking
// the key against the policy and the signature against the key. The context
// bounds an agent's answer (the CLI's --sign-timeout); a key file signs at
// once. A signer that returns garbage, as a hostile agent might, is caught by
// the Verify of the output and nothing is returned.
func Sign(ctx context.Context, payload []byte, key ssh.Signer, ns Namespace) (Record, error) {
	if err := ns.check(); err != nil {
		return Record{}, err
	}
	if err := checkPayloadBounds(payload); err != nil {
		return Record{}, err
	}
	if key == nil {
		return Record{}, errors.New("signing: no signing key")
	}
	pub := key.PublicKey()
	if err := CheckKeyPolicy(pub); err != nil {
		return Record{}, err
	}
	fp := Fingerprint(pub)
	if b, ok := key.(contextBinder); ok {
		defer b.bindContext(ctx)()
	}
	if err := ctx.Err(); err != nil {
		return Record{}, fmt.Errorf("signing: sign with %s: %w", fp, err)
	}
	sig, err := sshsig.Sign(bytes.NewReader(payload), key, HashAlgorithm, string(ns))
	if err != nil {
		if cerr := deadlineError(ctx, err); cerr != nil {
			return Record{}, fmt.Errorf("signing: sign with %s: %w (%v)", fp, cerr, err)
		}
		return Record{}, fmt.Errorf("signing: sign with %s: %w", fp, err)
	}
	blob := sig.Marshal()
	if len(blob) > MaxSignatureBytes {
		return Record{}, fmt.Errorf("%w: %d bytes, more than %d", ErrSignerOutput, len(blob), MaxSignatureBytes)
	}
	if _, err := Verify(payload, blob, ns, fp); err != nil {
		return Record{}, fmt.Errorf("%w: %w", ErrSignerOutput, err)
	}
	return Record{Payload: bytes.Clone(payload), Signature: blob, Signer: fp}, nil
}

// Verify checks that sig is an sshsig signature over exactly payload under ns,
// made with the key whose fingerprint is signer, and returns that key. The
// order is fixed: bounds, blob shape, key policy, fingerprint, hash algorithm,
// the RSA signature algorithm, namespace, then the cryptography, so a refusal
// names the first rule broken and no signature from a weak or unexpected key
// reaches the verifier.
func Verify(payload, sig []byte, ns Namespace, signer string) (ssh.PublicKey, error) {
	if err := ns.check(); err != nil {
		return nil, err
	}
	if err := checkPayloadBounds(payload); err != nil {
		return nil, err
	}
	parsed, err := parseSignature(sig)
	if err != nil {
		return nil, err
	}
	if err := CheckKeyPolicy(parsed.PublicKey); err != nil {
		return nil, err
	}
	if got := Fingerprint(parsed.PublicKey); got != signer {
		return nil, fmt.Errorf("%w: made with %s, record names %s", ErrNotTheExpectedKey, got, strconv.Quote(signer))
	}
	if parsed.HashAlgorithm != HashAlgorithm {
		return nil, fmt.Errorf("%w: %s", ErrHashAlgorithm, strconv.Quote(parsed.HashAlgorithm.String()))
	}
	if parsed.PublicKey.Type() == ssh.KeyAlgoRSA && parsed.Signature.Format != RSASignatureAlgorithm {
		return nil, fmt.Errorf("%w: %s, want %s", ErrSignatureAlgorithm, strconv.Quote(parsed.Signature.Format), RSASignatureAlgorithm)
	}
	if parsed.Namespace != string(ns) {
		return nil, fmt.Errorf("%w: %s, verifying under %s", ErrNamespaceMismatch, strconv.Quote(parsed.Namespace), ns)
	}
	if err := sshsig.Verify(bytes.NewReader(payload), parsed, parsed.PublicKey, HashAlgorithm, string(ns)); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignature, err)
	}
	return parsed.PublicKey, nil
}

// parseSignature bounds and parses an sshsig wire blob.
func parseSignature(sig []byte) (*sshsig.Signature, error) {
	if len(sig) == 0 {
		return nil, fmt.Errorf("%w: empty", ErrSignatureFormat)
	}
	if len(sig) > MaxSignatureBytes {
		return nil, fmt.Errorf("%w: %d bytes, more than %d", ErrSignatureFormat, len(sig), MaxSignatureBytes)
	}
	parsed, err := sshsig.ParseSignature(sig)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignatureFormat, err)
	}
	return parsed, nil
}

// checkPayloadBounds refuses an empty or oversized payload before anything
// hashes it.
func checkPayloadBounds(payload []byte) error {
	if len(payload) == 0 {
		return fmt.Errorf("%w: empty", ErrPayload)
	}
	if len(payload) > MaxPayloadBytes {
		return fmt.Errorf("%w: %d bytes, more than %d", ErrPayload, len(payload), MaxPayloadBytes)
	}
	return nil
}

// recordView is the document RecordDigest hashes; the keys sort as written.
type recordView struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
	Signer    string `json:"signer"`
}

// RecordDigest is the `sigref` token an audit entry carries: the lower-case
// hex SHA-256 of the RFC 8785 form of {"payload","signature","signer"} with the
// two byte fields in standard base64. The entry's hash, and through it the
// chain, commits to the exact record, so a row swapped under an entry no
// longer matches what the chain verified.
func RecordDigest(r Record) string {
	view := recordView{
		Payload:   base64.StdEncoding.EncodeToString(r.Payload),
		Signature: base64.StdEncoding.EncodeToString(r.Signature),
		Signer:    r.Signer,
	}
	raw, err := json.Marshal(view)
	if err != nil {
		// Three strings cannot fail to marshal; a change that made them
		// would be a programming error, not an input.
		panic("signing: marshal record view: " + err.Error())
	}
	canon, err := gate.Canonical(raw)
	if err != nil {
		panic("signing: canonicalise record view: " + err.Error())
	}
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:])
}

// Fingerprint is the one key identity this package prints: `SHA256:` and the
// unpadded base64 of the SHA-256 of the key's wire form, as `ssh-keygen -l`
// prints it.
func Fingerprint(pub ssh.PublicKey) string {
	return ssh.FingerprintSHA256(pub)
}

// Armor renders an sshsig wire blob as the PEM block `ssh-keygen -Y verify`
// reads (`-----BEGIN SSH SIGNATURE-----`). The blob is parsed first, so an
// invalid one is refused rather than framed.
func Armor(sig []byte) ([]byte, error) {
	if _, err := parseSignature(sig); err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: sshsig.PEMType, Bytes: sig}), nil
}

// Unarmor reads one PEM block of type SSH SIGNATURE, as ssh-keygen writes it,
// and returns the wire blob after parsing it. Headers, a second block or
// trailing text are refused; the library's Unarmor would ignore them.
func Unarmor(armored []byte) ([]byte, error) {
	if len(armored) > MaxArmoredSignatureBytes {
		return nil, fmt.Errorf("%w: armored form is %d bytes, more than %d", ErrSignatureFormat, len(armored), MaxArmoredSignatureBytes)
	}
	block, rest := pem.Decode(armored)
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block", ErrSignatureFormat)
	}
	if block.Type != sshsig.PEMType {
		return nil, fmt.Errorf("%w: PEM type %s, want %s", ErrSignatureFormat, strconv.Quote(block.Type), sshsig.PEMType)
	}
	if len(block.Headers) != 0 {
		return nil, fmt.Errorf("%w: PEM block carries headers", ErrSignatureFormat)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("%w: data after the PEM block", ErrSignatureFormat)
	}
	if _, err := parseSignature(block.Bytes); err != nil {
		return nil, err
	}
	return block.Bytes, nil
}
