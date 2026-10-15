package trust

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"

	"github.com/sairam0424/toolwarrant/internal/signing"
)

const (
	// Threshold is the one threshold v0.4 accepts (O-14): one signature per
	// record. A list carrying any other value is refused, so the records of
	// v0.4 cannot claim a rule no verifier applies.
	Threshold = 1
	// MinVersion is the version of the bootstrap list; every rotation is one
	// above the list in force.
	MinVersion = 1
)

var (
	// ErrList is returned for a list that is not well formed: no operator or
	// more than signing.MaxSigners, a duplicate name after normalisation, a
	// duplicate key by fingerprint, a key line or key policy refusal (the
	// signing error is wrapped too), a version below MinVersion, or a Record
	// that Validate did not produce.
	ErrList = errors.New("trust: not a valid trust list")
	// ErrUnsupportedThreshold is returned for a threshold other than Threshold.
	ErrUnsupportedThreshold = errors.New("trust: threshold is not 1, the only threshold this release enforces")
)

// Operator is one listed person: the canonical name, the key as the one
// authorized_keys line the list stores, and the key's SHA256: fingerprint,
// which is how a signature names it.
type Operator struct {
	Name        string
	Key         string
	Fingerprint string
}

// Record is a trust list Validate accepted: the version, the threshold, and
// the operators in the order the list gives them, names canonical, keys and
// names unique. Every rule function refuses a Record that did not come from
// Validate or whose fields were changed after it did (sum binds the content),
// so a zero, hand-built or altered value authorises nothing.
type Record struct {
	Version   int
	Threshold int
	Signers   []Operator
	sum       [sha256.Size]byte
}

// Validate applies every rule a list must satisfy on its own, independent of
// what list came before it: a version from MinVersion, a threshold of exactly
// Threshold, one to signing.MaxSigners operators, every name a D7 name after
// normalisation and unique, every key its one canonical line, within the key
// policy and unique by fingerprint. The returned Record carries the names in
// canonical form; the list itself is not changed.
func Validate(l signing.TrustList) (Record, error) {
	if l.Version < MinVersion {
		return Record{}, fmt.Errorf("%w: version %d is below %d", ErrList, l.Version, MinVersion)
	}
	if l.Threshold != Threshold {
		return Record{}, fmt.Errorf("%w: got %d", ErrUnsupportedThreshold, l.Threshold)
	}
	if len(l.Signers) == 0 || len(l.Signers) > signing.MaxSigners {
		return Record{}, fmt.Errorf("%w: signers must name 1 to %d operators, not %d", ErrList, signing.MaxSigners, len(l.Signers))
	}
	signers := make([]Operator, 0, len(l.Signers))
	names := make(map[string]int, len(l.Signers))
	keys := make(map[string]int, len(l.Signers))
	for i, s := range l.Signers {
		op, err := validateOperator(i, s)
		if err != nil {
			return Record{}, err
		}
		if j, dup := names[op.Name]; dup {
			return Record{}, fmt.Errorf("%w: signers[%d] and signers[%d] both name %s", ErrList, j, i, strconv.Quote(op.Name))
		}
		if j, dup := keys[op.Fingerprint]; dup {
			return Record{}, fmt.Errorf("%w: signers[%d] and signers[%d] both hold the key %s", ErrList, j, i, op.Fingerprint)
		}
		names[op.Name], keys[op.Fingerprint] = i, i
		signers = append(signers, op)
	}
	r := Record{Version: l.Version, Threshold: l.Threshold, Signers: signers}
	r.sum = r.digest()
	return r, nil
}

// validateOperator applies the per-operator rules to signers[i]: a D7 name
// and a canonical key line whose key passes the policy.
func validateOperator(i int, s signing.Signer) (Operator, error) {
	name, err := NormalizeName(s.Name)
	if err != nil {
		return Operator{}, fmt.Errorf("%w: signers[%d].name: %w", ErrList, i, err)
	}
	pub, err := signing.ParseAuthorizedKey(s.Key)
	if err != nil {
		return Operator{}, fmt.Errorf("%w: signers[%d].key: %w", ErrList, i, err)
	}
	if err := signing.CheckKeyPolicy(pub); err != nil {
		return Operator{}, fmt.Errorf("%w: signers[%d].key: %w", ErrList, i, err)
	}
	return Operator{Name: name, Key: s.Key, Fingerprint: signing.Fingerprint(pub)}, nil
}

// check refuses a Record that Validate did not produce or that was changed
// after it did: the stored sum must equal the digest of the current content.
func (r Record) check() error {
	if r.sum != r.digest() {
		return fmt.Errorf("%w: the record was not produced by Validate or was changed after it", ErrList)
	}
	return nil
}

// digest binds the content of a Record: the version, the threshold, the
// number of operators and each operator's name, key and fingerprint, every
// field as a netstring (decimal length, a colon, the bytes) so that no two
// contents share an encoding.
func (r Record) digest() [sha256.Size]byte {
	var buf []byte
	field := func(s string) {
		buf = append(strconv.AppendInt(buf, int64(len(s)), 10), ':')
		buf = append(buf, s...)
	}
	field(strconv.Itoa(r.Version))
	field(strconv.Itoa(r.Threshold))
	field(strconv.Itoa(len(r.Signers)))
	for _, op := range r.Signers {
		field(op.Name)
		field(op.Key)
		field(op.Fingerprint)
	}
	return sha256.Sum256(buf)
}
