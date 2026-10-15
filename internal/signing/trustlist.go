package signing

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/sairam0424/toolwarrant/internal/gate"
	"github.com/sairam0424/toolwarrant/internal/strictjson"
)

// Signer is one operator of a trust list: a name as D7 spells it and the
// public key as an authorized_keys line (`type base64`, no comment, no
// options), the form MarshalKey writes and ParseAuthorizedKey reads back.
type Signer struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

// TrustList is the TypeTrustList payload: the operators and their keys in
// force from the audit entry that carries it, for this catalog, on top of this
// head, signed by one of the keys the rotation rule allows (internal/trust
// holds the rules over a list; this package holds its shape).
type TrustList struct {
	Catalog   string
	PrevHead  string
	SignedAt  time.Time
	Signer    string
	Signers   []Signer
	Threshold int
	Version   int
}

// trustListView is the JSON shape of a trust list, keys in RFC 8785 order.
type trustListView struct {
	Catalog   string   `json:"catalog"`
	PrevHead  string   `json:"prev_head"`
	SignedAt  string   `json:"signed_at"`
	Signer    string   `json:"signer"`
	Signers   []Signer `json:"signers"`
	Threshold int      `json:"threshold"`
	Type      string   `json:"type"`
	Version   int      `json:"version"`
}

// trustListKeys is the exact key set ParseTrustList accepts, and signerKeys
// the exact key set of each element of signers.
func trustListKeys() []string {
	return []string{"catalog", "prev_head", "signed_at", "signer", "signers", "threshold", "type", "version"}
}

func signerKeys() []string { return []string{"key", "name"} }

// validate applies the shape rules shared by MarshalTrustList and
// ParseTrustList: identity, head and fingerprint shapes, one to MaxSigners
// operators each with a D7 name and a canonical key line, a positive threshold
// no larger than the list and a positive version. Uniqueness, the key policy,
// the exact threshold and the rotation rule are internal/trust's.
func (l TrustList) validate() error {
	switch {
	case !isLowerHex(l.Catalog, catalogIdentityHexLen):
		return fmt.Errorf("%w: catalog must be %d lower-case hex digits", ErrPayload, catalogIdentityHexLen)
	case !isLowerHex(l.PrevHead, hexDigestLen):
		return fmt.Errorf("%w: prev_head must be %d lower-case hex digits", ErrPayload, hexDigestLen)
	case !isFingerprint(l.Signer):
		return fmt.Errorf("%w: signer must be a SHA256: fingerprint", ErrPayload)
	case len(l.Signers) == 0 || len(l.Signers) > MaxSigners:
		return fmt.Errorf("%w: signers must name 1 to %d operators, not %d", ErrPayload, MaxSigners, len(l.Signers))
	case l.Threshold < 1 || l.Threshold > len(l.Signers):
		return fmt.Errorf("%w: threshold must be between 1 and the number of signers", ErrPayload)
	case l.Version < 1 || l.Version > maxTrustVersion:
		return fmt.Errorf("%w: version must be between 1 and %d", ErrPayload, maxTrustVersion)
	}
	for i, s := range l.Signers {
		if !isActorName(s.Name) {
			return fmt.Errorf("%w: signers[%d].name %s must match ^[a-z0-9][a-z0-9._@-]{0,63}$", ErrPayload, i, strconv.Quote(s.Name))
		}
		if _, err := ParseAuthorizedKey(s.Key); err != nil {
			return fmt.Errorf("%w: signers[%d].key: %v", ErrPayload, i, err)
		}
	}
	return nil
}

// MarshalTrustList produces the exact bytes that are signed and stored: the
// RFC 8785 form of the list with its type.
func MarshalTrustList(l TrustList) ([]byte, error) {
	if err := l.validate(); err != nil {
		return nil, err
	}
	signedAt, err := formatSignedAt(l.SignedAt)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(trustListView{
		Catalog: l.Catalog, PrevHead: l.PrevHead, SignedAt: signedAt, Signer: l.Signer,
		Signers: l.Signers, Threshold: l.Threshold, Type: TypeTrustList, Version: l.Version,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPayload, err)
	}
	canon, err := gate.Canonical(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPayload, err)
	}
	return canon, nil
}

// ParseTrustList reads a trust list from bytes whose signature already
// verified, accepting exactly what MarshalTrustList writes: TypeTrustList as
// the type (read first; a decision under this parser is ErrType), the
// canonical form, the eight keys, each signer an object of exactly key and
// name, and the integers canonical and within bounds.
func ParseTrustList(b []byte) (TrustList, error) {
	m, err := parsePayloadObject(b, TypeTrustList, trustListKeys())
	if err != nil {
		return TrustList{}, err
	}
	l := TrustList{}
	strs := map[string]*string{"catalog": &l.Catalog, "prev_head": &l.PrevHead, "signer": &l.Signer}
	for k, dst := range strs {
		if *dst, err = stringField(m, k); err != nil {
			return TrustList{}, err
		}
	}
	signedAt, err := stringField(m, "signed_at")
	if err != nil {
		return TrustList{}, err
	}
	if l.SignedAt, err = parseSignedAt(signedAt); err != nil {
		return TrustList{}, err
	}
	if l.Threshold, err = intField(m, "threshold", 1, MaxSigners); err != nil {
		return TrustList{}, err
	}
	if l.Version, err = intField(m, "version", 1, maxTrustVersion); err != nil {
		return TrustList{}, err
	}
	if l.Signers, err = parseSigners(m["signers"]); err != nil {
		return TrustList{}, err
	}
	if err := l.validate(); err != nil {
		return TrustList{}, err
	}
	return l, nil
}

// parseSigners reads the signers array: one to MaxSigners objects of exactly
// key and name, both strings, no duplicate key inside an element.
func parseSigners(raw json.RawMessage) ([]Signer, error) {
	var elems []json.RawMessage
	if err := json.Unmarshal(raw, &elems); err != nil || elems == nil {
		return nil, fmt.Errorf("%w: signers is not an array", ErrPayload)
	}
	if len(elems) == 0 || len(elems) > MaxSigners {
		return nil, fmt.Errorf("%w: signers must name 1 to %d operators, not %d", ErrPayload, MaxSigners, len(elems))
	}
	out := make([]Signer, 0, len(elems))
	for i, e := range elems {
		if err := strictjson.Object(e); err != nil {
			return nil, fmt.Errorf("%w: signers[%d]: %v", ErrPayload, i, err)
		}
		fields, err := exactKeys(e, signerKeys())
		if err != nil {
			return nil, fmt.Errorf("%w: signers[%d]: %v", ErrPayload, i, err)
		}
		var s Signer
		if s.Key, err = stringField(fields, "key"); err != nil {
			return nil, fmt.Errorf("signers[%d]: %w", i, err)
		}
		if s.Name, err = stringField(fields, "name"); err != nil {
			return nil, fmt.Errorf("signers[%d]: %w", i, err)
		}
		out = append(out, s)
	}
	return out, nil
}
