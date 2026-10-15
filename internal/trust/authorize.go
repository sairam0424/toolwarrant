package trust

import (
	"errors"
	"fmt"
	"strconv"
)

var (
	// ErrUnauthorizedSigner is returned when a key is not in the list: a
	// signature that verifies under it proves who held the key, not that the
	// key may decide (finding 6).
	ErrUnauthorizedSigner = errors.New("trust: the signing key is not in the trust list")
	// ErrAnotherOperatorsKey is returned when the key is listed, but for
	// another person than the one the entry names; the error names both.
	ErrAnotherOperatorsKey = errors.New("trust: the signing key is listed for another operator")
)

// Lookup returns the name the list gives the key with this fingerprint. A
// Record Validate did not produce, or one changed since, names nobody.
func (r Record) Lookup(fingerprint string) (name string, ok bool) {
	if r.check() != nil {
		return "", false
	}
	for _, op := range r.Signers {
		if op.Fingerprint == fingerprint {
			return op.Name, true
		}
	}
	return "", false
}

// Authorize decides whether the key with this fingerprint may act as actor:
// the key must be listed, and listed for exactly that person. actor is
// normalised as every stored actor is, so a stored name compares as itself and
// a spelling D7 refuses is ErrName. Validity of the signature is the caller's
// (signing.Verify); this is the second check, separate from it.
func (r Record) Authorize(fingerprint, actor string) error {
	if err := r.check(); err != nil {
		return err
	}
	want, err := NormalizeName(actor)
	if err != nil {
		return err
	}
	name, ok := r.Lookup(fingerprint)
	if !ok {
		return fmt.Errorf("%w: %s is listed for nobody; a valid signature from it authorises nothing", ErrUnauthorizedSigner, strconv.Quote(fingerprint))
	}
	if name != want {
		return fmt.Errorf("%w: %s is %s's key, the entry names %s", ErrAnotherOperatorsKey, fingerprint, strconv.Quote(name), strconv.Quote(want))
	}
	return nil
}
