package trust

import (
	"errors"
	"fmt"
	"strconv"
)

var (
	// ErrBootstrapVersion is returned for a bootstrap whose version is not
	// MinVersion: a first list that claims a history no chain holds.
	ErrBootstrapVersion = errors.New("trust: a bootstrap list must be version 1")
	// ErrNotSelfSigned is returned for a bootstrap signed by a key its own
	// list does not hold; the first list vouches for itself (trust on first
	// use), so its signer must be one of its operators.
	ErrNotSelfSigned = errors.New("trust: the bootstrap is not signed by a key of its own list")
	// ErrNotThePinnedRoot is returned when the operator pinned a root
	// fingerprint and the bootstrap was signed by another key: the catalog
	// was re-bootstrapped or replaced.
	ErrNotThePinnedRoot = errors.New("trust: the bootstrap is not signed by the pinned trust root")
	// ErrRollback is returned for a rotation whose version is not exactly one
	// above the list in force: TUF 5.3.5 names both a lower and a skipped
	// version a rollback attack, since a verifier that accepted either could
	// be walked back to a list that still holds a revoked key.
	ErrRollback = errors.New("trust: list version is not exactly one above the list in force")
	// ErrSignerNotInBothLists is returned for a rotation whose signing key is
	// not in both the list in force and the new list (TUF 5.3.4 at a
	// threshold of one): a key that is leaving cannot sign its own
	// replacement and a key that is arriving cannot vouch for itself.
	ErrSignerNotInBothLists = errors.New("trust: the rotation is not signed by a key of both the list in force and the new list")
)

// CheckBootstrap decides whether next may start the trust list of a catalog
// when signer (the fingerprint of the key the signature verified under)
// signed it: next is version MinVersion, signer is one of next's keys, and,
// when pinnedRoot is not empty, signer equals it. An empty pinnedRoot means
// trust on first use (O-11); the CLI and `serve --trust-root` pass the
// operator's pin.
func CheckBootstrap(next Record, signer, pinnedRoot string) error {
	if err := next.check(); err != nil {
		return err
	}
	if next.Version != MinVersion {
		return fmt.Errorf("%w: got version %d", ErrBootstrapVersion, next.Version)
	}
	if _, ok := next.Lookup(signer); !ok {
		return fmt.Errorf("%w: signed by %s", ErrNotSelfSigned, strconv.Quote(signer))
	}
	if pinnedRoot != "" && signer != pinnedRoot {
		return fmt.Errorf("%w: signed by %s, the pinned root is %s", ErrNotThePinnedRoot, signer, strconv.Quote(pinnedRoot))
	}
	return nil
}

// CheckRotation decides whether next may replace prev when signer (the
// fingerprint of the key the signature verified under) signed it:
// next.Version is exactly prev.Version+1 and signer is a key of both lists.
// With one signature per record this is TUF's root rotation rule at a
// threshold of one; it lets one key add or remove any other, and it lets the
// last remaining key neither remove itself nor hand the list to a key that
// has not signed anything yet.
func CheckRotation(prev, next Record, signer string) error {
	if err := prev.check(); err != nil {
		return fmt.Errorf("list in force: %w", err)
	}
	if err := next.check(); err != nil {
		return fmt.Errorf("new list: %w", err)
	}
	if next.Version != prev.Version+1 {
		return fmt.Errorf("%w: got version %d, the list in force is version %d", ErrRollback, next.Version, prev.Version)
	}
	_, inPrev := prev.Lookup(signer)
	_, inNext := next.Lookup(signer)
	if !inPrev || !inNext {
		return fmt.Errorf("%w: signed by %s (in the list in force: %t, in the new list: %t)", ErrSignerNotInBothLists, strconv.Quote(signer), inPrev, inNext)
	}
	return nil
}
