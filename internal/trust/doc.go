// Package trust holds the pure rules of the signed operator trust list
// (D22 (c), the research report L13 findings 6, 9 and 10): which lists are
// well formed, which list may follow which, and which key stands for which
// person. It decides rules 3 and 4 of the chain walk described in the v0.4
// plan; the catalog applies them to the records it reads and the CLI to the
// list it is about to sign. The package imports internal/signing (the
// payload shape, the key line, the key policy and the two namespaces) and
// golang.org/x/text/unicode/norm (the NFKC fold the catalog's normalizeActor
// applies), and nothing else: no catalog, no cmd, no I/O, no state outside
// the values it is handed.
//
// A list. Validate turns a signing.TrustList into a Record: every name
// normalised as D7 does (NFKC, lower-cased, then ^[a-z0-9][a-z0-9._@-]{0,63}$,
// the rule of internal/catalog's normalizeActor re-implemented in NormalizeName
// so this package needs no catalog import) and unique, every key parsed from
// its one canonical line, within signing.CheckKeyPolicy and unique by
// fingerprint, one to signing.MaxSigners operators, and a threshold of exactly
// one (ErrUnsupportedThreshold; O-14 fixes v0.4 at one signature per record).
// Names are unique so that a person is one entry: a second key is enrolled
// under a second name, and a future threshold above one counts people, not
// keys (finding 9, the CVE-2020-6174 class, where duplicate keys were counted
// twice). Every other function refuses a Record that Validate did not produce.
//
// Rotation, TUF's rule at threshold one (finding 10). The first list is the
// bootstrap: version 1, signed by one of its own keys (trust on first use),
// and, when the operator pinned a root (serve --trust-root, O-11), by that
// fingerprint. Every later list is a rotation: its version is exactly one
// above the list in force (N and N+2 are both ErrRollback, TUF 5.3.5) and its
// signing key is in both the list in force and the new list (TUF 5.3.4 at a
// threshold of one; removing a key takes a signature from a key that stays,
// so the last signer cannot remove itself and a list can never be emptied).
// State folds the two event kinds in seq order and refuses a second bootstrap
// (ErrSecondBootstrap) and a rotation before any bootstrap (ErrNoList).
//
// Authorisation is separate from validity (finding 6). A signature that
// verifies under a key proves who held that key, not that the key may decide:
// Record.Authorize requires the key to be listed and listed for exactly the
// actor the entry names, so a valid signature from an unlisted key is
// ErrUnauthorizedSigner and one from another operator's key is
// ErrAnotherOperatorsKey, naming both people; the catalog turns either into
// ErrCorrupt, never a warning.
//
// The residual, stated in the plan and carried into every document: at a
// threshold of one, one compromised key rotates the list and can evict the
// other signer; the rotation rule allows it because the compromised key is
// in both lists. Threshold two is the fix and is deferred (O-14). Removal is
// not retroactive: a decision a key signed before its removal stands.
//
// AllowedSigners renders a Record as the allowed_signers file stock
// `ssh-keygen -Y verify` reads, one line per key with both namespaces, so an
// auditor re-verifies every record of this catalog without toolwarrant.
package trust
