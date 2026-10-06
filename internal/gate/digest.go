// Package gate holds the approval logic that decides which MCP tools callers
// may see and call. Approvals are bound to a digest of the whole tool
// definition, so any change to a description, schema, annotation or _meta
// member makes the tool unapproved until an owner approves the new version.
//
// Digest profile. DigestProfile names the rule that turns a definition into
// its digest, so that an approval can record which rule it was made under.
// Under "full-v1" the digest is the SHA-256 of the RFC 8785 (JCS) canonical
// form of the whole tool object: no key is excluded. _meta is included because
// hosts act on it (MCP Apps ui.resourceUri, OpenAI Apps SDK openai/* members),
// so a change there needs re-approval like any other.
//
// What the digest refuses rather than confuses. RFC 8785 writes every number
// as an IEEE 754 double in ES6 shortest form, so two definitions whose numbers
// differ only beyond double precision (9007199254740993 and 9007199254740992,
// or 1e-400 and 0) would canonicalise alike and one could be served as the
// other. CanonicalTool therefore refuses a definition whose number tokens do
// not denote exactly the value their canonical form denotes (ErrNumberPrecision);
// such a definition can be neither approved nor served. Likewise a definition
// that is not valid UTF-8 (ErrNotUTF8), or one with a lone or ill-paired
// surrogate escape in a key or a value, is refused instead of being hashed as
// its U+FFFD look-alike: encoding/json would quietly substitute U+FFFD in keys,
// so the original bytes, never a re-encoding, are what gets canonicalised.
//
// Known limit. agentgateway v1.6.0 re-serialises tool definitions before the
// ExtMCP hook and drops top-level keys and annotations keys it does not know,
// so a tool carrying such a key can never match its approved digest at the
// gateway. This package does not hash a projection; the processor and the CLI
// report the mismatch instead.
package gate

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/gowebpki/jcs"

	"github.com/sairam0424/toolwarrant/internal/strictjson"
)

// DigestProfile names the rule under which Digest is computed, to be stored
// next to every approval: the SHA-256 of the RFC 8785 canonical form of the
// whole tool object, with no key excluded.
const DigestProfile = "full-v1"

// VolatileKeys used to list top-level keys left out of the digest. Under
// DigestProfile nothing is left out, so it is always nil; it remains only so
// that callers written against the earlier profile keep compiling, and
// CanonicalTool does not consult it.
var VolatileKeys []string

// Errors returned by CanonicalTool and Digest, so callers can tell a hostile
// definition from a broken one.
var (
	// ErrNotUTF8 means the definition is not valid UTF-8. A JSON decoder would
	// read the bad bytes as U+FFFD and two different byte strings would share a
	// digest, so the definition is refused.
	ErrNotUTF8 = errors.New("gate: tool definition is not valid UTF-8")
	// ErrNumberPrecision means a number in the definition is not exact in IEEE
	// 754 double precision: RFC 8785 would canonicalise it to a different
	// value, so two different definitions would share a digest. The definition
	// is refused.
	ErrNumberPrecision = errors.New("gate: number is not exact in IEEE 754 double precision")
)

// canonicalize is the single place the RFC 8785 library is used, so it can be
// swapped or cross-checked. Every approval depends on it.
var canonicalize = jcs.Transform

// Canonical returns the RFC 8785 (JCS) canonical form of a JSON document.
func Canonical(raw []byte) ([]byte, error) {
	return canonicalize(raw)
}

// CanonicalTool returns the exact bytes that Digest hashes: the RFC 8785
// canonical form of the whole tool object. It fails on anything that is not a
// JSON object with unambiguous keys, on invalid UTF-8, on lone surrogate
// escapes and on numbers that double precision cannot hold, so that callers
// can fail closed.
func CanonicalTool(tool []byte) ([]byte, error) {
	if !utf8.Valid(tool) {
		return nil, ErrNotUTF8
	}
	// Two top-level keys that a decoder would merge would let the digest hide
	// a shadowed field. Refuse such definitions instead.
	if err := strictjson.Object(tool); err != nil {
		return nil, fmt.Errorf("gate: tool definition: %w", err)
	}
	// The original bytes are canonicalised, never a re-encoding: the RFC 8785
	// step refuses a lone or ill-paired surrogate escape and a malformed UTF-8
	// sequence in a key as well as in a value, where a round trip through a Go
	// map would have replaced them with U+FFFD before anything could notice.
	canon, err := canonicalize(tool)
	if err != nil {
		return nil, fmt.Errorf("gate: canonicalize tool: %w", err)
	}
	if err := checkNumbers(tool); err != nil {
		return nil, err
	}
	return canon, nil
}

// DigestOfCanonical returns the lowercase hex SHA-256 of bytes previously
// produced by CanonicalTool.
func DigestOfCanonical(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

// Digest returns the lowercase hex SHA-256 of CanonicalTool(tool).
func Digest(tool []byte) (string, error) {
	canon, err := CanonicalTool(tool)
	if err != nil {
		return "", err
	}
	return DigestOfCanonical(canon), nil
}
