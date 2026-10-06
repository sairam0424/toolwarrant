// Package gate holds the approval logic that decides which MCP tools callers
// may see and call. Approvals are bound to a digest of the whole tool
// definition, so any change to a description, schema or annotation makes the
// tool unapproved until an owner approves the new version.
package gate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/gowebpki/jcs"

	"github.com/sairam0424/toolwarrant/internal/strictjson"
)

// VolatileKeys are top-level tool keys that legitimately change between
// requests without changing what the tool is or does, so they are excluded
// from the digest. Everything else, including fields this code has never heard
// of, is part of the tool's identity: a new field is a change that needs
// approval.
var VolatileKeys = []string{"_meta"}

// canonicalize is the single place the RFC 8785 library is used, so it can be
// swapped or cross-checked. Every approval depends on it.
var canonicalize = jcs.Transform

// Canonical returns the RFC 8785 (JCS) canonical form of a JSON document.
func Canonical(raw []byte) ([]byte, error) {
	return canonicalize(raw)
}

// CanonicalTool returns the exact bytes that Digest hashes: the RFC 8785
// canonical form of the tool object after removing VolatileKeys. It fails on
// anything that is not a JSON object so that callers can fail closed.
func CanonicalTool(tool []byte) ([]byte, error) {
	// Decoding into a map keeps only the last of two duplicate keys, so the
	// digest could hide a shadowed field. Refuse such definitions instead.
	if err := strictjson.Object(tool); err != nil {
		return nil, fmt.Errorf("gate: tool definition: %w", err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(tool, &obj); err != nil || obj == nil {
		return nil, errors.New("gate: tool definition is not a JSON object")
	}
	for _, k := range VolatileKeys {
		delete(obj, k)
	}
	stripped, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("gate: re-encode tool: %w", err)
	}
	canon, err := canonicalize(stripped)
	if err != nil {
		return nil, fmt.Errorf("gate: canonicalize tool: %w", err)
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
