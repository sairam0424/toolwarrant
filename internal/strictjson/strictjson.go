// Package strictjson rejects JSON objects that two parsers could read
// differently. Every component that names or hashes a tool (the digest, the
// crawler, the ExtMCP processor) must agree with the gateway, the upstream and
// the client on what the tool is called and what it says; a single shared check
// keeps them from disagreeing with each other.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

var (
	// ErrNotObject means the input is not exactly one JSON object.
	ErrNotObject = errors.New("strictjson: not a single JSON object")
	// ErrAmbiguousKeys means the object has a repeated key, or a key that
	// differs from "name" only by case.
	ErrAmbiguousKeys = errors.New("strictjson: object has duplicate or ambiguous keys")
)

// NameKey is the one field whose exact spelling decides which tool a message is
// about.
const NameKey = "name"

// initialKeyCapacity sizes the duplicate-detection set for a typical tool.
const initialKeyCapacity = 8

// Object checks that raw is a single JSON object with unique top-level keys and
// no key that case-folds to "name" other than "name" itself.
//
// Go's encoding/json keeps the LAST of two duplicate keys and matches struct
// fields case-insensitively, while other parsers keep the first or match
// exactly. Without this check:
//
//   - a tool {"name":"x","description":"evil","description":"safe"} would hash as
//     the "safe" definition that was approved while its raw bytes still carry
//     "evil" first, which a first-wins client would obey;
//   - a call {"name":"wipe_database","Name":"echo"} would be judged as "echo"
//     but routed as "wipe_database" by a case-sensitive gateway.
//
// Only top-level keys are checked here. The RFC 8785 step in gate rejects
// duplicates below the top level, and nested property names such as "name" and
// "Name" in an input schema are legitimate.
func Object(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	open, err := dec.Token()
	if err != nil {
		return fmt.Errorf("strictjson: read object: %w", err)
	}
	if delim, ok := open.(json.Delim); !ok || delim != '{' {
		return ErrNotObject
	}
	seen := make(map[string]struct{}, initialKeyCapacity)
	for dec.More() {
		if err := checkNextKey(dec, seen); err != nil {
			return err
		}
	}
	if _, err := dec.Token(); err != nil { // the closing brace
		return fmt.Errorf("strictjson: read object end: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return ErrNotObject // trailing data after the object
	}
	return nil
}

// checkNextKey reads one key and skips its value, recording the key in seen.
func checkNextKey(dec *json.Decoder, seen map[string]struct{}) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("strictjson: read key: %w", err)
	}
	key, ok := tok.(string)
	if !ok {
		return ErrNotObject
	}
	if _, dup := seen[key]; dup {
		return ErrAmbiguousKeys
	}
	if key != NameKey && strings.EqualFold(key, NameKey) {
		return ErrAmbiguousKeys
	}
	seen[key] = struct{}{}
	var skipped json.RawMessage
	if err := dec.Decode(&skipped); err != nil {
		return fmt.Errorf("strictjson: read value: %w", err)
	}
	return nil
}
