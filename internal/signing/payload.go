package signing

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/sairam0424/toolwarrant/internal/gate"
	"github.com/sairam0424/toolwarrant/internal/strictjson"
)

// The shape rules every payload field obeys. The names follow the catalog's
// own rules (D7 for actors, validateServerName for servers), repeated here
// because the catalog imports this package, not the reverse.
const (
	// signedAtLayout is the one spelling of signed_at: RFC 3339, UTC, whole
	// seconds, so one instant has one byte form.
	signedAtLayout = "2006-01-02T15:04:05Z"
	// catalogIdentityHexLen is the length of meta.identity (D14 (e)): 16
	// random bytes in lower-case hex.
	catalogIdentityHexLen = 32
	// maxActorNameLen and maxServerNameLen are the catalog's caps (D7,
	// validateServerName).
	maxActorNameLen  = 64
	maxServerNameLen = 63
	// maxTrustVersion bounds a trust-list version; lists are rotated by
	// people, so a version near the bound is a forged document.
	maxTrustVersion = 1 << 31
	// canonicalIntPattern is what a canonical JSON non-negative integer looks
	// like: no sign, no leading zero, no fraction, no exponent.
	canonicalIntPattern = "^(0|[1-9][0-9]*)$"
)

// ErrType is returned when a payload carries another `type` than the parser
// it was handed to accepts (a trust list read as a decision, or the reverse).
var ErrType = errors.New("signing: payload type is not the one this parser accepts")

// parsePayloadObject applies the rules every payload shares before any field
// is read: bounds, valid UTF-8, exact RFC 8785 form (the bytes equal their own
// canonicalisation, so whitespace, key order, number spelling and escapes are
// all fixed), no duplicate top-level key, the `type` equal to typ, read before
// anything else because it decides how the rest is read (finding 8), and
// exactly the key set want. It returns the raw value of every key.
func parsePayloadObject(b []byte, typ string, want []string) (map[string]json.RawMessage, error) {
	if err := checkPayloadBounds(b); err != nil {
		return nil, err
	}
	if !utf8.Valid(b) {
		return nil, fmt.Errorf("%w: not valid UTF-8", ErrPayload)
	}
	canon, err := gate.Canonical(b)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPayload, err)
	}
	if !bytes.Equal(canon, b) {
		return nil, fmt.Errorf("%w: not in RFC 8785 canonical form", ErrPayload)
	}
	m, err := decodeObject(b)
	if err != nil {
		return nil, err
	}
	if _, ok := m["type"]; !ok {
		return nil, fmt.Errorf("%w: missing key \"type\"", ErrPayload)
	}
	got, err := stringField(m, "type")
	if err != nil {
		return nil, err
	}
	if got != typ {
		return nil, fmt.Errorf("%w: %s, want %s", ErrType, strconv.Quote(got), typ)
	}
	return m, checkKeySet(m, want)
}

// exactKeys decodes one JSON object whose key set is exactly want.
func exactKeys(b []byte, want []string) (map[string]json.RawMessage, error) {
	m, err := decodeObject(b)
	if err != nil {
		return nil, err
	}
	return m, checkKeySet(m, want)
}

// decodeObject decodes one JSON object into its raw values, refusing a
// duplicate key and trailing data.
func decodeObject(b []byte) (map[string]json.RawMessage, error) {
	if err := strictjson.Object(b); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPayload, err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	var m map[string]json.RawMessage
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPayload, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: data after the object", ErrPayload)
	}
	return m, nil
}

// checkKeySet refuses a missing or an unknown key.
func checkKeySet(m map[string]json.RawMessage, want []string) error {
	for _, k := range want {
		if _, ok := m[k]; !ok {
			return fmt.Errorf("%w: missing key %s", ErrPayload, strconv.Quote(k))
		}
	}
	if len(m) != len(want) {
		for k := range m {
			if !contains(want, k) {
				return fmt.Errorf("%w: unknown key %s", ErrPayload, strconv.Quote(k))
			}
		}
	}
	return nil
}

// contains reports whether set holds s.
func contains(set []string, s string) bool {
	for _, v := range set {
		if v == s {
			return true
		}
	}
	return false
}

// stringField reads key as a JSON string.
func stringField(m map[string]json.RawMessage, key string) (string, error) {
	var s string
	if err := json.Unmarshal(m[key], &s); err != nil {
		return "", fmt.Errorf("%w: %s is not a string", ErrPayload, key)
	}
	return s, nil
}

// intField reads key as a canonical non-negative integer within [lo, hi].
func intField(m map[string]json.RawMessage, key string, lo, hi int) (int, error) {
	raw := string(m[key])
	if !isCanonicalInt(raw) {
		return 0, fmt.Errorf("%w: %s is not a canonical integer (%s)", ErrPayload, key, canonicalIntPattern)
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < lo || n > hi {
		return 0, fmt.Errorf("%w: %s must be between %d and %d", ErrPayload, key, lo, hi)
	}
	return n, nil
}

// isCanonicalInt matches canonicalIntPattern by hand, as the catalog's name
// rules do, so the pattern string in the error is the rule and no regexp
// state is kept.
func isCanonicalInt(s string) bool {
	if s == "" || len(s) > len(strconv.Itoa(maxTrustVersion))+1 {
		return false
	}
	if s == "0" {
		return true
	}
	if s[0] < '1' || s[0] > '9' {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// parseSignedAt reads signed_at in exactly signedAtLayout.
func parseSignedAt(s string) (time.Time, error) {
	t, err := time.Parse(signedAtLayout, s)
	if err != nil || t.UTC().Format(signedAtLayout) != s {
		return time.Time{}, fmt.Errorf("%w: signed_at must be RFC 3339 UTC to the second, as %s", ErrPayload, signedAtLayout)
	}
	return t.UTC(), nil
}

// formatSignedAt renders a time in signedAtLayout; a zero time is refused
// because the signer's clock is part of the record.
func formatSignedAt(t time.Time) (string, error) {
	if t.IsZero() {
		return "", fmt.Errorf("%w: signed_at is unset", ErrPayload)
	}
	return t.UTC().Truncate(time.Second).Format(signedAtLayout), nil
}

// isLowerHex reports whether s is exactly n lower-case hex digits.
func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// isLowerAlnum reports whether c is a lower-case ASCII letter or a digit.
func isLowerAlnum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}

// isActorName matches ^[a-z0-9][a-z0-9._@-]{0,63}$ (D7, as normalizeActor
// leaves a name).
func isActorName(name string) bool {
	if name == "" || len(name) > maxActorNameLen {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if isLowerAlnum(c) || (i > 0 && (c == '.' || c == '_' || c == '@' || c == '-')) {
			continue
		}
		return false
	}
	return true
}

// isServerName matches ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ up to maxServerNameLen
// (validateServerName).
func isServerName(name string) bool {
	if name == "" || len(name) > maxServerNameLen {
		return false
	}
	last := len(name) - 1
	for i := 0; i < len(name); i++ {
		c := name[i]
		if isLowerAlnum(c) || (c == '-' && i > 0 && i < last) {
			continue
		}
		return false
	}
	return true
}

// isFingerprint reports whether s is a SHA256: fingerprint as Fingerprint
// prints it: the prefix and 43 unpadded standard-base64 characters that decode
// to 32 bytes.
func isFingerprint(s string) bool {
	if len(s) != fingerprintLen || s[:len(fingerprintPrefix)] != fingerprintPrefix {
		return false
	}
	raw, err := base64.RawStdEncoding.Strict().DecodeString(s[len(fingerprintPrefix):])
	return err == nil && len(raw) == 32
}
