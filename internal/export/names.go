package export

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	// maxEncodedNameBytes caps an encoded server or tool name. With the
	// ".json" suffix a file name stays well under the 255-byte limit of common
	// file systems, so a hostile name cannot make Write fail half way through.
	maxEncodedNameBytes = 200

	// jsonSuffix is the single dot that may appear in a file name.
	jsonSuffix = ".json"

	// upperHex is the alphabet of percent escapes. Upper case keeps the
	// encoding canonical, so two encodings compare equal only for equal names.
	upperHex = "0123456789ABCDEF"

	// nibbleBits and nibbleMask split a byte into its two hex digits.
	nibbleBits = 4
	nibbleMask = 0x0f
)

// errNameTooLong is returned when an encoded name exceeds maxEncodedNameBytes.
var errNameTooLong = errors.New("name is too long once encoded")

// isSafeByte reports whether c may appear unescaped in a file name. The set is
// deliberately tiny: no dot (so no leading dot, "." or ".."), no separators,
// no NUL, no shell or Windows metacharacters, and no percent sign, which is
// what makes the encoding injective.
func isSafeByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	default:
		return c == '_' || c == '-'
	}
}

// encodeName turns a hostile server or tool name into one safe path component.
// Every byte outside [A-Za-z0-9_-] becomes %XX, so the mapping is injective
// (distinct names can never share a file) and the result can never contain a
// path separator, a NUL or a dot. kind is only used in error messages, which
// never echo the name itself.
func encodeName(kind, raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("export: %s name is empty", kind)
	}
	if !utf8.ValidString(raw) {
		return "", fmt.Errorf("export: %s name is not valid UTF-8", kind)
	}
	// An encoded name is never shorter than the raw one; refuse early so a
	// multi-megabyte name does not get encoded only to be thrown away.
	if len(raw) > maxEncodedNameBytes {
		return "", fmt.Errorf("export: %s name: %w", kind, errNameTooLong)
	}
	var b strings.Builder
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if isSafeByte(c) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(upperHex[c>>nibbleBits])
		b.WriteByte(upperHex[c&nibbleMask])
	}
	if b.Len() > maxEncodedNameBytes {
		return "", fmt.Errorf("export: %s name: %w", kind, errNameTooLong)
	}
	return b.String(), nil
}

// relPath joins an encoded server directory and tool file name the way they
// appear in MANIFEST.json: always with forward slashes.
func relPath(encServer, encTool string) string {
	return encServer + "/" + encTool + jsonSuffix
}
