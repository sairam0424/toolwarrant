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

	// percentEscapeLen is the length of one %XX escape.
	percentEscapeLen = 3
)

// errNameTooLong is returned when an encoded name exceeds maxEncodedNameBytes.
var errNameTooLong = errors.New("name is too long once encoded")

// isSafeByte reports whether c may appear unescaped in a file name. The set is
// deliberately tiny: no dot (so no leading dot, "." or ".."), no separators,
// no NUL, no shell or Windows metacharacters, and no percent sign, which is
// what makes the encoding injective.
//
// Known limit: the Windows reserved device names (CON, PRN, AUX, NUL, COM1-9,
// LPT1-9) consist of safe bytes and pass through unchanged, so on Windows a
// server called CON could not get a directory and a tool called NUL would open
// the device instead of a file. The export targets darwin and linux; Windows
// hosts are not supported.
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

// isEncodedName reports whether enc is exactly what encodeName produces for
// some name: the safe alphabet, upper-case %XX escapes, and an escape only
// where the byte needed one. MANIFEST.json is the one place an encoded name is
// read back, and that file lives in a directory other people can edit, so a
// non-canonical spelling is refused rather than decoded.
func isEncodedName(kind, enc string) bool {
	raw, ok := percentDecode(enc)
	if !ok {
		return false
	}
	again, err := encodeName(kind, string(raw))
	return err == nil && again == enc
}

// percentDecode inverts the escaping. It refuses any byte outside the alphabet
// and any escape that is not exactly two upper-case hex digits.
func percentDecode(enc string) ([]byte, bool) {
	out := make([]byte, 0, len(enc))
	for i := 0; i < len(enc); i++ {
		c := enc[i]
		if c != '%' {
			if !isSafeByte(c) {
				return nil, false
			}
			out = append(out, c)
			continue
		}
		if i+percentEscapeLen > len(enc) {
			return nil, false
		}
		hi, lo := hexValue(enc[i+1]), hexValue(enc[i+2])
		if hi < 0 || lo < 0 {
			return nil, false
		}
		out = append(out, byte(hi<<nibbleBits|lo))
		i += percentEscapeLen - 1
	}
	return out, true
}

// hexValue returns the value of an upper-case hex digit, or -1 for anything
// else; lower-case digits are not canonical and so not accepted.
func hexValue(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// relPath joins an encoded server directory and tool file name the way they
// appear in MANIFEST.json: always with forward slashes.
func relPath(encServer, encTool string) string {
	return encServer + "/" + encTool + jsonSuffix
}

// lowerASCII lower-cases an encoded path. Encoded paths are pure ASCII, so
// this is exactly the folding a case-insensitive file system applies.
func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
