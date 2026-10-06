package textdiff

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// failer is the part of testing.TB that the helpers need. *rapid.T has it too
// but is not a testing.TB.
type failer interface {
	Helper()
	Fatalf(format string, args ...any)
}

// unescape inverts Escape (inline=false) or escapeInline (inline=true). It is
// strict on purpose: any backslash sequence Escape could not have produced is
// an error, which is how the tests prove the output is unambiguous.
func unescape(s string, inline bool) (string, error) {
	var out []byte
	for i := 0; i < len(s); {
		if s[i] != '\\' {
			out = append(out, s[i])
			i++
			continue
		}
		if i+1 >= len(s) {
			return "", errors.New("dangling backslash")
		}
		switch s[i+1] {
		case '\\':
			out = append(out, '\\')
			i += 2
		case 't':
			out = append(out, '\t')
			i += 2
		case 'n':
			if !inline {
				return "", errors.New(`\n is not produced by Escape`)
			}
			out = append(out, '\n')
			i += 2
		case 'u', 'x':
			next, err := unescapeNumeric(&out, s, i)
			if err != nil {
				return "", err
			}
			i = next
		default:
			return "", fmt.Errorf("unknown escape %q", s[i:i+2])
		}
	}
	return string(out), nil
}

// unescapeNumeric decodes \u{HEX} or \x{HH} at s[i:] and returns the index
// after the closing brace.
func unescapeNumeric(out *[]byte, s string, i int) (int, error) {
	kind := s[i+1]
	if i+2 >= len(s) || s[i+2] != '{' {
		return 0, errors.New("missing brace")
	}
	end := strings.IndexByte(s[i:], '}')
	if end < 0 {
		return 0, errors.New("missing closing brace")
	}
	digits := s[i+3 : i+end]
	if digits != strings.ToUpper(digits) {
		return 0, fmt.Errorf("hex digits %q are not upper case", digits)
	}
	v, err := strconv.ParseUint(digits, 16, 32)
	if err != nil {
		return 0, err
	}
	switch kind {
	case 'u':
		if len(digits) < 4 || !utf8.ValidRune(rune(v)) {
			return 0, fmt.Errorf("bad \\u escape %q", digits)
		}
		*out = utf8.AppendRune(*out, rune(v))
	default:
		if len(digits) != 2 {
			return 0, fmt.Errorf("bad \\x escape %q", digits)
		}
		*out = append(*out, byte(v))
	}
	return i + end + 1, nil
}

// countNumericEscapes counts \u{..} and \x{..} tokens in escaped text.
func countNumericEscapes(e string) int {
	n := 0
	for i := 0; i < len(e); i++ {
		if e[i] != '\\' {
			continue
		}
		if e[i+1] == 'u' || e[i+1] == 'x' {
			n++
		}
		i++ // skip the escaped character
	}
	return n
}

// assertSafe fails if out could act on a terminal or hide anything: a byte
// below 0x20 other than newline, DEL, ESC, invalid UTF-8, or any rune that
// Escape would itself have escaped.
func assertSafe(t failer, out string) {
	t.Helper()
	if !utf8.ValidString(out) {
		t.Fatalf("output is not valid UTF-8: %q", out)
	}
	for i := 0; i < len(out); i++ {
		c := out[i]
		if (c < 0x20 && c != '\n') || c == 0x7F {
			t.Fatalf("output has raw control byte 0x%02X at %d: %q", c, i, out)
		}
	}
	if f := Findings(out); len(f) != 0 {
		t.Fatalf("output still contains a suspicious rune %+v: %q", f[0], out)
	}
}

// changeLines returns the lines of a Unified result that are additions or
// deletions, ignoring the two header lines.
func changeLines(out string) []string {
	lines := strings.Split(out, "\n")
	var changes []string
	for i, l := range lines {
		if i < 2 {
			continue
		}
		if strings.HasPrefix(l, "-") || strings.HasPrefix(l, "+") {
			changes = append(changes, l)
		}
	}
	return changes
}

// tagSpell writes ASCII text as Unicode tag characters.
func tagSpell(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		b.WriteRune(tagBlockStart + rune(s[i]))
	}
	return b.String()
}

// numberedLines returns "prefix1\nprefix2\n..." without a trailing newline.
func numberedLines(prefix string, n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = prefix + strconv.Itoa(i+1)
	}
	return strings.Join(parts, "\n")
}
