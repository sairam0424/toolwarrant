package drift

import (
	"sort"
	"strings"

	"github.com/sairam0424/toolwarrant/internal/textdiff"
)

// mergedKeys returns the union of both key sets in byte order.
func mergedKeys(from, to map[string]any) []string {
	seen := make(map[string]bool, len(from)+len(to))
	out := make([]string, 0, len(from)+len(to))
	for _, m := range []map[string]any{from, to} {
		for k := range m {
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	sort.Strings(out)
	return out
}

// escapedNewline is how a line break inside a key is shown, in the \u{HEX}
// form textdiff.Escape uses for every other invisible character; Escape keeps
// a newline, and a path must stay on one line.
const escapedNewline = `\u{000A}`

// segment renders an object key as a path segment. A simple key prints as
// .key; anything else is quoted and escaped, with a quotation mark written \"
// (Escape doubles every real backslash, so the form is unambiguous and
// distinct keys give distinct paths), so the path is safe to print.
func segment(k string) string {
	if isSimpleKey(k) {
		return "." + k
	}
	escaped := strings.ReplaceAll(textdiff.Escape(k), "\n", escapedNewline)
	return `["` + strings.ReplaceAll(escaped, `"`, `\"`) + `"]`
}

// isSimpleKey reports whether k is non-empty ASCII letters, digits, _ and -.
func isSimpleKey(k string) bool {
	if k == "" {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		isAlnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !isAlnum && c != '_' && c != '-' {
			return false
		}
	}
	return true
}
