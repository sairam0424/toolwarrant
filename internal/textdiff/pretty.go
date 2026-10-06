package textdiff

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	// maxIndentDepth caps the indentation of the pretty-printed definition.
	// encoding/json indents two spaces per nesting level, so a definition
	// nested 255 deep turned every four-byte array item into a 516-byte line
	// and a 256 KiB definition into 94 MB of diff. Past this depth every level
	// is indented the same, which keeps the output proportional to the input
	// while the first levels still read as usual.
	maxIndentDepth = 8
	indentUnit     = "  "

	// jsonHex is the lower-case alphabet encoding/json uses in \u escapes.
	jsonHex = "0123456789abcdef"

	// lineSeparator and paragraphSeparator are the only characters above DEL
	// that encoding/json escapes, because a JavaScript parser would read them
	// as line breaks.
	lineSeparator      = '\u2028'
	paragraphSeparator = '\u2029'
)

// prettyJSON renders a decoded document exactly as encoding/json does with
// SetIndent("", "  ") and HTML escaping off (keys sorted, "<" stays "<",
// numbers verbatim, no trailing newline), except that the indentation stops
// growing at maxIndentDepth. It fails on a value decodeJSON cannot produce
// rather than guessing how to print it.
func prettyJSON(v any) (string, error) {
	var sb strings.Builder
	if err := writeValue(&sb, v, 0); err != nil {
		return "", err
	}
	return sb.String(), nil
}

func writeValue(sb *strings.Builder, v any, depth int) error {
	switch t := v.(type) {
	case nil:
		sb.WriteString("null")
	case bool:
		if t {
			sb.WriteString("true")
		} else {
			sb.WriteString("false")
		}
	case json.Number:
		sb.WriteString(string(t))
	case string:
		writeJSONString(sb, t)
	case []any:
		return writeArray(sb, t, depth)
	case map[string]any:
		return writeObject(sb, t, depth)
	default:
		return fmt.Errorf("encode json: unexpected value of type %T", v)
	}
	return nil
}

func writeArray(sb *strings.Builder, items []any, depth int) error {
	if len(items) == 0 {
		sb.WriteString("[]")
		return nil
	}
	sb.WriteString("[\n")
	for i, el := range items {
		if i > 0 {
			sb.WriteString(",\n")
		}
		writeIndent(sb, depth+1)
		if err := writeValue(sb, el, depth+1); err != nil {
			return err
		}
	}
	sb.WriteByte('\n')
	writeIndent(sb, depth)
	sb.WriteByte(']')
	return nil
}

func writeObject(sb *strings.Builder, obj map[string]any, depth int) error {
	if len(obj) == 0 {
		sb.WriteString("{}")
		return nil
	}
	keys := sortedKeys(obj)
	sb.WriteString("{\n")
	for i, k := range keys {
		if i > 0 {
			sb.WriteString(",\n")
		}
		writeIndent(sb, depth+1)
		writeJSONString(sb, k)
		sb.WriteString(": ")
		if err := writeValue(sb, obj[k], depth+1); err != nil {
			return err
		}
	}
	sb.WriteByte('\n')
	writeIndent(sb, depth)
	sb.WriteByte('}')
	return nil
}

// sortedKeys returns the keys of obj in byte order, as encoding/json does.
func sortedKeys(obj map[string]any) []string {
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// writeIndent writes the indentation for depth, capped at maxIndentDepth.
func writeIndent(sb *strings.Builder, depth int) {
	for i := 0; i < min(depth, maxIndentDepth); i++ {
		sb.WriteString(indentUnit)
	}
}

// writeJSONString writes s as a JSON string literal with the escaping rules of
// encoding/json when HTML escaping is off: quote and backslash are escaped,
// the short escapes \b \f \n \r \t are used, the other C0 controls become
// \u00XX, U+2028 and U+2029 become \u2028 and \u2029, a byte that is not
// valid UTF-8 becomes the replacement character U+FFFD, and everything else,
// DEL included, is written as it is. Escape, which runs over every line of
// the result, is what makes the invisible characters visible afterwards.
func writeJSONString(sb *strings.Builder, s string) {
	sb.WriteByte('"')
	start := 0
	for i := 0; i < len(s); {
		if c := s[i]; c < utf8.RuneSelf {
			if c >= asciiPrintable && c != '"' && c != '\\' {
				i++
				continue
			}
			sb.WriteString(s[start:i])
			writeJSONEscape(sb, c)
			i++
			start = i
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			sb.WriteString(s[start:i])
			sb.WriteRune(utf8.RuneError)
			start = i + size
		case r == lineSeparator, r == paragraphSeparator:
			sb.WriteString(s[start:i])
			sb.WriteString(`\u202`)
			sb.WriteByte(jsonHex[r&nibbleMask])
			start = i + size
		}
		i += size
	}
	sb.WriteString(s[start:])
	sb.WriteByte('"')
}

// writeJSONEscape writes the escape for an ASCII byte that cannot appear raw.
func writeJSONEscape(sb *strings.Builder, c byte) {
	switch c {
	case '\\', '"':
		sb.WriteByte('\\')
		sb.WriteByte(c)
	case '\b':
		sb.WriteString(`\b`)
	case '\f':
		sb.WriteString(`\f`)
	case '\n':
		sb.WriteString(`\n`)
	case '\r':
		sb.WriteString(`\r`)
	case '\t':
		sb.WriteString(`\t`)
	default:
		sb.WriteString(`\u00`)
		sb.WriteByte(jsonHex[c>>nibbleBits])
		sb.WriteByte(jsonHex[c&nibbleMask])
	}
}
