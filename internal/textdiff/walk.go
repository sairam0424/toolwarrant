package textdiff

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// decodeJSON parses exactly one JSON document. Numbers stay as their original
// text so pretty-printing never rewrites them. Trailing data is an error: a
// document with anything after the value is not canonical JSON.
func decodeJSON(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("decode json: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("decode json: unexpected data after the document")
	}
	return v, nil
}

// prettyJSON renders v with sorted keys and two-space indentation and without
// a trailing newline. HTML escaping is off so "<" stays "<" and the approver
// reads the text the agent will read.
func prettyJSON(v any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return "", fmt.Errorf("encode json: %w", err)
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}

// stringEntry is one decoded string found in a document: either a string
// value or an object key. path is a display path such as $.a["b c"][0].
type stringEntry struct {
	path  string
	value string
	isKey bool
}

// collectStrings lists every string value and object key in v in a fixed
// order (keys sorted, arrays by index). The decoded text is used, not the raw
// JSON, because a JSON escape such as backslash-u-200b hides the character in the source.
func collectStrings(v any) []stringEntry {
	w := &walker{}
	w.visit(v, "$")
	return w.entries
}

type walker struct{ entries []stringEntry }

func (w *walker) visit(v any, path string) {
	switch t := v.(type) {
	case string:
		w.entries = append(w.entries, stringEntry{path: path, value: t})
	case []any:
		for i, el := range t {
			w.visit(el, path+"["+strconv.Itoa(i)+"]")
		}
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			child := path + keySegment(k)
			w.entries = append(w.entries, stringEntry{path: child, value: k, isKey: true})
			w.visit(t[k], child)
		}
	}
}

// keySegment renders an object key as a path segment. Simple keys print as
// .key; anything else is quoted and escaped so the path is unambiguous and
// safe to print. A quote inside the key is written \" and a real backslash is
// always doubled by the escaper, so distinct keys give distinct paths.
func keySegment(k string) string {
	if isSimpleKey(k) {
		return "." + k
	}
	return `["` + strings.ReplaceAll(escapeInline(k), `"`, `\"`) + `"]`
}

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

// stringValues returns the string values (not keys) by display path.
func stringValues(entries []stringEntry) map[string]string {
	out := make(map[string]string, len(entries))
	for _, e := range entries {
		if !e.isKey {
			out[e.path] = e.value
		}
	}
	return out
}
