package textdiff

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// decodeJSON parses exactly one JSON document. Numbers stay as their original
// text so pretty-printing never rewrites them. Trailing data is an error: a
// document with anything after the value is not canonical JSON. Bytes that are
// not valid UTF-8 are an error too, because the decoder would otherwise turn
// them into U+FFFD without saying so and the approver would review a text the
// upstream never sent.
func decodeJSON(raw []byte) (any, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("decode json: not valid UTF-8")
	}
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

// noIndex marks a pathNode that is an object key or the root, not an array
// element.
const noIndex = -1

// pathNode is one segment of a display path such as $.a["b c"][0]. A node
// points at its parent and holds only its own segment, so the strings of a
// document share their prefixes: the path text is built only for the few
// entries that are printed. The first version built a full string per value,
// which for a 255-deep array of 65,000 items was 50 MB of paths.
type pathNode struct {
	parent *pathNode
	key    string
	index  int
}

// rootNode returns the node that renders as "$".
func rootNode() *pathNode {
	return &pathNode{index: noIndex}
}

// child returns the node for key k below n.
func (n *pathNode) child(k string) *pathNode {
	return &pathNode{parent: n, key: k, index: noIndex}
}

// element returns the node for array index i below n.
func (n *pathNode) element(i int) *pathNode {
	return &pathNode{parent: n, index: i}
}

// String renders the display path, escaped and safe to print.
func (n *pathNode) String() string {
	var chain []*pathNode
	for p := n; p.parent != nil; p = p.parent {
		chain = append(chain, p)
	}
	var sb strings.Builder
	sb.WriteByte('$')
	for i := len(chain) - 1; i >= 0; i-- {
		seg := chain[i]
		if seg.index != noIndex {
			sb.WriteByte('[')
			sb.WriteString(strconv.Itoa(seg.index))
			sb.WriteByte(']')
			continue
		}
		sb.WriteString(keySegment(seg.key))
	}
	return sb.String()
}

// stringEntry is one decoded string found in a document: either a string
// value or an object key. For a key, node is the path of the member it names.
type stringEntry struct {
	node  *pathNode
	value string
	isKey bool
}

// walkStrings calls visit for every string value and object key in v in a
// fixed order (keys sorted, arrays by index). The decoded text is used, not
// the raw JSON, because a JSON escape such as backslash-u-200b hides the
// character in the source.
func walkStrings(v any, node *pathNode, visit func(stringEntry)) {
	switch t := v.(type) {
	case string:
		visit(stringEntry{node: node, value: t})
	case []any:
		for i, el := range t {
			walkStrings(el, node.element(i), visit)
		}
	case map[string]any:
		for _, k := range sortedKeys(t) {
			child := node.child(k)
			visit(stringEntry{node: child, value: k, isKey: true})
			walkStrings(t[k], child, visit)
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
