// Package mcpwire holds the small, pure helpers that work on raw MCP JSON-RPC
// payloads as they pass through an ExtMCP processor.
//
// Nothing here knows about gRPC, SQLite or policy. Keeping these functions pure
// makes them easy to test and lets a hash over a served tool definition stay
// stable: tool objects are passed through as raw JSON, never decoded into Go
// types that would drop unknown fields or rewrite numbers.
//
// A tools/list result is read with a streaming decoder, never materialised as
// a slice of entries: a page of a million tiny entries is refused at the
// caller's entry cap after reading that many entries and nothing else, and
// every entry handed to a caller is a slice of the input, not a copy.
package mcpwire

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const toolsKey = "tools"

var (
	// ErrNoTools means a tools/list result had no usable "tools" array. Callers
	// should treat it as a reason to fail closed, not to pass the result through.
	ErrNoTools = errors.New("mcpwire: result has no tools array")

	// ErrTooManyTools means a tools array holds more entries than the cap the
	// caller set. The scan stops at the first entry past the cap without
	// reading it, so a hostile page costs the caller the cap, never the page.
	ErrTooManyTools = errors.New("mcpwire: tools array has more entries than the cap")

	errNotObject = errors.New("mcpwire: tools/list result is not a JSON object")
)

// ToolsList is a tools/list result that has been read once and found to be a
// JSON object with a tools array: the entry point for callers that walk the
// entries more than once (the processor's two passes) without paying the
// top-level scan twice. Members that repeat at the top level are normalised the
// way encoding/json reads them, the last value winning, so a result rewritten
// from a ToolsList never carries two copies of a key that two parsers could
// read differently.
type ToolsList struct {
	members  []member
	tools    []byte
	maxTools int
}

// member is one top-level member of the result: the exact bytes of its key as
// written and of the value of its last occurrence.
type member struct {
	key   []byte
	value []byte
}

// skipValue is the decode target for a value that is only to be read past:
// encoding/json hands UnmarshalJSON a slice of its buffer, so skipping a value
// costs the scan and no copy.
type skipValue struct{}

func (*skipValue) UnmarshalJSON([]byte) error { return nil }

// toolHead is what is decoded from each entry: the name alone. Every other
// field is skipped by the decoder without being allocated.
type toolHead struct {
	Name string `json:"name"`
}

// ParseToolsList reads raw as a tools/list result. maxTools, when positive,
// caps the entries of every tools array on the page: the scan stops with
// ErrTooManyTools before reading the entry past the cap. A result that is not
// strictly valid JSON (the token stream alone would accept a trailing comma),
// is not an object, or whose tools member (the last one, when repeated) is not
// an array is an error, so the caller can fail closed.
func ParseToolsList(raw []byte, maxTools int) (*ToolsList, error) {
	if !json.Valid(raw) {
		return nil, fmt.Errorf("%w: not valid JSON", errNotObject)
	}
	return parse(raw, maxTools)
}

// parse is ParseToolsList after validation. Every error branch below is kept
// although validation makes most of them unreachable: a decoder that stops
// agreeing with json.Valid must fail the page, not pass it.
func parse(raw []byte, maxTools int) (*ToolsList, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := expectDelim(dec, '{'); err != nil {
		return nil, fmt.Errorf("%w: %w", errNotObject, err)
	}
	l := &ToolsList{maxTools: maxTools}
	index := make(map[string]int)
	for dec.More() {
		key, rawKey, err := readKey(dec, raw)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errNotObject, err)
		}
		value, err := readMember(dec, raw, key, maxTools)
		if err != nil {
			return nil, err
		}
		if i, seen := index[key]; seen {
			l.members[i].value = value
			continue
		}
		index[key] = len(l.members)
		l.members = append(l.members, member{key: rawKey, value: value})
	}
	if err := expectDelim(dec, '}'); err != nil {
		return nil, fmt.Errorf("%w: %w", errNotObject, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: data after the object", errNotObject)
	}
	i, ok := index[toolsKey]
	if !ok {
		return nil, ErrNoTools
	}
	l.tools = l.members[i].value
	if !startsArray(l.tools) {
		return nil, ErrNoTools
	}
	return l, nil
}

// readMember reads the value of one top-level member and returns its exact
// bytes. A tools array is walked entry by entry, so the decoder's buffer never
// has to hold the whole array and the cap is enforced here, before any caller
// sees a name; every other value is skipped in one piece.
func readMember(dec *json.Decoder, raw []byte, key string, maxTools int) ([]byte, error) {
	start := dec.InputOffset()
	if key == toolsKey && startsArray(raw[start:]) {
		skip := func(int, []byte) error { return nil }
		if err := eachElement(dec, raw, maxTools, func() any { return &skipValue{} }, skip); err != nil {
			return nil, err
		}
		return valueBytes(raw[start:dec.InputOffset()]), nil
	}
	if err := dec.Decode(&skipValue{}); err != nil {
		return nil, fmt.Errorf("%w: member %q: %w", errNotObject, key, err)
	}
	return valueBytes(raw[start:dec.InputOffset()]), nil
}

// Walk calls visit for every entry of the tools array in page order with the
// entry's name and its exact bytes, and builds nothing: a caller that only
// needs to count or check names pays for the scan alone. An entry without a
// string name is an error; an error from visit stops the walk and is returned
// as is.
func (l *ToolsList) Walk(visit func(name string, tool []byte) error) error {
	var head toolHead
	next := func() any {
		head.Name = ""
		return &head
	}
	return eachElement(json.NewDecoder(bytes.NewReader(l.tools)), l.tools, l.maxTools, next, func(i int, tool []byte) error {
		if head.Name == "" {
			return noName(i)
		}
		return visit(head.Name, tool)
	})
}

// Filter rewrites the result with every tool for which allow returns false
// removed and returns it with the names that were dropped, in page order.
// Every other top-level member and the bytes of every kept tool are written
// exactly as they arrived, members in their order of first appearance; only
// the whitespace between them is dropped. No value is re-encoded, so a digest
// over a kept tool is a digest over what the upstream sent.
func (l *ToolsList) Filter(allow func(name string, tool []byte) bool) (out []byte, dropped []string, err error) {
	var buf bytes.Buffer
	buf.Grow(len(l.tools) + 2)
	buf.WriteByte('{')
	for i, m := range l.members {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(m.key)
		buf.WriteByte(':')
		if bytes.Equal(m.value, l.tools) && string(l.keyOf(i)) == toolsKey {
			if dropped, err = l.writeTools(&buf, allow); err != nil {
				return nil, nil, err
			}
			continue
		}
		buf.Write(m.value)
	}
	buf.WriteByte('}')
	return buf.Bytes(), dropped, nil
}

// keyOf decodes the key of member i. Keys are kept as written for the output;
// the decoded form is only needed to find the tools member again.
func (l *ToolsList) keyOf(i int) string {
	var key string
	if err := json.Unmarshal(l.members[i].key, &key); err != nil {
		return ""
	}
	return key
}

// writeTools writes the filtered tools array into buf and returns the names
// it left out.
func (l *ToolsList) writeTools(buf *bytes.Buffer, allow func(name string, tool []byte) bool) ([]string, error) {
	var dropped []string
	kept := 0
	buf.WriteByte('[')
	err := l.Walk(func(name string, tool []byte) error {
		if !allow(name, tool) {
			dropped = append(dropped, name)
			return nil
		}
		if kept > 0 {
			buf.WriteByte(',')
		}
		kept++
		buf.Write(tool)
		return nil
	})
	if err != nil {
		return nil, err
	}
	buf.WriteByte(']')
	return dropped, nil
}

// FilterToolsList removes every tool for which allow returns false from a
// tools/list JSON-RPC result and returns the rewritten result plus the names
// that were dropped (in their original order).
//
// Every other top-level field (nextCursor, _meta, extensions) and the bytes of
// every kept tool are preserved. A result that is not valid JSON, has no tools
// array, or contains a tool without a string name is an error: a gate that
// cannot read a tool must not let it through.
func FilterToolsList(raw []byte, allow func(name string) bool) (out []byte, dropped []string, err error) {
	return FilterToolsListRaw(raw, func(name string, _ []byte) bool { return allow(name) })
}

// FilterToolsListRaw is FilterToolsList for callers that need to look at the
// tool itself, for example to compute a digest of its definition. allow gets
// the tool's name and its exact raw JSON bytes. There is no entry cap; a
// caller that must bound its work uses ParseToolsList.
func FilterToolsListRaw(raw []byte, allow func(name string, tool []byte) bool) (out []byte, dropped []string, err error) {
	l, err := ParseToolsList(raw, 0)
	if err != nil {
		return nil, nil, err
	}
	return l.Filter(allow)
}

// ToolCallName returns params.name from the params of a tools/call request.
func ToolCallName(params []byte) (string, error) {
	var p struct {
		Name any `json:"name"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return "", fmt.Errorf("mcpwire: tools/call params are not a JSON object: %w", err)
	}
	s, ok := p.Name.(string)
	if !ok || s == "" {
		return "", errors.New("mcpwire: tools/call params have no string name")
	}
	return s, nil
}

// eachElement reads the array at the decoder's position (its opening bracket
// not yet consumed) and calls visit with each element's index and exact bytes
// after decoding it into the value next returns. The element past maxTools
// (when positive) is never read: the walk stops with ErrTooManyTools first.
func eachElement(dec *json.Decoder, src []byte, maxTools int, next func() any, visit func(i int, elem []byte) error) error {
	if err := expectDelim(dec, '['); err != nil {
		return fmt.Errorf("%w: %w", ErrNoTools, err)
	}
	for i := 0; dec.More(); i++ {
		if maxTools > 0 && i >= maxTools {
			return ErrTooManyTools
		}
		start := dec.InputOffset()
		if err := dec.Decode(next()); err != nil {
			return fmt.Errorf("%w: %w", noName(i), err)
		}
		if err := visit(i, valueBytes(src[start:dec.InputOffset()])); err != nil {
			return err
		}
	}
	if err := expectDelim(dec, ']'); err != nil {
		return fmt.Errorf("%w: %w", ErrNoTools, err)
	}
	return nil
}

// expectDelim consumes one token and requires it to be the delimiter d.
func expectDelim(dec *json.Decoder, d json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if got, ok := tok.(json.Delim); !ok || got != d {
		return fmt.Errorf("expected %q, found %v", d, tok)
	}
	return nil
}

// readKey consumes one token and requires it to be an object key, returning
// it decoded and as written.
func readKey(dec *json.Decoder, src []byte) (string, []byte, error) {
	start := dec.InputOffset()
	tok, err := dec.Token()
	if err != nil {
		return "", nil, err
	}
	key, ok := tok.(string)
	if !ok {
		return "", nil, fmt.Errorf("expected a member name, found %v", tok)
	}
	return key, valueBytes(src[start:dec.InputOffset()]), nil
}

// startsArray reports whether the next value in b, after the separator and
// whitespace the decoder has not consumed yet, opens an array.
func startsArray(b []byte) bool {
	v := valueBytes(b)
	return len(v) > 0 && v[0] == '['
}

// valueBytes trims what the decoder leaves in front of a value it has just
// read: whitespace and the comma or colon that separated it from the previous
// token. No JSON value or key begins with any of these bytes, so the trim is
// exact.
func valueBytes(b []byte) []byte {
	return bytes.TrimLeft(b, " \t\r\n,:")
}

// noName is the error for an entry that is not an object with a string name.
func noName(i int) error {
	return fmt.Errorf("mcpwire: tool %d has no string name", i)
}
