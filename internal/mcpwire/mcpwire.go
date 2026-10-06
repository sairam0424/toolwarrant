// Package mcpwire holds the small, pure helpers that work on raw MCP JSON-RPC
// payloads as they pass through an ExtMCP processor.
//
// Nothing here knows about gRPC, SQLite or policy. Keeping these functions pure
// makes them easy to test and lets a hash over a served tool definition stay
// stable: tool objects are passed through as raw JSON, never decoded into Go
// types that would drop unknown fields or rewrite numbers.
package mcpwire

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// ErrNoTools means a tools/list result had no usable "tools" array. Callers
// should treat it as a reason to fail closed, not to pass the result through.
var ErrNoTools = errors.New("mcpwire: result has no tools array")

// FilterToolsList removes every tool for which allow returns false from a
// tools/list JSON-RPC result and returns the rewritten result plus the names
// that were dropped (in their original order).
//
// Every other top-level field (nextCursor, _meta, extensions) and the bytes of
// every kept tool are preserved. A result that is not valid JSON, has no tools
// array, or contains a tool without a string name is an error: a gate that
// cannot read a tool must not let it through.
func FilterToolsList(raw []byte, allow func(name string) bool) (out []byte, dropped []string, err error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, nil, fmt.Errorf("mcpwire: tools/list result is not a JSON object: %w", err)
	}
	rawTools, ok := top["tools"]
	if !ok {
		return nil, nil, ErrNoTools
	}
	var tools []json.RawMessage
	if err := json.Unmarshal(rawTools, &tools); err != nil || tools == nil {
		return nil, nil, ErrNoTools
	}

	kept := make([]json.RawMessage, 0, len(tools))
	for i, t := range tools {
		var head struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(t, &head); err != nil || head.Name == "" {
			return nil, nil, fmt.Errorf("mcpwire: tool %d has no string name", i)
		}
		if allow(head.Name) {
			kept = append(kept, t)
		} else {
			dropped = append(dropped, head.Name)
		}
	}

	encodedTools, err := marshalNoEscape(kept)
	if err != nil {
		return nil, nil, err
	}
	top["tools"] = encodedTools
	out, err = marshalNoEscape(top)
	if err != nil {
		return nil, nil, err
	}
	return out, dropped, nil
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

// marshalNoEscape is json.Marshal without HTML escaping. The default encoder
// rewrites <, > and & inside raw messages to < and friends, which changes
// a tool's bytes (and so any digest over them) without changing its meaning.
func marshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
