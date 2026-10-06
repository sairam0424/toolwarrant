package crawl

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/sairam0424/toolwarrant/internal/gate"
	"github.com/sairam0424/toolwarrant/internal/strictjson"
	"github.com/sairam0424/toolwarrant/internal/toolname"
)

// Reason says which rule an unusable tool broke. The values are short fixed
// tokens that carry no upstream bytes, so they can be stored in an audit
// record and shown as they are.
type Reason string

const (
	// ReasonUnreadable means the listed value is not a JSON object with
	// unique, unambiguous top-level keys and a string "name": a bare string in
	// the tools array, a duplicate or case-variant key, a numeric name,
	// invalid UTF-8, trailing bytes, and so on. Nothing about such a tool can
	// be trusted, not even its name.
	ReasonUnreadable Reason = "unreadable"
	// ReasonInvalidName means the name breaks the shared rule in
	// internal/toolname (empty, over 256 bytes, not NFC, control or invisible
	// characters, padding spaces), or its JSON literal holds a lone surrogate
	// that encoding/json would silently decode as U+FFFD. No component can
	// address such a tool, so no name is reported for it.
	ReasonInvalidName Reason = "invalid-name"
	// ReasonTooLarge means the definition is longer than Options.MaxToolBytes.
	// It is reported without being hashed.
	ReasonTooLarge Reason = "too-large"
	// ReasonTooDeep means arrays and objects nest deeper than maxToolDepth
	// levels.
	ReasonTooDeep Reason = "too-deep"
	// ReasonNotCanonical means RFC 8785 canonicalisation, as internal/gate
	// applies it, refused the definition (a lone surrogate escape in a key or
	// a value, a number that IEEE 754 double precision cannot hold exactly, a
	// duplicate key below the top level), so no digest exists for it.
	ReasonNotCanonical Reason = "not-canonical"
	// ReasonDuplicateName means another listed tool carries the same name.
	// Every copy is unusable, because a gateway may route a call to any of
	// them and the approved one cannot be told from the impostor by name.
	ReasonDuplicateName Reason = "duplicate-name"
)

// Fixed details for rules whose underlying error text must not be passed on.
const (
	// detailNameLiteral explains ReasonInvalidName when the name decodes but
	// its JSON literal does not canonicalise.
	detailNameLiteral = "the name's JSON literal holds a lone surrogate escape"
	// detailNotJSON explains an unreadable verdict from the depth walk, which
	// readName has normally ruled out already.
	detailNotJSON = "not well-formed JSON"
	// detailNotCanonical stands in for the canonicaliser's own message, which
	// may quote bytes from the definition.
	detailNotCanonical = "RFC 8785 canonicalisation refused the definition: a lone surrogate escape, a number that double precision cannot hold exactly, or a duplicate key below the top level"
)

// literalWrapOpen wraps a name's JSON literal in an object for the
// canonicaliser, which is written for whole documents.
const literalWrapOpen = `{"n":`

// UnusableTool is a listed tool the crawl could not accept. It is reported
// rather than dropped so that the catalog can mark the name as unusable, a
// serving veto, instead of treating the tool as absent, and so that nothing an
// upstream sent is silently lost.
type UnusableTool struct {
	// Name is the tool's name when it could be read and passes the shared
	// tool-name rule; otherwise it is empty. It is never a name the catalog
	// would refuse, but it is still upstream text: quote it before showing it.
	Name string
	// Raw is the exact bytes the server sent, bounded by Options.MaxMessageBytes.
	Raw json.RawMessage
	// Reason says which rule the tool broke.
	Reason Reason
	// Detail says more precisely how, in fixed words that carry code points
	// and numbers but never upstream bytes (the rune a name may not contain,
	// the size or depth against its cap, how often a name was listed), so
	// that it can be stored in an audit record and shown as it is.
	Detail string
}

// vetTool applies to one listed tool every rule the digest and the catalog
// apply later, cheapest first, and returns the name the tool is listed under,
// the first rule it breaks (empty when it is usable) and the detail for the
// record. The name is empty whenever it cannot be trusted. Repeated names are
// judged over the whole listing by finish.
func vetTool(raw []byte, maxBytes int) (name string, reason Reason, detail string) {
	name, literal, err := readName(raw)
	if err != nil {
		return "", ReasonUnreadable, detailOf(err)
	}
	if err := toolname.Validate(name); err != nil {
		return "", ReasonInvalidName, detailOf(err)
	}
	if !literalCanonicalises(literal) {
		return "", ReasonInvalidName, detailNameLiteral
	}
	if len(raw) > maxBytes {
		return name, ReasonTooLarge, fmt.Sprintf("%d bytes, the cap is %d", len(raw), maxBytes)
	}
	depth, ok := jsonDepth(raw)
	switch {
	case !ok:
		return "", ReasonUnreadable, detailNotJSON
	case depth > maxToolDepth:
		return name, ReasonTooDeep, fmt.Sprintf("nests %d levels, the cap is %d", depth, maxToolDepth)
	}
	if _, err := gate.CanonicalTool(raw); err != nil {
		return name, ReasonNotCanonical, detailNotCanonical
	}
	return name, "", ""
}

// detailOf reduces an error from readName or toolname.Validate to the words
// after its sentinel. Both build their messages from fixed strings and code
// points only, never from upstream bytes, so the result is safe to keep.
func detailOf(err error) string {
	msg := err.Error()
	for _, sentinel := range []error{ErrMalformed, toolname.ErrInvalid} {
		msg = strings.TrimPrefix(msg, sentinel.Error()+": ")
	}
	return msg
}

// readName reads the "name" member of one listed tool with the strictness the
// digest uses: exactly one JSON object, no duplicate or case-variant top-level
// keys, valid UTF-8, and a string name. It returns the decoded name and the
// name's JSON literal. Its errors are fixed text wrapping ErrMalformed.
func readName(raw []byte) (string, json.RawMessage, error) {
	if err := strictjson.Object(raw); err != nil {
		if errors.Is(err, strictjson.ErrAmbiguousKeys) {
			return "", nil, fmt.Errorf("%w: tool has duplicate or ambiguous keys", ErrMalformed)
		}
		return "", nil, fmt.Errorf("%w: tool is not a valid JSON object", ErrMalformed)
	}
	fields, err := decodeObject(raw)
	if err != nil {
		return "", nil, fmt.Errorf("%w: tool is not a valid JSON object", ErrMalformed)
	}
	literal := bytes.TrimSpace(fields["name"])
	// The literal must be a JSON string: Unmarshal would quietly leave the
	// name empty for null, which is "no name", not "an empty name".
	if !bytes.HasPrefix(literal, []byte{'"'}) {
		return "", nil, fmt.Errorf("%w: tool has no string name", ErrMalformed)
	}
	var name string
	if err := json.Unmarshal(literal, &name); err != nil {
		return "", nil, fmt.Errorf("%w: tool has no string name", ErrMalformed)
	}
	return name, literal, nil
}

// literalCanonicalises reports whether the JSON literal of a name survives RFC
// 8785 canonicalisation. encoding/json decodes a lone surrogate escape such as
// \ud800 to U+FFFD without complaint, so a name read through it could be a
// look-alike of what the server sent; the canonicaliser refuses the literal
// instead, and so must the crawler, or it would report a name no component can
// match.
func literalCanonicalises(literal json.RawMessage) bool {
	wrapped := make([]byte, 0, len(literalWrapOpen)+len(literal)+1)
	wrapped = append(wrapped, literalWrapOpen...)
	wrapped = append(wrapped, literal...)
	wrapped = append(wrapped, '}')
	_, err := gate.Canonical(wrapped)
	return err == nil
}

// jsonDepth returns the deepest nesting of arrays and objects in raw, counting
// the outermost value as level 1. ok is false, with a depth of 0, when raw is
// not well-formed JSON (a truncated value included), which readName has
// already ruled out; the check stays so that the function fails closed on its
// own. Numbers are read as text so that a value outside the double range does
// not end the walk: here they are structure, not values.
func jsonDepth(raw []byte) (int, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	depth, deepest := 0, 0
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			if depth != 0 {
				return 0, false
			}
			return deepest, true
		}
		if err != nil {
			return 0, false
		}
		delim, isDelim := tok.(json.Delim)
		if !isDelim {
			continue
		}
		if delim == '{' || delim == '[' {
			depth++
			deepest = max(deepest, depth)
			continue
		}
		depth--
	}
}
