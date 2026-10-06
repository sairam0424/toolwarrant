package crawl

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// maxErrorMessageBytes caps server text copied into an RPCError.
	maxErrorMessageBytes = 256
	// maxServerInfoBytes caps serverInfo text copied into a Result.
	maxServerInfoBytes = 256
	// maxProtocolVersionBytes caps the negotiated protocol version, which is
	// echoed back in a request header.
	maxProtocolVersionBytes = 64
	// maxSessionIDBytes caps the session id, which is echoed back in a header.
	maxSessionIDBytes = 512
	// firstVisibleASCII and lastVisibleASCII bound the bytes the MCP spec
	// allows in a session id.
	firstVisibleASCII = 0x21
	lastVisibleASCII  = 0x7e
)

// rpcErrorBody is the JSON-RPC error object.
type rpcErrorBody struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// decodeObject parses raw as exactly one JSON object and returns its members
// as raw JSON, byte for byte.
//
// It is stricter than encoding/json on purpose. Duplicate keys are rejected
// because different parsers keep different duplicates, which would let the
// crawler and the gateway disagree about a tool. Keys are matched exactly
// (encoding/json would match "Name" to "name"), invalid UTF-8 is rejected,
// and trailing data after the object is rejected.
func decodeObject(raw []byte) (map[string]json.RawMessage, error) {
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("%w: invalid UTF-8", ErrMalformed)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("%w: invalid JSON", ErrMalformed)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("%w: not a JSON object", ErrMalformed)
	}
	fields := map[string]json.RawMessage{}
	for dec.More() {
		keyTok, err := dec.Token()
		key, isString := keyTok.(string)
		if err != nil || !isString {
			return nil, fmt.Errorf("%w: invalid JSON object", ErrMalformed)
		}
		if _, dup := fields[key]; dup {
			return nil, fmt.Errorf("%w: duplicate object key", ErrMalformed)
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, fmt.Errorf("%w: invalid JSON value", ErrMalformed)
		}
		fields[key] = value
	}
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("%w: unterminated JSON object", ErrMalformed)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: data after JSON object", ErrMalformed)
	}
	return fields, nil
}

// isNull reports whether raw is absent or the JSON literal null.
func isNull(raw json.RawMessage) bool {
	return len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

// matchMessage inspects one JSON-RPC message from the server. It reports
// matched=true with the response result when the message answers request id,
// an *RPCError when it answers with an error, and matched=false for anything
// else, such as notifications, server-initiated requests and responses to
// other ids, which the caller ignores.
func matchMessage(data []byte, id int) (result json.RawMessage, matched bool, err error) {
	fields, err := decodeObject(data)
	if err != nil {
		return nil, false, err
	}
	if _, isCall := fields["method"]; isCall {
		return nil, false, nil
	}
	rawID := bytes.TrimSpace(fields["id"])
	isOurs := bytes.Equal(rawID, []byte(strconv.Itoa(id)))
	idIsNull := bytes.Equal(rawID, []byte("null"))
	errBody, hasError := fields["error"]
	hasError = hasError && !isNull(errBody)
	// A server that cannot even parse our request answers with id null; only
	// one request is ever in flight, so that error is ours.
	if !isOurs && (!hasError || !idIsNull) {
		return nil, false, nil
	}
	if hasError {
		return nil, true, parseRPCError(errBody)
	}
	if isNull(fields["result"]) {
		return nil, false, fmt.Errorf("%w: response has neither result nor error", ErrMalformed)
	}
	return fields["result"], true, nil
}

// parseRPCError turns a JSON-RPC error object into an *RPCError, or into
// ErrMalformed when it is not one.
func parseRPCError(raw json.RawMessage) error {
	var body rpcErrorBody
	if err := json.Unmarshal(raw, &body); err != nil {
		return fmt.Errorf("%w: invalid JSON-RPC error object", ErrMalformed)
	}
	return &RPCError{Code: body.Code, Message: sanitizeText(body.Message, maxErrorMessageBytes)}
}

// parseToolsPage extracts the tools array and the next cursor from a
// tools/list result. Each returned tool is the exact bytes the server sent;
// whether a tool is usable is decided per tool by vetTool, not here, so that
// one bad tool cannot hide the rest of the page.
func parseToolsPage(result json.RawMessage) (tools []json.RawMessage, next string, err error) {
	fields, err := decodeObject(result)
	if err != nil {
		return nil, "", err
	}
	rawTools := bytes.TrimSpace(fields["tools"])
	if len(rawTools) == 0 || rawTools[0] != '[' {
		return nil, "", fmt.Errorf("%w: result has no tools array", ErrMalformed)
	}
	if err := json.Unmarshal(rawTools, &tools); err != nil {
		return nil, "", fmt.Errorf("%w: invalid tools array", ErrMalformed)
	}
	if rawCursor, ok := fields["nextCursor"]; ok && !isNull(rawCursor) {
		if err := json.Unmarshal(rawCursor, &next); err != nil {
			return nil, "", fmt.Errorf("%w: nextCursor is not a string", ErrMalformed)
		}
		if len(next) > maxCursorBytes || !utf8.ValidString(next) {
			return nil, "", fmt.Errorf("%w: unusable nextCursor", ErrMalformed)
		}
	}
	return tools, next, nil
}

// initInfo is what the initialize result tells us.
type initInfo struct {
	protocol string
	name     string
	version  string
}

// parseInitResult reads the negotiated protocol version, which is required,
// and the optional serverInfo.
func parseInitResult(result json.RawMessage) (initInfo, error) {
	fields, err := decodeObject(result)
	if err != nil {
		return initInfo{}, err
	}
	var info initInfo
	if err := json.Unmarshal(fields["protocolVersion"], &info.protocol); err != nil || !validProtocolVersion(info.protocol) {
		return initInfo{}, fmt.Errorf("%w: initialize result has no usable protocolVersion", ErrMalformed)
	}
	var server struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	// serverInfo is informational, so a bad one is dropped, not fatal.
	if err := json.Unmarshal(fields["serverInfo"], &server); err == nil {
		info.name = sanitizeText(server.Name, maxServerInfoBytes)
		info.version = sanitizeText(server.Version, maxServerInfoBytes)
	}
	return info, nil
}

// validProtocolVersion accepts the date-like tokens MCP uses and rejects
// anything that could be abused once echoed into a request header.
func validProtocolVersion(v string) bool {
	if v == "" || len(v) > maxProtocolVersionBytes {
		return false
	}
	for _, r := range v {
		if r > unicode.MaxASCII || (!unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '.') {
			return false
		}
	}
	return true
}

// validSessionID applies the MCP rule that a session id is non-empty visible
// ASCII, and bounds its length.
func validSessionID(id string) bool {
	if id == "" || len(id) > maxSessionIDBytes {
		return false
	}
	for i := 0; i < len(id); i++ {
		if id[i] < firstVisibleASCII || id[i] > lastVisibleASCII {
			return false
		}
	}
	return true
}

// sanitizeText makes server-supplied text safe to put in an error or a
// record: control characters and invalid UTF-8 become spaces and the result
// is cut to at most limit bytes on a rune boundary.
func sanitizeText(s string, limit int) string {
	var b strings.Builder
	for _, r := range s {
		if r == utf8.RuneError || unicode.IsControl(r) {
			r = ' '
		}
		if b.Len()+utf8.RuneLen(r) > limit {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}
