package processor

import (
	"strconv"
	"strings"
	"unicode/utf8"

	api "github.com/sairam0424/toolwarrant/internal/extmcpv1"
)

// cause is the class of reason a hook was denied. Reasons go back to the
// client, so they name the tool (when it was read) and the class and nothing
// else: never a digest, a state or any catalog content.
type cause string

const (
	causeNotApproved     cause = "not approved"
	causeChanged         cause = "changed since approval"
	causeUnverified      cause = "not yet verified"
	causeStale           cause = "crawl evidence too old"
	causeUnavailable     cause = "catalog unavailable"
	causeUnreadable      cause = "request could not be read"
	causeWrongBackend    cause = "wrong backend"
	causeUnauthenticated cause = "wrong or missing processor secret"
	causeThrottled       cause = "too many concurrent hooks"
)

const (
	reasonListUnavailable  = "tools/list denied: catalog unavailable"
	reasonListUnverifiable = "tools/list denied: tool list could not be verified"
	reasonListThrottled    = "tools/list denied: too many concurrent hooks"
	reasonCallUnreadable   = "tools/call denied: request could not be read"
	reasonCallThrottled    = "tools/call denied: too many concurrent hooks"

	// methodHook names the method in a reason for a hook refused before its
	// method mattered, so the reason never echoes a method string the caller
	// chose.
	methodHook = "hook"

	// maxNameBytes caps a tool name in a log line or reason, so a hostile
	// multi-megabyte name cannot bloat logs or responses.
	maxNameBytes   = 256
	truncationMark = "..."
	// maxLoggedNames caps the names listed in one log line.
// The same cap bounds the per-tool `digest mismatch` lines written for one
// tools/list page (logMismatches in list.go), in page order; the summary
// line's mismatched= count carries the full number.
	maxLoggedNames = 10
	// maxErrBytes caps an error message in a log line.
	maxErrBytes = 512
)

// quoteName renders an untrusted tool name for a log line or a reason. The
// strconv.Quote escapes newlines, control characters and bidi overrides, so a
// name cannot start a fake log line or reorder the text around it.
func quoteName(name string) string {
	return strconv.Quote(truncate(name, maxNameBytes))
}

// quoteErr renders an error for a log line in the same safe form. Errors from
// parsing hostile input can carry fragments of it.
func quoteErr(err error) string {
	if err == nil {
		return `""`
	}
	return strconv.Quote(truncate(err.Error(), maxErrBytes))
}

// quoteNames renders up to maxLoggedNames names as one log value.
func quoteNames(names []string) string {
	shown := names
	if len(shown) > maxLoggedNames {
		shown = shown[:maxLoggedNames]
	}
	quoted := make([]string, len(shown))
	for i, n := range shown {
		quoted[i] = quoteName(n)
	}
	out := strings.Join(quoted, ", ")
	if extra := len(names) - len(shown); extra > 0 {
		out += " (+" + strconv.Itoa(extra) + " more)"
	}
	return out
}

// truncate shortens s to at most max bytes without splitting a UTF-8 sequence.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + truncationMark
}

// callReason is the client-facing reason for a tools/call denied after its
// tool name was read.
func callReason(name string, c cause) string {
	return "tool " + quoteName(name) + ": " + string(c)
}

// deniedReason is the client-facing reason for a hook refused before its
// payload was read: the method and the cause class, nothing else.
func deniedReason(method string, c cause) string {
	return method + " denied: " + string(c)
}

func passRequest() *api.McpRequestResult {
	return &api.McpRequestResult{Result: &api.McpRequestResult_Pass{Pass: &api.Pass{}}}
}

func denyRequest(code api.AuthorizationError_Code, reason string) *api.McpRequestResult {
	return &api.McpRequestResult{Result: &api.McpRequestResult_Error{
		Error: &api.AuthorizationError{Code: code, Reason: reason}}}
}

func passResponse() *api.McpResponseResult {
	return &api.McpResponseResult{Result: &api.McpResponseResult_Pass{Pass: &api.Pass{}}}
}

func mutatedResponse(out []byte) *api.McpResponseResult {
	return &api.McpResponseResult{Result: &api.McpResponseResult_Mutated{Mutated: out}}
}

func denyResponse(code api.AuthorizationError_Code, reason string) *api.McpResponseResult {
	return &api.McpResponseResult{Result: &api.McpResponseResult_Error{
		Error: &api.AuthorizationError{Code: code, Reason: reason}}}
}
