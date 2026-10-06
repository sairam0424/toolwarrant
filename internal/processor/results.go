package processor

import (
	"strconv"
	"strings"
	"unicode/utf8"

	api "github.com/sairam0424/toolwarrant/internal/extmcpv1"
)

// cause is the class of reason a call was denied. Reasons go back to the
// client, so they name the tool and the class and nothing else: never a
// digest, a state or any catalog content.
type cause string

const (
	causeNotApproved cause = "not approved"
	causeChanged     cause = "changed since approval"
	causeUnverified  cause = "not yet verified"
	causeUnavailable cause = "catalog unavailable"
)

const (
	reasonListUnavailable  = "tools/list denied: catalog unavailable"
	reasonListUnverifiable = "tools/list denied: tool list could not be verified"
	reasonCallUnreadable   = "tools/call denied: request could not be read"

	// maxNameBytes caps a tool name in a log line or reason, so a hostile
	// multi-megabyte name cannot bloat logs or responses.
	maxNameBytes   = 256
	truncationMark = "..."
	// maxLoggedNames caps the hidden names listed in one log line.
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

// callReason is the client-facing reason for a denied tools/call.
func callReason(name string, c cause) string {
	return "tool " + quoteName(name) + ": " + string(c)
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
