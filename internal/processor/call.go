package processor

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	api "github.com/sairam0424/toolwarrant/internal/extmcpv1"
	"github.com/sairam0424/toolwarrant/internal/mcpwire"
	"github.com/sairam0424/toolwarrant/internal/strictjson"
)

// CheckRequest denies a tools/call unless the tool's approval is current, and
// passes every other method through.
//
// The hook carries only the tool's name, not its definition, so "current" is
// judged from live evidence: what the gateway last listed for the tool
// (observed) and the digest the latest crawl found upstream (LastSeen). A call
// is allowed only when the tool is approved and served, at least one piece of
// evidence exists, and no piece of evidence contradicts the approved digest;
// see judgeCall for the exact rule.
func (s *Server) CheckRequest(ctx context.Context, req *api.McpRequest) (*api.McpRequestResult, error) {
	hooked := req.GetMethod() == methodToolsCall
	if d := s.admit(ctx, req.GetMetadataContext(), req.GetServiceNames(), hooked); d != nil {
		return s.refuseCall(ctx, hooked, d), nil
	}
	if !hooked {
		return passRequest(), nil
	}
	release, ok := s.acquire()
	if !ok {
		return s.denyCall(ctx, api.AuthorizationError_RESOURCE_EXHAUSTED, "", causeThrottled, errThrottled), nil
	}
	defer release()
	name, err := callName(req.GetMcpRequest())
	if err != nil {
		return s.denyCall(ctx, api.AuthorizationError_INVALID, "", causeUnreadable, err), nil
	}
	cur, err := s.current(ctx)
	if err != nil {
		s.noteSourceError(ctx, methodToolsCall, err)
		return s.denyCall(ctx, api.AuthorizationError_PERMISSION_DENIED, name, causeUnavailable, nil), nil
	}
	if c, ok := s.judgeCall(cur.snap, name); !ok {
		return s.denyCall(ctx, api.AuthorizationError_PERMISSION_DENIED, name, c, nil), nil
	}
	s.stats.callsAllowed.Add(1)
	if s.log.Enabled(ctx, slog.LevelDebug) { // the hot path: skip the quoting when nobody listens
		s.log.DebugContext(ctx, "tools/call allowed", "server", s.server, "tool", quoteName(name))
	}
	return passRequest(), nil
}

// refuseCall turns an admission denial into a result. For tools/call it is a
// counted denial; for any other method the hook is refused without touching
// the call counters, because it was never about a call.
func (s *Server) refuseCall(ctx context.Context, hooked bool, d *denial) *api.McpRequestResult {
	if hooked {
		return s.denyCall(ctx, d.code, "", d.cause, nil)
	}
	s.log.InfoContext(ctx, "hook denied", "server", s.server, "cause", string(d.cause))
	return denyRequest(d.code, deniedReason(methodHook, d.cause))
}

// denyCall counts and logs a refused tools/call and builds its result. name is
// "" when the request was refused before its tool name could be read; the
// reason then carries only the cause class.
func (s *Server) denyCall(ctx context.Context, code api.AuthorizationError_Code, name string, c cause, err error) *api.McpRequestResult {
	s.stats.callsDenied.Add(1)
	attrs := []any{"server", s.server, "cause", string(c)}
	if name != "" {
		attrs = append(attrs, "tool", quoteName(name))
	}
	if err != nil {
		attrs = append(attrs, "err", quoteErr(err))
	}
	s.log.InfoContext(ctx, "tools/call denied", attrs...)
	if name == "" {
		return denyRequest(code, deniedReason(methodToolsCall, c))
	}
	return denyRequest(code, callReason(name, c))
}

// callName extracts the tool name from tools/call params. The params are first
// checked for keys that a different parser could resolve to another tool.
func callName(params []byte) (string, error) {
	if len(params) > maxPayloadBytes {
		return "", errPayloadSize
	}
	if err := strictjson.Object(params); err != nil {
		return "", fmt.Errorf("read tools/call params: %w", err)
	}
	name, err := mcpwire.ToolCallName(params)
	if err != nil {
		return "", fmt.Errorf("read tool name: %w", err)
	}
	return name, nil
}

// judgeCall applies the call rule to one tool name and returns the cause class
// when the call must be denied. The evidence is what the gateway last listed
// for the tool (observed) and what the latest crawl saw (LastSeen):
//
//   - not in the catalog, or in a state that can never serve: not approved;
//   - any present evidence other than the approved digest (including the
//     conflict marker a bad page leaves behind): changed since approval;
//   - a LastSeen that is not a digest, such as the catalog's "unusable"
//     marker: the crawl could not verify the live definition;
//   - no evidence at all: not yet verified.
//
// A LastSeen of "" (absent at the last crawl) is not a contradiction once the
// gateway itself has listed the approved definition, so observed alone allows
// the call then.
func (s *Server) judgeCall(snap catalog.Snapshot, name string) (cause, bool) {
	policy, inCatalog := snap.Tools[name]
	// snap.Serves is the single definition of "may be served": asking it with
	// the approved digest as the live one answers "could this tool ever be
	// served", which rules out missing, unapproved, disabled, deprecated and
	// pending tools without this package knowing the lifecycle states.
	if !inCatalog || !snap.Serves(name, policy.Approved) {
		return causeNotApproved, false
	}
	observed, listed := s.observedDigest(name)
	if listed && observed != policy.Approved {
		return causeChanged, false
	}
	switch {
	case policy.LastSeen == policy.Approved:
		return "", true
	case policy.LastSeen == "":
		if listed {
			return "", true
		}
		return causeUnverified, false
	case !isDigest(policy.LastSeen):
		return causeUnverified, false
	default:
		return causeChanged, false
	}
}

// crawlVerifiable reports whether a LastSeen value can be weighed as evidence
// at all: a digest, or "" for a tool the latest crawl did not list, which D9
// does not count against the gateway's own listing. Anything else is a marker
// the catalog uses to say the live definition could not be verified; such a
// tool is neither listed (judgeListed) nor callable (judgeCall) until a clean
// crawl records a digest, so what a client sees is exactly what it may call.
func crawlVerifiable(lastSeen string) bool {
	return lastSeen == "" || isDigest(lastSeen)
}

// isDigest reports whether s has the shape of a gate digest: SHA-256 as 64
// lowercase hex characters. Anything else stored in LastSeen is a marker the
// catalog uses to say the live definition could not be verified.
func isDigest(s string) bool {
	if len(s) != digestHexLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
