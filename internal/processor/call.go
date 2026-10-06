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
// judged from live evidence: the digest the gateway last listed for the tool
// (observed) and the digest the latest crawl found upstream (LastSeen). A call
// is allowed only when the tool is approved and served, at least one piece of
// evidence exists, and every piece of evidence equals the approved digest.
func (s *Server) CheckRequest(ctx context.Context, req *api.McpRequest) (*api.McpRequestResult, error) {
	if req.GetMethod() != methodToolsCall {
		return passRequest(), nil
	}
	name, err := callName(req.GetMcpRequest())
	if err != nil {
		s.stats.callsDenied.Add(1)
		s.log.InfoContext(ctx, "tools/call denied", "server", s.server,
			"cause", "unreadable request", "err", quoteErr(err))
		return denyRequest(api.AuthorizationError_INVALID, reasonCallUnreadable), nil
	}
	snap, err := s.current(ctx)
	if err != nil {
		s.noteSourceError(ctx, methodToolsCall, err)
		s.stats.callsDenied.Add(1)
		return denyRequest(api.AuthorizationError_PERMISSION_DENIED, callReason(name, causeUnavailable)), nil
	}
	if c, ok := s.judgeCall(snap, name); !ok {
		s.stats.callsDenied.Add(1)
		s.log.InfoContext(ctx, "tools/call denied", "server", s.server,
			"tool", quoteName(name), "cause", string(c))
		return denyRequest(api.AuthorizationError_PERMISSION_DENIED, callReason(name, c)), nil
	}
	s.stats.callsAllowed.Add(1)
	if s.log.Enabled(ctx, slog.LevelDebug) { // the hot path: skip the quoting when nobody listens
		s.log.DebugContext(ctx, "tools/call allowed", "server", s.server, "tool", quoteName(name))
	}
	return passRequest(), nil
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

// judgeCall applies the call policy to one tool name and returns the cause
// class when the call must be denied.
func (s *Server) judgeCall(snap catalog.Snapshot, name string) (cause, bool) {
	policy, inCatalog := snap.Tools[name]
	// snap.Serves is the single definition of "may be served": asking it with
	// the approved digest as the live one answers "could this tool ever be
	// served", which rules out missing, unapproved, disabled, deprecated and
	// pending tools without this package knowing the lifecycle states.
	if !inCatalog || !snap.Serves(name, policy.Approved) {
		return causeNotApproved, false
	}
	if seen, listed := s.observedDigest(name); listed && seen != policy.Approved {
		return causeChanged, false
	}
	switch {
	case policy.LastSeen == "":
		// Absent at the last crawl, or never crawled: nothing says the upstream
		// still serves the approved definition.
		return causeUnverified, false
	case policy.LastSeen != policy.Approved:
		return causeChanged, false
	}
	return "", true
}
