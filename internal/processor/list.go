package processor

import (
	"context"
	"log/slog"

	api "github.com/sairam0424/toolwarrant/internal/extmcpv1"
)

// CheckResponse filters a tools/list result down to the tools whose current
// definition is the approved one, and passes every other method through.
//
// Every failure path returns an AuthorizationError. The one thing this hook
// must never do is hand back the upstream's list unfiltered, so a Pass result
// is only ever produced for a method other than tools/list.
func (s *Server) CheckResponse(ctx context.Context, resp *api.McpResponse) (*api.McpResponseResult, error) {
	hooked := resp.GetMethod() == methodToolsList
	if d := s.admit(ctx, resp.GetMetadataContext(), resp.GetServiceNames(), hooked); d != nil {
		return s.refuseList(ctx, hooked, d), nil
	}
	if !hooked {
		return passResponse(), nil
	}
	release, ok := s.acquire()
	if !ok {
		return s.denyList(ctx, api.AuthorizationError_RESOURCE_EXHAUSTED, reasonListThrottled, errThrottled), nil
	}
	defer release()
	cur, err := s.current(ctx)
	if err != nil {
		s.noteSourceError(ctx, methodToolsList, err)
		s.stats.listsDenied.Add(1)
		return denyResponse(api.AuthorizationError_PERMISSION_DENIED, reasonListUnavailable), nil
	}
	raw := resp.GetMcpResponse()
	if len(raw) > maxPayloadBytes {
		// Never parsed, so evidence about nothing: every servable tool of the
		// snapshot is marked before the page is denied, as for any page the
		// processor cannot read through to the end (D14).
		s.markPageUnread(ctx, cur)
		return s.denyList(ctx, api.AuthorizationError_INVALID, reasonListUnverifiable, errPayloadSize), nil
	}
	page, err := s.filterList(ctx, cur, raw)
	if err != nil {
		return s.denyList(ctx, api.AuthorizationError_INVALID, reasonListUnverifiable, err), nil
	}
	s.countServed(page)
	s.logList(ctx, page)
	// Always the re-encoded result, even when nothing was hidden: the gateway
	// then sees exactly what was parsed here, with no second "tools" key or
	// other duplicate that a different parser might read differently.
	return mutatedResponse(page.out), nil
}

// refuseList turns an admission denial into a result. For tools/list it is a
// counted denial of the page; for any other method the hook is refused
// without touching the list counters, because it was never about a list.
func (s *Server) refuseList(ctx context.Context, hooked bool, d *denial) *api.McpResponseResult {
	if hooked {
		return s.denyList(ctx, d.code, deniedReason(methodToolsList, d.cause), nil)
	}
	s.log.InfoContext(ctx, "hook denied", "server", s.server, "cause", string(d.cause))
	return denyResponse(d.code, deniedReason(methodHook, d.cause))
}

// denyList counts and logs a refused tools/list and builds the error result.
func (s *Server) denyList(ctx context.Context, code api.AuthorizationError_Code, reason string, err error) *api.McpResponseResult {
	s.stats.listsDenied.Add(1)
	s.log.InfoContext(ctx, "tools/list denied", "server", s.server, "reason", reason, "err", quoteErr(err))
	return denyResponse(code, reason)
}

// countServed accounts for one served page.
func (s *Server) countServed(page filtered) {
	s.stats.listsServed.Add(1)
	s.stats.toolsHidden.Add(uint64(len(page.hidden)))
	s.stats.toolsMismatched.Add(uint64(len(page.report.mismatched)))
	s.stats.toolsUnapproved.Add(uint64(page.report.unapproved))
	s.stats.toolsOversized.Add(uint64(page.report.oversized))
	s.stats.toolsUnverified.Add(uint64(page.report.unverified))
}

// logList reports one served page: at Info when something was hidden, at
// Debug otherwise, preceded by one Info line naming the tools hidden for a
// digest mismatch, which is the case an owner must act on (drift, or the
// re-serialisation limit in the package comment). Names are quoted and capped;
// no definition is ever logged.
func (s *Server) logList(ctx context.Context, page filtered) {
	if n := len(page.report.mismatched); n > 0 {
		s.log.InfoContext(ctx, "digest mismatch",
			"server", s.server, "tools", n, "names", quoteNames(page.report.mismatched))
	}
	level := slog.LevelDebug
	if len(page.hidden) > 0 {
		level = slog.LevelInfo
	}
	s.log.Log(ctx, level, "tools/list filtered",
		"server", s.server, "hidden", len(page.hidden), "hidden_tools", quoteNames(page.hidden),
		"unapproved", page.report.unapproved, "oversized", page.report.oversized, "unverified", page.report.unverified)
}
