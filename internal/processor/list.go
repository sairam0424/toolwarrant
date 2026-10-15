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
		// Never parsed, so evidence about nothing: every catalog tool of the
		// snapshot is marked before the page is denied, as for any page the
		// processor cannot read through to the end (D14, D15). Over the wire
		// the transport refuses such a message first and pageRefused does the
		// same; this branch is the rule for a caller that hands the page in.
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

// pageRefused is the processor's side of a CheckResponse message the gRPC
// transport refused for size (serve.go, watchRefusal). The message was never
// read, so nothing about it is known, not even its method; under the emitted
// configuration the gateway sends CheckResponse for tools/list only, and a
// page the processor could not read through to the end is evidence about
// nothing (D14), so every catalog tool of the snapshot is marked exactly as
// CheckResponse marks for an oversized page it reads itself, and the refusal
// is counted and logged as a denied tools/list. The gateway has already seen
// the hook fail and fails the listing closed; the marking is what keeps the
// evidence of older listings from outliving the page (D15). The catalog is
// read first, as in CheckResponse: a refusal while the catalog is unreadable
// is a source error like any other hook and marks nothing. The hook's context
// carries the gateway's deadline, which must not cut the marking short, so
// the catalog is read under the processor's own timeout alone. No concurrency
// slot is taken: the marking carries no payload and must not be skipped for
// want of one.
func (s *Server) pageRefused(ctx context.Context, cause error) {
	ctx = context.WithoutCancel(ctx)
	cur, err := s.current(ctx)
	if err != nil {
		s.noteSourceError(ctx, methodToolsList, err)
		s.stats.listsDenied.Add(1)
		return
	}
	s.markPageUnread(ctx, cur)
	s.noteListDenied(ctx, reasonListUnverifiable, cause)
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
	s.noteListDenied(ctx, reason, err)
	return denyResponse(code, reason)
}

// noteListDenied counts and logs one refused tools/list, whether the hook
// built the denial itself or the transport refused the page before it ran.
func (s *Server) noteListDenied(ctx context.Context, reason string, err error) {
	s.stats.listsDenied.Add(1)
	s.log.InfoContext(ctx, "tools/list denied", "server", s.server, "reason", reason, "err", quoteErr(err))
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
// Debug otherwise, preceded by the digest mismatch lines (logMismatches),
// which name the case an owner must act on (drift, or the re-serialisation
// limit in the package comment). Names are quoted and capped; no definition
// is ever logged. The summary line counts the mismatched tools next to the
// other hidden categories, so the count is on one line however many mismatch
// lines the cap left out.
func (s *Server) logList(ctx context.Context, page filtered) {
	s.logMismatches(ctx, page.report.mismatched)
	level := slog.LevelDebug
	if len(page.hidden) > 0 {
		level = slog.LevelInfo
	}
	s.log.Log(ctx, level, "tools/list filtered",
		"server", s.server, "hidden", len(page.hidden), "hidden_tools", quoteNames(page.hidden),
		"mismatched", len(page.report.mismatched), "unapproved", page.report.unapproved,
		"oversized", page.report.oversized, "unverified", page.report.unverified)
}

// logMismatches writes one Info line per tool hidden for a digest mismatch, up
// to maxLoggedNames per page as for every list of names. Each line carries
// the quoted name, the approved digest and the live one, the digest the
// upstream's definition hashes to right now: 64 hex digits, so the line says
// what the upstream serves without logging a byte of it. The field names are
// the rows of `toolwarrant show` (`approved:`, `live:`), and the live digest
// is what `toolwarrant diff SERVER TOOL --to LIVE` takes once a crawl has
// recorded the same definition as pending (D21 (f)). The count of mismatched
// tools beyond the cap is on the page summary line.
func (s *Server) logMismatches(ctx context.Context, mismatched []mismatch) {
	shown := mismatched
	if len(shown) > maxLoggedNames {
		shown = shown[:maxLoggedNames]
	}
	for _, m := range shown {
		s.log.InfoContext(ctx, "digest mismatch",
			"server", s.server, "tool", quoteName(m.name), "approved", m.approved, "live", m.live)
	}
}
