package processor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	api "github.com/sairam0424/toolwarrant/internal/extmcpv1"
	"github.com/sairam0424/toolwarrant/internal/gate"
	"github.com/sairam0424/toolwarrant/internal/mcpwire"
	"github.com/sairam0424/toolwarrant/internal/strictjson"
)

var errDuplicateTool = errors.New("processor: tool name appears twice in one page")

// CheckResponse filters a tools/list result down to the tools whose current
// definition is the approved one, and passes every other method through.
//
// Every failure path returns an AuthorizationError. The one thing this hook
// must never do is hand back the upstream's list unfiltered, so a Pass result
// is only ever produced for a method other than tools/list.
func (s *Server) CheckResponse(ctx context.Context, resp *api.McpResponse) (*api.McpResponseResult, error) {
	if resp.GetMethod() != methodToolsList {
		return passResponse(), nil
	}
	raw := resp.GetMcpResponse()
	if len(raw) > maxPayloadBytes {
		return s.denyList(ctx, api.AuthorizationError_INVALID, reasonListUnverifiable, errPayloadSize), nil
	}
	snap, err := s.current(ctx)
	if err != nil {
		s.noteSourceError(ctx, methodToolsList, err)
		s.stats.listsDenied.Add(1)
		return denyResponse(api.AuthorizationError_PERMISSION_DENIED, reasonListUnavailable), nil
	}
	out, hidden, err := s.filterList(ctx, snap, raw)
	if err != nil {
		return s.denyList(ctx, api.AuthorizationError_INVALID, reasonListUnverifiable, err), nil
	}
	s.stats.listsServed.Add(1)
	s.stats.toolsHidden.Add(uint64(len(hidden)))
	s.logList(ctx, hidden)
	// Always the re-encoded result, even when nothing was hidden: the gateway
	// then sees exactly what was parsed here, with no second "tools" key or
	// other duplicate that a different parser might read differently.
	return mutatedResponse(out), nil
}

// listFilter is the state of one filtering pass over one tools/list page.
type listFilter struct {
	srv      *Server
	snap     catalog.Snapshot
	seen     map[string]struct{}
	overflow int
	failure  error
}

// allow decides whether one tool is shown. mcpwire's callback cannot return an
// error, so a failure is parked in f.failure (and every later tool is hidden
// without work) and the caller turns it into a denial of the whole page.
func (f *listFilter) allow(name string, tool []byte) bool {
	if f.failure != nil {
		return false
	}
	// A tool the catalog has never heard of is hidden without being hashed:
	// its content cannot change the answer, and a hostile upstream must not be
	// able to spend our CPU, or deny the whole page, with tools we never serve.
	if _, inCatalog := f.snap.Tools[name]; !inCatalog {
		return false
	}
	// The failure text goes to the log only, and the name is quoted there, so an
	// operator can see which tool broke the page without the client learning why.
	digest, err := toolDigest(tool)
	if err != nil {
		f.failure = fmt.Errorf("tool %s: %w", quoteName(name), err)
		return false
	}
	if _, dup := f.seen[name]; dup {
		f.failure = fmt.Errorf("tool %s: %w", quoteName(name), errDuplicateTool)
		return false
	}
	f.seen[name] = struct{}{}
	if !f.srv.observe(name, digest) {
		f.overflow++
	}
	return f.snap.Serves(name, digest)
}

// filterList runs mcpwire.FilterToolsListRaw with the catalog policy. The
// returned bytes are only meaningful when err is nil.
func (s *Server) filterList(ctx context.Context, snap catalog.Snapshot, raw []byte) ([]byte, []string, error) {
	f := &listFilter{srv: s, snap: snap, seen: make(map[string]struct{})}
	out, hidden, err := mcpwire.FilterToolsListRaw(raw, f.allow)
	if f.overflow > 0 {
		s.log.WarnContext(ctx, "observed-digest table is full, some tools are not tracked",
			"server", s.server, "max_tracked", s.maxTracked, "untracked", f.overflow)
	}
	if f.failure != nil {
		return nil, nil, f.failure
	}
	if err != nil {
		return nil, nil, fmt.Errorf("filter tools/list: %w", err)
	}
	return out, hidden, nil
}

// toolDigest is the digest of one tool definition exactly as the crawler and
// the approval step compute it (gate.Digest over the raw bytes), after
// rejecting definitions that different parsers would read differently.
func toolDigest(tool []byte) (string, error) {
	if err := strictjson.Object(tool); err != nil {
		return "", fmt.Errorf("read tool definition: %w", err)
	}
	digest, err := gate.Digest(tool)
	if err != nil {
		return "", fmt.Errorf("digest tool definition: %w", err)
	}
	return digest, nil
}

// denyList counts and logs a refused tools/list and builds the error result.
func (s *Server) denyList(ctx context.Context, code api.AuthorizationError_Code, reason string, err error) *api.McpResponseResult {
	s.stats.listsDenied.Add(1)
	s.log.InfoContext(ctx, "tools/list denied", "server", s.server, "reason", reason, "err", quoteErr(err))
	return denyResponse(code, reason)
}

// logList reports one served page: at Info when something was hidden, at
// Debug otherwise. Names are quoted; no definition is ever logged.
func (s *Server) logList(ctx context.Context, hidden []string) {
	level := slog.LevelDebug
	if len(hidden) > 0 {
		level = slog.LevelInfo
	}
	s.log.Log(ctx, level, "tools/list filtered",
		"server", s.server, "hidden", len(hidden), "hidden_tools", quoteNames(hidden))
}
