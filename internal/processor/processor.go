// Package processor is the ExtMCP gRPC processor that enforces the catalog at
// the gateway ("strict mode").
//
// The gateway asks this processor about two things. For a tools/list response
// it shows a tool only while the definition the upstream serves right now
// hashes to the digest a named person approved. For a tools/call request it
// denies the call unless the approval is still current. Nothing is served
// until approved, and every failure (unreadable input, unreachable catalog)
// denies: a gate that cannot decide must not let anything through.
//
// One Server guards one upstream. Every byte it reads from the upstream or
// from a client is hostile; the catalog Source is the only trusted input.
package processor

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	api "github.com/sairam0424/toolwarrant/internal/extmcpv1"
)

const (
	methodToolsList = "tools/list"
	methodToolsCall = "tools/call"

	// DefaultMaxTracked bounds how many tool digests the processor remembers
	// from tools/list responses when Config.MaxTracked is not set.
	DefaultMaxTracked = 100000

	// maxPayloadBytes is the largest MCP payload the processor will parse. It
	// equals the gRPC receive limit, so the two layers agree on "too big".
	maxPayloadBytes = 32 << 20

	// sourceTimeout bounds one hook's catalog reads, so a wedged database
	// cannot hold the reload lock (and so every hook) forever.
	sourceTimeout = 10 * time.Second
)

// Source is the processor's view of the catalog. It is deliberately tiny so a
// test can fake it and so the processor never writes to the catalog.
type Source interface {
	// Generation returns a counter that changes whenever the catalog changes.
	// The processor polls it on every hook and reloads only when it moves.
	Generation(ctx context.Context) (int64, error)
	// Snapshot returns the serving policy of one server. The returned Tools
	// map must not be modified by the Source afterwards.
	Snapshot(ctx context.Context, server string) (catalog.Snapshot, error)
}

// Config configures one Server.
type Config struct {
	// Server is the catalog server name this processor guards. An empty name
	// makes every hook deny.
	Server string
	// Logger receives denials, hides and errors. Nil means slog.Default().
	Logger *slog.Logger
	// MaxTracked caps the tool digests remembered from tools/list responses.
	// Zero or negative means DefaultMaxTracked.
	MaxTracked int
}

// Stats are monotonically increasing counters, read with Server.Stats.
type Stats struct {
	// ListsServed counts tools/list results returned after filtering,
	// including pages the filter emptied.
	ListsServed uint64
	// ListsDenied counts tools/list results replaced by an error.
	ListsDenied uint64
	// ToolsHidden counts tool definitions removed from served lists.
	ToolsHidden uint64
	// CallsAllowed counts tools/call requests passed to the upstream.
	CallsAllowed uint64
	// CallsDenied counts tools/call requests refused for any reason.
	CallsDenied uint64
	// SourceErrors counts catalog reads that failed or returned an unusable
	// snapshot. Each one also denied the hook that needed it.
	SourceErrors uint64
}

// counters holds the atomic backing of Stats.
type counters struct {
	listsServed  atomic.Uint64
	listsDenied  atomic.Uint64
	toolsHidden  atomic.Uint64
	callsAllowed atomic.Uint64
	callsDenied  atomic.Uint64
	sourceErrors atomic.Uint64
}

// Server implements the ExtMCP service. Create it with New; it is safe for
// concurrent use because the gateway calls both hooks concurrently.
type Server struct {
	api.UnimplementedExtMcpServer

	src        Source
	server     string
	log        *slog.Logger
	maxTracked int

	// cache holds the snapshot for one generation. Readers load it without a
	// lock; loadMu only serialises reloads so a burst of hooks after a change
	// produces one Snapshot call.
	cache  atomic.Pointer[cachedSnapshot]
	loadMu sync.Mutex

	// observed maps a tool name to the digest of the definition most recently
	// seen in a tools/list response. It only ever holds names that are in the
	// catalog snapshot, so a hostile upstream cannot grow it.
	obsMu    sync.Mutex
	observed map[string]string

	stats counters
}

// Compile-time proof that Server can be registered with the generated service.
var _ api.ExtMcpServer = (*Server)(nil)

// New returns a Server that enforces src's policy for cfg.Server. A nil src
// or empty cfg.Server is not an error here: the hooks deny instead, because a
// processor that panics or passes traffic when misconfigured fails open.
func New(src Source, cfg Config) *Server {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	maxTracked := cfg.MaxTracked
	if maxTracked <= 0 {
		maxTracked = DefaultMaxTracked
	}
	return &Server{
		src:        src,
		server:     cfg.Server,
		log:        logger,
		maxTracked: maxTracked,
		observed:   make(map[string]string),
	}
}

// Stats returns a consistent-enough copy of the counters. Each field is read
// atomically; the set is not a single atomic snapshot.
func (s *Server) Stats() Stats {
	return Stats{
		ListsServed:  s.stats.listsServed.Load(),
		ListsDenied:  s.stats.listsDenied.Load(),
		ToolsHidden:  s.stats.toolsHidden.Load(),
		CallsAllowed: s.stats.callsAllowed.Load(),
		CallsDenied:  s.stats.callsDenied.Load(),
		SourceErrors: s.stats.sourceErrors.Load(),
	}
}
