// Package processor is the ExtMCP gRPC processor that enforces the catalog at
// the gateway ("strict mode").
//
// The gateway asks this processor about two things. For a tools/list response
// it shows a tool only while the definition the upstream serves right now
// hashes to the digest a named person approved. For a tools/call request it
// denies the call unless the approval is still current. Nothing is served
// until approved, and every failure (unreadable input, unreachable catalog,
// too much work) denies: a gate that cannot decide must not let anything
// through.
//
// One Server guards one upstream, and one processor address belongs to exactly
// one upstream: a hook whose service_names does not name the configured
// Target is denied rather than judged with this server's approvals. Every byte
// read from the upstream or from a client is hostile; the catalog Source is
// the only trusted input, and the optional shared secret (Config.Secret) is
// the only proof that a hook comes from the gateway at all.
//
// Known limit (v0.1): agentgateway re-serialises tool definitions before the
// hook and drops top-level keys and annotation keys it does not know. Such a
// tool can never hash to its approved digest. This version does not hash a
// projection; it detects the case and reports it (Stats.ToolsMismatched and
// the "digest mismatch" log line), so the tool stays hidden until the catalog
// approves the definition the gateway actually serves.
package processor

import (
	"context"
	"crypto/tls"
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

	// DefaultMaxTracked is the upper bound on the observed-evidence table when
	// Config.MaxTracked is not set. The table is sized from the catalog
	// snapshot at every reload, so this bound is only reached by a server
	// whose catalog holds more tools than this.
	DefaultMaxTracked = 100000

	// SecretMetadataKey is the metadata_context field that carries the shared
	// secret. The gateway fills it from the processor's metadata entry in its
	// configuration (a CEL string literal), one field per configured key.
	SecretMetadataKey = "toolwarrant_secret"
)

// Source is the processor's view of the catalog. It is deliberately tiny so a
// test can fake it and so the processor never writes to the catalog.
type Source interface {
	// Generation returns a counter that changes whenever the catalog changes.
	// The processor polls it on every hook and reloads only when it moves. An
	// error that is catalog.ErrCorrupt (catalog.ErrReplaced among them: the
	// file at the path is no longer the one the Source opened) also tells the
	// processor that the snapshot it cached can no longer be trusted, so the
	// next successful read reloads even when the counter has not moved.
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
	// Target is the backend name the gateway reports in service_names for the
	// route this processor guards. The emitted configuration names the backend
	// after the server, so empty means Server. A hook about another backend,
	// about several, or about none is denied: judging it here would serve one
	// upstream's approval on another.
	Target string
	// Logger receives denials, hides and errors. Nil means slog.Default().
	Logger *slog.Logger
	// MaxTracked is the upper bound on the table of digests remembered from
	// tools/list responses. The table is sized from the catalog snapshot at
	// every reload (the snapshot's tool count plus a small margin) and holds
	// only tools the snapshot could serve, so it never needs more than that
	// and this bound matters only when a server's catalog exceeds it. Then a
	// new entry evicts one whose digest agrees with its approval, never a
	// contradiction; when nothing agreeing is left the new evidence is dropped,
	// counted in Stats.EvidenceDropped, and from then on a servable tool with
	// no listing evidence is denied until a listing records it. Zero or
	// negative means DefaultMaxTracked.
	MaxTracked int
	// Secret, when set, must arrive on every hook as the metadata_context
	// string field SecretMetadataKey and is compared in constant time. Empty
	// disables the check, which is only safe on a listener that nobody but the
	// gateway can reach.
	Secret string
	// AllowRemoteListener lets Serve accept a TCP listener on a non-loopback
	// address. Without it Serve refuses such a listener, because without a
	// Secret or a verified client certificate whoever reaches the port decides
	// what the gateway serves.
	AllowRemoteListener bool
	// TLS, when set, makes Serve terminate TLS on the listener with this
	// configuration (grpc credentials.NewTLS). Serve works on a copy whose
	// MinVersion is TLS 1.3 whatever the caller set below it; the caller's
	// value is never written to. With ClientAuth tls.RequireAndVerifyClientCert
	// (and a ClientCAs pool, which is required then) every connection must
	// present a certificate that pool signed, which authenticates the hooks as
	// the shared secret does and so silences the no-secret warning of a
	// non-loopback listener (owner decision O-2, D19); any other
	// ClientAuth value protects the bytes on the wire only. A connection the
	// handshake refuses never reaches a hook, so Stats does not count it; the
	// transport's log line does. Nil serves plaintext, as every version before
	// did.
	TLS *tls.Config
	// MaxEvidenceAge bounds how long a digest seen in a tools/list response
	// counts as evidence for a tools/call. Zero means it never expires. The
	// crawl side of the evidence (LastSeen) carries no timestamp yet and is
	// not aged here.
	MaxEvidenceAge time.Duration
}

// Stats are monotonically increasing counters, read with Server.Stats.
type Stats struct {
	// ListsServed counts tools/list results returned after filtering,
	// including pages the filter emptied.
	ListsServed uint64
	// ListsDenied counts tools/list results replaced by an error.
	ListsDenied uint64
	// ToolsHidden counts tool definitions removed from served lists, for any
	// reason. Tools the catalog has never heard of have no counter of their
	// own: they are ToolsHidden minus the four categories below.
	ToolsHidden uint64
	// ToolsMismatched counts hidden tools that are approved and enabled but
	// whose live definition hashes to another digest: drift, or a definition
	// the gateway re-serialised (see the package comment).
	ToolsMismatched uint64
	// ToolsUnapproved counts hidden catalog tools without a current approval.
	ToolsUnapproved uint64
	// ToolsOversized counts hidden tools whose raw definition exceeded the
	// per-tool cap and were hidden without being hashed.
	ToolsOversized uint64
	// ToolsUnverified counts hidden tools whose live definition hashes to the
	// approved digest while the latest crawl recorded a marker, not a digest,
	// in LastSeen (the catalog's "unusable": an invalid or duplicated
	// definition, or an exhausted proposal budget). Such a tool is hidden
	// because judgeCall denies every call to it as not yet verified until a
	// clean crawl records a digest: a tool hidden for a marker is also
	// uncallable (D9). The reverse does not hold: a listed tool may still be
	// denied until the crawl, or a listing, records the digest the gateway
	// shows, and no listing counter records that.
	ToolsUnverified uint64
	// CallsAllowed counts tools/call requests passed to the upstream.
	CallsAllowed uint64
	// CallsDenied counts tools/call requests refused for any reason.
	CallsDenied uint64
	// WrongBackend counts hooks denied because service_names did not name
	// exactly the configured Target.
	WrongBackend uint64
	// Unauthenticated counts hooks denied for a missing or wrong shared secret.
	Unauthenticated uint64
	// Throttled counts hooks denied because every concurrency slot was taken.
	Throttled uint64
	// SourceErrors counts catalog reads that failed or returned an unusable
	// snapshot. Each one also denied the hook that needed it.
	SourceErrors uint64
	// EvidenceDropped counts listing evidence the observed table could not
	// keep because it was full and every entry it could have replaced
	// contradicts its approval (Config.MaxTracked). A non-zero count is a
	// standing condition, not a moment: while it holds, a servable tool with no
	// listing evidence is denied as not yet verified until a listing records
	// it, because the missing entry may be the contradiction that was lost.
	EvidenceDropped uint64
}

// counters holds the atomic backing of Stats.
type counters struct {
	listsServed     atomic.Uint64
	listsDenied     atomic.Uint64
	toolsHidden     atomic.Uint64
	toolsMismatched atomic.Uint64
	toolsUnapproved atomic.Uint64
	toolsOversized  atomic.Uint64
	toolsUnverified atomic.Uint64
	callsAllowed    atomic.Uint64
	callsDenied     atomic.Uint64
	wrongBackend    atomic.Uint64
	unauthenticated atomic.Uint64
	throttled       atomic.Uint64
	sourceErrors    atomic.Uint64
	evidenceDropped atomic.Uint64
}

// Server implements the ExtMCP service. Create it with New; it is safe for
// concurrent use because the gateway calls both hooks concurrently.
type Server struct {
	api.UnimplementedExtMcpServer

	src         Source
	server      string
	target      string
	secret      string
	allowRemote bool
	// tlsConf is Config.TLS hardened to TLS 1.3 (hardenTLS); nil serves
	// plaintext.
	tlsConf    *tls.Config
	log        *slog.Logger
	maxTracked int
	maxAge     time.Duration
	// now is the clock behind evidence ages; tests replace it.
	now func() time.Time

	// cache holds the snapshot for one generation. Readers load it without a
	// lock; loadMu only serialises reloads so a burst of hooks after a change
	// produces one Snapshot call. It is written under obsMu (install) so the
	// observed table is always sized for the snapshot the hooks see.
	cache  atomic.Pointer[cachedSnapshot]
	loadMu sync.Mutex
	// taint counts the Source reports that made the cached snapshot
	// untrustworthy (distrust in snapshot.go): a cachedSnapshot is reused only
	// while it carries the current count. distrustLogged makes the Error line
	// for the condition appear once per episode rather than once per hook.
	taint          atomic.Uint64
	distrustLogged atomic.Bool

	// observed maps a tool name to what the gateway's own tools/list traffic
	// last showed for it. It only ever holds servable tools of the catalog
	// snapshot, so a hostile upstream cannot grow it, and obsLimit is its
	// capacity: set from the snapshot at each reload, at most maxTracked.
	obsMu    sync.Mutex
	observed map[string]observation
	obsLimit int

	// digests remembers the gate digest of definitions this processor has
	// already canonicalised, by the SHA-256 of their raw bytes, so a page that
	// lists an unchanged catalog costs one hash per tool rather than one
	// canonicalisation. It is bounded and never changes an answer.
	digests *digestCache

	// slots is the concurrency semaphore: one token per hook doing work.
	slots chan struct{}
	// wrongBackendSeen makes the first mismatching service_names value, and
	// only the first, visible in the log.
	wrongBackendSeen atomic.Bool

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
	target := cfg.Target
	if target == "" {
		target = cfg.Server
	}
	return &Server{
		src:         src,
		server:      cfg.Server,
		target:      target,
		secret:      cfg.Secret,
		allowRemote: cfg.AllowRemoteListener,
		tlsConf:     hardenTLS(cfg.TLS),
		log:         logger,
		maxTracked:  maxTracked,
		maxAge:      cfg.MaxEvidenceAge,
		now:         time.Now,
		observed:    make(map[string]observation),
		digests:     newDigestCache(digestCacheEntries),
		slots:       make(chan struct{}, maxConcurrentHooks),
	}
}

// Stats returns a consistent-enough copy of the counters. Each field is read
// atomically; the set is not a single atomic snapshot.
func (s *Server) Stats() Stats {
	return Stats{
		ListsServed:     s.stats.listsServed.Load(),
		ListsDenied:     s.stats.listsDenied.Load(),
		ToolsHidden:     s.stats.toolsHidden.Load(),
		ToolsMismatched: s.stats.toolsMismatched.Load(),
		ToolsUnapproved: s.stats.toolsUnapproved.Load(),
		ToolsOversized:  s.stats.toolsOversized.Load(),
		ToolsUnverified: s.stats.toolsUnverified.Load(),
		CallsAllowed:    s.stats.callsAllowed.Load(),
		CallsDenied:     s.stats.callsDenied.Load(),
		WrongBackend:    s.stats.wrongBackend.Load(),
		Unauthenticated: s.stats.unauthenticated.Load(),
		Throttled:       s.stats.throttled.Load(),
		SourceErrors:    s.stats.sourceErrors.Load(),
		EvidenceDropped: s.stats.evidenceDropped.Load(),
	}
}
