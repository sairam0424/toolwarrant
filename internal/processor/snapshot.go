package processor

import (
	"context"
	"errors"
	"fmt"
	"maps"

	"github.com/sairam0424/toolwarrant/internal/catalog"
)

var (
	errNotConfigured    = errors.New("processor: no catalog source or server name configured")
	errSnapshotMismatch = errors.New("processor: snapshot belongs to a different server")
	errSnapshotStale    = errors.New("processor: snapshot is older than the catalog generation")
)

// cachedSnapshot pairs a snapshot with the generation that was read BEFORE it
// was loaded. Keying on the earlier read is deliberate: if the catalog moves
// while the snapshot is being read, the next hook sees a different generation
// and reloads, so the cache can be redundant but never stale. A cachedSnapshot
// is never modified after it is stored, so hooks read it without a lock.
type cachedSnapshot struct {
	generation int64
	snap       catalog.Snapshot
}

// current returns the snapshot for the catalog's current generation. It polls
// Generation on every call and calls Snapshot only when the generation moved
// or nothing is cached. On any source failure it returns an error and the
// caller must deny: the previous snapshot is never used as a fallback, because
// it may still show a tool the owner has since disabled.
func (s *Server) current(ctx context.Context) (*cachedSnapshot, error) {
	if s.src == nil || s.server == "" {
		return nil, errNotConfigured
	}
	ctx, cancel := context.WithTimeout(ctx, sourceTimeout)
	defer cancel()

	gen, err := s.src.Generation(ctx)
	if err != nil {
		return nil, fmt.Errorf("read catalog generation: %w", err)
	}
	if c := s.cache.Load(); c != nil && c.generation == gen {
		return c, nil
	}
	return s.reload(ctx, gen)
}

// reload loads and caches the snapshot for generation gen. Reloads are
// serialised; a goroutine that waited behind another re-checks the cache so
// a burst of hooks after a change costs one Snapshot call.
func (s *Server) reload(ctx context.Context, gen int64) (*cachedSnapshot, error) {
	s.loadMu.Lock()
	defer s.loadMu.Unlock()

	if c := s.cache.Load(); c != nil && c.generation == gen {
		return c, nil
	}
	snap, err := s.src.Snapshot(ctx, s.server)
	if err != nil {
		return nil, fmt.Errorf("load catalog snapshot: %w", err)
	}
	if err := s.validate(snap, gen); err != nil {
		return nil, err
	}
	// Clone so the hooks, which read the map without a lock, cannot race with a
	// Source that keeps writing to the map it returned.
	frozen := snap
	frozen.Tools = maps.Clone(snap.Tools)

	c := &cachedSnapshot{generation: gen, snap: frozen}
	s.cache.Store(c)
	s.pruneObserved(frozen.Tools)
	s.log.Debug("catalog snapshot loaded", "server", s.server, "generation", gen, "tools", len(frozen.Tools))
	return c, nil
}

// validate rejects a snapshot that cannot be trusted to describe this server
// at (or after) the generation the processor just read. An unset Generation
// (zero) is accepted so a Source that does not stamp snapshots still works.
func (s *Server) validate(snap catalog.Snapshot, gen int64) error {
	if snap.Server != "" && snap.Server != s.server {
		return errSnapshotMismatch
	}
	if snap.Generation != 0 && snap.Generation < gen {
		return errSnapshotStale
	}
	return nil
}

// noteSourceError counts and logs a catalog failure. The hook that hit it
// returns a denial; this is the one place the failure is reported.
func (s *Server) noteSourceError(ctx context.Context, method string, err error) {
	s.stats.sourceErrors.Add(1)
	s.log.ErrorContext(ctx, "catalog unavailable, denying",
		"server", s.server, "method", method, "err", quoteErr(err))
}
