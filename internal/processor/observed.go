package processor

import (
	"time"

	"github.com/sairam0424/toolwarrant/internal/catalog"
)

// observedConflict is stored instead of a digest when a page shows the
// upstream serving something under a catalog name that cannot be the approved
// definition: the name twice, a definition too large to be approved, or one
// too broken to hash. It is not 64 hex characters, so it never equals an
// approved digest, and judgeCall denies the tool until a clean page replaces
// it with the digest the upstream really serves.
const observedConflict = "conflict"

// observation is what the processor remembers about one catalog tool from
// the gateway's own tools/list traffic.
type observation struct {
	digest string // a digest, or observedConflict
	seenAt time.Time
}

// observe remembers what the upstream served for a catalog tool in a
// tools/list response. gen is the generation of the snapshot that said the
// name is a catalog tool. It reports false when the table is full and the
// name is new; updating a tracked name always succeeds because it does not
// grow the table.
//
// Only names in the current snapshot are ever written. That, plus
// pruneObserved, keeps the table bounded by the catalog rather than by what a
// hostile upstream chooses to send.
func (s *Server) observe(name, digest string, gen int64) bool {
	s.obsMu.Lock()
	defer s.obsMu.Unlock()
	if !s.stillListed(name, gen) {
		return true // dropped on purpose: the catalog no longer has the tool
	}
	if _, tracked := s.observed[name]; !tracked && len(s.observed) >= s.maxTracked {
		return false
	}
	s.observed[name] = observation{digest: digest, seenAt: s.now()}
	return true
}

// stillListed reports whether name is a tool of the snapshot the processor
// currently serves from. A hook that read generation gen and then lost a race
// with a reload may be about to record a name the newer snapshot dropped;
// pruneObserved has already run for that snapshot, so the entry would outlive
// it and wrongly deny a tool re-created under the name. When gen is still
// current the caller established membership against this very snapshot and
// no lookup is needed. When it moved, the name is re-checked against the
// newer snapshot rather than dropped outright: the digest describes what the
// upstream serves now, which is newer evidence than anything in the table.
// Must be called with obsMu held, so it is ordered against pruneObserved.
func (s *Server) stillListed(name string, gen int64) bool {
	c := s.cache.Load()
	if c == nil {
		return false
	}
	if c.generation == gen {
		return true
	}
	_, ok := c.snap.Tools[name]
	return ok
}

// observedDigest returns what the most recent tools/list that included the
// named tool showed for it: a digest or observedConflict. Evidence older than
// MaxEvidenceAge is not returned, because a digest the gateway listed long ago
// says nothing about what the upstream serves now.
func (s *Server) observedDigest(name string) (string, bool) {
	s.obsMu.Lock()
	defer s.obsMu.Unlock()
	o, ok := s.observed[name]
	if !ok {
		return "", false
	}
	if s.maxAge > 0 && s.now().Sub(o.seenAt) > s.maxAge {
		return "", false
	}
	return o.digest, true
}

// pruneObserved forgets tools that are no longer in the catalog, so a tool
// that is deleted and re-created starts with no stale evidence and the table
// cannot accumulate names over the life of the process.
func (s *Server) pruneObserved(tools map[string]catalog.ToolPolicy) {
	s.obsMu.Lock()
	defer s.obsMu.Unlock()
	for name := range s.observed {
		if _, ok := tools[name]; !ok {
			delete(s.observed, name)
		}
	}
}

// trackedCount is the number of remembered observations; tests use it to
// check the MaxTracked bound.
func (s *Server) trackedCount() int {
	s.obsMu.Lock()
	defer s.obsMu.Unlock()
	return len(s.observed)
}
