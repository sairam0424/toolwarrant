package processor

import (
	"time"

	"github.com/sairam0424/toolwarrant/internal/catalog"
)

const (
	// observedConflict is stored instead of a digest when a page shows the
	// upstream serving something under a catalog name that cannot be the
	// approved definition (the name twice, a definition too large to be
	// approved, one too broken to hash), or when a page could not be read
	// through to the end and so says nothing reliable about any tool. It is
	// not 64 hex characters, so it never equals an approved digest, and
	// judgeCall denies the tool until a clean page replaces it with the digest
	// the upstream really serves.
	observedConflict = "conflict"

	// trackedMargin is the headroom the observed table keeps above the tool
	// count of the snapshot it was sized for. Only servable tools of the
	// current snapshot are ever recorded, so the table never needs more than
	// that count; the margin absorbs a hook that judged against the previous
	// snapshot and records a tool both snapshots carry while the newer one is
	// being installed.
	trackedMargin = 16

	// evictionSample bounds how many entries observe inspects when it looks
	// for one to evict from a full table. Without a bound a full table would
	// let one hostile page cost a scan of the whole table per tool. Go map
	// iteration starts at a random position, so successive samples differ.
	evictionSample = 32
)

// observation is what the processor remembers about one catalog tool from
// the gateway's own tools/list traffic.
type observation struct {
	digest string // a digest, or observedConflict
	seenAt time.Time
}

// observeOutcome says what observe did with one piece of evidence, so the
// filter can report evictions and losses once per page rather than per tool.
type observeOutcome uint8

const (
	// observeStored means the evidence is in the table, or was dropped on
	// purpose because the catalog no longer has the tool.
	observeStored observeOutcome = iota
	// observeEvicted means the evidence is in the table and an entry that
	// agreed with its approval was forgotten to make room.
	observeEvicted
	// observeDropped means the evidence was lost: the table is full and every
	// entry it inspected contradicts its approval, so nothing could be
	// forgotten without re-allowing a call the gateway's own listing denied.
	observeDropped
)

// observe remembers what the upstream served for a catalog tool in a
// tools/list response. gen is the generation of the snapshot that said the
// name is a catalog tool. Updating a tracked name always succeeds because it
// does not grow the table. A new name in a full table evicts an entry whose
// digest equals its approved digest (evictAgreeing) and, when there is none,
// is dropped: the loss is counted in Stats.EvidenceDropped, and from then on
// judgeCall denies every servable tool that has no listing evidence, because
// the missing entry could be the contradiction that was lost.
//
// The table is sized from the snapshot at every reload (install), so with the
// default MaxTracked it is never full; the eviction and the drop exist for a
// catalog larger than the configured bound.
func (s *Server) observe(name, digest string, gen int64) observeOutcome {
	s.obsMu.Lock()
	defer s.obsMu.Unlock()
	c := s.cache.Load()
	if c == nil || !stillListed(c, name, gen) {
		return observeStored // dropped on purpose: the catalog no longer has the tool
	}
	outcome := observeStored
	if _, tracked := s.observed[name]; !tracked && len(s.observed) >= s.obsLimit {
		if !s.evictAgreeing(c.snap) {
			s.stats.evidenceDropped.Add(1)
			return observeDropped
		}
		outcome = observeEvicted
	}
	s.observed[name] = observation{digest: digest, seenAt: s.now()}
	return outcome
}

// evictAgreeing forgets one tracked tool whose observed digest equals its
// approved digest in the current snapshot and reports whether it found one.
// Such an entry is safe to lose: without it judgeCall falls back to the
// crawl's word or denies as not yet verified, never the other way round. An
// entry that contradicts its approval (a changed digest or the conflict
// marker) is never evicted, because losing it would re-allow a call the
// gateway's own listing had denied. At most evictionSample entries are
// inspected. Must be called with obsMu held.
func (s *Server) evictAgreeing(snap catalog.Snapshot) bool {
	inspected := 0
	for name, o := range s.observed {
		if inspected++; inspected > evictionSample {
			return false
		}
		if o.digest == snap.Tools[name].Approved {
			delete(s.observed, name)
			return true
		}
	}
	return false
}

// stillListed reports whether name is a tool of the snapshot the processor
// currently serves from. A hook that read generation gen and then lost a race
// with a reload may be about to record a name the newer snapshot dropped;
// install has already pruned the table for that snapshot, so the entry would
// outlive it and wrongly deny a tool re-created under the name. When gen is
// still current the caller established membership against this very snapshot
// and no lookup is needed. When it moved, the name is re-checked against the
// newer snapshot rather than dropped outright: the digest describes what the
// upstream serves now, which is newer evidence than anything in the table.
func stillListed(c *cachedSnapshot, name string, gen int64) bool {
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

// install publishes a loaded snapshot and fits the observed table to it in one
// step under obsMu, so no hook can record against a table whose size belongs
// to another snapshot. Tools the snapshot no longer has are forgotten (a tool
// deleted and re-created starts without stale evidence, and the table cannot
// accumulate names over the life of the process), and the capacity becomes
// the snapshot's tool count plus trackedMargin, never more than MaxTracked.
func (s *Server) install(c *cachedSnapshot) {
	s.obsMu.Lock()
	defer s.obsMu.Unlock()
	s.cache.Store(c)
	for name := range s.observed {
		if _, ok := c.snap.Tools[name]; !ok {
			delete(s.observed, name)
		}
	}
	s.obsLimit = min(len(c.snap.Tools)+trackedMargin, s.maxTracked)
}

// trackedCount is the number of remembered observations; tests use it to
// check the table bound.
func (s *Server) trackedCount() int {
	s.obsMu.Lock()
	defer s.obsMu.Unlock()
	return len(s.observed)
}

// trackedLimit is the current capacity of the observed table; tests use it to
// check that install sizes the table from the snapshot.
func (s *Server) trackedLimit() int {
	s.obsMu.Lock()
	defer s.obsMu.Unlock()
	return s.obsLimit
}
