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
	// count of the snapshot it was sized for. Only catalog tools of the
	// snapshot the hooks judge against are ever recorded (and, while the
	// snapshot is empty, names the table already tracks), so the table never
	// needs more than that count; the margin absorbs a hook that judged against
	// the previous snapshot and records a tool both snapshots carry while the
	// newer one is being installed.
	trackedMargin = 16

	// evictionSample bounds how many entries observe inspects when it looks
	// for one to evict from a full table. Without a bound a full table would
	// let one hostile page cost a scan of the whole table per tool. Go map
	// iteration starts at a random position, so successive samples differ.
	evictionSample = 32
)

// observation is what the processor remembers about one catalog tool from
// the gateway's own tools/list traffic. approved is the digest the snapshot
// approved when the evidence was recorded, so a prune can tell an entry that
// agreed with its approval from a contradiction after the tool has left the
// snapshot and no approval is left to compare with.
type observation struct {
	digest   string // a digest, or observedConflict
	approved string
	seenAt   time.Time
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
// tools/list response, together with the approval the current snapshot gives
// the tool. Updating a tracked name always succeeds because it does not grow
// the table. A new name in a full table evicts an entry whose
// digest equals its approved digest (evictAgreeing) and, when there is none,
// is dropped: the loss is counted in Stats.EvidenceDropped, and from then on
// judgeCall denies every servable tool that has no listing evidence, because
// the missing entry could be the contradiction that was lost.
//
// While the snapshot is empty (a paused server) a tracked name is updated in
// place under the approval it was recorded with, since the empty snapshot has
// none to compare with and the pause keeps the table (install); a name the
// table does not track is not evidence about anything a resumed server could
// serve and is not recorded (D15).
//
// The table is sized from the snapshot at every reload (install), so with the
// default MaxTracked it is never full; the eviction and the drop exist for a
// catalog larger than the configured bound.
func (s *Server) observe(name, digest string) observeOutcome {
	s.obsMu.Lock()
	defer s.obsMu.Unlock()
	c := s.cache.Load()
	if c == nil {
		return observeStored
	}
	prev, tracked := s.observed[name]
	if !stillListed(c, name) {
		if len(c.snap.Tools) > 0 || !tracked {
			return observeStored // dropped on purpose: the catalog no longer has the tool
		}
		s.observed[name] = observation{digest: digest, approved: prev.approved, seenAt: s.now()}
		return observeStored
	}
	outcome := observeStored
	if !tracked && len(s.observed) >= s.obsLimit {
		if !s.evictAgreeing(c.snap) {
			s.stats.evidenceDropped.Add(1)
			return observeDropped
		}
		outcome = observeEvicted
	}
	s.observed[name] = observation{digest: digest, approved: c.snap.Tools[name].Approved, seenAt: s.now()}
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
// currently serves from. A hook that judged against an earlier snapshot and
// then lost a race with a reload may be about to record a name the newer
// snapshot dropped; install has already pruned the table for that snapshot, so
// the entry would outlive it and wrongly deny a tool re-created under the
// name. The name is re-checked rather than dropped outright: the digest
// describes what the upstream serves now, which is newer evidence than
// anything in the table. It is checked even when the hook's generation is
// still the current one, because two snapshots can carry the same generation
// number with different contents (one read after the catalog moved on, or
// installed after a newer one by a hook that read the number earlier), and an
// entry recorded against a snapshot that lacks the name would carry no
// approval to compare with and be kept by prune as a contradiction (D14).
func stillListed(c *cachedSnapshot, name string) bool {
	_, ok := c.snap.Tools[name]
	return ok
}

// tracked reports whether the table holds evidence under name. The filter
// asks while the snapshot is empty (a paused server), when the tracked names
// are all a page can be evidence about (D15).
func (s *Server) tracked(name string) bool {
	s.obsMu.Lock()
	defer s.obsMu.Unlock()
	_, ok := s.observed[name]
	return ok
}

// markTracked replaces the evidence of every tracked entry with the conflict
// marker, under the approval each was recorded with. It is what a page the
// processor could not read to the end says while the snapshot is empty (a
// paused server): there is no snapshot to mark, and the names the table
// tracks are the only ones the page can be evidence against, so the agreeing
// digests older listings left must not outlive it (D15).
func (s *Server) markTracked() {
	s.obsMu.Lock()
	defer s.obsMu.Unlock()
	now := s.now()
	for name, o := range s.observed {
		s.observed[name] = observation{digest: observedConflict, approved: o.approved, seenAt: now}
	}
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
// to another snapshot. A non-empty snapshot prunes the table: a tool it no
// longer has is forgotten when its evidence agreed with the approval that
// stood when it was recorded (a tool deleted and re-created then starts
// without stale evidence) and kept when it contradicted it (a changed digest
// or the conflict marker), because losing a contradiction would re-allow a
// call the gateway's own listing had denied; a re-created tool with a kept
// contradiction is denied as changed until a listing records what the
// upstream serves under the name. An empty snapshot is a paused server and
// leaves the table alone: pause refuses crawls, so what the gateway listed
// before the pause, and what it lists during the pause about those same
// names (observe, markTracked), is the only evidence the resumed server can
// be judged on (D14, D15). The capacity becomes the larger of the snapshot's
// tool count and the entries kept, plus trackedMargin, never more than
// MaxTracked.
func (s *Server) install(c *cachedSnapshot) {
	s.obsMu.Lock()
	defer s.obsMu.Unlock()
	s.cache.Store(c)
	if len(c.snap.Tools) > 0 {
		s.prune(c.snap)
	}
	s.obsLimit = min(max(len(c.snap.Tools), len(s.observed))+trackedMargin, s.maxTracked)
}

// prune forgets the tools absent from next whose evidence agreed with their
// approval at the time; a contradiction is kept. Must be called with obsMu
// held.
func (s *Server) prune(next catalog.Snapshot) {
	for name, o := range s.observed {
		if _, ok := next.Tools[name]; ok {
			continue
		}
		if o.digest == o.approved {
			delete(s.observed, name)
		}
	}
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
