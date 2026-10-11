package catalog

import (
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/gate"
)

// RecheckTTL is how long a Store trusts its own re-check of one version row.
//
// Every read path re-hashes the canonical bytes behind a digest it hands out.
// The processor reloads a Snapshot whenever the generation moves, and every
// crawl moves it, so without a memory a server of many approved tools would
// be read and hashed in full on every crawl: up to MaxToolBytes per tool,
// about 2.5 GB for MaxToolsPerCrawl tools. Within RecheckTTL of a successful
// check the same Store neither reads nor hashes that row's bytes again, so a
// row is hashed at most once per RecheckTTL per Store (two readers racing on
// a row not yet remembered may each hash it once).
//
// The window this opens is exactly this: a change to the stored canonical
// bytes of a version that this Store verified less than RecheckTTL ago is not
// reported by Snapshot, Approved or Versions until RecheckTTL has passed
// since that check, or until a Store without that memory reads the row. The
// memory is per Store, is dropped by Close, and a forensic open never has
// one. Nothing else is covered by it: a changed digest column, a changed
// digest profile, a dangling or foreign approved pointer, a missing approval
// or proposer row, and a row that failed its check are all reported at once,
// and a decision loads its tool afresh and always re-hashes it.
const RecheckTTL = 10 * time.Minute

// recheckCacheEntries bounds the rows one Store remembers: a few servers at
// MaxToolsPerCrawl, a few megabytes at most. A larger catalog only costs
// misses, never answers.
const recheckCacheEntries = 32768

// verifier re-checks version rows against their stored digests and remembers
// each row it has verified, by row id, for RecheckTTL. A hit is only ever
// returned for the row id and the digest string that were verified together,
// so the memory can skip work but cannot vouch for a row whose digest changed.
// A row that fails is never remembered. Eviction picks a uniformly random
// victim, as the processor's digest cache does: a catalog larger than the
// bound still hits in proportion to the bound, where least-recently-used would
// miss on every row of a reload that cycles through all of them.
//
// All methods are safe for concurrent use. The hash itself runs outside the
// lock, so readers do not serialise on it.
type verifier struct {
	// now is the Store's clock, read at call time so a test can replace it.
	now func() time.Time
	// bound is the most rows remembered; zero remembers nothing, so every
	// call hashes.
	bound int
	// hashes counts the digests computed; tests read it to prove that a hit
	// skipped the work.
	hashes atomic.Int64

	mu   sync.RWMutex
	rows map[int64]verifiedRow
	// ids holds every key of rows in no particular order, so a victim can be
	// drawn uniformly without walking the map. Its length is the bound.
	ids []int64
}

// verifiedRow is what the verifier remembers about one row.
type verifiedRow struct {
	digest string
	// until is when the memory lapses; the row is trusted while now is
	// before it.
	until time.Time
}

// newVerifier returns an empty verifier remembering at most bound rows; a
// bound of zero or less remembers nothing.
func newVerifier(now func() time.Time, bound int) *verifier {
	return &verifier{now: now, bound: bound, rows: make(map[int64]verifiedRow)}
}

// remembered reports whether row id was verified with this digest less than
// RecheckTTL ago. A lapsed memory, or one for another digest, is a miss.
func (v *verifier) remembered(id int64, digest string) bool {
	now := v.now()
	v.mu.RLock()
	defer v.mu.RUnlock()
	r, ok := v.rows[id]
	return ok && r.digest == digest && now.Before(r.until)
}

// check hashes canonical and reports whether the result is digest. A success
// is remembered; a failure is not, so a bad row is hashed on every read until
// it is repaired.
func (v *verifier) check(id int64, digest string, canonical []byte) bool {
	v.hashes.Add(1)
	if gate.DigestOfCanonical(canonical) != digest {
		return false
	}
	v.remember(id, digest)
	return true
}

// verify is remembered or check: the hash is skipped only for a row verified
// with this digest within RecheckTTL.
func (v *verifier) verify(id int64, digest string, canonical []byte) bool {
	return v.remembered(id, digest) || v.check(id, digest, canonical)
}

// verifySeal reports whether audit entry e re-seals from a predecessor whose
// hash is prevHash (Genesis when ""): its prev_hash must be that hash and its
// hash must be what audit.Seal computes over its fields. The memory is keyed by
// seq with the entry's hash as the digest, so a hit vouches only for the exact
// entry that was verified; a rewritten entry has another hash and misses. The
// Store keeps a separate verifier for entries (Store.sealed), so a version
// row id and an entry seq can never share a key.
func (v *verifier) verifySeal(e audit.Entry, prevHash string) bool {
	if v.remembered(e.Seq, e.Hash) {
		return true
	}
	v.hashes.Add(1)
	sealed, err := audit.Seal(audit.Entry{Hash: prevHash}, e)
	if err != nil || sealed.Hash != e.Hash || sealed.PrevHash != e.PrevHash {
		return false
	}
	v.remember(e.Seq, e.Hash)
	return true
}

// remember records a successful check of row id. When the memory is full a
// random row makes room; a row already remembered is refreshed in place.
func (v *verifier) remember(id int64, digest string) {
	if v.bound <= 0 {
		return
	}
	until := v.now().Add(RecheckTTL)
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, ok := v.rows[id]; !ok {
		if len(v.ids) < v.bound {
			v.ids = append(v.ids, id)
		} else {
			victim := rand.IntN(len(v.ids))
			delete(v.rows, v.ids[victim])
			v.ids[victim] = id
		}
	}
	v.rows[id] = verifiedRow{digest: digest, until: until}
}

// drop forgets every row. Close calls it, so a closed Store vouches for
// nothing.
func (v *verifier) drop() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.rows = make(map[int64]verifiedRow)
	v.ids = nil
}

// size is the number of rows remembered, lapsed ones included; tests use it
// to check the bound.
func (v *verifier) size() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.rows)
}

// hashCount is the number of digests computed so far.
func (v *verifier) hashCount() int64 { return v.hashes.Load() }
