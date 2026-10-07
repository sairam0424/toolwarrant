package processor

import (
	"crypto/sha256"
	"math/rand/v2"
	"sync"
)

// digestCacheEntries bounds the digest cache. An upstream lists the same
// definitions on every page, so one entry per catalog tool is all the cache
// needs; 4096 covers any catalog this processor is meant for in well under a
// megabyte, and a larger or churning catalog only costs misses, never answers.
const digestCacheEntries = 4096

// rawKey identifies a tool definition by the SHA-256 of its raw bytes, all 32
// of them: the cache can answer for other bytes only if SHA-256 collides, the
// assumption every approval already rests on.
type rawKey [sha256.Size]byte

// digestCache remembers the gate digest of tool definitions by the SHA-256 of
// their raw bytes. Canonicalising a definition (RFC 8785 plus the number
// exactness check) costs far more than hashing its bytes, and the definitions
// an upstream lists are the same on every page, so for an unchanged catalog
// the per-tool cost drops to one SHA-256. Correctness never depends on the
// cache: it holds only what compute returned for the exact bytes under the
// key, so a hit skips work without changing an answer. Failures are not
// remembered; a definition that cannot be hashed denies its page whether or
// not it was seen before, and remembering it would only keep hostile bytes
// around.
//
// Eviction picks a uniformly random victim. A list that cycles through more
// definitions than the cache holds then still hits in proportion to the cache
// size, where least-recently-used would miss on every one of them.
type digestCache struct {
	// compute is toolDigest; tests replace it to count the work a hit skips.
	compute func(tool []byte) (string, error)
	max     int

	mu      sync.RWMutex
	entries map[rawKey]string
	// keys holds every key of entries in no particular order, so a victim can
	// be drawn uniformly without walking the map. Its length is the bound.
	keys []rawKey
}

// newDigestCache returns an empty cache holding at most max results; a max
// below one means digestCacheEntries.
func newDigestCache(max int) *digestCache {
	if max <= 0 {
		max = digestCacheEntries
	}
	return &digestCache{compute: toolDigest, max: max, entries: make(map[rawKey]string)}
}

// digest returns compute(tool), from the cache when these exact bytes were
// digested before.
func (c *digestCache) digest(tool []byte) (string, error) {
	key := rawKey(sha256.Sum256(tool))
	if d, ok := c.lookup(key); ok {
		return d, nil
	}
	d, err := c.compute(tool)
	if err != nil {
		return "", err
	}
	c.store(key, d)
	return d, nil
}

func (c *digestCache) lookup(key rawKey) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	d, ok := c.entries[key]
	return d, ok
}

// store remembers one result. When the cache is full a random entry makes
// room, so it never holds more than max results; a key another hook stored
// meanwhile is left as it is, the answer being the same.
func (c *digestCache) store(key rawKey, digest string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries[key]; ok {
		return
	}
	if len(c.keys) < c.max {
		c.keys = append(c.keys, key)
	} else {
		victim := rand.IntN(len(c.keys))
		delete(c.entries, c.keys[victim])
		c.keys[victim] = key
	}
	c.entries[key] = digest
}

// size is the number of cached results; tests use it to check the bound.
func (c *digestCache) size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
