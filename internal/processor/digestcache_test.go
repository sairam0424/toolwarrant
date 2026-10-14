package processor

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/catalog"
)

// countCompute replaces a cache's slow path with one that counts its calls, so
// a test can see the work a hit skips. It must run before the cache is shared
// between goroutines.
func countCompute(c *digestCache) *atomic.Int64 {
	n := new(atomic.Int64)
	inner := c.compute
	c.compute = func(tool []byte) (string, error) {
		n.Add(1)
		return inner(tool)
	}
	return n
}

// F4: an unchanged definition looked up again is not canonicalised again. The
// first lookup pays for RFC 8785 and the number check; every later lookup of
// the same bytes costs one SHA-256.
func TestDigestCache_SameBytesAreCanonicalisedOnce(t *testing.T) {
	c := newDigestCache(16)
	n := countCompute(c)
	want := mustDigest(t, echoV1)
	for i := 0; i < 5; i++ {
		got, err := c.digest(echoV1)
		if err != nil || got != want {
			t.Fatalf("lookup %d = %q, %v; want %q", i, got, err, want)
		}
	}
	if calls := n.Load(); calls != 1 {
		t.Fatalf("5 lookups of the same bytes canonicalised %d times, want 1", calls)
	}
	if c.size() != 1 {
		t.Fatalf("size = %d, want 1", c.size())
	}
}

// The key is the whole SHA-256 of the raw bytes, so bytes that differ at all,
// even where the canonical form does not, are looked up and computed apart; a
// hit is only ever the answer for the very bytes asked about.
func TestDigestCache_DifferentBytesNeverShareAnEntry(t *testing.T) {
	if len(rawKey{}) != sha256.Size || sha256.Size != 32 {
		t.Fatalf("the key holds %d bytes, want the full 32-byte hash", len(rawKey{}))
	}
	c := newDigestCache(16)
	n := countCompute(c)
	same := [][]byte{
		echoV1,
		[]byte(`{ "name":"echo", "description":"Echoes.", "inputSchema":{"type":"object","properties":{"m":{"type":"string"}}} }`),
		[]byte(`{"inputSchema":{"type":"object","properties":{"m":{"type":"string"}}},"description":"Echoes.","name":"echo"}`),
	}
	want := mustDigest(t, echoV1)
	for i, raw := range same {
		if mustDigest(t, raw) != want {
			t.Fatalf("setup: variant %d does not canonicalise to echoV1", i)
		}
		if got, err := c.digest(raw); err != nil || got != want {
			t.Fatalf("variant %d = %q, %v; want %q", i, got, err, want)
		}
	}
	if calls := n.Load(); calls != int64(len(same)) {
		t.Fatalf("%d byte-different variants canonicalised %d times, want one each", len(same), calls)
	}
	if got, err := c.digest(echoV2); err != nil || got == want {
		t.Fatalf("a changed definition = %q, %v; must not equal the approved digest", got, err)
	}
	if c.size() != len(same)+1 {
		t.Fatalf("size = %d, want %d", c.size(), len(same)+1)
	}
}

// A definition that cannot be hashed denies its page whether or not it was
// seen before; remembering the failure would only keep hostile bytes around.
func TestDigestCache_FailuresAreNotRemembered(t *testing.T) {
	c := newDigestCache(16)
	n := countCompute(c)
	broken := []byte(`{"name":"echo","inputSchema":{"a":1,"a":2}}`)
	for i := 0; i < 3; i++ {
		if _, err := c.digest(broken); err == nil {
			t.Fatal("a definition with a duplicate key was hashed")
		}
	}
	if calls := n.Load(); calls != 3 || c.size() != 0 {
		t.Fatalf("%d computations and %d entries for a failing definition, want 3 and 0", calls, c.size())
	}
}

// The bound holds through any number of distinct definitions, the victim list
// mirrors the entries, and whatever is in the cache answers exactly.
func TestDigestCache_IsBoundedAndExactUnderEviction(t *testing.T) {
	const max = 8
	c := newDigestCache(max)
	defs := make([][]byte, 0, 10*max)
	for i := 0; i < 10*max; i++ {
		defs = append(defs, tool(fmt.Sprintf("t%d", i), "d"))
	}
	for i, raw := range defs {
		if got, err := c.digest(raw); err != nil || got != mustDigest(t, raw) {
			t.Fatalf("definition %d = %q, %v", i, got, err)
		}
		if c.size() > max {
			t.Fatalf("after %d definitions the cache holds %d, over the bound %d", i+1, c.size(), max)
		}
	}
	if c.size() != max {
		t.Fatalf("size = %d, want the bound %d", c.size(), max)
	}
	n := countCompute(c)
	for i, raw := range defs {
		if got, err := c.digest(raw); err != nil || got != mustDigest(t, raw) {
			t.Fatalf("definition %d after eviction = %q, %v", i, got, err)
		}
	}
	if calls := n.Load(); calls < int64(len(defs)-max) || calls > int64(len(defs)) {
		t.Errorf("%d recomputations for %d definitions through a %d-entry cache", calls, len(defs), max)
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.keys) != len(c.entries) {
		t.Fatalf("%d keys mirror %d entries", len(c.keys), len(c.entries))
	}
	for _, k := range c.keys {
		if _, ok := c.entries[k]; !ok {
			t.Fatal("a key in the victim list is not in the cache")
		}
	}
}

// Below one, the bound means the default; New gives every Server a cache.
func TestDigestCache_Defaults(t *testing.T) {
	for _, n := range []int{0, -1} {
		if c := newDigestCache(n); c.max != digestCacheEntries || c.compute == nil {
			t.Errorf("newDigestCache(%d): max %d, compute set %v", n, c.max, c.compute != nil)
		}
	}
	if c := newDigestCache(3); c.max != 3 {
		t.Errorf("max = %d, want 3", c.max)
	}
	if s := New(nil, Config{Server: testServer}); s.digests == nil || s.digests.max != digestCacheEntries {
		t.Error("New did not give the server a digest cache with the default bound")
	}
}

// Hooks run concurrently and share the cache. Run with -race: every answer is
// the digest of the bytes asked about and the bound holds throughout.
func TestDigestCache_SafeUnderConcurrentHooks(t *testing.T) {
	const (
		max     = 16
		workers = 8
		rounds  = 400
	)
	c := newDigestCache(max)
	defs := make([][]byte, 64)
	wants := make([]string, len(defs))
	for i := range defs {
		defs[i] = tool(fmt.Sprintf("c%d", i), "concurrent")
		wants[i] = mustDigest(t, defs[i])
	}
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				k := (w*7 + i) % len(defs)
				got, err := c.digest(defs[k])
				if err != nil || got != wants[k] {
					t.Errorf("worker %d: definition %d = %q, %v; want %q", w, k, got, err, wants[k])
					return
				}
				if n := c.size(); n > max {
					t.Errorf("worker %d: cache holds %d entries, over the bound %d", w, n, max)
					return
				}
			}
		}(w)
	}
	wg.Wait()
}

// A second store for a key another hook filled meanwhile keeps the entry: both
// computed the same answer for the same bytes.
func TestDigestCache_StoreKeepsAnExistingEntry(t *testing.T) {
	c := newDigestCache(4)
	key := rawKey(sha256.Sum256(echoV1))
	c.store(key, "first")
	c.store(key, "second")
	if d, ok := c.lookup(key); !ok || d != "first" || c.size() != 1 {
		t.Fatalf("entry = %q, %v, size %d; want the first answer kept", d, ok, c.size())
	}
}

// F4 at the hook: the same page listed again costs no canonicalisation, serves
// the same tools and leaves the same evidence; a changed definition is new
// bytes and is hashed and hidden as before; an unknown tool is still never
// hashed. Before the cache every page canonicalised every catalog tool.
func TestCheckResponse_UnchangedDefinitionsAreNotReCanonicalised(t *testing.T) {
	const n = 5
	defs := make([][]byte, n)
	policies := make(map[string]catalog.ToolPolicy, n)
	for i := range defs {
		name := fmt.Sprintf("t%d", i)
		defs[i] = tool(name, "stable")
		policies[name] = servedPolicy(mustDigest(t, defs[i]))
	}
	s, _ := newTestServer(newFakeSource(policies))
	calls := countCompute(s.digests)

	first := servedNames(t, list(t, s, listBody("", defs...)))
	if len(first) != n || calls.Load() != n {
		t.Fatalf("first page served %v with %d canonicalisations, want %d tools and %d", first, calls.Load(), n, n)
	}
	second := servedNames(t, list(t, s, listBody("c2", defs...)))
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("second page served %v, want %v", second, first)
	}
	if c := calls.Load(); c != n {
		t.Fatalf("listing the same definitions again canonicalised %d more tools, want none", c-n)
	}
	for name, p := range policies {
		if seen, _, ok := s.observedDigest(name); !ok || seen != p.Approved {
			t.Errorf("evidence for %s = %q, %v; want the approved digest", name, seen, ok)
		}
	}

	changed := tool("t1", "changed")
	page := append([][]byte{}, defs...)
	page[1] = changed
	page = append(page, tool("zzz", "unknown"))
	got := servedNames(t, list(t, s, listBody("", page...)))
	if len(got) != n-1 || calls.Load() != n+1 {
		t.Fatalf("changed page served %v with %d canonicalisations, want %d tools and %d", got, calls.Load(), n-1, n+1)
	}
	if seen, _, ok := s.observedDigest("t1"); !ok || seen != mustDigest(t, changed) {
		t.Errorf("evidence for the changed tool = %q, %v", seen, ok)
	}
	if st := s.Stats(); st.ListsServed != 3 || st.ToolsMismatched != 1 || st.ToolsHidden != 2 {
		t.Errorf("stats = %+v", st)
	}
}
