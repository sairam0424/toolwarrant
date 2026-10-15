package catalog

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/gate"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

const (
	benchTools = 1000
	// benchToolBytes is the description size of each benchmark tool: a long
	// but realistic definition, well under MaxToolBytes and, times benchTools,
	// under MaxCrawlBytes.
	benchToolBytes = 8 << 10
	// benchLargeTools is the tool count of the two 10000-tool benchmarks: a
	// server holding MaxToolsPerCrawl approved tools, the count known limit
	// L16 and D21 (d) reason about.
	benchLargeTools = MaxToolsPerCrawl
	// benchLargeEnv names the environment variable that lets the at-cap
	// benchmark run: its store is about 5 GiB on disk and takes minutes to
	// fill, so it never runs by accident.
	benchLargeEnv = "TOOLWARRANT_BENCH_LARGE"
	// benchServer is the one server every benchmark store holds.
	benchServer = "alpha"
	// benchNameFormat spells the tool names; every name has the same length,
	// so every raw definition of one benchmark has the same length too.
	benchNameFormat = "tool-%05d"
)

// BenchmarkSnapshot1000Approved measures the processor's reload of a server
// with 1000 approved tools of about 8 KiB each. hashes/op is the number of
// SHA-256 computed per reload: since D21 (d) a reload hashes the audit
// entries it anchors to and no canonical bytes, one hash per distinct entry,
// so a store whose approvals are the newest entries about their tools hashes
// once per tool (TestBenchmarkSnapshotHashesOnlyAuditEntries). Before D21 (d)
// the same benchmark ran as two sub-benchmarks, "uncached" (every reload read
// and hashed every approved definition, hashes/op equal to the tool count) and
// "cached" (a reload within the ten-minute memory, hashes/op zero), and both
// are recorded in D21 (d) for comparison.
func BenchmarkSnapshot1000Approved(b *testing.B) {
	benchSnapshot(b, benchStore(b), benchTools)
}

// BenchmarkSnapshot10000Approved8KiB is the same reload at MaxToolsPerCrawl
// tools of about 8 KiB, about 80 MiB of canonical bytes: the measurement
// D21 (d) rests on, before and after the serving path stopped reading bytes.
// The store is filled by several complete crawls, since one crawl is capped
// at MaxCrawlBytes (benchFill says how and what state that leaves).
func BenchmarkSnapshot10000Approved8KiB(b *testing.B) {
	s := benchOpen(b)
	benchFill(b, s, benchLargeTools, benchToolBytes)
	benchSnapshot(b, s, benchLargeTools)
}

// BenchmarkSnapshot10000ApprovedAtCap is the same reload at MaxToolBytes per
// tool: MaxToolsPerCrawl times MaxToolBytes, about 2.5 GiB of canonical
// bytes, the upper bound known limit L16 named. The catalog itself
// never reaches it: MaxServerBytes caps one server at 1 GiB of canonical
// bytes across every version (servercaps.go), so this benchmark lifts the
// per-server byte cap on its own Store, as the cap tests lower theirs, and
// measures a file no sequence of crawls can build; the reachable worst case
// is 1 GiB. It runs only with TOOLWARRANT_BENCH_LARGE=1: the store is about
// 5 GiB on disk (the raw definition is stored next to the canonical one) and
// takes minutes to fill.
func BenchmarkSnapshot10000ApprovedAtCap(b *testing.B) {
	if os.Getenv(benchLargeEnv) != "1" {
		b.Skipf("set %s=1 to run: the store is about 5 GiB on disk and takes minutes to fill", benchLargeEnv)
	}
	s := benchOpen(b)
	s.caps = serverCaps{tools: s.caps.tools, bytes: math.MaxInt64}
	benchFill(b, s, benchLargeTools, benchCapDescBytes())
	benchSnapshot(b, s, benchLargeTools)
}

// benchSnapshot reloads benchServer until the benchmark is satisfied, fails
// on an error or a snapshot of other than n tools, and reports the SHA-256
// computed per reload, which since D21 (d) are the audit entries the reload
// anchors to (chainMemory.hashCount). It logs the store's size first: a
// benchmark's log is printed without -v only from a leaf, and this is one.
func benchSnapshot(b *testing.B, s *Store, n int) {
	benchLogFileSize(b, s)
	start := s.chain.hashCount()
	b.ReportAllocs()
	for b.Loop() {
		snap, err := s.Snapshot(bg, benchServer)
		if err != nil || len(snap.Tools) != n {
			b.Fatalf("Snapshot = %d tools, %v", len(snap.Tools), err)
		}
	}
	b.ReportMetric(float64(s.chain.hashCount()-start)/float64(b.N), "hashes/op")
}

// TestBenchmarkSnapshotHashesOnlyAuditEntries pins what hashes/op counts since
// D21 (d): a reload hashes the audit entries it anchors to, each distinct
// entry once, and no canonical bytes. The two anchors of a tool (its newest
// approval entry and its newest state-bearing entry) are one entry while the
// approval is the newest entry about the tool, so a reload of a freshly
// approved store hashes once per tool; a later lifecycle entry per tool (here
// the tool.missing entry a complete crawl that lists none of them writes, the
// state of a tool whose upstream stopped listing it) makes them two entries,
// so the reload hashes twice the tool count. A rewrite of a definition's bytes
// changes neither count, because the reload never reads them.
func TestBenchmarkSnapshotHashesOnlyAuditEntries(t *testing.T) {
	t.Parallel()
	const n = 8
	s, path := newStoreAt(t, benchPolicy())
	approvedServer(t, s, n)
	reloadHashes := func() int64 {
		t.Helper()
		before := s.chain.hashCount()
		if snap := mustSnapshot(t, s, benchServer); len(snap.Tools) != n {
			t.Fatalf("Snapshot = %d tools, want %d", len(snap.Tools), n)
		}
		return s.chain.hashCount() - before
	}
	if got := reloadHashes(); got != n {
		t.Fatalf("a reload of %d tools whose approval is the newest entry about each hashed %d entries, want %d (one per tool, both anchors naming the same entry)", n, got, n)
	}
	if rep := mustCrawl(t, s, benchServer); len(rep.Changes) != n {
		t.Fatalf("an empty complete crawl reported %d changes, want one tool.missing per tool", len(rep.Changes))
	}
	if got := reloadHashes(); got != 2*n {
		t.Fatalf("a reload of %d tools with a lifecycle entry after each approval hashed %d entries, want %d (twice the tool count: the approval entry and the state entry)", n, got, 2*n)
	}
	tamperCanonical(t, path, digestOf(t, benchName(0), "v1"), []byte(`{"name":"tool-00000"}`))
	res := testing.Benchmark(func(b *testing.B) { benchSnapshot(b, s, n) })
	if got := res.Extra["hashes/op"]; got != 2*n {
		t.Errorf("hashes/op = %v, want %d: the benchmark's metric is the count of anchor entries hashed, and a rewrite of the bytes changes nothing the reload reads", got, 2*n)
	}
}

// benchLogFileSize logs the size of the store's file and its WAL once filled:
// the pager runs with SQLite's default cache (the store sets no cache_size,
// openmodes.go), so how much of a reload is page reads depends on the ratio
// of the two. A missing WAL is fine; any other stat error is a failure.
func benchLogFileSize(b *testing.B, s *Store) {
	b.Helper()
	var total int64
	for _, p := range []string{s.path, s.path + "-wal"} {
		fi, err := os.Stat(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			b.Fatal(err)
		}
		total += fi.Size()
	}
	b.Logf("store is %d MiB on disk (file and WAL)", total>>20)
}

// benchStore opens a store with one server of benchTools approved tools.
func benchStore(b *testing.B) *Store {
	b.Helper()
	s := benchOpen(b)
	benchFill(b, s, benchTools, benchToolBytes)
	return s
}

// benchOpen opens an empty store under benchPolicy and registers benchServer.
func benchOpen(b *testing.B) *Store {
	b.Helper()
	s, err := Open(filepath.Join(b.TempDir(), "catalog.db"), benchPolicy())
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = s.Close() })
	if _, err := s.AddServer(bg, ServerSpec{Name: benchServer, URL: "https://alpha.example.com/mcp"}, alice); err != nil {
		b.Fatal(err)
	}
	return s
}

// benchPolicy is the default policy with deprecation off: a store filled by
// several crawls (benchFill) would otherwise deprecate its first slice on the
// third miss and leave it out of the snapshot, and the benchmark would reload
// fewer tools than it names. The 1000-tool store is filled by one crawl, which
// the setting does not touch.
func benchPolicy() lifecycle.Policy {
	p := lifecycle.DefaultPolicy()
	p.DeprecateAfter = 0
	return p
}

// benchFill gives benchServer n approved tools whose description is descBytes
// long. MaxCrawlBytes bounds one complete crawl, so n tools of 8 KiB (about
// 80 MiB) or of MaxToolBytes (about 2.5 GiB) cannot arrive in one crawl, from
// this helper or from a real upstream: the store is filled by successive
// complete crawls of disjoint slices, each as large as the cap admits. A tool
// a later crawl does not list is missing (LastSeen "", MissingCrawls + 1 and
// a tool.missing entry), the state of a tool whose upstream stopped listing
// it. Every tool is approved after the last crawl, as the 1000-tool store is,
// so the approval entry is the newest entry about every tool and the reload
// anchors every approved version, listed or missing, through one entry each
// (readPolicyRows keeps every non-deprecated tool with an approved version).
// A crawl the catalog records as failed is fatal with its class, so the
// benchmark never reloads fewer tools than it names. The split is logged
// (visible with -v, since this runs in the parent benchmark) so that a record
// of a run quotes the run rather than a derivation of the constants.
func benchFill(b *testing.B, s *Store, n, descBytes int) {
	b.Helper()
	desc := strings.Repeat("x", descBytes)
	rawBytes := len(def(benchName(0), desc))
	perCrawl := min(n, MaxCrawlBytes/rawBytes)
	crawls := (n + perCrawl - 1) / perCrawl
	b.Logf("filling %d tools of %d raw bytes each in %d complete crawls of at most %d tools (MaxCrawlBytes %d)", n, rawBytes, crawls, perCrawl, MaxCrawlBytes)
	digests := make([]string, 0, n)
	for from := 0; from < n; from += perCrawl {
		digests = append(digests, benchCrawl(b, s, from, min(from+perCrawl, n), desc)...)
	}
	for i, d := range digests {
		if err := s.Approve(bg, benchServer, benchName(i), d, bob); err != nil {
			b.Fatal(err)
		}
	}
}

// benchCrawl records one complete crawl listing the tools from (included) to
// to (excluded) and returns their digests in order. The raw definitions of
// one slice are built here and dropped on return, so the at-cap store never
// holds more than one crawl's bytes in memory.
func benchCrawl(b *testing.B, s *Store, from, to int, desc string) []string {
	b.Helper()
	tools := make([]CrawledTool, 0, to-from)
	digests := make([]string, 0, to-from)
	for i := from; i < to; i++ {
		raw := def(benchName(i), desc)
		d, err := gate.Digest(raw)
		if err != nil {
			b.Fatal(err)
		}
		tools = append(tools, CrawledTool{Name: benchName(i), Raw: raw})
		digests = append(digests, d)
	}
	rep, err := s.RecordCrawl(bg, CrawlInput{Server: benchServer, Complete: true, Tools: tools}, crawler)
	if err != nil {
		b.Fatal(err)
	}
	if !rep.Complete {
		b.Fatalf("crawl of tools %d to %d was recorded as failed under class %q", from, to-1, rep.Error)
	}
	return digests
}

// benchName is the name of the i-th benchmark tool.
func benchName(i int) string { return fmt.Sprintf(benchNameFormat, i) }

// benchCapDescBytes is the description length that brings one raw definition
// to MaxToolBytes exactly, the largest the catalog accepts (tooldef.go refuses
// a longer one); def quotes a plain ASCII description byte for byte.
func benchCapDescBytes() int { return MaxToolBytes - len(def(benchName(0), "")) }
