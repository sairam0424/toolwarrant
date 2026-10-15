package catalog

import (
	"context"
	"net/url"
	"testing"
)

// The read pool's page cache, measured and not changed. D21 (f) tracks whether
// a larger SQLite page cache or a memory map would shorten the 10000-tool
// reload, whose profile (PR 5.1) was dominated by page reads. The two
// benchmarks below run the reload of BenchmarkSnapshot10000Approved8KiB with
// the benchmark's own read pool reopened under one more pragma. openmodes.go is
// untouched: whether a reader should carry either setting (memory per
// connection times maxReadConns, a memory map against a WAL file) is the
// owner's decision, and this file only puts the numbers on the table.

const (
	// benchCacheSizePragma raises the page cache of one connection to 64 MiB
	// (a negative cache_size counts KiB); SQLite's default is 2000 KiB.
	benchCacheSizePragma = "cache_size(-65536)"
	// benchMmapSizePragma lets SQLite map up to 256 MiB of the file instead of
	// reading its pages through the cache; the 10000-tool store is about
	// 256 MiB on disk with its WAL (benchLogFileSize), far past the default
	// cache.
	benchMmapSizePragma = "mmap_size(268435456)"
)

// BenchmarkSnapshot10000Approved8KiBCache64MiB is the reload of
// BenchmarkSnapshot10000Approved8KiB with the read pool's page cache raised
// to 64 MiB per connection.
func BenchmarkSnapshot10000Approved8KiBCache64MiB(b *testing.B) {
	benchSnapshotWithPragma(b, benchCacheSizePragma, "cache_size")
}

// BenchmarkSnapshot10000Approved8KiBMmap256MiB is the reload of
// BenchmarkSnapshot10000Approved8KiB with the read pool reading the file
// through a memory map of up to 256 MiB.
func BenchmarkSnapshot10000Approved8KiBMmap256MiB(b *testing.B) {
	benchSnapshotWithPragma(b, benchMmapSizePragma, "mmap_size")
}

// benchSnapshotWithPragma fills the large store exactly as the plain benchmark
// does, swaps its read pool for one carrying the pragma, reads the setting
// back from a pooled connection so the log shows what ran (a build whose
// SQLite caps the setting would show the cap, not the request), and measures
// the reload.
func benchSnapshotWithPragma(b *testing.B, pragma, name string) {
	s := benchOpen(b)
	benchFill(b, s, benchLargeTools, benchToolBytes)
	benchSwapReadPool(b, s, pragma)
	var got int64
	if err := s.rdb.QueryRowContext(context.Background(), "PRAGMA "+name).Scan(&got); err != nil {
		b.Fatal(err)
	}
	b.Logf("the read pool runs with %s = %d", name, got)
	benchSnapshot(b, s, benchLargeTools)
}

// benchSwapReadPool closes the Store's read pool and opens another one on the
// reader DSN with one more _pragma value. The DSN is dsnFor's, extended here
// and nowhere else, so the production readers keep their four pragmas and the
// experiment stays inside the benchmark.
func benchSwapReadPool(b *testing.B, s *Store, pragma string) {
	b.Helper()
	u, err := url.Parse(dsnFor(s.path, connReader, DefaultBusyTimeout))
	if err != nil {
		b.Fatal(err)
	}
	q := u.Query()
	q.Add("_pragma", pragma)
	u.RawQuery = q.Encode()
	rdb, err := openPool(u.String(), maxReadConns)
	if err != nil {
		b.Fatal(err)
	}
	if err := s.rdb.Close(); err != nil {
		b.Fatal(err)
	}
	s.rdb = rdb
}
