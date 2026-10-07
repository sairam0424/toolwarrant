package catalog

import (
	"fmt"
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
)

// BenchmarkSnapshot1000Approved measures the processor's reload of a server
// with 1000 approved tools of about 8 KiB each. "uncached" reads and hashes
// every row on every reload, as every reload did before the verifier;
// "cached" is a reload after one warm reload. Both run in the same binary
// against the same database; hashes/op is the number of SHA-256 computed per
// reload.
func BenchmarkSnapshot1000Approved(b *testing.B) {
	s := benchStore(b)
	b.Run("uncached", func(b *testing.B) {
		s.verified = newVerifier(s.clock, 0)
		benchSnapshot(b, s)
	})
	b.Run("cached", func(b *testing.B) {
		s.verified = newVerifier(s.clock, recheckCacheEntries)
		if _, err := s.Snapshot(bg, "alpha"); err != nil {
			b.Fatal(err)
		}
		benchSnapshot(b, s)
	})
}

func benchSnapshot(b *testing.B, s *Store) {
	start := s.verified.hashCount()
	b.ReportAllocs()
	for b.Loop() {
		snap, err := s.Snapshot(bg, "alpha")
		if err != nil || len(snap.Tools) != benchTools {
			b.Fatalf("Snapshot = %d tools, %v", len(snap.Tools), err)
		}
	}
	b.ReportMetric(float64(s.verified.hashCount()-start)/float64(b.N), "hashes/op")
}

// benchStore opens a store with one server of benchTools approved tools.
func benchStore(b *testing.B) *Store {
	b.Helper()
	s, err := Open(filepath.Join(b.TempDir(), "catalog.db"), lifecycle.DefaultPolicy())
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = s.Close() })
	if _, err := s.AddServer(bg, ServerSpec{Name: "alpha", URL: "https://alpha.example.com/mcp"}, alice); err != nil {
		b.Fatal(err)
	}
	tools := make([]CrawledTool, benchTools)
	desc := strings.Repeat("x", benchToolBytes)
	for i := range tools {
		name := fmt.Sprintf("tool-%05d", i)
		tools[i] = CrawledTool{Name: name, Raw: def(name, desc)}
	}
	if _, err := s.RecordCrawl(bg, CrawlInput{Server: "alpha", Complete: true, Tools: tools}, crawler); err != nil {
		b.Fatal(err)
	}
	for _, tl := range tools {
		d, err := gate.Digest(tl.Raw)
		if err != nil {
			b.Fatal(err)
		}
		if err := s.Approve(bg, "alpha", tl.Name, d, bob); err != nil {
			b.Fatal(err)
		}
	}
	return s
}
