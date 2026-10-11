package catalog

import (
	"fmt"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// The fourth review's growth measurement (D14 d): an upstream that lists fresh
// unusable names on every crawl created no row and no version, only one
// tool.rejected entry per name, so neither the per-crawl nor the per-server
// caps engaged and the log grew by megabytes per crawl. A crawl that would
// reject more than MaxRejectedPerCrawl entries is now recorded as failed under
// its own class and adds no tool.rejected entry.

// rejectedNames lists n fresh names with unusable definitions.
func rejectedNames(generation, n int) []UnusableTool {
	out := make([]UnusableTool, n)
	for i := range out {
		out[i] = UnusableTool{Name: fmt.Sprintf("gen%d-decoy-%05d", generation, i), Reason: "not-canonical", Detail: "RFC 8785 canonicalisation refused the definition"}
	}
	return out
}

func TestRecordCrawl_RejectedEntriesStopAtTheCap(t *testing.T) {
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("echo", "v1"))
	db := rawDB(t, path)
	before := mustCount(t, db, `SELECT COUNT(*) FROM audit_log`)

	// At the cap the crawl is complete and every name is recorded once.
	rep, err := s.RecordCrawl(bg, CrawlInput{Server: "alpha", Complete: true, Tools: []CrawledTool{tool("echo", "v1")},
		Unusable: rejectedNames(0, MaxRejectedPerCrawl)}, crawler)
	if err != nil || !rep.Complete || len(rep.Rejected) != MaxRejectedPerCrawl {
		t.Fatalf("crawl at the cap = %+v, %v; want a complete crawl with every name rejected", rep.Error, err)
	}
	if added := mustCount(t, db, `SELECT COUNT(*) FROM audit_log`) - before; added != MaxRejectedPerCrawl+1 {
		t.Fatalf("audit entries added at the cap = %d, want %d plus the crawl", added, MaxRejectedPerCrawl)
	}
	before = mustCount(t, db, `SELECT COUNT(*) FROM audit_log`)

	// One over the cap: a failed crawl under its class, one entry, no row.
	rep, err = s.RecordCrawl(bg, CrawlInput{Server: "alpha", Complete: true, Tools: []CrawledTool{tool("echo", "v2")},
		Unusable: rejectedNames(1, MaxRejectedPerCrawl+1)}, crawler)
	if err != nil || rep.Complete || rep.Error != failureRejectedCap || len(rep.Rejected) != 0 || len(rep.Changes) != 0 || rep.CrawlID <= 0 {
		t.Fatalf("crawl over the cap = %+v, %v; want a recorded failure of class %s", rep, err, failureRejectedCap)
	}
	if added := mustCount(t, db, `SELECT COUNT(*) FROM audit_log`) - before; added != 1 {
		t.Errorf("audit entries added over the cap = %d, want 1 (crawl.failed only)", added)
	}
	if e := entryOf(t, s, evCrawlFailed); !strings.HasSuffix(e.Detail, " reason="+failureRejectedCap) {
		t.Errorf("crawl.failed detail = %q", e.Detail)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM tools`); n != 1 {
		t.Errorf("tool rows = %d, want the one known tool", n)
	}
	if v := mustTool(t, s, "alpha", "echo"); v.LastSeen != digestOf(t, "echo", "v1") {
		t.Errorf("a failed crawl observed echo: %+v", v)
	}
	var complete, errClass string
	if err := db.QueryRowContext(bg, `SELECT complete, error FROM crawls WHERE id = ?`, rep.CrawlID).Scan(&complete, &errClass); err != nil || complete != "0" || errClass != failureRejectedCap {
		t.Errorf("crawls row = complete %q, error %q, %v", complete, errClass, err)
	}

	// Known tools listed unusable are observed, not rejected, so they do not
	// count; nameless entries do.
	in := CrawlInput{Server: "alpha", Complete: true, Unusable: append(rejectedNames(2, MaxRejectedPerCrawl), unusableOf("echo", "not-canonical"))}
	if rep, err := s.RecordCrawl(bg, in, crawler); err != nil || !rep.Complete || len(rep.Rejected) != MaxRejectedPerCrawl {
		t.Fatalf("crawl with a known unusable tool at the cap = %+v, %v; want complete", rep.Error, err)
	}
	in = CrawlInput{Server: "alpha", Complete: true, Unusable: append(rejectedNames(3, MaxRejectedPerCrawl), UnusableTool{Reason: "invalid-name"})}
	if rep, err := s.RecordCrawl(bg, in, crawler); err != nil || rep.Complete || rep.Error != failureRejectedCap {
		t.Fatalf("crawl with a nameless entry over the cap = %+v, %v; want %s", rep.Error, err, failureRejectedCap)
	}
	mustBeClean(t, s, "after the capped crawls")
}

// The constant is pinned: a tenth of the per-crawl cap on entries.
func TestRecordCrawl_RejectedCapConstant(t *testing.T) {
	if MaxRejectedPerCrawl != 1000 || MaxRejectedPerCrawl*10 != MaxToolsPerCrawl {
		t.Errorf("MaxRejectedPerCrawl = %d, want 1000 (a tenth of MaxToolsPerCrawl %d)", MaxRejectedPerCrawl, MaxToolsPerCrawl)
	}
	if !isClassToken(failureRejectedCap) {
		t.Errorf("failure class %q is not a class token", failureRejectedCap)
	}
}
