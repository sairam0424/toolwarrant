package catalog

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// Third review, ingest-3 (D13(c)): an upstream that lists fresh names on
// every crawl grew the catalog without bound (the proposal budget is per tool)
// and made every later crawl load every row the server ever had. Now a fixed
// cap on tool rows and on stored canonical bytes per server turns such a crawl
// into a recorded failure, and a crawl loads the live set only.

// freshNames lists n tools under names no earlier crawl used.
func freshNames(generation, n int) []CrawledTool {
	tools := make([]CrawledTool, n)
	for i := range tools {
		name := fmt.Sprintf("gen%d-tool-%05d", generation, i)
		tools[i] = CrawledTool{Name: name, Raw: def(name, "fresh name every crawl")}
	}
	return tools
}

// fileSize returns the size of the database file after a checkpoint, so that
// pages waiting in the WAL are counted.
func fileSize(t *testing.T, s *Store, path string) int64 {
	t.Helper()
	if _, err := s.wdb.ExecContext(bg, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Size()
}

// The row cap holds: crawls of fresh names fill the server up to the cap, the
// next one is recorded as failed under its class and adds nothing, and the
// file stops growing. The caps are lowered on the Store so that the test
// reaches them in seconds; the constants are pinned separately.
func TestRecordCrawl_RenamedToolsStopAtTheServerCap(t *testing.T) {
	t.Parallel()
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	const perCrawl, crawls = 100, 3
	s.caps = serverCaps{tools: perCrawl * crawls, bytes: MaxServerBytes}
	mustAddServer(t, s, "alpha")
	db := rawDB(t, path)
	for c := 0; c < crawls; c++ {
		if rep := mustCrawl(t, s, "alpha", freshNames(c, perCrawl)...); !rep.Complete {
			t.Fatalf("crawl %d within the cap = %+v", c, rep)
		}
	}
	rows := mustCount(t, db, `SELECT COUNT(*) FROM tools`)
	versions := mustCount(t, db, `SELECT COUNT(*) FROM tool_versions`)
	size := fileSize(t, s, path)
	before := takeTrace(t, s)
	if rows != perCrawl*crawls {
		t.Fatalf("precondition: %d rows, want the cap %d", rows, perCrawl*crawls)
	}

	for c := crawls; c < crawls+3; c++ {
		rep, err := s.RecordCrawl(bg, crawlOf(freshNames(c, perCrawl)...), crawler)
		if err != nil || rep.Complete || rep.Error != failureServerTools || len(rep.Changes) != 0 || rep.CrawlID <= 0 {
			t.Fatalf("crawl %d over the cap = %+v, %v; want a recorded failure of class %s", c, rep, err, failureServerTools)
		}
		if e := entryOf(t, s, "crawl.failed"); !strings.HasSuffix(e.Detail, " reason="+failureServerTools) {
			t.Errorf("crawl.failed detail = %q", e.Detail)
		}
	}
	if got := mustCount(t, db, `SELECT COUNT(*) FROM tools`); got != rows {
		t.Errorf("tool rows grew from %d to %d past the cap", rows, got)
	}
	if got := mustCount(t, db, `SELECT COUNT(*) FROM tool_versions`); got != versions {
		t.Errorf("version rows grew from %d to %d past the cap", versions, got)
	}
	if got := takeTrace(t, s); got.gen != before.gen+3 || got.audits != before.audits+3 {
		t.Errorf("trace %+v -> %+v, want one write and one audit entry per refused crawl", before, got)
	}
	// Three refused crawls cost three crawls rows and three audit entries, a
	// few hundred bytes: the file holds within a page of what it was.
	if got := fileSize(t, s, path); got > size+8192 {
		t.Errorf("file grew from %d to %d bytes past the cap", size, got)
	}
	// One fresh name too many is refused; a crawl that lists only known names
	// (the live set, deprecated or not) still completes.
	if rep, _ := s.RecordCrawl(bg, crawlOf(append(freshNames(0, perCrawl), tool("one-more", "v1"))...), crawler); rep.Complete {
		t.Error("a crawl one row over the cap completed")
	}
	if rep := mustCrawl(t, s, "alpha", freshNames(0, perCrawl)...); !rep.Complete {
		t.Errorf("a crawl within the cap = %+v", rep)
	}
	mustBeClean(t, s, "after the refused crawls")
}

// The byte cap holds the same way: a definition the server has no room for
// fails the crawl, and a crawl of known digests still completes.
func TestRecordCrawl_NewDefinitionsStopAtTheServerByteCap(t *testing.T) {
	t.Parallel()
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("echo", "v1"))
	db := rawDB(t, path)
	stored := int64(mustCount(t, db, `SELECT SUM(length(canonical)) FROM tool_versions`))
	next := tool("echo", "v2")
	p, terr := prepareTool(next)
	if terr != nil {
		t.Fatal(terr)
	}
	s.caps = serverCaps{tools: MaxToolsPerServer, bytes: stored + int64(len(p.canonical)) - 1}

	rep, err := s.RecordCrawl(bg, crawlOf(next), crawler)
	if err != nil || rep.Complete || rep.Error != failureServerBytes || len(rep.Changes) != 0 {
		t.Fatalf("crawl over the byte cap = %+v, %v; want a recorded failure of class %s", rep, err, failureServerBytes)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM tool_versions`); n != 1 {
		t.Errorf("versions = %d, want the one from before", n)
	}
	if rep := mustCrawl(t, s, "alpha", tool("echo", "v1")); !rep.Complete || kindsOf(rep)["echo"] != ChangeUnchanged {
		t.Errorf("a crawl of a known digest = %+v", rep)
	}
	s.caps.bytes++
	if rep := mustCrawl(t, s, "alpha", next); !rep.Complete || kindsOf(rep)["echo"] != ChangeChanged {
		t.Errorf("the same crawl with room for it = %+v", rep)
	}
	// A tool over its proposal budget stores nothing, so it adds no bytes.
	s.caps.bytes = stored + int64(len(p.canonical))
	for i := 0; i < MaxProposalsPerDecision; i++ {
		s.caps.bytes += int64(len(p.canonical)) + 16
		mustCrawl(t, s, "alpha", tool("echo", fmt.Sprintf("variant %02d", i)))
	}
	if v := mustTool(t, s, "alpha", "echo"); !v.Unusable {
		t.Fatalf("precondition: %+v, want the budget exhausted", v)
	}
	rep = mustCrawl(t, s, "alpha", tool("echo", "over budget"))
	if !rep.Complete || len(rep.Changes) != 1 || rep.Changes[0].Reason != reasonBudget {
		t.Errorf("an over-budget definition with no byte room = %+v, want observed under the budget reason, not a cap failure", rep)
	}
}

// A crawl loads the live set and the deprecated tools it lists, nothing else:
// a deprecated row whose versions would fail the load does not touch a crawl
// that does not name it, and fails the one that does.
func TestRecordCrawl_DeprecatedToolsAreLoadedOnlyWhenListed(t *testing.T) {
	t.Parallel()
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("gone", "v1"), tool("keep", "v1"))
	for i := 0; i < lifecycle.DefaultPolicy().DeprecateAfter; i++ {
		mustCrawl(t, s, "alpha", tool("keep", "v1"))
	}
	if st := stateOf(t, s, "alpha", "gone"); st != lifecycle.Deprecated {
		t.Fatalf("precondition: state = %s, want deprecated", st)
	}
	db := rawDB(t, path)
	mustExec(t, db, `DROP TRIGGER tool_versions_immutable`)
	mustExec(t, db, `UPDATE tool_versions SET digest_profile = 'legacy-v0' WHERE tool_id = (SELECT id FROM tools WHERE name = 'gone')`)
	restoreGuard(t, db, "tool_versions_immutable")

	rep := mustCrawl(t, s, "alpha", tool("keep", "v1"), tool("fresh", "v1"))
	if len(rep.Changes) != 2 || kindsOf(rep)["fresh"] != ChangeNew {
		t.Errorf("crawl without the deprecated name = %+v", rep.Changes)
	}
	if _, err := s.RecordCrawl(bg, crawlOf(tool("gone", "v1"), tool("keep", "v1")), crawler); !errors.Is(err, ErrCorrupt) {
		t.Errorf("crawl naming the deprecated tool = %v, want ErrCorrupt from loading it", err)
	}
	// Unusable listings of a deprecated name load it too.
	in := CrawlInput{Server: "alpha", Complete: true, Tools: []CrawledTool{tool("keep", "v1")}, Unusable: []UnusableTool{unusableOf("gone", "not-canonical")}}
	if _, err := s.RecordCrawl(bg, in, crawler); !errors.Is(err, ErrCorrupt) {
		t.Errorf("unusable listing of the deprecated tool = %v, want ErrCorrupt", err)
	}
	// Repaired, the deprecated tool reappears when listed.
	mustExec(t, db, `DROP TRIGGER tool_versions_immutable`)
	mustExec(t, db, `UPDATE tool_versions SET digest_profile = 'full-v1'`)
	restoreGuard(t, db, "tool_versions_immutable")
	if rep := mustCrawl(t, s, "alpha", tool("gone", "v1"), tool("keep", "v1")); kindsOf(rep)["gone"] != ChangeReappeared {
		t.Errorf("reappearance = %+v", rep.Changes)
	}
}

// The caps are what the documentation says, and a crawl within the per-crawl
// caps always fits an empty server.
func TestServerCaps_Constants(t *testing.T) {
	t.Parallel()
	if MaxToolsPerServer != 50000 || MaxServerBytes != 1<<30 {
		t.Errorf("MaxToolsPerServer = %d, MaxServerBytes = %d; the documentation names 50000 and 1 GiB", MaxToolsPerServer, MaxServerBytes)
	}
	if MaxToolsPerServer < MaxToolsPerCrawl || MaxServerBytes < MaxCrawlBytes {
		t.Error("a single crawl within the per-crawl caps must fit an empty server")
	}
	if caps := defaultServerCaps(); caps.tools != MaxToolsPerServer || caps.bytes != MaxServerBytes {
		t.Errorf("defaultServerCaps = %+v", caps)
	}
	for _, class := range []string{failureServerTools, failureServerBytes} {
		if !isClassToken(class) || class == failureTooManyTools || class == failureTooLarge {
			t.Errorf("%q is not a distinct class token", class)
		}
	}
}

// A deprecated tool keeps its row out of every crawl, except while it still
// carries the unusable marker from a sighting: the lifecycle clears that
// marker the first time a crawl does not list the tool (observeMissing), so
// the store must load it once more for that crawl and may skip it afterwards.
// Without this the store and the lifecycle model diverge (the model test found
// it: store LastSeen unusable, model LastSeen empty).
func TestRecordCrawl_DeprecatedToolWithAMarkerIsClearedOnce(t *testing.T) {
	t.Parallel()
	s, _ := newStoreAt(t, lifecycle.DefaultPolicy())
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("gone", "v1"), tool("keep", "v1"))
	for i := 0; i < lifecycle.DefaultPolicy().DeprecateAfter; i++ {
		mustCrawl(t, s, "alpha", tool("keep", "v1"))
	}
	if st := stateOf(t, s, "alpha", "gone"); st != lifecycle.Deprecated {
		t.Fatalf("precondition: state = %s, want deprecated", st)
	}
	in := CrawlInput{Server: "alpha", Complete: true, Tools: []CrawledTool{tool("keep", "v1")}, Unusable: []UnusableTool{unusableOf("gone", "not-canonical")}}
	if rep := mustCrawlInput(t, s, in); kindsOf(rep)["gone"] != ChangeUnusable {
		t.Fatalf("unusable sighting of the deprecated tool = %+v", rep.Changes)
	}
	if v := mustTool(t, s, "alpha", "gone"); v.State != lifecycle.Deprecated || v.LastSeen != lifecycle.UnusableDigest || !v.Unusable {
		t.Fatalf("after the sighting: %+v, want deprecated with the unusable marker", v)
	}
	rep := mustCrawl(t, s, "alpha", tool("keep", "v1"))
	if len(rep.Changes) != 2 || kindsOf(rep)["gone"] != ChangeMissing {
		t.Errorf("first crawl without the marked tool = %+v, want a missing line for it", rep.Changes)
	}
	if v := mustTool(t, s, "alpha", "gone"); v.State != lifecycle.Deprecated || v.LastSeen != "" || v.Unusable {
		t.Errorf("after the clearing crawl: %+v, want deprecated with an empty LastSeen", v)
	}
	if rep := mustCrawl(t, s, "alpha", tool("keep", "v1")); len(rep.Changes) != 1 {
		t.Errorf("second crawl without the tool = %+v, want the deprecated tool skipped", rep.Changes)
	}
}
