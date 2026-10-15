package catalog

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

func TestRecordCrawl_FirstCrawlDiscoversAndNeverApproves(t *testing.T) {
	t.Parallel()
	s, path := newStoreAt(t, defaultPolicyForTests())
	mustAddServer(t, s, "alpha")

	rep := mustCrawl(t, s, "alpha", tool("b", "v1"), tool("a", "v1"))
	if !rep.Complete || rep.CrawlID <= 0 || len(rep.Changes) != 2 || len(rep.Rejected) != 0 || rep.Error != "" {
		t.Fatalf("report = %+v", rep)
	}
	for i, want := range []string{"a", "b"} {
		c := rep.Changes[i]
		if c.Tool != want || c.Kind != ChangeNew || c.State != lifecycle.PendingReview || c.Digest != digestOf(t, want, "v1") || c.Reason != "" {
			t.Errorf("Changes[%d] = %+v", i, c)
		}
	}
	for _, n := range []string{"a", "b"} {
		v := mustTool(t, s, "alpha", n)
		if v.Approved != "" || v.Pending != digestOf(t, n, "v1") || v.LastSeen != v.Pending || v.Versions != 1 || v.Drifted || v.Unusable {
			t.Errorf("tool %s = %+v", n, v)
		}
	}
	want := []string{"server.added",
		"tool.discovered", "version.proposed", "tool.discovered", "version.proposed", "crawl.completed"}
	if got := auditEvents(t, s); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("audit events = %v\nwant %v", got, want)
	}
	if e := entryOf(t, s, "crawl.completed"); e.Detail != "crawl="+itoa(rep.CrawlID)+" tools=2 changes=2 rejected=0" {
		t.Errorf("crawl.completed detail = %q", e.Detail)
	}
	snap := mustSnapshot(t, s, "alpha")
	if len(snap.Tools) != 2 || snap.CrawledAt.IsZero() {
		t.Fatalf("Snapshot = %+v", snap)
	}
	for n, p := range snap.Tools {
		if p.Approved != "" || snap.Serves(n, p.LastSeen) {
			t.Errorf("nothing is approved yet, but %s is served: %+v", n, p)
		}
	}
	if list, err := s.Approved(bg); err != nil || len(list) != 0 {
		t.Errorf("Approved = %v, %v; want none", list, err)
	}
	if n := mustCount(t, rawDB(t, path), `SELECT COUNT(*) FROM tools WHERE state = 'discovered'`); n != 0 {
		t.Errorf("%d tools persisted in the transient discovered state", n)
	}
	if _, err := s.VerifyAudit(bg); err != nil {
		t.Errorf("VerifyAudit: %v", err)
	}
}

func TestRecordCrawl_RecrawlOfSameDefinitionIsUnchanged(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("echo", "v1"))
	before := auditCount(t, s)

	rep := mustCrawl(t, s, "alpha", tool("echo", "v1"))
	if k := kindsOf(rep)["echo"]; k != ChangeUnchanged {
		t.Fatalf("kind = %s, want unchanged", k)
	}
	if got := auditCount(t, s); got != before+1 || entryOf(t, s, "crawl.completed").Detail == "" {
		t.Errorf("audit grew by %d, want only the crawl.completed entry", got-before)
	}
	if v := mustTool(t, s, "alpha", "echo"); v.Versions != 1 {
		t.Errorf("versions = %d", v.Versions)
	}
}

func TestRecordCrawl_DriftRevertAndStrictMode(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustAddServer(t, s, "alpha")
	d1, d2 := digestOf(t, "echo", "v1"), digestOf(t, "echo", "v2")
	mustCrawl(t, s, "alpha", tool("echo", "v1"))
	mustApprove(t, s, "alpha", "echo", d1)

	rep := mustCrawl(t, s, "alpha", tool("echo", "v2"))
	if c := rep.Changes[0]; c.Kind != ChangeChanged || c.State != lifecycle.ChangedPendingReapproval || c.Digest != d2 {
		t.Fatalf("drift change = %+v", c)
	}
	v := mustTool(t, s, "alpha", "echo")
	if v.Approved != d1 || v.Pending != d2 || v.LastSeen != d2 || !v.Drifted || v.Versions != 2 {
		t.Fatalf("drifted tool = %+v", v)
	}
	ev := entryOf(t, s, "tool.drifted")
	if ev.Detail != "digest="+d2+" state=enabled->changed_pending_reapproval last_seen="+d2+" proposals=0->1" ||
		ev.BeforeHash != d1 || ev.AfterHash != d1 || ev.Subject != "alpha/echo" || ev.Actor != "crawler" || ev.ActorType != "system" {
		t.Errorf("drift audit entry = %+v", ev)
	}
	snap := mustSnapshot(t, s, "alpha")
	if snap.Serves("echo", d2) {
		t.Error("strict mode: the unapproved definition must not be served")
	}
	if !snap.Serves("echo", d1) {
		t.Error("the approved definition is served again as soon as the upstream serves it")
	}
	if p := snap.Tools["echo"]; p.LastSeen != d2 || p.Approved != d1 || p.State != lifecycle.ChangedPendingReapproval {
		t.Errorf("policy = %+v", p)
	}

	rep = mustCrawl(t, s, "alpha", tool("echo", "v1"))
	if c := rep.Changes[0]; c.Kind != ChangeReverted || c.State != lifecycle.Enabled || c.Digest != d1 {
		t.Fatalf("revert change = %+v", c)
	}
	vs, err := s.Versions(bg, "alpha", "echo")
	if err != nil || len(vs) != 2 || vs[0].Status != lifecycle.VersionApproved || vs[1].Status != lifecycle.VersionSuperseded {
		t.Fatalf("versions after revert = %+v, %v", vs, err)
	}
}

func TestRecordCrawl_MissingDeprecatedAndReappeared(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustAddServer(t, s, "alpha")
	da := digestOf(t, "a", "v1")
	mustCrawl(t, s, "alpha", tool("a", "v1"), tool("b", "v1"))
	mustApprove(t, s, "alpha", "a", da)

	for i, want := range []ChangeKind{ChangeMissing, ChangeMissing, ChangeDeprecated} {
		rep := mustCrawl(t, s, "alpha", tool("b", "v1"))
		kinds := kindsOf(rep)
		if kinds["a"] != want || kinds["b"] != ChangeUnchanged {
			t.Fatalf("crawl %d: kinds = %v, want a=%s", i+1, kinds, want)
		}
		for _, c := range rep.Changes {
			if c.Tool == "a" && c.Digest != "" {
				t.Errorf("an absent tool has no live digest, got %q", c.Digest)
			}
		}
	}
	if v := mustTool(t, s, "alpha", "a"); v.State != lifecycle.Deprecated || v.MissingCrawls != 3 || v.LastSeen != "" {
		t.Fatalf("deprecated tool = %+v", v)
	}
	snap := mustSnapshot(t, s, "alpha")
	if _, ok := snap.Tools["a"]; ok || snap.Serves("a", da) {
		t.Errorf("a deprecated tool must not be in the snapshot: %+v", snap.Tools)
	}
	if list, _ := s.Approved(bg); len(list) != 0 {
		t.Errorf("Approved lists a deprecated tool: %+v", list)
	}
	// A deprecated tool that stays away produces no further noise: it is not
	// loaded and has no report line (D13: the crawl's cost follows the live set).
	if rep := mustCrawl(t, s, "alpha", tool("b", "v1")); len(rep.Changes) != 1 || rep.Changes[0].Tool != "b" {
		t.Errorf("deprecated and still absent: report %+v, want b alone", rep.Changes)
	}
	if v := mustTool(t, s, "alpha", "a"); v.State != lifecycle.Deprecated || v.MissingCrawls != 3 {
		t.Errorf("deprecated tool after one more crawl = %+v, want untouched", v)
	}

	rep := mustCrawl(t, s, "alpha", tool("a", "v1"), tool("b", "v1"))
	if c := rep.Changes[0]; c.Tool != "a" || c.Kind != ChangeReappeared || c.State != lifecycle.PendingReview {
		t.Fatalf("reappearance = %+v", c)
	}
	if v := mustTool(t, s, "alpha", "a"); v.Approved != "" || v.Pending != da || v.MissingCrawls != 0 {
		t.Errorf("after reappearing the old approval must be gone: %+v", v)
	}
}

// A tool that comes back after a missed crawl is "returned" (D5: the flip
// from denied to served gets its own event and its own report line).
func TestRecordCrawl_ReturnAfterMissIsReportedAndAudited(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustAddServer(t, s, "alpha")
	dA := digestOf(t, "echo", "A")
	mustCrawl(t, s, "alpha", tool("echo", "A"), tool("other", "x"))
	mustApprove(t, s, "alpha", "echo", dA)
	if k := kindsOf(mustCrawl(t, s, "alpha", tool("other", "x")))["echo"]; k != ChangeMissing {
		t.Fatalf("kind after the miss = %s", k)
	}
	n0 := auditCount(t, s)
	rep := mustCrawl(t, s, "alpha", tool("echo", "A"), tool("other", "x"))
	if c := rep.Changes[0]; c.Kind != ChangeReturned || c.Digest != dA || c.State != lifecycle.Enabled {
		t.Fatalf("return = %+v", c)
	}
	added := auditEvents(t, s)[n0:]
	if strings.Join(added, ",") != "tool.returned,tool.reverted,crawl.completed" {
		t.Errorf("audit events added by the return = %v", added)
	}
	if v := mustTool(t, s, "alpha", "echo"); v.MissingCrawls != 0 || v.LastSeen != dA {
		t.Errorf("tool after return = %+v", v)
	}
}

func TestRecordCrawl_IncompleteCrawlChangesNoTool(t *testing.T) {
	t.Parallel()
	s, path := newStoreAt(t, defaultPolicyForTests())
	db := rawDB(t, path)
	mustAddServer(t, s, "alpha")
	d := digestOf(t, "a", "v1")
	mustCrawl(t, s, "alpha", tool("a", "v1"), tool("b", "v1"))
	mustApprove(t, s, "alpha", "a", d)
	tools := mustCount(t, db, `SELECT COUNT(*) FROM tools`)
	versions := mustCount(t, db, `SELECT COUNT(*) FROM tool_versions`)
	gen, audits := mustGeneration(t, s), auditCount(t, s)
	crawledAt := mustSnapshot(t, s, "alpha").CrawledAt

	rep, err := s.RecordCrawl(bg, CrawlInput{
		Server: "alpha", Complete: false,
		Error: "get https://host/mcp?token=SECRET123: timeout\nline2\x00",
		Tools: []CrawledTool{tool("brand-new", "v1")},
	}, crawler)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Complete || len(rep.Changes) != 0 || rep.CrawlID <= 0 || rep.Error != "error" {
		t.Fatalf("report = %+v", rep)
	}
	if got := mustCount(t, db, `SELECT COUNT(*) FROM tools`); got != tools {
		t.Errorf("an incomplete crawl created a tool: %d -> %d", tools, got)
	}
	if got := mustCount(t, db, `SELECT COUNT(*) FROM tool_versions`); got != versions {
		t.Errorf("an incomplete crawl created a version: %d -> %d", versions, got)
	}
	for n, want := range map[string]lifecycle.State{"a": lifecycle.Enabled, "b": lifecycle.PendingReview} {
		if v := mustTool(t, s, "alpha", n); v.State != want || v.MissingCrawls != 0 || v.LastSeen != digestOf(t, n, "v1") {
			t.Errorf("tool %s moved: %+v", n, v)
		}
	}
	if mustGeneration(t, s) != gen+1 || auditCount(t, s) != audits+1 {
		t.Errorf("the failure is one committed write with one audit entry")
	}
	if snap := mustSnapshot(t, s, "alpha"); !snap.CrawledAt.Equal(crawledAt) {
		t.Errorf("CrawledAt moved to %v after an incomplete crawl; it names the latest complete one (%v)", snap.CrawledAt, crawledAt)
	}
	e := entryOf(t, s, "crawl.failed")
	if strings.Contains(e.Detail, "SECRET") || strings.Contains(e.Detail, "timeout") || e.Subject != "alpha" ||
		e.Detail != "crawl="+itoa(rep.CrawlID)+" tools=1 complete=false reason=error" {
		t.Errorf("crawl.failed entry = %+v", e)
	}
	var complete, toolCount int
	var stored string
	if err := db.QueryRowContext(bg, `SELECT complete, tool_count, error FROM crawls WHERE id = ?`, rep.CrawlID).
		Scan(&complete, &toolCount, &stored); err != nil {
		t.Fatal(err)
	}
	// The crawls row keeps the class and a quoted, sanitised fragment: a
	// terminal that prints it sees escapes, never raw bytes.
	if complete != 0 || toolCount != 1 || stored != `error "get https://host/mcp?token=SECRET123: timeout line2?"` {
		t.Errorf("crawls row = %d %d %q", complete, toolCount, stored)
	}

	long, err := s.RecordCrawl(bg, CrawlInput{Server: "alpha", Error: strings.Repeat(cp(eAcute), 5000)}, crawler)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRowContext(bg, `SELECT length(CAST(error AS BLOB)) FROM crawls WHERE id = ?`, long.CrawlID).Scan(&n); err != nil || n > 2*maxCrawlErrorBytes {
		t.Errorf("stored error is %d bytes (%v), limit %d plus quoting", n, err, maxCrawlErrorBytes)
	}

	// A class the caller already reduced is kept as it is, in the row and the
	// log; a phrase with spaces is quoted in the log so key=value stays readable.
	for class, inLog := range map[string]string{"timeout": "timeout", "http status 401": `"http status 401"`} {
		classed, err := s.RecordCrawl(bg, CrawlInput{Server: "alpha", Error: class}, crawler)
		if err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRowContext(bg, `SELECT error FROM crawls WHERE id = ?`, classed.CrawlID).Scan(&stored); err != nil || stored != class {
			t.Errorf("stored class = %q, %v", stored, err)
		}
		if e := entryOf(t, s, "crawl.failed"); !strings.HasSuffix(e.Detail, " reason="+inLog) || classed.Error != class {
			t.Errorf("classed failure: detail %q, report error %q", e.Detail, classed.Error)
		}
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestRecordCrawl_ProposerCannotApproveOwnCrawl(t *testing.T) {
	t.Parallel()
	t.Run("default policy", func(t *testing.T) {
		s := newStore(t)
		mustAddServer(t, s, "alpha")
		if _, err := s.RecordCrawl(bg, crawlOf(tool("echo", "v1")), alice); err != nil {
			t.Fatal(err)
		}
		gen, audits := mustGeneration(t, s), auditCount(t, s)
		err := s.Approve(bg, "alpha", "echo", digestOf(t, "echo", "v1"), alice)
		if !errors.Is(err, lifecycle.ErrSelfApproval) {
			t.Fatalf("Approve by the proposer: %v, want ErrSelfApproval", err)
		}
		if mustGeneration(t, s) != gen || auditCount(t, s) != audits || stateOf(t, s, "alpha", "echo") != lifecycle.PendingReview {
			t.Error("a refused approval must leave no trace")
		}
		mustApprove(t, s, "alpha", "echo", digestOf(t, "echo", "v1"))
	})
	t.Run("self approval allowed by policy", func(t *testing.T) {
		p := lifecycle.DefaultPolicy()
		p.AllowSelfApproval = true
		s, _ := newStoreAt(t, p)
		mustAddServer(t, s, "alpha")
		if _, err := s.RecordCrawl(bg, crawlOf(tool("echo", "v1")), alice); err != nil {
			t.Fatal(err)
		}
		if err := s.Approve(bg, "alpha", "echo", digestOf(t, "echo", "v1"), alice); err != nil {
			t.Fatalf("Approve: %v", err)
		}
	})
}

// D1: _meta is part of the digest (hosts act on it), so a changed _meta is a
// new definition that needs its own approval.
func TestRecordCrawl_ChangedMetaIsANewDefinition(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustAddServer(t, s, "alpha")
	withMeta := func(id string) CrawledTool {
		return CrawledTool{Name: "echo", Raw: []byte(`{"name":"echo","description":"d","_meta":{"ui/resourceUri":"ui://` + id + `"}}`)}
	}
	mustCrawl(t, s, "alpha", withMeta("one"))
	rep := mustCrawl(t, s, "alpha", withMeta("two"))
	if k := kindsOf(rep)["echo"]; k != ChangeChanged {
		t.Fatalf("a changed _meta must be a new definition, got %s", k)
	}
	vs, err := s.Versions(bg, "alpha", "echo")
	if err != nil || len(vs) != 2 || vs[0].Digest == vs[1].Digest {
		t.Fatalf("versions = %+v, %v; want two distinct digests", vs, err)
	}
}
