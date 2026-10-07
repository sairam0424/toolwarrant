package catalog

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Store-level input handling: what AddServer and RecordCrawl do with bad or
// hostile input, and what they write while doing it.

func TestAddServer_RejectsBadInputAndWritesNothing(t *testing.T) {
	s := newStore(t)
	before := mustGeneration(t, s)
	good := ServerSpec{Name: "alpha", URL: "https://a.example.com/mcp"}
	for name, tc := range map[string]struct {
		spec ServerSpec
		by   Actor
	}{
		"empty name":      {ServerSpec{Name: "", URL: good.URL}, alice},
		"uppercase name":  {ServerSpec{Name: "Alpha", URL: good.URL}, alice},
		"injection name":  {ServerSpec{Name: "a'); DROP TABLE servers;--", URL: good.URL}, alice},
		"bad url":         {ServerSpec{Name: "alpha", URL: "ftp://x"}, alice},
		"injection url":   {ServerSpec{Name: "alpha", URL: "https://x.example.com/'; DROP TABLE servers;--"}, alice},
		"owner with ctrl": {ServerSpec{Name: "alpha", URL: good.URL, OwnerGroup: "team\x00a"}, alice},
		"no actor":        {good, Actor{Type: ActorHuman}},
		"bad actor type":  {good, Actor{Name: "alice", Type: "root"}},
		"spaced actor":    {good, Actor{Name: "al ice", Type: ActorHuman}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := s.AddServer(bg, tc.spec, tc.by); !errors.Is(err, ErrInvalid) {
				t.Fatalf("AddServer: %v, want ErrInvalid", err)
			}
		})
	}
	if got := mustGeneration(t, s); got != before {
		t.Errorf("rejected input moved the generation %d -> %d", before, got)
	}
	if servers, err := s.Servers(bg); err != nil || len(servers) != 0 {
		t.Errorf("Servers = %v, %v; want none", servers, err)
	}
}

func TestServers_StoreAndReturnExactlyWhatWasGiven(t *testing.T) {
	s := newStore(t)
	spec := ServerSpec{Name: "beta", URL: "http://127.0.0.1:9000/mcp?x=1", OwnerGroup: "data team", AllowPrivate: true}
	added, err := s.AddServer(bg, spec, alice)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddServer(bg, ServerSpec{Name: "alpha", URL: "https://a.example.com"}, alice); err != nil {
		t.Fatal(err)
	}
	got, err := s.Server(bg, "beta")
	if err != nil {
		t.Fatal(err)
	}
	if got.ServerSpec != spec || got.ID != added.ID || !got.CreatedAt.Equal(added.CreatedAt) || got.CreatedAt.IsZero() || got.Paused {
		t.Errorf("Server = %+v, AddServer returned %+v", got, added)
	}
	list, err := s.Servers(bg)
	if err != nil || len(list) != 2 || list[0].Name != "alpha" || list[1].Name != "beta" {
		t.Fatalf("Servers = %+v, %v; want alpha then beta", list, err)
	}
	for _, name := range []string{"missing", "", "Beta", "beta'--", "x\x00y"} {
		if _, err := s.Server(bg, name); !errors.Is(err, ErrNotFound) {
			t.Errorf("Server(%q) = %v, want ErrNotFound", name, err)
		}
	}
	if _, err := s.AddServer(bg, spec, bob); !errors.Is(err, ErrExists) {
		t.Errorf("duplicate AddServer = %v, want ErrExists", err)
	}
}

func TestInjectionLookingValuesAreStoredAsPlainData(t *testing.T) {
	s, path := newStoreAt(t, defaultPolicyForTests())
	mustAddServer(t, s, "alpha")
	nasty := []string{
		"x'; DROP TABLE tools; --",
		`x" OR 1=1 --`,
		"x%' UNION SELECT * FROM audit_log --",
		"`backtick`",
		"semi;colon",
	}
	tools := make([]CrawledTool, len(nasty))
	for i, n := range nasty {
		tools[i] = CrawledTool{Name: n, Raw: def(n, "desc "+n)}
	}
	rep := mustCrawl(t, s, "alpha", tools...)
	if len(rep.Changes) != len(nasty) {
		t.Fatalf("got %d changes, want %d", len(rep.Changes), len(nasty))
	}
	for _, n := range nasty {
		v := mustTool(t, s, "alpha", n)
		if v.Name != n || v.State != "pending_review" {
			t.Errorf("tool %q came back as %+v", n, v)
		}
		if _, err := s.Versions(bg, "alpha", n); err != nil {
			t.Errorf("Versions(%q): %v", n, err)
		}
	}
	// Lookups with hostile names are plain misses, and the tables are intact.
	for _, n := range []string{"x' OR '1'='1", "%", "_", "alpha' --"} {
		if _, err := s.Tool(bg, "alpha", n); !errors.Is(err, ErrNotFound) {
			t.Errorf("Tool(%q) = %v, want ErrNotFound", n, err)
		}
		if _, err := s.Snapshot(bg, n); !errors.Is(err, ErrNotFound) {
			t.Errorf("Snapshot(%q) = %v, want ErrNotFound", n, err)
		}
	}
	if list, err := s.Tools(bg, "alpha' OR '1'='1"); err != nil || len(list) != 0 {
		t.Errorf("Tools with a hostile filter = %v, %v; want empty", list, err)
	}
	if n := mustCount(t, rawDB(t, path), `SELECT COUNT(*) FROM tools`); n != len(nasty) {
		t.Errorf("tools table has %d rows, want %d", n, len(nasty))
	}
}

// An actor the catalog cannot attribute an audit entry to writes nothing.
func TestRecordCrawl_RejectsBadActorsAndWritesNothing(t *testing.T) {
	s, path := newStoreAt(t, defaultPolicyForTests())
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("keep", "v1"))
	db := rawDB(t, path)
	genBefore, auditBefore := mustGeneration(t, s), auditCount(t, s)
	crawlsBefore := mustCount(t, db, `SELECT COUNT(*) FROM crawls`)
	for name, by := range map[string]Actor{
		"no actor":       {},
		"bad actor type": {Name: "x", Type: "root"},
		"spaced actor":   {Name: "cr awler", Type: ActorSystem},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := s.RecordCrawl(bg, crawlOf(tool("a", "1")), by); !errors.Is(err, ErrInvalid) {
				t.Fatalf("RecordCrawl: %v, want ErrInvalid", err)
			}
		})
	}
	if got := mustGeneration(t, s); got != genBefore {
		t.Errorf("generation %d -> %d after rejected crawls", genBefore, got)
	}
	if got := auditCount(t, s); got != auditBefore {
		t.Errorf("audit entries %d -> %d after rejected crawls", auditBefore, got)
	}
	if got := mustCount(t, db, `SELECT COUNT(*) FROM crawls`); got != crawlsBefore {
		t.Errorf("crawls rows %d -> %d after rejected crawls", crawlsBefore, got)
	}
	if list, _ := s.Tools(bg, ""); len(list) != 1 || list[0].Name != "keep" {
		t.Errorf("tools after rejected crawls = %+v", list)
	}
}

// A listing that breaks a whole-crawl cap is recorded as a failed crawl under
// its class and changes no tool.
func TestRecordCrawl_ListingOverACapIsRecordedAsFailed(t *testing.T) {
	s, path := newStoreAt(t, defaultPolicyForTests())
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("keep", "v1"))
	db := rawDB(t, path)

	tooMany := make([]CrawledTool, MaxToolsPerCrawl+1)
	for i := range tooMany {
		tooMany[i] = CrawledTool{Name: fmt.Sprintf("t%d", i), Raw: []byte(`{"name":"x"}`)}
	}
	pad := strings.Repeat("x", MaxToolBytes-64)
	tooLarge := make([]CrawledTool, MaxCrawlBytes/MaxToolBytes+2)
	for i := range tooLarge {
		name := fmt.Sprintf("big%03d", i)
		tooLarge[i] = CrawledTool{Name: name, Raw: []byte(`{"name":"` + name + `","pad":"` + pad + `"}`)}
	}
	for name, tc := range map[string]struct {
		tools []CrawledTool
		class string
	}{
		"over 10000 tools": {tooMany, failureTooManyTools},
		"over 32 MiB":      {tooLarge, failureTooLarge},
	} {
		t.Run(name, func(t *testing.T) {
			before := takeTrace(t, s)
			rep, err := s.RecordCrawl(bg, crawlOf(tc.tools...), crawler)
			if err != nil || rep.Complete || rep.Error != tc.class || len(rep.Changes) != 0 || rep.CrawlID <= 0 {
				t.Fatalf("report = %+v, %v; want a recorded failure of class %s", rep, err, tc.class)
			}
			if got := takeTrace(t, s); got.gen != before.gen+1 || got.audits != before.audits+1 {
				t.Errorf("trace %+v -> %+v, want one write and one audit entry", before, got)
			}
			if e := entryOf(t, s, "crawl.failed"); !strings.HasSuffix(e.Detail, " reason="+tc.class) {
				t.Errorf("crawl.failed detail = %q", e.Detail)
			}
			var stored string
			if err := db.QueryRowContext(bg, `SELECT error FROM crawls WHERE id = ?`, rep.CrawlID).Scan(&stored); err != nil || stored != tc.class {
				t.Errorf("crawls.error = %q, %v", stored, err)
			}
		})
	}
	if list, _ := s.Tools(bg, ""); len(list) != 1 || list[0].Name != "keep" || list[0].LastSeen != digestOf(t, "keep", "v1") {
		t.Errorf("tools after refused listings = %+v", list)
	}
}

func TestRecordCrawl_AcceptsNamesTheRulesAllow(t *testing.T) {
	s := newStore(t)
	mustAddServer(t, s, "alpha")
	names := []string{"plain", "with space", cp(0x65E5, 0x672C, 0x8A9E), "emoji" + cp(0x1F600), "dots.and-dashes_1", strings.Repeat("n", maxToolNameBytes)}
	in := make([]CrawledTool, len(names))
	for i, n := range names {
		in[i] = CrawledTool{Name: n, Raw: def(n, "d")}
	}
	rep := mustCrawl(t, s, "alpha", in...)
	if len(rep.Changes) != len(names) || len(rep.Rejected) != 0 {
		t.Fatalf("changes = %d, rejected = %d, want %d and 0", len(rep.Changes), len(rep.Rejected), len(names))
	}
	for _, n := range names {
		if got := stateOf(t, s, "alpha", n); got != "pending_review" {
			t.Errorf("%q: state %s", n, got)
		}
	}
}
