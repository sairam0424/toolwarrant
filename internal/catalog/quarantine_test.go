package catalog

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// D3 regression (reviewers' "one poison name freezes the whole server"): a
// tool with a hostile name is quarantined on its own; the crawl is recorded
// and every other tool is observed, so LastSeen follows the upstream.
func TestRecordCrawl_PoisonNameIsQuarantined(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustAddServer(t, s, "alpha")
	dA, dChanged := digestOf(t, "echo", "A"), digestOf(t, "echo", "CHANGED")
	mustCrawl(t, s, "alpha", tool("echo", "A"))
	mustApprove(t, s, "alpha", "echo", dA)

	poisons := map[string]string{
		"zero width space": "zero" + cp(zwsp) + "width",
		"no-break space":   "list" + cp(nbsp) + "files",
		"tab":              "list\tfiles",
		"257 bytes":        strings.Repeat("a", 257),
		"NFD":              "cafe" + cp(acuteMark),
	}
	for label, name := range poisons {
		t.Run(label, func(t *testing.T) {
			gen, audits := mustGeneration(t, s), auditCount(t, s)
			rep, err := s.RecordCrawl(bg, crawlOf(tool("echo", "CHANGED"), CrawledTool{Name: name, Raw: def(name, "x")}), crawler)
			if err != nil || !rep.Complete {
				t.Fatalf("RecordCrawl = %+v, %v; one bad name must not fail the crawl", rep, err)
			}
			if len(rep.Changes) != 1 || rep.Changes[0].Tool != "echo" || rep.Changes[0].Digest != dChanged {
				t.Fatalf("changes = %+v", rep.Changes)
			}
			if len(rep.Rejected) != 1 || rep.Rejected[0].Name != "" || rep.Rejected[0].Reason != reasonInvalidName ||
				strings.Contains(rep.Rejected[0].Detail, name) {
				t.Fatalf("rejected = %+v; the name must not be shown", rep.Rejected)
			}
			if mustGeneration(t, s) != gen+1 || auditCount(t, s) <= audits {
				t.Error("the crawl was not recorded")
			}
			e := entryOf(t, s, "tool.rejected")
			if e.Subject != "alpha" || !strings.HasSuffix(e.Detail, " reason=invalid-name name=<unprintable>") || strings.Contains(e.Detail, name) {
				t.Errorf("tool.rejected entry = %+v", e)
			}
			if p := mustSnapshot(t, s, "alpha").Tools["echo"]; p.LastSeen != dChanged || p.Approved != dA {
				t.Errorf("echo policy = %+v; LastSeen must follow the upstream", p)
			}
			if !strings.Contains(entryOf(t, s, "crawl.completed").Detail, "rejected=1") {
				t.Error("crawl.completed does not count the rejection")
			}
			mustCrawl(t, s, "alpha", tool("echo", "A")) // back on the approval for the next case
		})
	}
	// Even an incomplete crawl that carries a poison tool is recorded.
	gen := mustGeneration(t, s)
	rep, err := s.RecordCrawl(bg, CrawlInput{Server: "alpha", Error: "timeout", Tools: []CrawledTool{tool("a\x00", "x")}}, crawler)
	if err != nil || rep.Complete || rep.Error != "timeout" || mustGeneration(t, s) != gen+1 {
		t.Errorf("incomplete crawl with a poison tool: %+v, %v", rep, err)
	}
	if list, _ := s.Tools(bg, "alpha"); len(list) != 1 {
		t.Errorf("tools = %+v; no row for a rejected name", list)
	}
}

// A known tool the crawler found unusable is marked, hidden and audited; an
// unknown one is rejected without a row.
func TestRecordCrawl_UnusableObservations(t *testing.T) {
	t.Parallel()
	s, path := newStoreAt(t, defaultPolicyForTests())
	mustAddServer(t, s, "alpha")
	dA := digestOf(t, "echo", "A")
	mustCrawl(t, s, "alpha", tool("echo", "A"))
	mustApprove(t, s, "alpha", "echo", dA)

	rep, err := s.RecordCrawl(bg, CrawlInput{Server: "alpha", Complete: true, Unusable: []UnusableTool{
		unusableOf("echo", "not-canonical"),
		{Name: "ghost", Reason: "Too-Large", Detail: "300000 bytes, the cap is 262144"},
		{Name: "", Reason: "unreadable", Detail: "not well-formed JSON"},
	}}, crawler)
	if err != nil || !rep.Complete {
		t.Fatalf("RecordCrawl = %+v, %v", rep, err)
	}
	if len(rep.Changes) != 1 {
		t.Fatalf("changes = %+v", rep.Changes)
	}
	if c := rep.Changes[0]; c.Tool != "echo" || c.Kind != ChangeUnusable || c.Digest != "" || c.Reason != "not-canonical" || c.State != lifecycle.Enabled {
		t.Errorf("echo change = %+v", c)
	}
	if len(rep.Rejected) != 2 || rep.Rejected[0] != (RejectedTool{Name: "ghost", Reason: "too-large", Detail: "300000 bytes, the cap is 262144"}) ||
		rep.Rejected[1] != (RejectedTool{Name: "", Reason: "unreadable", Detail: "not well-formed JSON"}) {
		t.Errorf("rejected = %+v", rep.Rejected)
	}
	v := mustTool(t, s, "alpha", "echo")
	if !v.Unusable || v.LastSeen != lifecycle.UnusableDigest || !v.Drifted || v.Versions != 1 || v.Approved != dA {
		t.Errorf("tool = %+v", v)
	}
	snap := mustSnapshot(t, s, "alpha")
	if p := snap.Tools["echo"]; p.LastSeen != lifecycle.UnusableDigest || snap.Serves("echo", p.LastSeen) || !snap.Serves("echo", dA) {
		t.Errorf("policy = %+v: the marker is never served, the approval stands", p)
	}
	if e := entryOf(t, s, "tool.unusable"); e.Subject != "alpha/echo" || e.Detail != "digest=- state=enabled->enabled last_seen=unusable proposals=0->0 reason=not-canonical" {
		t.Errorf("tool.unusable entry = %+v", e)
	}
	entries, _ := s.AuditEntries(bg, 0, 0)
	var rejectedDetails []string
	for _, e := range entries {
		if e.Event == "tool.rejected" {
			rejectedDetails = append(rejectedDetails, e.Subject+" "+e.Detail)
		}
	}
	if len(rejectedDetails) != 2 || !strings.HasSuffix(rejectedDetails[0], ` reason=too-large name="ghost"`) ||
		!strings.HasPrefix(rejectedDetails[0], "alpha/ghost ") || !strings.HasSuffix(rejectedDetails[1], " reason=unreadable name=<unprintable>") ||
		!strings.HasPrefix(rejectedDetails[1], "alpha ") {
		t.Errorf("tool.rejected entries = %q", rejectedDetails)
	}
	if n := mustCount(t, rawDB(t, path), `SELECT COUNT(*) FROM tools`); n != 1 {
		t.Errorf("%d tool rows; an unknown unusable name must not create one", n)
	}
	// A second unusable sighting changes nothing and is reported as such.
	rep2, _ := s.RecordCrawl(bg, CrawlInput{Server: "alpha", Complete: true, Unusable: []UnusableTool{unusableOf("echo", "not-canonical")}}, crawler)
	if k := kindsOf(rep2)["echo"]; k != ChangeUnchanged {
		t.Errorf("repeated unusable sighting: kind %s", k)
	}
	// A usable definition on the approved digest brings it back.
	rep3 := mustCrawl(t, s, "alpha", tool("echo", "A"))
	if c := rep3.Changes[0]; c.Kind != ChangeReverted || c.Digest != dA {
		t.Errorf("after the marker clears = %+v", c)
	}
	if v := mustTool(t, s, "alpha", "echo"); v.Unusable || v.Drifted {
		t.Errorf("tool after recovery = %+v", v)
	}
}

// Definitions the catalog itself refuses are quarantined with a class, whether
// the crawler vetted them or not.
func TestRecordCrawl_RefusedDefinitionsAreQuarantinedByClass(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("known", "v1"))
	deep := strings.Repeat(`{"a":`, MaxJSONDepth+1) + "1" + strings.Repeat("}", MaxJSONDepth+1)
	cases := map[string]struct {
		raw    string
		reason string
	}{
		"not json":            {`nope`, reasonUnreadable},
		"empty":               {``, reasonUnreadable},
		"array":               {`[{"name":"NAME"}]`, reasonUnreadable},
		"string":              {`"NAME"`, reasonUnreadable},
		"null":                {`null`, reasonUnreadable},
		"without name":        {`{"description":"d"}`, reasonUnreadable},
		"name is a number":    {`{"name":1}`, reasonUnreadable},
		"name capitalised":    {`{"Name":"NAME"}`, reasonUnreadable},
		"name mismatch":       {`{"name":"other"}`, reasonNameMismatch},
		"trailing data":       {`{"name":"NAME"} {"name":"NAME"}`, reasonUnreadable},
		"bad utf8":            {"{\"name\":\"NAME\",\"d\":\"\xff\"}", reasonUnreadable},
		"duplicate top key":   {`{"name":"NAME","d":1,"d":2}`, reasonNotCanonical},
		"nested duplicate":    {`{"name":"NAME","s":{"k":1,"k":2}}`, reasonNotCanonical},
		"inexact number":      {`{"name":"NAME","x":1e400}`, reasonNotCanonical},
		"lone surrogate":      {`{"name":"NAME","d":"\ud800"}`, reasonNotCanonical},
		"too deep":            {`{"name":"NAME","x":` + deep + `}`, reasonTooDeep},
		"over the byte cap":   {`{"name":"NAME","pad":"` + strings.Repeat("x", MaxToolBytes) + `"}`, reasonTooLarge},
		"depth at the cap ok": {`{"name":"NAME","x":` + strings.Repeat(`{"a":`, MaxJSONDepth-2) + "1" + strings.Repeat("}", MaxJSONDepth-2) + `}`, ""},
	}
	i := 0
	for label, tc := range cases {
		i++
		fresh := fmt.Sprintf("fresh-%d", i) // a name no earlier case has turned into a tool
		t.Run(label, func(t *testing.T) {
			for _, name := range []string{"known", fresh} {
				raw := []byte(strings.ReplaceAll(tc.raw, "NAME", name))
				rep, err := s.RecordCrawl(bg, crawlOf(CrawledTool{Name: name, Raw: raw}), crawler)
				if err != nil || !rep.Complete {
					t.Fatalf("%s: RecordCrawl = %+v, %v", name, rep, err)
				}
				switch {
				case tc.reason == "":
					if k := kindsOf(rep)[name]; k != ChangeNew && k != ChangeChanged {
						t.Errorf("%s: a valid definition was not observed: %+v", name, rep)
					}
				case name == "known":
					c := changeOf(rep, "known")
					if c.Kind != ChangeUnusable || c.Reason != tc.reason || len(rep.Rejected) != 0 {
						t.Errorf("known: change = %+v rejected = %+v, want unusable with reason %s", c, rep.Rejected, tc.reason)
					}
				default:
					if len(rep.Rejected) != 1 || rep.Rejected[0].Reason != tc.reason || rep.Rejected[0].Name != fresh {
						t.Errorf("%s: rejected = %+v, want reason %s", fresh, rep.Rejected, tc.reason)
					}
					if _, err := s.Tool(bg, "alpha", fresh); !errors.Is(err, ErrNotFound) {
						t.Errorf("%s got a tool row: %v", fresh, err)
					}
				}
			}
			mustCrawl(t, s, "alpha", tool("known", "v1")) // reset the marker between cases
		})
	}
}

// changeOf returns the report line for one tool.
func changeOf(rep CrawlReport, name string) ToolChange {
	for _, c := range rep.Changes {
		if c.Tool == name {
			return c
		}
	}
	return ToolChange{}
}

// Every copy of a repeated name is unusable (D3): a known tool is marked, an
// unknown name is rejected once.
func TestRecordCrawl_DuplicateNamesAreUnusable(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("dup", "v1"))
	rep := mustCrawl(t, s, "alpha", tool("dup", "v1"), tool("dup", "v2"), tool("twice", "a"), tool("twice", "b"), tool("solo", "x"))
	if c := rep.Changes[0]; c.Tool != "dup" || c.Kind != ChangeUnusable || c.Reason != reasonDuplicateName {
		t.Errorf("dup = %+v", c)
	}
	if len(rep.Rejected) != 1 || rep.Rejected[0].Name != "twice" || rep.Rejected[0].Reason != reasonDuplicateName ||
		rep.Rejected[0].Detail != "the name is listed 2 times" {
		t.Errorf("rejected = %+v", rep.Rejected)
	}
	if kindsOf(rep)["solo"] != ChangeNew || mustTool(t, s, "alpha", "dup").Versions != 1 {
		t.Errorf("the other tools must be observed normally: %+v", rep.Changes)
	}
	// A name listed once as usable and once as unusable is listed twice.
	rep = mustCrawlInput(t, s, CrawlInput{Server: "alpha", Complete: true, Tools: []CrawledTool{tool("solo", "x")},
		Unusable: []UnusableTool{unusableOf("solo", "too-deep")}})
	if c := kindsOf(rep)["solo"]; c != ChangeUnusable {
		t.Errorf("solo listed in both lists: kind %s", c)
	}
}

func mustCrawlInput(t *testing.T, s *Store, in CrawlInput) CrawlReport {
	t.Helper()
	rep, err := s.RecordCrawl(bg, in, crawler)
	if err != nil {
		t.Fatalf("RecordCrawl: %v", err)
	}
	return rep
}

// Look-alikes of a name (reviewers' finding) are rejected, so an approver can
// never be shown two tools that render alike.
func TestRecordCrawl_LookAlikeNamesAreRejected(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustAddServer(t, s, "alpha")
	variants := []string{
		"echo" + cp(vs16), "ec" + cp(cgj) + "ho", "echo" + cp(vs17), "echo" + cp(hangulFill), "echo" + cp(brailleBlnk),
		"echo" + cp(choseongFil), "cafe" + cp(acuteMark), "echo ", "ec  ho",
	}
	tools := []CrawledTool{tool("echo", "v1"), tool("caf"+cp(eAcute), "v1")}
	for _, n := range variants {
		tools = append(tools, tool(n, "v1"))
	}
	rep := mustCrawl(t, s, "alpha", tools...)
	if len(rep.Changes) != 2 || len(rep.Rejected) != len(variants) {
		t.Fatalf("changes = %d, rejected = %d; want 2 and %d", len(rep.Changes), len(rep.Rejected), len(variants))
	}
	for _, r := range rep.Rejected {
		if r.Name != "" || r.Reason != reasonInvalidName {
			t.Errorf("rejected = %+v", r)
		}
	}
	if list, _ := s.Tools(bg, "alpha"); len(list) != 2 {
		t.Errorf("%d tools on alpha, want 2", len(list))
	}
}

// What the crawler says about an unusable tool is bounded and sanitised, and
// a reason that is not a class token becomes the generic class.
func TestRecordCrawl_CrawlerDetailsAreBounded(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustAddServer(t, s, "alpha")
	hostile := strings.Repeat("x", 2*maxDetailBytes) + cp(rlo) + "\x00"
	rep := mustCrawlInput(t, s, CrawlInput{Server: "alpha", Complete: true, Unusable: []UnusableTool{
		{Name: "ghost", Reason: "Totally Weird: " + cp(zwsp), Detail: hostile},
	}})
	if len(rep.Rejected) != 1 {
		t.Fatalf("rejected = %+v", rep.Rejected)
	}
	r := rep.Rejected[0]
	if r.Reason != reasonUnusable || len(r.Detail) > maxDetailBytes || strings.ContainsRune(r.Detail, rlo) || strings.Contains(r.Detail, "\x00") {
		t.Errorf("rejected = reason %q detail %d bytes %q", r.Reason, len(r.Detail), r.Detail)
	}
	if e := entryOf(t, s, "tool.rejected"); !strings.HasSuffix(e.Detail, fmt.Sprintf(" reason=%s name=%q", reasonUnusable, "ghost")) {
		t.Errorf("entry = %+v", e)
	}
}
