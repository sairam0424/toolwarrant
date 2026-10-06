package catalog

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestValidateServerName(t *testing.T) {
	long63 := "a" + strings.Repeat("b", 62)
	for _, tc := range []struct {
		name string
		ok   bool
	}{
		{"a", true}, {"0", true}, {"my-server_1", true}, {long63, true},
		{"", false}, {"-a", false}, {"_a", false}, {"A", false}, {"a b", false}, {"a.b", false},
		{"a/b", false}, {"a\n", false}, {"a\x00", false}, {"é", false}, {long63 + "c", false},
		{"a'; DROP TABLE servers; --", false}, {"../etc", false},
	} {
		err := validateServerName(tc.name)
		if tc.ok != (err == nil) {
			t.Errorf("validateServerName(%q) = %v, want ok=%t", tc.name, err, tc.ok)
		}
		if err != nil && !errors.Is(err, ErrInvalid) {
			t.Errorf("validateServerName(%q) error %v is not ErrInvalid", tc.name, err)
		}
	}
}

func TestValidateURL(t *testing.T) {
	long := "https://example.com/" + strings.Repeat("a", maxURLBytes)
	for _, tc := range []struct {
		url string
		ok  bool
	}{
		{"https://example.com/mcp", true},
		{"http://localhost:8080/mcp", true},
		{"HTTPS://Example.com/mcp?x=1", true},
		{"http://[::1]:9000/", true},
		{"https://example.com:65535/", true},
		{"", false},
		{long, false},
		{"ftp://example.com/", false},
		{"file:///etc/passwd", false},
		{"javascript:alert(1)", false},
		{"//example.com/mcp", false},
		{"example.com/mcp", false},
		{"https:///path", false},
		{"https://user:pw@example.com/", false},
		{"https://user@example.com/", false},
		{"https://example.com/#frag", false},
		{"https://example.com/#", false},
		{"https://example.com:0/", false},
		{"https://example.com:99999/", false},
		{"https://example.com/a b", false},
		{"https://example.com/\x00", false},
		{"https://example.com/\n", false},
		{"https://exa\\mple.com/", false},
		{"https://example.com/é", false},
		{"https:opaque", false},
	} {
		err := validateURL(tc.url)
		if tc.ok != (err == nil) {
			t.Errorf("validateURL(%.60q) = %v, want ok=%t", tc.url, err, tc.ok)
		}
		if err != nil && !errors.Is(err, ErrInvalid) {
			t.Errorf("validateURL(%.60q) error %v is not ErrInvalid", tc.url, err)
		}
	}
}

func TestValidateActor(t *testing.T) {
	for _, tc := range []struct {
		actor Actor
		ok    bool
	}{
		{Actor{"alice", ActorHuman}, true},
		{Actor{"ci bot", ActorSystem}, true},
		{Actor{"José@example.com", ActorHuman}, true},
		{Actor{"", ActorHuman}, false},
		{Actor{"alice", ""}, false},
		{Actor{"alice", "robot"}, false},
		{Actor{" alice", ActorHuman}, false},
		{Actor{"alice ", ActorHuman}, false},
		{Actor{"al\tice", ActorHuman}, false},
		{Actor{"al\u200bice", ActorHuman}, false},
		{Actor{"alice\n", ActorHuman}, false},
		{Actor{strings.Repeat("a", maxActorNameBytes+1), ActorHuman}, false},
		{Actor{"bad\xffutf8", ActorHuman}, false},
	} {
		err := validateActor(tc.actor)
		if tc.ok != (err == nil) {
			t.Errorf("validateActor(%q, %q) = %v, want ok=%t", tc.actor.Name, tc.actor.Type, err, tc.ok)
		}
	}
}

func TestValidateToolName(t *testing.T) {
	for _, tc := range []struct {
		name string
		ok   bool
	}{
		{"echo", true}, {"with space", true}, {"snake_case-and.dots", true}, {"日本語", true}, {"emoji😀", true},
		{strings.Repeat("a", maxToolNameBytes), true},
		{"", false},
		{strings.Repeat("a", maxToolNameBytes+1), false},
		{"tab\there", false},
		{"new\nline", false},
		{"nul\x00byte", false},
		{"del\x7f", false},
		{"zero\u200bwidth", false},    // Cf
		{"joiner\u200dx", false},      // Cf
		{"bidi\u202eevil", false},     // Cf
		{"bom\ufeffx", false},         // Cf
		{"nbsp\u00a0x", false},        // Zs
		{"ideographic\u3000x", false}, // Zs
		{"line\u2028sep", false},      // Zl
		{"para\u2029sep", false},      // Zp
		{"private\ue000use", false},   // Co
		{"bad\xc3\x28utf8", false},
		{"surrogate\xed\xa0\x80", false}, // Cs encoded in UTF-8 is invalid UTF-8
	} {
		err := validateToolName(tc.name)
		if tc.ok != (err == nil) {
			t.Errorf("validateToolName(%q) = %v, want ok=%t", tc.name, err, tc.ok)
		}
	}
}

func TestNormalizeDigestAndPrefix(t *testing.T) {
	full := strings.Repeat("ab12", 16)
	if got, err := normalizeDigest(strings.ToUpper(full)); err != nil || got != full {
		t.Errorf("normalizeDigest(upper) = %q, %v", got, err)
	}
	for _, bad := range []string{"", "abc", full[:63], full + "0", strings.Repeat("g", 64), " " + full[1:]} {
		if _, err := normalizeDigest(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("normalizeDigest(%.20q) = %v, want ErrInvalid", bad, err)
		}
	}
	if got, err := normalizePrefix("ABCDEF12"); err != nil || got != "abcdef12" {
		t.Errorf("normalizePrefix = %q, %v", got, err)
	}
	for _, bad := range []string{"", "abcdef1", strings.Repeat("a", 65), "abcdefgh", "abcdef1%"} {
		if _, err := normalizePrefix(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("normalizePrefix(%q) = %v, want ErrInvalid", bad, err)
		}
	}
}

func TestSanitizeText(t *testing.T) {
	if got := sanitizeText("a\nb\tc\x00d\u200be", 100); got != "a b c?d?e" {
		t.Errorf("sanitizeText = %q", got)
	}
	if got := sanitizeText("bad\xffbyte", 100); got != "bad?byte" {
		t.Errorf("invalid UTF-8: %q", got)
	}
	// Cutting must land on a rune boundary.
	cut := sanitizeText(strings.Repeat("é", 10), 5)
	if !utf8.ValidString(cut) || len(cut) > 5 {
		t.Errorf("cut = %q (%d bytes)", cut, len(cut))
	}
	if got := quote(strings.Repeat("x", 500)); len(got) > maxQuotedBytes+8 {
		t.Errorf("quote did not truncate: %d bytes", len(got))
	}
}

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
	if got.ServerSpec != spec || got.ID != added.ID || !got.CreatedAt.Equal(added.CreatedAt) || got.CreatedAt.IsZero() {
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

func TestRecordCrawl_RejectsBadInputAndWritesNothing(t *testing.T) {
	s, path := newStoreAt(t, defaultPolicyForTests())
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("keep", "v1"))
	db := rawDB(t, path)
	genBefore := mustGeneration(t, s)
	auditBefore := auditCount(t, s)
	crawlsBefore := mustCount(t, db, `SELECT COUNT(*) FROM crawls`)

	tooMany := make([]CrawledTool, maxToolsPerCrawl+1)
	for i := range tooMany {
		tooMany[i] = CrawledTool{Name: fmt.Sprintf("t%d", i), Raw: []byte(`{"name":"x"}`)}
	}
	deep := strings.Repeat(`{"a":`, maxJSONDepth+2) + "1" + strings.Repeat("}", maxJSONDepth+2)
	huge := `{"name":"big","pad":"` + strings.Repeat("x", maxToolBytes) + `"}`

	for name, tc := range map[string]struct {
		in CrawlInput
		by Actor
	}{
		"duplicate names":       {crawlOf(tool("a", "1"), tool("a", "2")), crawler},
		"empty name":            {crawlOf(CrawledTool{Name: "", Raw: []byte(`{"name":""}`)}), crawler},
		"control in name":       {crawlOf(CrawledTool{Name: "a\x00b", Raw: def("a\x00b", "d")}), crawler},
		"zero width in name":    {crawlOf(CrawledTool{Name: "a\u200bb", Raw: def("a\u200bb", "d")}), crawler},
		"name too long":         {crawlOf(CrawledTool{Name: strings.Repeat("n", 257), Raw: def(strings.Repeat("n", 257), "d")}), crawler},
		"raw not json":          {crawlOf(CrawledTool{Name: "a", Raw: []byte(`nope`)}), crawler},
		"raw empty":             {crawlOf(CrawledTool{Name: "a", Raw: nil}), crawler},
		"raw is an array":       {crawlOf(CrawledTool{Name: "a", Raw: []byte(`[{"name":"a"}]`)}), crawler},
		"raw is a string":       {crawlOf(CrawledTool{Name: "a", Raw: []byte(`"a"`)}), crawler},
		"raw null":              {crawlOf(CrawledTool{Name: "a", Raw: []byte(`null`)}), crawler},
		"raw without name":      {crawlOf(CrawledTool{Name: "a", Raw: []byte(`{"description":"d"}`)}), crawler},
		"raw name mismatch":     {crawlOf(CrawledTool{Name: "a", Raw: def("b", "d")}), crawler},
		"raw name is a number":  {crawlOf(CrawledTool{Name: "a", Raw: []byte(`{"name":1}`)}), crawler},
		"raw name capitalised":  {crawlOf(CrawledTool{Name: "a", Raw: []byte(`{"Name":"a"}`)}), crawler},
		"raw duplicate top key": {crawlOf(CrawledTool{Name: "a", Raw: []byte(`{"name":"a","description":"x","description":"y"}`)}), crawler},
		"raw duplicate escaped": {crawlOf(CrawledTool{Name: "a", Raw: []byte(`{"name":"a","d":1,"d":2}`)}), crawler},
		"raw nested duplicate":  {crawlOf(CrawledTool{Name: "a", Raw: []byte(`{"name":"a","s":{"k":1,"k":2}}`)}), crawler},
		"raw trailing data":     {crawlOf(CrawledTool{Name: "a", Raw: []byte(`{"name":"a"} {"name":"a"}`)}), crawler},
		"raw bad utf8":          {crawlOf(CrawledTool{Name: "a", Raw: []byte("{\"name\":\"a\",\"d\":\"\xff\"}")}), crawler},
		"raw too deep":          {crawlOf(CrawledTool{Name: "a", Raw: []byte(`{"name":"a","x":` + deep + `}`)}), crawler},
		"raw over 1 MiB":        {crawlOf(CrawledTool{Name: "big", Raw: []byte(huge)}), crawler},
		"over 10000 tools":      {CrawlInput{Server: "alpha", Complete: true, Tools: tooMany}, crawler},
		"invalid tool, incomplete crawl": {
			CrawlInput{Server: "alpha", Complete: false, Error: "boom", Tools: []CrawledTool{{Name: "a\x00", Raw: []byte(`{}`)}}}, crawler},
		"no actor":       {crawlOf(tool("a", "1")), Actor{}},
		"bad actor type": {crawlOf(tool("a", "1")), Actor{Name: "x", Type: "root"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := s.RecordCrawl(bg, tc.in, tc.by); !errors.Is(err, ErrInvalid) {
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

func TestRecordCrawl_AcceptsNamesTheRulesAllow(t *testing.T) {
	s := newStore(t)
	mustAddServer(t, s, "alpha")
	names := []string{"plain", "with space", "日本語", "emoji😀", "dots.and-dashes_1", strings.Repeat("n", maxToolNameBytes)}
	in := make([]CrawledTool, len(names))
	for i, n := range names {
		in[i] = CrawledTool{Name: n, Raw: def(n, "d")}
	}
	rep := mustCrawl(t, s, "alpha", in...)
	if len(rep.Changes) != len(names) {
		t.Fatalf("changes = %d, want %d", len(rep.Changes), len(names))
	}
	for _, n := range names {
		if got := stateOf(t, s, "alpha", n); got != "pending_review" {
			t.Errorf("%q: state %s", n, got)
		}
	}
}

func crawlOf(tools ...CrawledTool) CrawlInput {
	return CrawlInput{Server: "alpha", Complete: true, Tools: tools}
}
