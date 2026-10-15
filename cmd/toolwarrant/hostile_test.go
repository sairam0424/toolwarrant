package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	_ "modernc.org/sqlite" // the tests reach into the database to tamper with it

	"github.com/sairam0424/toolwarrant/internal/catalog"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// The hostile characters are built from their code points so that no source
// file carries an invisible character of its own (an editor or pipeline that
// rewrites \u escapes cannot rewrite these).
const (
	zeroWidth = string(rune(0x200B))
	bidi      = string(rune(0x202E))
	esc       = string(rune(0x1B))
	bearerVar = "TW_BEARER"
	// canary is the substring every planted sensitive value carries, so one
	// wantNotContains proves that none of them reached the output.
	canary = "CANARY"
)

// plant returns a recognisable value to put where a credential would be.
func plant(kind string) string { return kind + "-" + canary + "-VALUE" }

// execSQL edits the catalog behind the CLI's back, the way an attacker with
// file access would.
func execSQL(t *testing.T, path string, stmts ...string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
}

func queryRow(t *testing.T, path, query string, dest ...any) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.QueryRow(query).Scan(dest...); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
}

func TestApproveRefusesSuspiciousCharactersUnlessAccepted(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	u := newUpstream(t, map[string]string{"sneaky": "Harmless" + zeroWidth + " tool " + esc + "[31m" + bidi})
	c.ok("server", "add", "s1", u.url(), "--allow-private")
	c.ok("crawl", "s1")
	v := c.tool("s1", "sneaky").Pending

	r := c.fail(exitFailure, "--as", "alice", "approve", "s1", "sneaky", "--hash", v)
	wantContains(t, "stderr", r.stderr, "suspicious characters", "U+200B", "U+001B", "U+202E", "$.description", "--accept-suspicious", "3 suspicious")
	wantNotContains(t, "stderr", r.stderr, zeroWidth, esc, bidi)
	if tv := c.tool("s1", "sneaky"); tv.State != "pending_review" {
		t.Fatalf("a refused approval must change nothing: %+v", tv.toolJSON)
	}

	out := c.ok("diff", "s1", "sneaky")
	wantContains(t, "diff", out, `\u{200B}`, `\u{001B}`, `\u{202E}`, "Suspicious characters")
	wantNotContains(t, "diff", out, zeroWidth, esc, bidi)

	r = c.run("--as", "alice", "approve", "s1", "sneaky", "--hash", v, "--accept-suspicious")
	if r.code != exitOK {
		t.Fatalf("approve --accept-suspicious: exit %d: %s", r.code, r.stderr)
	}
	wantContains(t, "stderr", r.stderr, "warning: approving despite 3 suspicious")
	wantNotContains(t, "stderr", r.stderr, zeroWidth, esc, bidi)
	if tv := c.tool("s1", "sneaky"); tv.State != "enabled" {
		t.Fatalf("after accepted approval: %+v", tv.toolJSON)
	}
}

// Rows changed behind the audit log: since D15 (b) the catalog trusts a
// version only when the verified audit walk proposed it, and since the state
// anchor (D17 c, eighth review) every path that acts on a tool refuses a row
// the log never created, so a tool renamed by hand in the database is
// ErrCorrupt in list, show and crawl alike, and no command writes an audit
// entry about the hostile name. Whichever way a command answers, the hostile
// name reaches the terminal escaped only: in text mode as \u{...} on stdout,
// in an error as a quoted string on stderr, and JSON mode carries the raw
// name for machines when it answers at all. audit list, which never consults
// the tools table, is checked for raw bytes only.
func TestHostileToolNamesFromTheDatabaseAreEscaped(t *testing.T) {
	t.Parallel()
	c, _ := fixture(t)
	hostile := "ev" + zeroWidth + "il" + esc + "[31m" + bidi
	execSQL(t, c.db, "UPDATE tools SET name = 'ev' || char(8203) || 'il' || char(27) || '[31m' || char(8238) WHERE name = 'add'")
	escaped := func(name string, args ...string) result {
		t.Helper()
		r := c.run(args...)
		wantNotContains(t, name+" stdout", r.stdout, zeroWidth, esc, bidi)
		wantNotContains(t, name+" stderr", r.stderr, zeroWidth, esc, bidi)
		switch r.code {
		case exitOK:
			wantContains(t, name+" stdout", r.stdout, `\u{200B}`)
		case exitFailure:
			wantContains(t, name+" stderr", r.stderr, "integrity check failed", `\u200b`)
		default:
			t.Errorf("%s: exit %d\nstdout: %s\nstderr: %s", name, r.code, r.stdout, r.stderr)
		}
		return r
	}
	if r := escaped("list", "list"); r.code == exitOK {
		wantContains(t, "list", r.stdout, `s1/ev\u{200B}il\u{001B}[31m\u{202E}`)
	}
	if r := escaped("show", "show", "s1", hostile); r.code == exitOK {
		wantContains(t, "show", r.stdout, `ev\u{200B}il`)
	}
	if r := escaped("crawl", "crawl", "s1"); r.code == exitOK {
		wantContains(t, "crawl report", r.stdout, "missing")
	}
	auditOut := c.ok("audit", "list")
	wantNotContains(t, "audit list stdout", auditOut, zeroWidth, esc, bidi)

	r := c.run("list", "s1", "--json")
	wantNotContains(t, "json stderr", r.stderr, zeroWidth, esc, bidi)
	switch r.code {
	case exitOK:
		var rows []toolJSON
		if err := json.Unmarshal([]byte(r.stdout), &rows); err != nil {
			t.Fatalf("list --json is not json (%v):\n%s", err, r.stdout)
		}
		found := false
		for _, row := range rows {
			found = found || row.Tool == hostile
		}
		if !found {
			t.Errorf("json mode must carry the raw name for machines: %+v", rows)
		}
	case exitFailure:
		wantContains(t, "json stderr", r.stderr, "integrity check failed")
	default:
		t.Errorf("list --json: exit %d: %s", r.code, r.stderr)
	}
}

func TestUnknownCommandsAndSubcommandsAreEscaped(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	r := c.fail(exitUsage, "ev"+esc+"[31mil")
	wantContains(t, "stderr", r.stderr, `unknown command ev\u{001B}[31mil`)
	wantNotContains(t, "stderr", r.stderr, esc)
	r = c.fail(exitUsage, "server", "ev"+zeroWidth)
	wantContains(t, "stderr", r.stderr, `\u{200B}`)
	wantNotContains(t, "stderr", r.stderr, zeroWidth)
	r = c.fail(exitUsage, "serve", "--server", "s1", "--listen", "bad"+bidi+"addr")
	wantContains(t, "stderr", r.stderr, `\u{202E}`)
	wantNotContains(t, "stderr", r.stderr, bidi)
}

// D3: one hostile tool no longer fails the crawl. The crawl completes, the
// valid tools are recorded, the hostile entry is reported as rejected with its
// name withheld, and only --strict turns that into a failure.
func TestCrawlReportsAnInvisibleToolNameAsRejected(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	u := newUpstream(t, map[string]string{"echo" + zeroWidth: "Looks like echo.", "add": "Adds two numbers."})
	c.ok("server", "add", "s1", u.url(), "--allow-private")
	out := c.ok("crawl", "s1")
	wantContains(t, "crawl", out, "1 tools, new=1, 1 rejected", "REJECTED "+nameWithheld, "invalid-name", "U+200B")
	wantNotContains(t, "crawl", out, zeroWidth)
	var n int
	queryRow(t, c.db, "SELECT COUNT(*) FROM tools", &n)
	if n != 1 {
		t.Errorf("%d tools recorded, want only add", n)
	}
	rejected := false
	for _, e := range c.auditEntries() {
		if e.Event == "tool.rejected" {
			rejected = true
			wantNotContains(t, "audit detail", e.Detail, zeroWidth)
		}
	}
	if !rejected {
		t.Error("no tool.rejected audit entry")
	}
	var rep crawlJSON
	c.jsonInto(&rep, "crawl", "s1", "--json")
	if len(rep.Rejected) != 1 || rep.Rejected[0].Name != "" || rep.Rejected[0].Reason != "invalid-name" || !strings.Contains(rep.Rejected[0].Detail, "U+200B") {
		t.Errorf("crawl --json rejected = %+v", rep.Rejected)
	}
	r := c.fail(exitFailure, "crawl", "s1", "--strict")
	wantContains(t, "strict stderr", r.stderr, "--strict", "1 rejected", "0 unusable")
	wantContains(t, "strict stdout", r.stdout, "REJECTED")
	wantNotContains(t, "strict", r.stdout+r.stderr, zeroWidth)
	r = c.fail(exitFailure, "crawl", "s1", "--every", loopEvery.String(), "--strict")
	wantContains(t, "strict --every", r.stderr, "--strict refuses it")
}

// A known tool whose upstream starts listing a definition over the size cap is
// observed as unusable: hidden, flagged, nothing stored, and the approval kept
// for when a clean definition returns.
func TestCrawlMarksAKnownToolWithAnUnusableDefinition(t *testing.T) {
	t.Parallel()
	c, u := fixture(t)
	v1 := c.tool("s1", "echo").Pending
	c.approve("alice", "s1", "echo", v1)
	u.set("echo", strings.Repeat("a", catalog.MaxToolBytes+1))
	out := c.ok("crawl", "s1")
	wantContains(t, "crawl", out, "UNUSABLE", "too-large", "unusable=1", "unchanged=2", lifecycle.UnusableDigest)
	tv := c.tool("s1", "echo")
	if !tv.Unusable || tv.Live != lifecycle.UnusableDigest || tv.Approved != v1 || len(tv.History) != 1 {
		t.Fatalf("after an unusable observation: %+v history %d", tv.toolJSON, len(tv.History))
	}
	wantContains(t, "list", c.ok("list"), flagUnusable)
	r := c.fail(exitFailure, "diff", "s1", "echo")
	wantContains(t, "diff", r.stderr, "cannot be used")
	r = c.fail(exitFailure, "crawl", "s1", "--strict")
	wantContains(t, "strict", r.stderr, "0 rejected and 1 unusable")
	var rep crawlJSON
	c.jsonInto(&rep, "crawl", "s1", "--json")
	seen := false
	for _, ch := range rep.Changes {
		if ch.Tool == "echo" {
			seen = true
			if !ch.Unusable || ch.Reason != "too-large" || ch.Digest != "" {
				t.Errorf("echo change = %+v", ch)
			}
		}
	}
	if !seen {
		t.Errorf("echo missing from %+v", rep.Changes)
	}
	u.set("echo", echoV1)
	c.ok("crawl", "s1", "--strict")
	wantNotContains(t, "list", c.ok("list"), flagUnusable)
	if tv = c.tool("s1", "echo"); tv.Live != v1 || tv.Unusable {
		t.Fatalf("after the clean definition returned: %+v", tv.toolJSON)
	}
}

func TestServerURLsAreShownWithoutCredentials(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.ok("server", "add", "s1", "http://127.0.0.1:1/mcp?q="+plant("query"))
	out := c.ok("server", "list")
	wantContains(t, "server list", out, "http://127.0.0.1:1/mcp", "s1", "NAME", "PAUSED")
	wantNotContains(t, "server list", out, canary, "q=")
	var rows []serverJSON
	c.jsonInto(&rows, "server", "list", "--json")
	if len(rows) != 1 || rows[0].URL != "http://127.0.0.1:1/mcp" || rows[0].AllowPrivate || rows[0].Paused {
		t.Fatalf("server list --json = %+v", rows)
	}
	r := c.fail(exitFailure, "server", "add", "s2", "http://user:"+plant("pw")+"@127.0.0.1:1/mcp")
	wantContains(t, "stderr", r.stderr, "user info")
	wantNotContains(t, "stderr", r.stderr, canary)
	r = c.fail(exitFailure, "server", "add", "s1", "http://127.0.0.1:2/")
	wantContains(t, "stderr", r.stderr, "already exists")
	r = c.fail(exitFailure, "server", "add", "Bad Name", "http://127.0.0.1:2/")
	wantContains(t, "stderr", r.stderr, "invalid input")
	r = c.run("server", "add", "lab", "http://127.0.0.1:3/mcp", "--allow-private")
	if r.code != exitOK {
		t.Fatalf("server add --allow-private: %s", r.stderr)
	}
	wantContains(t, "stderr", r.stderr, "warning", "lab", "private")
	wantContains(t, "stdout", r.stdout, "added server lab at http://127.0.0.1:3/mcp")
}

func TestCrawlFailureIsRecordedWithoutSecrets(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	var gotAuth atomic.Value
	deny := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth.Store(r.Header.Get(headerAuthorization))
		w.Header().Set("WWW-Authenticate", `Bearer realm="`+plant("header")+`"`)
		http.Error(w, plant("body")+": rejected", http.StatusUnauthorized)
	}))
	defer deny.Close()
	c.ok("server", "add", "s1", deny.URL+"/mcp?q="+plant("query"), "--allow-private")
	c.env[bearerVar] = plant("bearer")

	r := c.fail(exitFailure, "crawl", "s1", "--bearer-env", bearerVar)
	all := r.stdout + r.stderr
	wantContains(t, "output", all, "crawl of s1 failed: http status 401", "recorded")
	wantNotContains(t, "output", all, canary, "q=", deny.URL)
	if got, _ := gotAuth.Load().(string); got != bearerScheme+plant("bearer") {
		t.Errorf("Authorization sent = %q, want the bearer value", got)
	}

	var complete int
	var stored string
	queryRow(t, c.db, "SELECT complete, error FROM crawls ORDER BY id DESC LIMIT 1", &complete, &stored)
	if complete != 0 || stored != "http status 401" {
		t.Errorf("crawls row = (%d, %q), want (0, \"http status 401\")", complete, stored)
	}
	entries := c.auditEntries()
	last := entries[len(entries)-1]
	if last.Event != "crawl.failed" || last.Actor != systemActorName || last.ActorType != "system" {
		t.Errorf("last audit entry = %+v", last)
	}
	wantNotContains(t, "audit detail", last.Detail, canary)
	wantNotContains(t, "list", c.ok("list"), "s1/")

	r = c.fail(exitUsage, "crawl", "s1", "--bearer-env", "NOPE")
	wantContains(t, "stderr", r.stderr, "NOPE", "unset")
	c.env["CRLF"] = "a\r\nX-Injected: 1"
	r = c.fail(exitUsage, "crawl", "s1", "--bearer-env", "CRLF")
	wantContains(t, "stderr", r.stderr, "line break")
}
