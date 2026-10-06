package main

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	_ "modernc.org/sqlite" // the tests reach into the database to tamper with it
)

const (
	zeroWidth = "​"
	bidi      = "‮"
	esc       = "\x1b"
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
	defer db.Close()
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
	defer db.Close()
	if err := db.QueryRow(query).Scan(dest...); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
}

func TestApproveRefusesSuspiciousCharactersUnlessAccepted(t *testing.T) {
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

func TestHostileToolNamesFromTheDatabaseAreEscaped(t *testing.T) {
	c, _ := fixture(t)
	hostile := "ev" + zeroWidth + "il" + esc + "[31m" + bidi
	execSQL(t, c.db, "UPDATE tools SET name = 'ev' || char(8203) || 'il' || char(27) || '[31m' || char(8238) WHERE name = 'add'")

	out := c.ok("list")
	wantContains(t, "list", out, `s1/ev\u{200B}il\u{001B}[31m\u{202E}`)
	wantNotContains(t, "list", out, zeroWidth, esc, bidi)
	out = c.ok("show", "s1", hostile)
	wantContains(t, "show", out, `ev\u{200B}il`)
	wantNotContains(t, "show", out, zeroWidth, esc, bidi)
	out = c.ok("crawl", "s1")
	wantContains(t, "crawl report", out, `\u{200B}`, "missing")
	wantNotContains(t, "crawl report", out, zeroWidth, esc, bidi)
	out = c.ok("audit", "list")
	wantContains(t, "audit list", out, `\u{200B}`)
	wantNotContains(t, "audit list", out, zeroWidth, esc, bidi)

	var rows []toolJSON
	c.jsonInto(&rows, "list", "s1", "--json")
	found := false
	for _, row := range rows {
		found = found || row.Tool == hostile
	}
	if !found {
		t.Errorf("json mode must carry the raw name for machines: %+v", rows)
	}
}

func TestUnknownCommandsAndSubcommandsAreEscaped(t *testing.T) {
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

func TestCrawlRefusesInvisibleCharactersInToolNames(t *testing.T) {
	c := newCLI(t)
	u := newUpstream(t, map[string]string{"echo" + zeroWidth: "Looks like echo."})
	c.ok("server", "add", "s1", u.url(), "--allow-private")
	r := c.fail(exitFailure, "crawl", "s1")
	wantContains(t, "stderr", r.stderr, "U+200B")
	wantNotContains(t, "stderr", r.stderr, zeroWidth)
	var n int
	queryRow(t, c.db, "SELECT COUNT(*) FROM tools", &n)
	if n != 0 {
		t.Errorf("%d tools recorded from a refused crawl", n)
	}
}

func TestServerURLsAreShownWithoutCredentials(t *testing.T) {
	c := newCLI(t)
	c.ok("server", "add", "s1", "http://127.0.0.1:1/mcp?q="+plant("query"))
	out := c.ok("server", "list")
	wantContains(t, "server list", out, "http://127.0.0.1:1/mcp", "s1", "NAME")
	wantNotContains(t, "server list", out, canary, "q=")
	var rows []serverJSON
	c.jsonInto(&rows, "server", "list", "--json")
	if len(rows) != 1 || rows[0].URL != "http://127.0.0.1:1/mcp" || rows[0].AllowPrivate {
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
