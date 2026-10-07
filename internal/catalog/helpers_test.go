package catalog

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/gate"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

var (
	alice   = Actor{Name: "alice", Type: ActorHuman}
	bob     = Actor{Name: "bob", Type: ActorHuman}
	carol   = Actor{Name: "carol", Type: ActorHuman}
	crawler = Actor{Name: "crawler", Type: ActorSystem}
)

// bg is the context used by tests that do not care about cancellation.
var bg = context.Background()

func dbPath(t *testing.T) string { return filepath.Join(t.TempDir(), "catalog.db") }

func openStore(t *testing.T, path string, p lifecycle.Policy) *Store {
	t.Helper()
	s, err := Open(path, p)
	if err != nil {
		t.Fatalf("Open(%q): %v", path, err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// newStore opens a fresh database with the default policy.
func newStore(t *testing.T) *Store {
	t.Helper()
	return openStore(t, dbPath(t), lifecycle.DefaultPolicy())
}

// newStoreAt opens a fresh database and also returns its path.
func newStoreAt(t *testing.T, p lifecycle.Policy) (*Store, string) {
	t.Helper()
	path := dbPath(t)
	return openStore(t, path, p), path
}

// rawDB opens a second, raw handle on the same file: the way someone with a
// SQLite shell would reach the data without going through the Store.
func rawDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	return openRaw(t, dsnFor(path, connWriter, DefaultBusyTimeout))
}

// rawDBNoFK is rawDB with foreign keys off, the sqlite3 shell's default.
func rawDBNoFK(t *testing.T, path string) *sql.DB {
	t.Helper()
	q := url.Values{}
	q.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", DefaultBusyTimeout.Milliseconds()))
	q.Add("_pragma", "foreign_keys(0)")
	u := url.URL{Scheme: "file", Path: path, RawQuery: q.Encode()}
	return openRaw(t, u.String())
}

func openRaw(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	db, err := sql.Open(driverName, dsn)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func mustExec(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(bg, query, args...); err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}

func mustCount(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(bg, query, args...).Scan(&n); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	return n
}

// def builds a well-formed tool definition.
func def(name, desc string) []byte {
	return []byte(fmt.Sprintf(`{"name":%q,"description":%q,"inputSchema":{"type":"object","properties":{}}}`, name, desc))
}

func tool(name, desc string) CrawledTool { return CrawledTool{Name: name, Raw: def(name, desc)} }

// unusableOf is an entry the crawler could not use.
func unusableOf(name, reason string) UnusableTool {
	return UnusableTool{Name: name, Reason: reason, Detail: "the definition broke a rule"}
}

func digestOf(t *testing.T, name, desc string) string {
	t.Helper()
	d, err := gate.Digest(def(name, desc))
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	return d
}

func mustAddServer(t *testing.T, s *Store, name string) Server {
	t.Helper()
	srv, err := s.AddServer(bg, ServerSpec{Name: name, URL: "https://" + name + ".example.com/mcp", OwnerGroup: "platform"}, alice)
	if err != nil {
		t.Fatalf("AddServer(%s): %v", name, err)
	}
	return srv
}

func crawlOf(tools ...CrawledTool) CrawlInput {
	return CrawlInput{Server: "alpha", Complete: true, Tools: tools}
}

func crawlFor(server string, tools ...CrawledTool) CrawlInput {
	return CrawlInput{Server: server, Complete: true, Tools: tools}
}

// bigCrawl lists n small tools under numbered names.
func bigCrawl(n int, variant string) []CrawledTool {
	tools := make([]CrawledTool, n)
	for i := range tools {
		name := fmt.Sprintf("tool-%05d", i)
		tools[i] = CrawledTool{Name: name, Raw: def(name, variant)}
	}
	return tools
}

func mustCrawl(t *testing.T, s *Store, server string, tools ...CrawledTool) CrawlReport {
	t.Helper()
	rep, err := s.RecordCrawl(bg, CrawlInput{Server: server, Complete: true, Tools: tools}, crawler)
	if err != nil {
		t.Fatalf("RecordCrawl(%s): %v", server, err)
	}
	return rep
}

func mustApprove(t *testing.T, s *Store, server, toolName, digest string) {
	t.Helper()
	if err := s.Approve(bg, server, toolName, digest, bob); err != nil {
		t.Fatalf("Approve(%s/%s): %v", server, toolName, err)
	}
}

func kindsOf(rep CrawlReport) map[string]ChangeKind {
	out := make(map[string]ChangeKind, len(rep.Changes))
	for _, c := range rep.Changes {
		out[c.Tool] = c.Kind
	}
	return out
}

func mustGeneration(t *testing.T, s *Store) int64 {
	t.Helper()
	g, err := s.Generation(bg)
	if err != nil {
		t.Fatalf("Generation: %v", err)
	}
	return g
}

func mustTool(t *testing.T, s *Store, server, toolName string) ToolView {
	t.Helper()
	v, err := s.Tool(bg, server, toolName)
	if err != nil {
		t.Fatalf("Tool(%s/%s): %v", server, toolName, err)
	}
	return v
}

func mustSnapshot(t *testing.T, s *Store, server string) Snapshot {
	t.Helper()
	snap, err := s.Snapshot(bg, server)
	if err != nil {
		t.Fatalf("Snapshot(%s): %v", server, err)
	}
	return snap
}

func auditEvents(t *testing.T, s *Store) []string {
	t.Helper()
	entries, err := s.AuditEntries(bg, 0, 0)
	if err != nil {
		t.Fatalf("AuditEntries: %v", err)
	}
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.Event
	}
	return out
}

func auditCount(t *testing.T, s *Store) int { return len(auditEvents(t, s)) }

func countEvents(t *testing.T, s *Store, event string) int {
	t.Helper()
	n := 0
	for _, e := range auditEvents(t, s) {
		if e == event {
			n++
		}
	}
	return n
}

// entryOf returns the newest audit entry with this event.
func entryOf(t *testing.T, s *Store, event string) audit.Entry {
	t.Helper()
	entries, err := s.AuditEntries(bg, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := len(entries) - 1; i >= 0; i-- {
		if entries[i].Event == event {
			return entries[i]
		}
	}
	t.Fatalf("no audit entry with event %s in %v", event, auditEvents(t, s))
	return audit.Entry{}
}

// stateOf returns the stored state of a tool, failing the test if it is absent.
func stateOf(t *testing.T, s *Store, server, toolName string) lifecycle.State {
	t.Helper()
	return mustTool(t, s, server, toolName).State
}

func defaultPolicyForTests() lifecycle.Policy { return lifecycle.DefaultPolicy() }
