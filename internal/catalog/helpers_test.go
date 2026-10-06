package catalog

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/gate"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

var (
	alice   = Actor{Name: "alice", Type: ActorHuman}
	bob     = Actor{Name: "bob", Type: ActorHuman}
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
	db, err := sql.Open(driverName, dsnFor(path, true))
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

// stateOf returns the stored state of a tool, failing the test if it is absent.
func stateOf(t *testing.T, s *Store, server, toolName string) lifecycle.State {
	t.Helper()
	return mustTool(t, s, server, toolName).State
}

func defaultPolicyForTests() lifecycle.Policy { return lifecycle.DefaultPolicy() }
