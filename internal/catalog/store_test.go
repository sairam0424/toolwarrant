package catalog

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

func TestOpen_CreatesSchemaAndSettings(t *testing.T) {
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	db := rawDB(t, path)

	var version int
	if err := db.QueryRowContext(bg, `PRAGMA user_version`).Scan(&version); err != nil || version != schemaVersion {
		t.Fatalf("user_version = %d, %v; want %d", version, err, schemaVersion)
	}
	var mode string
	if err := db.QueryRowContext(bg, `PRAGMA journal_mode`).Scan(&mode); err != nil || mode != "wal" {
		t.Fatalf("journal_mode = %q, %v; want wal", mode, err)
	}
	var fk int
	if err := db.QueryRowContext(bg, `PRAGMA foreign_keys`).Scan(&fk); err != nil || fk != 1 {
		t.Fatalf("foreign_keys = %d, %v; want 1 on every connection", fk, err)
	}
	for _, table := range []string{"meta", "servers", "crawls", "tools", "tool_versions", "tool_version_proposers", "approvals", "audit_log"} {
		if n := mustCount(t, db, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table); n != 1 {
			t.Errorf("table %s missing", table)
		}
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger'`); n != len(guardTriggers()) {
		t.Errorf("%d triggers, want %d", n, len(guardTriggers()))
	}
	if g := mustGeneration(t, s); g != 0 {
		t.Errorf("fresh generation = %d, want 0", g)
	}
	if s.ReadOnly() {
		t.Error("a store opened with Open is read-only")
	}
}

func TestOpen_ReopenKeepsDataAndIsIdempotent(t *testing.T) {
	path := dbPath(t)
	s1, err := Open(path, lifecycle.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	mustAddServer(t, s1, "alpha")
	gen := mustGeneration(t, s1)
	if err := s1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	s2 := openStore(t, path, lifecycle.DefaultPolicy())
	if _, err := s2.Server(bg, "alpha"); err != nil {
		t.Fatalf("server lost across reopen: %v", err)
	}
	if got := mustGeneration(t, s2); got != gen {
		t.Errorf("generation after reopen = %d, want %d", got, gen)
	}
}

func TestOpen_RefusesOtherSchemaVersions(t *testing.T) {
	// Versions 3, 4 and 5 are the previous unreleased builds (D13(i): the audit
	// detail format gained fields; D14(k): the catalog identity, the processor
	// address column and the new guards; D17(b): the positive-id guards); each
	// is refused like every other.
	for name, version := range map[string]int{"newer": 99, "older unreleased": 1, "third round": 3, "fourth round": 4, "fifth round": 5, "negative": -3} {
		t.Run(name, func(t *testing.T) {
			path := dbPath(t)
			s, err := Open(path, lifecycle.DefaultPolicy())
			if err != nil {
				t.Fatal(err)
			}
			_ = s.Close()
			mustExec(t, rawDB(t, path), `PRAGMA user_version = `+itoa(int64(version)))
			_, err = Open(path, lifecycle.DefaultPolicy())
			if !errors.Is(err, ErrSchema) {
				t.Fatalf("Open on a version %d database: %v, want ErrSchema", version, err)
			}
			if version > 0 && version < schemaVersion && !strings.Contains(err.Error(), "delete the file and run init again") {
				t.Errorf("an older database must tell the operator to re-initialise: %v", err)
			}
			if _, err := OpenWith(path, OpenOptions{ReadOnly: true}); !errors.Is(err, ErrSchema) {
				t.Errorf("read-only open on a version %d database: %v, want ErrSchema", version, err)
			}
		})
	}
}

// makePrivate gives a file the raw SQLite handle created the owner-only mode
// Open requires, so that the test reaches the check it is about.
func makePrivate(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestOpen_RefusesForeignDatabases(t *testing.T) {
	t.Run("another application's tables", func(t *testing.T) {
		path := dbPath(t)
		mustExec(t, rawDB(t, path), `CREATE TABLE notes (id INTEGER PRIMARY KEY)`)
		makePrivate(t, path)
		if _, err := Open(path, lifecycle.DefaultPolicy()); !errors.Is(err, ErrSchema) {
			t.Fatalf("Open: %v, want ErrSchema", err)
		}
	})
	t.Run("our version without our tables", func(t *testing.T) {
		path := dbPath(t)
		mustExec(t, rawDB(t, path), `PRAGMA user_version = `+itoa(schemaVersion))
		makePrivate(t, path)
		if _, err := Open(path, lifecycle.DefaultPolicy()); !errors.Is(err, ErrSchema) {
			t.Fatalf("Open: %v, want ErrSchema", err)
		}
	})
}

// A foreign database is refused before its journal mode is touched: pointing
// toolwarrant at the wrong file must not modify that file.
func TestOpen_LeavesAForeignDatabaseUntouched(t *testing.T) {
	path := dbPath(t)
	db := openRaw(t, "file:"+path+"?_pragma=journal_mode(delete)")
	mustExec(t, db, `CREATE TABLE theirs (x)`)
	mustExec(t, db, `INSERT INTO theirs VALUES (1)`)
	var before string
	if err := db.QueryRowContext(bg, `PRAGMA journal_mode`).Scan(&before); err != nil || before != "delete" {
		t.Fatalf("journal_mode before = %q, %v", before, err)
	}
	_ = db.Close()
	makePrivate(t, path)
	if _, err := Open(path, lifecycle.DefaultPolicy()); !errors.Is(err, ErrSchema) {
		t.Fatalf("Open on a foreign database: %v, want ErrSchema", err)
	}
	db2 := openRaw(t, "file:"+path)
	var after string
	if err := db2.QueryRowContext(bg, `PRAGMA journal_mode`).Scan(&after); err != nil || after != "delete" {
		t.Fatalf("journal_mode after the refused Open = %q, %v; the foreign file was modified", after, err)
	}
	if n := mustCount(t, db2, `SELECT COUNT(*) FROM theirs`); n != 1 {
		t.Errorf("foreign rows = %d", n)
	}
}

// A database that has lost a guard object is corrupt, not merely unguarded.
// Only a forensic open reads it, read-only, so that the tampering can be
// examined and VerifyAudit can name the broken entry.
func TestOpen_RefusesADatabaseWithAGuardDropped(t *testing.T) {
	for _, drop := range []string{`DROP TRIGGER tool_versions_immutable`, `DROP INDEX one_pending_version`, `DROP TRIGGER audit_log_no_update`} {
		s, path := seededStore(t)
		_ = s.Close()
		db := openRaw(t, "file:"+path)
		mustExec(t, db, drop)
		_, err := Open(path, lifecycle.DefaultPolicy())
		if !errors.Is(err, ErrCorrupt) {
			t.Errorf("after %s: Open = %v, want ErrCorrupt", drop, err)
		}
		if _, err := OpenWith(path, OpenOptions{ReadOnly: true}); !errors.Is(err, ErrCorrupt) {
			t.Errorf("after %s: read-only Open = %v, want ErrCorrupt", drop, err)
		}
		forensic, err := OpenWith(path, OpenOptions{Forensic: true})
		if err != nil {
			t.Fatalf("after %s: forensic Open = %v", drop, err)
		}
		if !forensic.ReadOnly() {
			t.Error("a forensic open is not read-only")
		}
		if _, err := forensic.AddServer(bg, ServerSpec{Name: "x", URL: "https://x.example.com"}, alice); !errors.Is(err, ErrReadOnly) {
			t.Errorf("write through a forensic open: %v, want ErrReadOnly", err)
		}
		if strings.Contains(drop, "audit_log_no_update") {
			mustExec(t, db, `UPDATE audit_log SET detail = 'nothing happened' WHERE seq = 2`)
			if b := brokenAt(t, verifyErr(forensic)); b.Seq != 2 {
				t.Errorf("forensic VerifyAudit found the break at %d, want 2", b.Seq)
			}
		} else if _, err := forensic.VerifyAudit(bg); err != nil {
			t.Errorf("forensic VerifyAudit: %v", err)
		}
		_ = forensic.Close()
	}
}

func TestOpen_RejectsBadPaths(t *testing.T) {
	dir := t.TempDir()
	garbage := filepath.Join(dir, "garbage.db")
	if err := os.WriteFile(garbage, []byte("this is definitely not a sqlite database file, just text"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		path string
		want error // nil means any error
	}{
		"empty":          {"", ErrInvalid},
		"memory":         {":memory:", ErrInvalid},
		"directory":      {dir, ErrInvalid},
		"missing parent": {filepath.Join(dir, "nope", "x.db"), nil},
		"garbage file":   {garbage, nil},
	} {
		t.Run(name, func(t *testing.T) {
			s, err := Open(tc.path, lifecycle.DefaultPolicy())
			if err == nil {
				_ = s.Close()
				t.Fatalf("Open(%q) succeeded", tc.path)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("Open(%q) = %v, want %v", tc.path, err, tc.want)
			}
		})
	}
}

func TestOpen_PathWithAwkwardCharacters(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a b#c%d")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"x y.db", "q?x=1.db", "h#f.db", "p%41.db", "amp&x.db"} {
		path := filepath.Join(dir, name)
		s := openStore(t, path, lifecycle.DefaultPolicy())
		mustAddServer(t, s, "alpha")
		if fi, err := os.Stat(path); err != nil || fi.Size() == 0 {
			t.Fatalf("database not created at the requested path %q: %v", name, err)
		}
	}
}

func TestOpen_NewFileIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}
	_, path := newStoreAt(t, lifecycle.DefaultPolicy())
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("database mode = %o, want owner-only", mode)
	}
}

func TestClose_MakesTheStoreUnusable(t *testing.T) {
	s, err := Open(dbPath(t), lifecycle.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := s.Generation(bg); err == nil {
		t.Error("Generation after Close succeeded")
	}
	if _, err := s.AddServer(bg, ServerSpec{Name: "x", URL: "https://x.example.com"}, alice); err == nil {
		t.Error("AddServer after Close succeeded")
	}
}

func TestGeneration_IncreasesByOneForEachCommittedWrite(t *testing.T) {
	s := newStore(t)
	g0 := mustGeneration(t, s)

	mustAddServer(t, s, "alpha")
	g1 := mustGeneration(t, s)
	mustCrawl(t, s, "alpha", tool("echo", "v1"))
	g2 := mustGeneration(t, s)
	mustApprove(t, s, "alpha", "echo", digestOf(t, "echo", "v1"))
	g3 := mustGeneration(t, s)
	if g1 != g0+1 || g2 != g1+1 || g3 != g2+1 {
		t.Fatalf("generations %d %d %d %d, want +1 per write", g0, g1, g2, g3)
	}

	// A crawl that changes nothing is still a committed write (it records the crawl).
	mustCrawl(t, s, "alpha", tool("echo", "v1"))
	if g := mustGeneration(t, s); g != g3+1 {
		t.Errorf("no-op crawl: generation %d, want %d", g, g3+1)
	}

	// Reads and refused writes leave it alone.
	before := mustGeneration(t, s)
	_, _ = s.Tools(bg, "")
	_, _ = s.Snapshot(bg, "alpha")
	if err := s.Approve(bg, "alpha", "echo", digestOf(t, "echo", "v1"), bob); err == nil {
		t.Fatal("approving an enabled tool must be refused")
	}
	if _, err := s.AddServer(bg, ServerSpec{Name: "alpha", URL: "https://a.example.com"}, alice); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate server: %v", err)
	}
	if after := mustGeneration(t, s); after != before {
		t.Errorf("generation moved from %d to %d without a committed write", before, after)
	}
}

func TestTwoHandlesShareOneFile(t *testing.T) {
	path := dbPath(t)
	writer := openStore(t, path, lifecycle.DefaultPolicy())
	reader := openStore(t, path, lifecycle.DefaultPolicy())

	last := mustGeneration(t, reader)
	step := func(name string, do func()) {
		t.Helper()
		do()
		g := mustGeneration(t, reader)
		if g <= last {
			t.Fatalf("%s: generation %d did not increase past %d", name, g, last)
		}
		if g2 := mustGeneration(t, writer); g2 != g {
			t.Fatalf("%s: handles disagree on the generation: %d vs %d", name, g, g2)
		}
		last = g
	}

	step("writer adds a server", func() { mustAddServer(t, writer, "alpha") })
	if _, err := reader.Server(bg, "alpha"); err != nil {
		t.Fatalf("reader does not see the server: %v", err)
	}
	step("writer crawls", func() { mustCrawl(t, writer, "alpha", tool("echo", "v1")) })
	if v := mustTool(t, reader, "alpha", "echo"); v.State != lifecycle.PendingReview {
		t.Fatalf("reader sees state %s", v.State)
	}
	step("reader approves", func() { mustApprove(t, reader, "alpha", "echo", digestOf(t, "echo", "v1")) })
	snap, err := writer.Snapshot(bg, "alpha")
	if err != nil || !snap.Serves("echo", digestOf(t, "echo", "v1")) {
		t.Fatalf("writer does not see the approval written through the other handle: %v %+v", err, snap)
	}
	if snap.Generation != last {
		t.Errorf("snapshot generation = %d, want %d", snap.Generation, last)
	}
	// Both handles append to one hash chain.
	if _, err := writer.VerifyAudit(bg); err != nil {
		t.Fatalf("VerifyAudit after interleaved writers: %v", err)
	}
}

// Several processes started together may all be the first to open a new file:
// exactly one creates the schema and the rest find it.
func TestOpen_ManyOpenersOfOneNewFile(t *testing.T) {
	path := dbPath(t)
	const openers = 8
	stores := make([]*Store, openers)
	errs := make([]error, openers)
	var wg sync.WaitGroup
	for i := range stores {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stores[i], errs[i] = Open(path, lifecycle.DefaultPolicy())
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("opener %d: %v", i, err)
			continue
		}
		t.Cleanup(func() { _ = stores[i].Close() })
		if g := mustGeneration(t, stores[i]); g != 0 {
			t.Errorf("opener %d: generation %d", i, g)
		}
	}
}

func TestOperations_RejectAnInvalidActorBeforeTakingTheLock(t *testing.T) {
	s := newStore(t)
	bad := Actor{Name: "", Type: ActorHuman}
	for name, err := range map[string]error{
		"enable":   s.Enable(bg, "alpha", "echo", bad),
		"disable":  s.Disable(bg, "alpha", "echo", bad),
		"rollback": s.Rollback(bg, "alpha", "echo", strings.Repeat("a", 64), bad),
		"reject":   s.Reject(bg, "alpha", "echo", strings.Repeat("a", 64), bad),
		"pause":    s.PauseServer(bg, "alpha", bad),
	} {
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s with no actor = %v, want ErrInvalid", name, err)
		}
	}
}
