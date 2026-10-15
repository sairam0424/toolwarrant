package catalog

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// The in-place migration of a version 6 file (D22 g), run against the frozen
// v0.3.0 fixture of schemav6_fixture_test.go.

// A read-write open migrates a version 6 file in place (D22 g): user_version
// becomes 7, the table and its four guards appear, every other table keeps
// every row, the audit head is the head v0.3.0 left, the snapshot serves the
// legacy approval and Integrity is clean. A second open finds a version 7
// file and migrates nothing.
func TestMigrate_V6FileIsMigratedInPlaceAndKeepsEveryRowAndTheHead(t *testing.T) {
	t.Parallel()
	f := newV6File(t)
	s := openStore(t, f.path, lifecycle.DefaultPolicy())
	db := rawDB(t, f.path)
	if v := mustCount(t, db, `PRAGMA user_version`); v != schemaVersion {
		t.Errorf("user_version after the read-write open = %d, want %d", v, schemaVersion)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM sqlite_master WHERE name LIKE ?`, v7Added); n != 5 {
		t.Errorf("%d objects named %s, want the table and its four guards", n, v7Added)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM sqlite_master`); n != v6Objects+5 {
		t.Errorf("sqlite_master holds %d objects, want %d (the version 6 objects plus five)", n, v6Objects+5)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM signed_records`); n != 0 {
		t.Errorf("signed_records holds %d rows after the migration, want none", n)
	}
	for table, want := range f.rows {
		if got := mustCount(t, db, `SELECT COUNT(*) FROM `+table); got != want {
			t.Errorf("%s holds %d rows after the migration, the version 6 file held %d", table, got, want)
		}
	}
	head, err := s.AuditHead(bg)
	if err != nil || head != f.head {
		t.Errorf("audit head after the migration = %s, %v; the version 6 file's head was %s", head, err, f.head)
	}
	if snap := mustSnapshot(t, s, "alpha"); !snap.Serves("echo", f.approved) || snap.Serves("echo", f.pending) {
		t.Errorf("the migrated snapshot does not serve the legacy approval %s alone: %+v", f.approved, snap)
	}
	mustBeClean(t, s, "after the migration")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	again := openStore(t, f.path, lifecycle.DefaultPolicy())
	if head2, err := again.AuditHead(bg); err != nil || head2 != f.head {
		t.Errorf("head after the second open = %s, %v; want %s", head2, err, f.head)
	}
	mustBeClean(t, again, "after the second open")
}

// A read-only open (the processor) and a forensic open (audit verify, audit
// list) of a version 6 file return ErrSchema naming the migration a
// read-write open runs, never the delete advice, and leave the file byte for
// byte as it was: neither path may write (D22 g).
func TestMigrate_ReadOnlyAndForensicOpensOfAV6FileNameTheMigrationAndWriteNothing(t *testing.T) {
	t.Parallel()
	f := newV6File(t)
	before := fileDigest(t, f.path)
	for name, opts := range map[string]OpenOptions{"read-only": {ReadOnly: true}, "forensic": {Forensic: true}} {
		_, err := OpenWith(f.path, opts)
		if !errors.Is(err, ErrSchema) {
			t.Fatalf("%s open of a version 6 file = %v, want ErrSchema", name, err)
		}
		for _, want := range []string{"schema version 6, written by a released build", "this build uses 7",
			`run "toolwarrant init" with this build`, "nothing is rewritten; back the file up first", "a read-only open does not migrate"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s open error %q does not say %q", name, err, want)
			}
		}
		if strings.Contains(err.Error(), "delete") {
			t.Errorf("%s open advised deletion of a released catalog: %v", name, err)
		}
	}
	if after := fileDigest(t, f.path); after != before {
		t.Errorf("the refused opens changed the file: %s before, %s after", before, after)
	}
	assertV6Shape(t, f.path)
}

// A version 6 file that already holds an object under a name the migration
// creates was edited outside toolwarrant (no v0.x build created one), so the
// read-write open refuses it as corrupt, names the object and writes nothing:
// the file stays version 6 with the foreign object in place for inspection.
func TestMigrate_RefusesAV6FileThatAlreadyHoldsAForeignSignedRecordsTable(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct{ ddl, label string }{
		"table":   {`CREATE TABLE signed_records (x)`, "table signed_records"},
		"trigger": {`CREATE TRIGGER signed_records_no_delete BEFORE DELETE ON approvals BEGIN SELECT 1; END`, "trigger signed_records_no_delete"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newV6File(t)
			mustExec(t, rawDBNoFK(t, f.path), tc.ddl)
			before := fileDigest(t, f.path)
			_, err := Open(f.path, lifecycle.DefaultPolicy())
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("Open = %v, want ErrCorrupt", err)
			}
			for _, want := range []string{"already holds " + tc.label, "nothing was written"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not say %q", err, want)
				}
			}
			if after := fileDigest(t, f.path); after != before {
				t.Errorf("the refused open changed the file: %s before, %s after", before, after)
			}
			db := rawDB(t, f.path)
			if v := mustCount(t, db, `PRAGMA user_version`); v != v6Version {
				t.Errorf("user_version = %d after the refused migration, want %d", v, v6Version)
			}
			if n := mustCount(t, db, `SELECT COUNT(*) FROM sqlite_master WHERE name LIKE ?`, v7Added); n != 1 {
				t.Errorf("%d objects named %s, want the planted one alone", n, v7Added)
			}
		})
	}
}

// Several processes may open a version 6 file at the same moment (a crawl on
// a schedule and an operator's init): the migration runs in the immediate
// transaction migrate holds, so exactly one process adds the objects and the
// others wait and then find version 7; every opener succeeds and sees the
// same rows and head.
func TestMigrate_TwoProcessesOpeningAV6FileAtOnceMigrateItOnce(t *testing.T) {
	t.Parallel()
	f := newV6File(t)
	const openers = 8
	stores := make([]*Store, openers)
	errs := make([]error, openers)
	var wg sync.WaitGroup
	for i := range stores {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stores[i], errs[i] = Open(f.path, lifecycle.DefaultPolicy())
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("opener %d: %v", i, err)
			continue
		}
		t.Cleanup(func() { _ = stores[i].Close() })
		if head, err := stores[i].AuditHead(bg); err != nil || head != f.head {
			t.Errorf("opener %d: head %s, %v; want %s", i, head, err, f.head)
		}
		if snap := mustSnapshot(t, stores[i], "alpha"); !snap.Serves("echo", f.approved) {
			t.Errorf("opener %d does not serve the legacy approval", i)
		}
	}
	db := rawDB(t, f.path)
	if v := mustCount(t, db, `PRAGMA user_version`); v != schemaVersion {
		t.Errorf("user_version = %d, want %d", v, schemaVersion)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM sqlite_master WHERE name LIKE ?`, v7Added); n != 5 {
		t.Errorf("%d objects named %s, want exactly the table and its four guards", n, v7Added)
	}
	if got := rowCounts(t, db); len(got) != len(f.rows) {
		t.Errorf("row counts %v, want %v", got, f.rows)
	} else {
		for table, want := range f.rows {
			if got[table] != want {
				t.Errorf("%s holds %d rows, want %d", table, got[table], want)
			}
		}
	}
	if errs[0] == nil {
		mustBeClean(t, stores[0], "after the concurrent migration")
	}
}
