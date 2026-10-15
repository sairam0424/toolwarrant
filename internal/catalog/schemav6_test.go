package catalog

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
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
			`back the file up, then run "toolwarrant init" with this build to migrate it in place`, "nothing is rewritten",
			"every command but serve, audit verify and audit list opens the file read-write and migrates it the same way, list and show included",
			"serve, audit verify and audit list never migrate"} {
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

// A version 6 file that lost a guard is corruption, not a file to migrate:
// the migration runs inside the transaction and the guard comparison after it
// fails, so the transaction rolls back and nothing commits (D22 g, the
// fail-closed half of the migration). Open is ErrCorrupt naming the guard,
// user_version is still 6, no object the migration creates exists, the 31
// objects that were there are what they were and the file's bytes are
// unchanged; the file stays a version 6 file for a v0.3.x build to inspect.
func TestMigrate_RefusesAV6FileThatLostAGuardAndCommitsNothing(t *testing.T) {
	t.Parallel()
	f := newV6File(t)
	mustExec(t, rawDBNoFK(t, f.path), `DROP TRIGGER approvals_no_update`)
	before := fileDigest(t, f.path)
	_, err := Open(f.path, lifecycle.DefaultPolicy())
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Open = %v, want ErrCorrupt", err)
	}
	if want := "guard trigger approvals_no_update is missing"; !strings.Contains(err.Error(), want) {
		t.Errorf("error %q does not say %q", err, want)
	}
	if after := fileDigest(t, f.path); after != before {
		t.Errorf("the rolled-back migration changed the file: %s before, %s after", before, after)
	}
	db := rawDB(t, f.path)
	if v := mustCount(t, db, `PRAGMA user_version`); v != v6Version {
		t.Errorf("user_version = %d after the rolled-back migration, want %d", v, v6Version)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM sqlite_master WHERE name LIKE ?`, v7Added); n != 0 {
		t.Errorf("%d objects named %s exist after the rolled-back migration, want none", n, v7Added)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM sqlite_master`); n != v6Objects-1 {
		t.Errorf("sqlite_master holds %d objects, want %d (the version 6 objects minus the dropped guard)", n, v6Objects-1)
	}
}

// Several processes may open a version 6 file at the same moment (a crawl on
// a schedule and an operator's init): the migration runs in the immediate
// transaction migrate holds, so exactly one process adds the objects and the
// others wait on the lock and then find version 7; every opener succeeds and
// sees the same rows and head. The openers are real processes: the test
// re-executes its own binary with this test selected and the file named in
// the environment (the standard library's pattern; the child half is
// openV6AsChild), every child says ready and then blocks until the parent
// closes its stdin, which the parent does for all of them at once, and four
// goroutines of this process open the file in the same instant.
func TestMigrate_TwoProcessesOpeningAV6FileAtOnceMigrateItOnce(t *testing.T) {
	if path := os.Getenv(v6ChildEnv); path != "" {
		openV6AsChild(t, path)
		return
	}
	t.Parallel()
	f := newV6File(t)
	const children, goroutines = 4, 4
	kids := startV6Children(t, f.path, children)
	stores := make([]*Store, goroutines)
	errs := make([]error, goroutines)
	var wg sync.WaitGroup
	for i := range stores {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stores[i], errs[i] = Open(f.path, lifecycle.DefaultPolicy())
		}()
	}
	for _, k := range kids {
		_ = k.stdin.Close() // the start signal
	}
	wg.Wait()
	for i, k := range kids {
		if head, err := k.wait(); err != nil {
			t.Errorf("child process %d: %v", i, err)
		} else if head != f.head {
			t.Errorf("child process %d read head %s, want %s", i, head, f.head)
		}
	}
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
	assertMigratedOnce(t, f)
	if errs[0] == nil {
		mustBeClean(t, stores[0], "after the concurrent migration")
	}
}

// assertMigratedOnce checks the file after the concurrent opens: version 7,
// exactly the table and its four guards, and every row the version 6 file held.
func assertMigratedOnce(t *testing.T, f v6Fixture) {
	t.Helper()
	db := rawDB(t, f.path)
	if v := mustCount(t, db, `PRAGMA user_version`); v != schemaVersion {
		t.Errorf("user_version = %d, want %d", v, schemaVersion)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM sqlite_master WHERE name LIKE ?`, v7Added); n != 5 {
		t.Errorf("%d objects named %s, want exactly the table and its four guards", n, v7Added)
	}
	got := rowCounts(t, db)
	if len(got) != len(f.rows) {
		t.Errorf("row counts %v, want %v", got, f.rows)
	}
	for table, want := range f.rows {
		if got[table] != want {
			t.Errorf("%s holds %d rows, want %d", table, got[table], want)
		}
	}
}

const (
	// v6ChildEnv names, in a child process's environment, the version 6 file
	// it opens. It travels through exec.Cmd.Env, never t.Setenv, so the test
	// stays parallel; a process that finds it set runs the child half of the
	// test and nothing else.
	v6ChildEnv = "TOOLWARRANT_TEST_MIGRATE_V6_PATH"
	// childReady is the line a child prints before it blocks on stdin, and
	// childHead starts the line that carries the audit head it read.
	childReady = "ready"
	childHead  = "head="
)

// openV6AsChild is the child half of the two-process test: it says ready,
// blocks until the parent closes its stdin (the start signal every child gets
// in the same instant), opens the file read-write, which migrates it or finds
// it migrated, and prints the audit head it reads. A failure fails the
// child's run of the test, and the parent sees it as a non-zero exit.
func openV6AsChild(t *testing.T, path string) {
	t.Helper()
	fmt.Println(childReady)
	if _, err := io.ReadAll(os.Stdin); err != nil {
		t.Fatalf("child: wait for the start signal: %v", err)
	}
	s, err := Open(path, lifecycle.DefaultPolicy())
	if err != nil {
		t.Fatalf("child: open the version 6 file: %v", err)
	}
	defer func() { _ = s.Close() }()
	head, err := s.AuditHead(bg)
	if err != nil {
		t.Fatalf("child: read the audit head: %v", err)
	}
	fmt.Println(childHead + head)
}

// v6Child is one child process of the two-process test: the command, the
// stdin whose close is its start signal, its stdout line by line and its
// stderr for the failure message.
type v6Child struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	out    *bufio.Scanner
	stderr bytes.Buffer
}

// startV6Children re-executes the test binary n times with this test
// selected and the file named in the environment, and returns once every
// child has said ready, so that all of them are blocked on the start signal.
func startV6Children(t *testing.T, path string, n int) []*v6Child {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	kids := make([]*v6Child, 0, n)
	for range n {
		k := &v6Child{cmd: exec.Command(exe, "-test.run=^"+t.Name()+"$", "-test.count=1")}
		k.cmd.Env = append(os.Environ(), v6ChildEnv+"="+path)
		k.cmd.Stderr = &k.stderr
		stdout, err := k.cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		k.out = bufio.NewScanner(stdout)
		if k.stdin, err = k.cmd.StdinPipe(); err != nil {
			t.Fatal(err)
		}
		if err := k.cmd.Start(); err != nil {
			t.Fatalf("start the child process: %v", err)
		}
		t.Cleanup(func() { _ = k.stdin.Close(); _ = k.cmd.Process.Kill(); _ = k.cmd.Wait() })
		kids = append(kids, k)
	}
	for i, k := range kids {
		if !k.out.Scan() || k.out.Text() != childReady {
			t.Fatalf("child process %d did not say ready: %q, %v; stderr: %s", i, k.out.Text(), k.out.Err(), k.stderr.String())
		}
	}
	return kids
}

// wait reads the rest of the child's stdout, returns the head it printed and
// fails on a non-zero exit or a missing head line, quoting what the child
// wrote (the testing package writes a failed test's messages to stdout).
func (k *v6Child) wait() (string, error) {
	var head string
	var lines []string
	for k.out.Scan() {
		line := k.out.Text()
		if strings.HasPrefix(line, childHead) {
			head = strings.TrimPrefix(line, childHead)
			continue
		}
		lines = append(lines, line)
	}
	if err := k.cmd.Wait(); err != nil {
		return "", fmt.Errorf("exit: %w; stdout: %q; stderr: %q", err, strings.Join(lines, "\n"), k.stderr.String())
	}
	if head == "" {
		return "", fmt.Errorf("printed no head line; stdout: %q", strings.Join(lines, "\n"))
	}
	return head, nil
}
