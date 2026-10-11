package catalog

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// The fourth review's availability trap (D14 c): a foreign unique index made
// every later write fail with a plain constraint error while Open succeeded
// and Integrity was clean. A unique index the schema did not create is now a
// foreign object, and a constraint failure inside a write transaction is
// ErrCorrupt.
func TestOpen_ForeignUniqueIndexIsCorrupt(t *testing.T) {
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	approvedEcho(t, s)
	mustExec(t, rawDB(t, path), `CREATE UNIQUE INDEX one_event_only ON audit_log (event)`)

	// Every write refuses: the repeated event hits the index inside the
	// transaction (ErrCorrupt by the constraint rule), and a write whose
	// events are new hits the guard check before it commits.
	for name, err := range map[string]error{
		"RecordCrawl": func() error { _, err := s.RecordCrawl(bg, crawlOf(tool("echo", "v1")), crawler); return err }(),
		"Disable":     s.Disable(bg, "alpha", "echo", alice),
	} {
		if !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s with a foreign unique index = %v, want ErrCorrupt", name, err)
		}
	}
	var state string
	if err := rawDB(t, path).QueryRowContext(bg, `SELECT state FROM tools WHERE name = 'echo'`).Scan(&state); err != nil || state != string(lifecycle.Enabled) {
		t.Errorf("state after the refused writes = %q, %v; want enabled: nothing may commit into the file", state, err)
	}
	for p, err := range allPaths(s, "alpha", "echo") {
		if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "unexpected index one_event_only") {
			t.Errorf("%s = %v, want ErrCorrupt naming the index", p, err)
		}
	}
	rep := mustIntegrity(t, s)
	if !slices.Equal(rep.ForeignObjects, []string{"index one_event_only"}) {
		t.Errorf("Integrity.ForeignObjects = %v, want the unique index", rep.ForeignObjects)
	}
	problemMentioning(t, rep, "unexpected index one_event_only")
	_ = s.Close()
	if _, err := Open(path, lifecycle.DefaultPolicy()); !errors.Is(err, ErrCorrupt) {
		t.Errorf("reopen = %v, want ErrCorrupt", err)
	}
	if _, err := OpenWith(path, OpenOptions{ReadOnly: true}); !errors.Is(err, ErrCorrupt) {
		t.Errorf("read-only reopen = %v, want ErrCorrupt", err)
	}
	f, err := OpenWith(path, OpenOptions{Forensic: true})
	if err != nil {
		t.Fatalf("forensic open = %v", err)
	}
	defer func() { _ = f.Close() }()
	if rep := mustIntegrity(t, f); !slices.Equal(rep.ForeignObjects, []string{"index one_event_only"}) {
		t.Errorf("forensic Integrity.ForeignObjects = %v", rep.ForeignObjects)
	}
}

// A plain index someone adds cannot change what a query returns or what a
// write does, so it is still tolerated, whatever its case or layout, and a
// unique one is recognised however it is written.
func TestOpen_PlainForeignIndexIsTolerated(t *testing.T) {
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	approvedEcho(t, s)
	mustExec(t, rawDB(t, path), "create\tindex   by_actor ON audit_log (actor)")
	mustCrawl(t, s, "alpha", tool("echo", "v1"))
	mustBeClean(t, s, "with a plain foreign index")
	_ = s.Close()
	s2, err := Open(path, lifecycle.DefaultPolicy())
	if err != nil {
		t.Fatalf("reopen with a plain foreign index = %v", err)
	}
	defer func() { _ = s2.Close() }()
	mustSnapshot(t, s2, "alpha")
	for ddl, unique := range map[string]bool{
		"CREATE UNIQUE INDEX x ON t (c)":          true,
		"create unique\n\tindex x ON t (c)":       true,
		"CREATE INDEX x ON t (c)":                 false,
		"CREATE INDEX unique_names ON t (unique)": false,
		"": false,
	} {
		if got := isUniqueIndexDDL(ddl); got != unique {
			t.Errorf("isUniqueIndexDDL(%q) = %t, want %t", ddl, got, unique)
		}
	}
}

// A constraint failure inside a write transaction is ErrCorrupt whatever
// statement hit it: the Store validates before it writes, so a constraint that
// fires is one the schema does not have or a guard refusing a row; any other
// error passes through as it is, so a bug is not disguised as tampering.
func TestInTx_ConstraintFailureIsCorrupt(t *testing.T) {
	s, _ := newStoreAt(t, lifecycle.DefaultPolicy())
	mustAddServer(t, s, "alpha")
	before := takeTrace(t, s)
	err := s.inTx(bg, func(t *txn) error {
		_, err := t.exec(bg, `INSERT INTO servers (name, url, owner_group, allow_private, paused, created_at) VALUES ('alpha', 'u', '', 0, 0, 't')`)
		return err
	})
	if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "UNIQUE constraint failed") {
		t.Errorf("duplicate insert inside inTx = %v, want ErrCorrupt wrapping the constraint", err)
	}
	err = s.inTx(bg, func(t *txn) error {
		_, err := t.exec(bg, `UPDATE audit_log SET actor = 'mallory'`)
		return err
	})
	if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "append-only") {
		t.Errorf("guarded update inside inTx = %v, want ErrCorrupt wrapping the guard's message", err)
	}
	err = s.inTx(bg, func(t *txn) error {
		_, err := t.exec(bg, `SELEC 1`)
		return err
	})
	if err == nil || errors.Is(err, ErrCorrupt) {
		t.Errorf("a syntax error inside inTx = %v, want the plain error", err)
	}
	before.mustEqual(t, s, "the refused transactions")
}
