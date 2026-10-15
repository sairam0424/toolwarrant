package catalog

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// The fourth review's replaced-file finding (D14 e): after the documented
// growth-cap recovery (delete the file, init, register and approve again) a
// running processor kept serving the deleted file's approvals from its open
// descriptor, its generation never moving. The Store now records the catalog
// identity and the file it opened, and Generation reports ErrReplaced once the
// path names another file.

// removeDatabase deletes the database and its WAL and SHM files.
func removeDatabase(t *testing.T, path string) {
	t.Helper()
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	}
}

func TestGeneration_DetectsADeletedAndReinitialisedFile(t *testing.T) {
	t.Parallel()
	path := dbPath(t)
	writer := openStore(t, path, lifecycle.DefaultPolicy())
	approvedEcho(t, writer)
	reader, err := OpenWith(path, OpenOptions{ReadOnly: true, MustExist: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	gen0 := mustGeneration(t, reader)
	mustSnapshot(t, reader, "alpha")
	_ = writer.Close()

	removeDatabase(t, path)
	fresh := openStore(t, path, lifecycle.DefaultPolicy())
	if _, err := fresh.Server(bg, "alpha"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the fresh catalog knows alpha: %v", err)
	}
	_, err = reader.Generation(bg)
	if !errors.Is(err, ErrReplaced) || !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), path) {
		t.Fatalf("Generation on the deleted file = %v, want ErrReplaced (an ErrCorrupt) naming %s", err, path)
	}
	if _, err := reader.Snapshot(bg, "alpha"); !errors.Is(err, ErrReplaced) {
		t.Errorf("Snapshot on the deleted file = %v, want ErrReplaced: the old approvals must not be served", err)
	}
	if _, err := reader.Approved(bg); !errors.Is(err, ErrReplaced) {
		t.Errorf("Approved on the deleted file = %v, want ErrReplaced", err)
	}
	if gen := mustGeneration(t, fresh); gen >= gen0 {
		t.Logf("note: the fresh catalog's generation %d is not below the old %d; the identity, not the counter, tells them apart", gen, gen0)
	}
	// A new reader on the path reads the fresh catalog.
	reader2, err := OpenWith(path, OpenOptions{ReadOnly: true, MustExist: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader2.Close() }()
	if _, err := reader2.Snapshot(bg, "alpha"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Snapshot through a new reader = %v, want ErrNotFound (the fresh catalog has no server)", err)
	}
}

func TestGeneration_DetectsARenamedFileAndRecoversWhenItReturns(t *testing.T) {
	t.Parallel()
	path := dbPath(t)
	s := openStore(t, path, lifecycle.DefaultPolicy())
	approvedEcho(t, s)
	gen := mustGeneration(t, s)
	if err := os.Rename(path, path+".moved"); err != nil {
		t.Fatal(err)
	}
	_, err := s.Generation(bg)
	if !errors.Is(err, ErrReplaced) || !strings.Contains(err.Error(), "no longer exists") {
		t.Fatalf("Generation with the file renamed away = %v, want ErrReplaced saying it no longer exists", err)
	}
	if _, err := s.Tools(bg, ""); !errors.Is(err, ErrReplaced) {
		t.Errorf("Tools with the file renamed away = %v, want ErrReplaced", err)
	}
	if err := os.Rename(path+".moved", path); err != nil {
		t.Fatal(err)
	}
	if got := mustGeneration(t, s); got != gen {
		t.Errorf("Generation after the file returned = %d, want %d: the same file is the same catalog", got, gen)
	}
}

func TestGeneration_DetectsAnotherIdentityInMeta(t *testing.T) {
	t.Parallel()
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	approvedEcho(t, s)
	db := rawDB(t, path)
	mustExec(t, db, `UPDATE meta SET value = ? WHERE key = 'identity'`, strings.Repeat("0f", 16))
	if _, err := s.Generation(bg); !errors.Is(err, ErrReplaced) || !strings.Contains(err.Error(), "another catalog identity") {
		t.Errorf("Generation with the identity rewritten = %v, want ErrReplaced", err)
	}
	mustExec(t, db, `DELETE FROM meta WHERE key = 'identity'`)
	if _, err := s.Generation(bg); !errors.Is(err, ErrCorrupt) || errors.Is(err, ErrReplaced) {
		t.Errorf("Generation with the identity gone = %v, want ErrCorrupt (not ErrReplaced)", err)
	}
}

// init writes a random identity; every init draws another; a reopen keeps it;
// a file whose identity is gone is refused except by a forensic open.
func TestOpen_WritesAndKeepsACatalogIdentity(t *testing.T) {
	t.Parallel()
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	identity := s.identity
	if len(identity) != 32 || !isHex(identity) {
		t.Fatalf("identity = %q, want 32 hex characters", identity)
	}
	var stored string
	if err := rawDB(t, path).QueryRowContext(bg, `SELECT value FROM meta WHERE key = 'identity'`).Scan(&stored); err != nil || stored != identity {
		t.Fatalf("stored identity = %q, %v; Store read %q", stored, err, identity)
	}
	_ = s.Close()
	s2 := openStore(t, path, lifecycle.DefaultPolicy())
	if s2.identity != identity {
		t.Errorf("reopen read identity %q, want %q", s2.identity, identity)
	}
	other, _ := newStoreAt(t, lifecycle.DefaultPolicy())
	if other.identity == identity {
		t.Errorf("two inits drew the same identity %q", identity)
	}
	if s2.file.known && s2.file == other.file {
		t.Errorf("two files share the device and inode %+v", s2.file)
	}
	_ = s2.Close()
	mustExec(t, rawDB(t, path), `DELETE FROM meta WHERE key = 'identity'`)
	if _, err := Open(path, lifecycle.DefaultPolicy()); !errors.Is(err, ErrCorrupt) {
		t.Errorf("Open without an identity = %v, want ErrCorrupt", err)
	}
	if _, err := OpenWith(path, OpenOptions{ReadOnly: true}); !errors.Is(err, ErrCorrupt) {
		t.Errorf("read-only open without an identity = %v, want ErrCorrupt", err)
	}
	f, err := OpenWith(path, OpenOptions{Forensic: true})
	if err != nil {
		t.Fatalf("forensic open without an identity = %v", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Generation(bg); err != nil {
		t.Errorf("Generation on a forensic open without an identity = %v; only the file is compared", err)
	}
}
