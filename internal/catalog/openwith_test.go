package catalog

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// Reviewers' "the processor needs write access": a read-only open serves every
// read and refuses every write, and sees what a writer commits.
func TestOpenWith_ReadOnly(t *testing.T) {
	path := dbPath(t)
	writer := openStore(t, path, lifecycle.DefaultPolicy())
	mustAddServer(t, writer, "alpha")
	mustCrawl(t, writer, "alpha", tool("echo", "v1"))
	d := digestOf(t, "echo", "v1")
	mustApprove(t, writer, "alpha", "echo", d)

	ro, err := OpenWith(path, OpenOptions{Policy: lifecycle.DefaultPolicy(), ReadOnly: true})
	if err != nil {
		t.Fatalf("read-only open: %v", err)
	}
	t.Cleanup(func() { _ = ro.Close() })
	if !ro.ReadOnly() {
		t.Error("ReadOnly() = false")
	}
	if snap := mustSnapshot(t, ro, "alpha"); !snap.Serves("echo", d) {
		t.Errorf("snapshot = %+v", snap)
	}
	if vs, err := ro.Versions(bg, "alpha", "echo"); err != nil || len(vs) != 1 {
		t.Errorf("Versions = %+v, %v", vs, err)
	}
	if list, err := ro.Approved(bg); err != nil || len(list) != 1 {
		t.Errorf("Approved = %+v, %v", list, err)
	}
	if _, err := ro.VerifyAudit(bg); err != nil {
		t.Errorf("VerifyAudit: %v", err)
	}
	for name, err := range map[string]error{
		"AddServer": func() error {
			_, err := ro.AddServer(bg, ServerSpec{Name: "beta", URL: "https://b.example.com"}, alice)
			return err
		}(),
		"RecordCrawl":  func() error { _, err := ro.RecordCrawl(bg, crawlOf(tool("echo", "v2")), crawler); return err }(),
		"Approve":      ro.Approve(bg, "alpha", "echo", d, bob),
		"Reject":       ro.Reject(bg, "alpha", "echo", d, bob),
		"Rollback":     ro.Rollback(bg, "alpha", "echo", d, bob),
		"Disable":      ro.Disable(bg, "alpha", "echo", bob),
		"Enable":       ro.Enable(bg, "alpha", "echo", bob),
		"PauseServer":  ro.PauseServer(bg, "alpha", bob),
		"ResumeServer": ro.ResumeServer(bg, "alpha", bob),
	} {
		if !errors.Is(err, ErrReadOnly) {
			t.Errorf("%s on a read-only store: %v, want ErrReadOnly", name, err)
		}
	}
	// The writer keeps writing; the reader follows the generation.
	gen := mustGeneration(t, ro)
	mustCrawl(t, writer, "alpha", tool("echo", "v2"))
	if got := mustGeneration(t, ro); got != gen+1 {
		t.Errorf("generation seen by the reader = %d, want %d", got, gen+1)
	}
	if v := mustTool(t, ro, "alpha", "echo"); !v.Drifted {
		t.Errorf("reader does not see the drift: %+v", v)
	}
	// A read-only open of a closed database works too (no -wal/-shm present).
	_ = writer.Close()
	ro2, err := OpenWith(path, OpenOptions{ReadOnly: true})
	if err != nil {
		t.Fatalf("read-only open after the writer closed: %v", err)
	}
	defer func() { _ = ro2.Close() }()
	if _, err := ro2.Snapshot(bg, "alpha"); err != nil {
		t.Error(err)
	}
}

func TestOpenWith_ReadOnlyAndMustExistRefuseAMissingFile(t *testing.T) {
	path := dbPath(t)
	for name, opts := range map[string]OpenOptions{
		"read-only":  {ReadOnly: true},
		"must exist": {MustExist: true},
		"both":       {ReadOnly: true, MustExist: true},
	} {
		if _, err := OpenWith(path, opts); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s on a missing file: %v, want ErrNotFound", name, err)
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s created the file", name)
		}
	}
	// An empty file is not a database yet: read-only refuses it, a read-write
	// open with MustExist initialises it.
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWith(path, OpenOptions{ReadOnly: true}); !errors.Is(err, ErrSchema) {
		t.Errorf("read-only open of an empty file: %v, want ErrSchema", err)
	}
	s, err := OpenWith(path, OpenOptions{MustExist: true})
	if err != nil {
		t.Fatalf("MustExist on an existing file: %v", err)
	}
	_ = s.Close()
}

// Reviewers' "a pre-existing 0644 database stays world-readable": such a file
// is refused unless the operator says it is meant to be shared, a fresh file
// and its WAL and SHM files are private, and a symbolic link is not followed.
func TestOpenWith_FileModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}
	dir := t.TempDir()
	shared := filepath.Join(dir, "shared.db")
	if err := os.WriteFile(shared, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(shared, lifecycle.DefaultPolicy()); !errors.Is(err, ErrInvalid) {
		t.Errorf("Open on a 0644 file: %v, want ErrInvalid", err)
	}
	if _, err := OpenWith(shared, OpenOptions{ReadOnly: true}); !errors.Is(err, ErrInvalid) {
		t.Errorf("read-only Open on a 0644 file: %v, want ErrInvalid", err)
	}
	s, err := OpenWith(shared, OpenOptions{Policy: lifecycle.DefaultPolicy(), AllowSharedFile: true})
	if err != nil {
		t.Fatalf("AllowSharedFile: %v", err)
	}
	mustAddServer(t, s, "alpha")
	_ = s.Close()

	fresh := filepath.Join(dir, "fresh.db")
	s2 := openStore(t, fresh, lifecycle.DefaultPolicy())
	mustAddServer(t, s2, "alpha")
	mustCrawl(t, s2, "alpha", tool("echo", "v1"))
	for _, suffix := range []string{"", "-wal", "-shm"} {
		fi, err := os.Stat(fresh + suffix)
		if err != nil {
			t.Fatalf("%s: %v", suffix, err)
		}
		if fi.Mode().Perm()&0o077 != 0 {
			t.Errorf("fresh.db%s is group or world accessible (%04o)", suffix, fi.Mode().Perm())
		}
	}

	target := filepath.Join(dir, "elsewhere.db")
	link := filepath.Join(dir, "link.db")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link, lifecycle.DefaultPolicy()); !errors.Is(err, ErrInvalid) {
		t.Errorf("Open on a symbolic link: %v, want ErrInvalid", err)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Error("Open followed the link and created the target")
	}
	if _, err := Open(dir, lifecycle.DefaultPolicy()); !errors.Is(err, ErrInvalid) {
		t.Errorf("Open on a directory: %v, want ErrInvalid", err)
	}
}
