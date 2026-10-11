package catalog

import (
	"errors"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// The fourth review's lockout (D14 f): whoever tampers with the file can also
// switch its journal mode back to DELETE, after which the forensic open that
// audit verify and audit list rely on refused the file, and the read-write
// open the message suggested was ErrCorrupt before it converted the file. A
// forensic open now takes a non-WAL file with immutable=1; the read-only and
// read-write opens keep their rules and leave the file as it is.
func TestOpenWith_ForensicOpensANonWALFile(t *testing.T) {
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	d1 := approvedEcho(t, s)
	_ = s.Close()
	db := rawDB(t, path)
	var mode string
	if err := db.QueryRowContext(bg, `PRAGMA journal_mode = DELETE`).Scan(&mode); err != nil || !strings.EqualFold(mode, "delete") {
		t.Fatalf("switch journal mode: %q, %v", mode, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// An intact file in DELETE mode: the processor's open still insists on
	// WAL, the forensic open reads it.
	if _, err := OpenWith(path, OpenOptions{ReadOnly: true}); err == nil || !strings.Contains(err.Error(), "needs a WAL-mode database") {
		t.Errorf("read-only open of a DELETE-mode file = %v, want the journal-mode refusal (the processor never reads such a file)", err)
	}
	f, err := OpenWith(path, OpenOptions{Forensic: true})
	if err != nil {
		t.Fatalf("forensic open of an intact DELETE-mode file = %v", err)
	}
	mustBeClean(t, f, "on the intact file")
	_ = f.Close()

	// The tampered file in DELETE mode: both the read-only and the read-write
	// open refuse (guards), neither converts the file, the forensic open names
	// the broken guard and serves every inspection.
	db = rawDB(t, path)
	mustExec(t, db, `DROP TRIGGER audit_log_no_update`)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWith(path, OpenOptions{ReadOnly: true}); !errors.Is(err, ErrCorrupt) {
		t.Errorf("read-only open of the tampered file = %v, want ErrCorrupt", err)
	}
	if _, err := Open(path, lifecycle.DefaultPolicy()); !errors.Is(err, ErrCorrupt) {
		t.Errorf("read-write open = %v, want ErrCorrupt from the guard check", err)
	}
	f, err = OpenWith(path, OpenOptions{Forensic: true})
	if err != nil {
		t.Fatalf("forensic open of a tampered DELETE-mode file = %v", err)
	}
	defer func() { _ = f.Close() }()
	if !f.ReadOnly() {
		t.Error("a forensic Store must be read-only")
	}
	sum, err := f.VerifyAudit(bg)
	if err != nil || sum.Entries == 0 {
		t.Errorf("VerifyAudit = %+v, %v", sum, err)
	}
	rep := mustIntegrity(t, f)
	problemMentioning(t, rep, "guard trigger audit_log_no_update is missing")
	if entries, err := f.AuditEntries(bg, 0, 0); err != nil || len(entries) != sum.Entries {
		t.Errorf("AuditEntries = %d, %v", len(entries), err)
	}
	if vs, err := f.Versions(bg, "alpha", "echo"); err != nil || len(vs) != 1 || vs[0].Digest != d1 {
		t.Errorf("Versions = %+v, %v", vs, err)
	}
	if views, err := f.Tools(bg, ""); err != nil || len(views) != 1 || views[0].Approved != d1 {
		t.Errorf("Tools on a forensic open = %+v, %v; the views read past the guard check as Open did", views, err)
	}
	if _, err := f.AddServer(bg, ServerSpec{Name: "beta", URL: "https://b.example.com"}, alice); !errors.Is(err, ErrReadOnly) {
		t.Errorf("AddServer on a forensic open = %v, want ErrReadOnly", err)
	}
	db = rawDB(t, path)
	if err := db.QueryRowContext(bg, `PRAGMA journal_mode`).Scan(&mode); err != nil || !strings.EqualFold(mode, "delete") {
		t.Errorf("journal mode after the opens = %q, %v; no open may convert a file it refuses", mode, err)
	}
}
