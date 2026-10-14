package catalog

import (
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/gate"
)

// bytesColumn matches a reference to the two byte columns of tool_versions in
// a statement, as whole words: missing_crawls is not raw.
var bytesColumn = regexp.MustCompile(`\b(canonical|raw)\b`)

// approvedServer registers alpha with n approved single-version tools.
func approvedServer(t *testing.T, s *Store, n int) {
	t.Helper()
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", bigCrawl(n, "v1")...)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("tool-%05d", i)
		mustApprove(t, s, "alpha", name, digestOf(t, name, "v1"))
	}
}

// digestPaths runs the reads that hand out digests and read no canonical
// bytes: the processor's snapshot and the two list views (D21 d).
func digestPaths(s *Store) map[string]func() error {
	return map[string]func() error{
		"Snapshot": func() error { _, err := s.Snapshot(bg, "alpha"); return err },
		"Tools":    func() error { _, err := s.Tools(bg, "alpha"); return err },
		"Tool":     func() error { _, err := s.Tool(bg, "alpha", "tool-00000"); return err },
	}
}

// bytePaths runs the reads that hand out canonical bytes and hash them on
// every call: the export's list and the version history show and diff read.
func bytePaths(s *Store) map[string]func() error {
	return map[string]func() error{
		"Approved": func() error { _, err := s.Approved(bg); return err },
		"Versions": func() error { _, err := s.Versions(bg, "alpha", "tool-00000"); return err },
	}
}

// wantCorrupt requires every read in paths to fail with ErrCorrupt whose
// message mentions fragment.
func wantCorrupt(t *testing.T, paths map[string]func() error, fragment, why string) {
	t.Helper()
	for name, read := range paths {
		if err := read(); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), fragment) {
			t.Errorf("%s = %v, want ErrCorrupt mentioning %q: %s", name, err, fragment, why)
		}
	}
}

// wantClean requires every read in paths to succeed.
func wantClean(t *testing.T, paths map[string]func() error, why string) {
	t.Helper()
	for name, read := range paths {
		if err := read(); err != nil {
			t.Errorf("%s = %v, want success: %s", name, err, why)
		}
	}
}

// restoreGuard re-creates one guard trigger from the schema's own statements,
// so that a fresh Open accepts the file again after a test dropped it.
func restoreGuard(t *testing.T, db *sql.DB, name string) {
	t.Helper()
	for _, stmt := range guardStatements() {
		if strings.HasPrefix(stmt, "CREATE TRIGGER "+name+" ") {
			mustExec(t, db, stmt)
			return
		}
	}
	t.Fatalf("no guard statement creates %s", name)
}

// tamperCanonical rewrites the stored bytes of one version behind the Store's
// back, the way a SQLite shell would, and puts the guard back afterwards.
func tamperCanonical(t *testing.T, path, digest string, canonical []byte) {
	t.Helper()
	db := rawDB(t, path)
	mustExec(t, db, `DROP TRIGGER tool_versions_immutable`)
	mustExec(t, db, `UPDATE tool_versions SET canonical = ? WHERE digest = ?`, canonical, digest)
	restoreGuard(t, db, "tool_versions_immutable")
}

// canonicalFor is the canonical form the catalog stored for a test definition.
func canonicalFor(t *testing.T, name, desc string) []byte {
	t.Helper()
	canonical, err := gate.CanonicalTool(def(name, desc))
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

// The paths that hand out bytes hash them on every call and keep nothing
// between calls (D21 d): a rewrite of an approved definition's bytes is
// ErrCorrupt on the very next call of the Store that just read them clean, on
// a fresh Store, on a read-only Store, and for a decision; the repaired row is
// clean again at once, with no memory to lapse on either side.
func TestApproved_TamperedBytesAreCaughtAtOnce(t *testing.T) {
	s, path := newStoreAt(t, defaultPolicyForTests())
	approvedServer(t, s, 2)
	digest := digestOf(t, "tool-00000", "v1")
	wantClean(t, bytePaths(s), "the rows are untouched and have just been written")
	tamperCanonical(t, path, digest, []byte(`{"name":"tool-00000"}`))

	wantCorrupt(t, bytePaths(s), "does not hash to its", "the Store that read the row clean a moment ago has no memory of it")
	fresh := openStore(t, path, defaultPolicyForTests())
	wantCorrupt(t, bytePaths(fresh), "does not hash to its", "a fresh Store")
	reader, err := OpenWith(path, OpenOptions{ReadOnly: true, MustExist: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	wantCorrupt(t, bytePaths(reader), "does not hash to its", "a read-only Store")
	if err := s.Disable(bg, "alpha", "tool-00000", alice); !errors.Is(err, ErrCorrupt) {
		t.Errorf("Disable = %v, want ErrCorrupt: a decision loads its tool afresh", err)
	}
	// The other tool is untouched, and the export says so for every row it
	// reads before the bad one: nothing is exported from a file with one bad row.
	if _, err := s.Versions(bg, "alpha", "tool-00001"); err != nil {
		t.Errorf("Versions of the untouched tool = %v", err)
	}

	tamperCanonical(t, path, digest, canonicalFor(t, "tool-00000", "v1"))
	wantClean(t, bytePaths(s), "the repaired row hashes to its digest again")
	wantClean(t, bytePaths(reader), "the repaired row hashes to its digest again on the read-only Store")
}

// A changed digest column is caught by the serving path at once and without
// reading a byte: alone, by the newest-decision rule (the approvals row's
// hash_seen no longer names it); rewritten together with hash_seen under
// re-created guards, by the chain anchor (the newest approval entry's
// after_hash is the digest the approver saw). Every path that hands out the
// digest or the bytes refuses it.
func TestSnapshot_AChangedDigestColumnIsCaughtByTheAnchor(t *testing.T) {
	forged := strings.Repeat("0", 64)
	cases := map[string]struct {
		rewriteHashSeen bool
		fragment        string
	}{
		"digest column alone":                  {false, "newest approval decision"},
		"digest column and hash_seen together": {true, "is not the one its newest approval entry"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s, path := newStoreAt(t, defaultPolicyForTests())
			approvedServer(t, s, 1)
			digest := digestOf(t, "tool-00000", "v1")
			mustSnapshot(t, s, "alpha")
			db := rawDB(t, path)
			mustExec(t, db, `DROP TRIGGER tool_versions_immutable`)
			mustExec(t, db, `UPDATE tool_versions SET digest = ? WHERE digest = ?`, forged, digest)
			restoreGuard(t, db, "tool_versions_immutable")
			if tc.rewriteHashSeen {
				mustExec(t, db, `DROP TRIGGER approvals_no_update`)
				mustExec(t, db, `UPDATE approvals SET hash_seen = ? WHERE hash_seen = ?`, forged, digest)
				restoreGuard(t, db, "approvals_no_update")
			}
			wantCorrupt(t, digestPaths(s), tc.fragment, "the digest handed out must be the one the approver decided on")
			for p, read := range bytePaths(s) {
				if err := read(); !errors.Is(err, ErrCorrupt) {
					t.Errorf("%s = %v, want ErrCorrupt", p, err)
				}
			}
		})
	}
}

func TestRecheck_APointerAtAnotherToolsVersionIsCorrupt(t *testing.T) {
	s, path := newStoreAt(t, defaultPolicyForTests())
	approvedServer(t, s, 2)
	mustSnapshot(t, s, "alpha")
	mustExec(t, rawDB(t, path),
		`UPDATE tools SET approved_version_id = (SELECT id FROM tool_versions WHERE digest = ?) WHERE name = 'tool-00001'`,
		digestOf(t, "tool-00000", "v1"))
	for _, name := range []string{"Snapshot", "Approved"} {
		paths := digestPaths(s)
		if name == "Approved" {
			paths = bytePaths(s)
		}
		if err := paths[name](); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s = %v, want ErrCorrupt: another tool's version carries its own digest and must not pass as this one's", name, err)
		}
	}
}

// The serving path reads no canonical bytes (D21 d): its statements name no
// canonical column, so a rewrite of the bytes behind an approved digest, with
// the digest column intact, is invisible to Snapshot, Tools and Tool, which
// keep handing out the anchored digest, the one the gateway compares the live
// definition with, so the rewrite cannot change what is served. The paths that
// hand out bytes, a decision and Integrity all refuse or name it at once.
func TestSnapshot_ReadsNoCanonicalBytesAndStillServesTheAnchoredDigest(t *testing.T) {
	for name, stmt := range map[string]string{"snapshotQuery": snapshotQuery, "toolViewsQuery": toolViewsQuery, "toolViewQuery": toolViewQuery} {
		if m := bytesColumn.FindString(stmt); m != "" {
			t.Errorf("%s names the %s column; the serving path must not read bytes:\n%s", name, m, stmt)
		}
	}
	if bytesColumn.FindString(versionViewQuery) == "" || bytesColumn.FindString(approvedQuery) == "" {
		t.Error("the statements of Versions and Approved must read the canonical bytes they hand out and hash")
	}
	s, path := newStoreAt(t, defaultPolicyForTests())
	approvedServer(t, s, 2)
	digest := digestOf(t, "tool-00000", "v1")
	before := mustSnapshot(t, s, "alpha")
	tamperCanonical(t, path, digest, []byte(`{"name":"tool-00000"}`))

	hashed := s.chain.hashCount()
	after := mustSnapshot(t, s, "alpha")
	if after.Tools["tool-00000"].Approved != digest || after.Tools["tool-00000"] != before.Tools["tool-00000"] {
		t.Errorf("policy of tool-00000 after a bytes-only rewrite = %+v, want the anchored digest %s unchanged", after.Tools["tool-00000"], digest[:12])
	}
	if got := s.chain.hashCount() - hashed; got != 2 {
		t.Errorf("the reload hashed %d entries, want 2: one anchor entry per tool and nothing else", got)
	}
	views, err := s.Tools(bg, "alpha")
	if err != nil || len(views) != 2 || views[0].Approved != digest {
		t.Errorf("Tools = %+v, %v; want the anchored digest listed", views, err)
	}
	if v, err := s.Tool(bg, "alpha", "tool-00000"); err != nil || v.Approved != digest {
		t.Errorf("Tool = %+v, %v; want the anchored digest", v, err)
	}
	fresh := openStore(t, path, defaultPolicyForTests())
	wantClean(t, digestPaths(fresh), "a fresh Store reads no bytes either")

	wantCorrupt(t, bytePaths(s), "does not hash to its", "every path that hands out bytes hashes them")
	if err := s.Disable(bg, "alpha", "tool-00000", alice); !errors.Is(err, ErrCorrupt) {
		t.Errorf("Disable = %v, want ErrCorrupt: a decision loads and hashes its tool", err)
	}
	rep := mustIntegrity(t, s)
	problemMentioning(t, rep, `"alpha/tool-00000"`, "does not hash to its digest")
}

// Versions hands out bytes and hashes every version on every call (D21 d): a
// rewrite of any version's bytes, approved or superseded, is ErrCorrupt on the
// next call of the Store that just listed them clean and of a read-only Store,
// while Tool, which show reads first and which hands out the digest alone,
// still answers; the repaired row is clean again at once.
func TestVersions_TamperedBytesAreCaughtAtOnce(t *testing.T) {
	s, path := newStoreAt(t, defaultPolicyForTests())
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("echo", "v1"))
	mustCrawl(t, s, "alpha", tool("echo", "v2"))
	mustApprove(t, s, "alpha", "echo", digestOf(t, "echo", "v2"))
	reader, err := OpenWith(path, OpenOptions{ReadOnly: true, MustExist: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	for _, st := range []*Store{s, reader} {
		if vs, err := st.Versions(bg, "alpha", "echo"); err != nil || len(vs) != 2 {
			t.Fatalf("Versions = %+v, %v", vs, err)
		}
	}
	for no, desc := range map[int]string{1: "v1", 2: "v2"} {
		digest := digestOf(t, "echo", desc)
		tamperCanonical(t, path, digest, []byte(`{"name":"echo"}`))
		want := fmt.Sprintf("version %d does not hash to its stored digest", no)
		for label, st := range map[string]*Store{"writer": s, "reader": reader} {
			if _, err := st.Versions(bg, "alpha", "echo"); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), want) {
				t.Errorf("%s Versions after rewriting version %d = %v, want ErrCorrupt mentioning %q", label, no, err, want)
			}
			if v, err := st.Tool(bg, "alpha", "echo"); err != nil || v.Approved != digestOf(t, "echo", "v2") {
				t.Errorf("%s Tool after rewriting version %d = %+v, %v; want the anchored digest, since the view reads no bytes", label, no, v, err)
			}
		}
		tamperCanonical(t, path, digest, canonicalFor(t, "echo", desc))
		for label, st := range map[string]*Store{"writer": s, "reader": reader} {
			if _, err := st.Versions(bg, "alpha", "echo"); err != nil {
				t.Errorf("%s Versions after repairing version %d = %v", label, no, err)
			}
		}
	}
}
