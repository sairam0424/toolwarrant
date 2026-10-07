package catalog

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sairam0424/toolwarrant/internal/gate"
)

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

// readPaths runs the three read paths that re-check approved rows.
func readPaths(s *Store) map[string]func() error {
	return map[string]func() error{
		"Snapshot": func() error { _, err := s.Snapshot(bg, "alpha"); return err },
		"Approved": func() error { _, err := s.Approved(bg); return err },
		"Versions": func() error { _, err := s.Versions(bg, "alpha", "tool-00000"); return err },
	}
}

func wantHashes(t *testing.T, s *Store, want int64, why string) {
	t.Helper()
	if got := s.verified.hashCount(); got != want {
		t.Fatalf("hashes = %d, want %d: %s", got, want, why)
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

func TestRecheck_AVerifiedRowIsNotHashedAgainWithinTheTTL(t *testing.T) {
	s := newStore(t)
	advance := clockAt(s, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	const n = 5
	approvedServer(t, s, n)
	wantHashes(t, s, 0, "decisions re-hash on their own and never through the memory")

	if snap := mustSnapshot(t, s, "alpha"); len(snap.Tools) != n {
		t.Fatalf("snapshot has %d tools", len(snap.Tools))
	}
	wantHashes(t, s, n, "the first reload hashes every approved row once")

	// A crawl moves the generation; the reload after it, the export and the
	// view all find the rows remembered.
	mustCrawl(t, s, "alpha", bigCrawl(n, "v1")...)
	for name, read := range readPaths(s) {
		if err := read(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	wantHashes(t, s, n, "a remembered row is not hashed by any read path")

	advance(RecheckTTL - time.Nanosecond)
	mustSnapshot(t, s, "alpha")
	wantHashes(t, s, n, "the memory holds until RecheckTTL")
	advance(time.Nanosecond)
	mustSnapshot(t, s, "alpha")
	wantHashes(t, s, 2*n, "after RecheckTTL every row is hashed once more")
	mustSnapshot(t, s, "alpha")
	wantHashes(t, s, 2*n, "and remembered again")
	if s.verified.size() != n {
		t.Errorf("remembered rows = %d, want %d", s.verified.size(), n)
	}
}

func TestRecheck_TamperedBytesAreCaughtAfterTheTTLAndAtOnceWithoutTheMemory(t *testing.T) {
	s, path := newStoreAt(t, defaultPolicyForTests())
	advance := clockAt(s, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	approvedServer(t, s, 1)
	digest := digestOf(t, "tool-00000", "v1")
	mustSnapshot(t, s, "alpha") // the row is now remembered
	tamperCanonical(t, path, digest, []byte(`{"name":"tool-00000"}`))

	// The window RecheckTTL documents: the Store that verified the row does
	// not look at its bytes again before the TTL has passed.
	for name, read := range readPaths(s) {
		if err := read(); err != nil {
			t.Fatalf("%s within RecheckTTL = %v; the documented window hides the change until the TTL", name, err)
		}
	}
	// A Store without that memory fails closed at once.
	fresh := openStore(t, path, defaultPolicyForTests())
	for name, read := range readPaths(fresh) {
		if err := read(); !errors.Is(err, ErrCorrupt) {
			t.Errorf("fresh Store %s = %v, want ErrCorrupt", name, err)
		}
	}
	// So does a decision, which loads its tool afresh.
	if err := s.Disable(bg, "alpha", "tool-00000", alice); !errors.Is(err, ErrCorrupt) {
		t.Errorf("Disable = %v, want ErrCorrupt", err)
	}
	// And so does the remembering Store once RecheckTTL has passed.
	advance(RecheckTTL)
	for name, read := range readPaths(s) {
		if err := read(); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s after RecheckTTL = %v, want ErrCorrupt", name, err)
		}
	}
	// A failed row is never remembered: it is hashed on every read until it
	// is repaired, then verified once and remembered.
	before := s.verified.hashCount()
	_, _ = s.Snapshot(bg, "alpha")
	_, _ = s.Snapshot(bg, "alpha")
	wantHashes(t, s, before+2, "a failed row is hashed on every read")
	canonical, err := gate.CanonicalTool(def("tool-00000", "v1"))
	if err != nil {
		t.Fatal(err)
	}
	tamperCanonical(t, path, digest, canonical)
	mustSnapshot(t, s, "alpha")
	mustSnapshot(t, s, "alpha")
	wantHashes(t, s, before+3, "the repaired row is verified once and remembered")
}

func TestRecheck_AChangedDigestIsCaughtAtOnceEvenWithinTheTTL(t *testing.T) {
	s, path := newStoreAt(t, defaultPolicyForTests())
	approvedServer(t, s, 1)
	mustSnapshot(t, s, "alpha")
	db := rawDB(t, path)
	mustExec(t, db, `DROP TRIGGER tool_versions_immutable`)
	mustExec(t, db, `UPDATE tool_versions SET digest = ?`, strings.Repeat("0", 64))
	restoreGuard(t, db, "tool_versions_immutable")
	for name, read := range readPaths(s) {
		if err := read(); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s = %v, want ErrCorrupt: the memory is for one digest only", name, err)
		}
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
		if err := readPaths(s)[name](); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s = %v, want ErrCorrupt: another tool's version hashes to its own digest and must not pass as this one's", name, err)
		}
	}
}

func TestRecheck_ReadOnlyOpenRemembersAndForensicOpenDoesNot(t *testing.T) {
	s, path := newStoreAt(t, defaultPolicyForTests())
	approvedServer(t, s, 3)
	for _, tc := range []struct {
		name   string
		opts   OpenOptions
		hashes int64 // after two reloads
	}{
		{"read-only", OpenOptions{ReadOnly: true}, 3},
		{"forensic", OpenOptions{Forensic: true}, 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := OpenWith(path, tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = r.Close() })
			mustSnapshot(t, r, "alpha")
			mustSnapshot(t, r, "alpha")
			wantHashes(t, r, tc.hashes, tc.name+" open, two reloads of three approved tools")
		})
	}
}

func TestRecheck_EveryStoreHasItsOwnMemoryAndCloseDropsIt(t *testing.T) {
	a, path := newStoreAt(t, defaultPolicyForTests())
	b := openStore(t, path, defaultPolicyForTests())
	if a.verified == nil || b.verified == nil || a.verified == b.verified {
		t.Fatal("each Store must have its own verifier")
	}
	if a.verified.bound != recheckCacheEntries {
		t.Errorf("bound = %d, want %d", a.verified.bound, recheckCacheEntries)
	}
	approvedServer(t, a, 2)
	mustSnapshot(t, a, "alpha")
	if a.verified.size() != 2 || b.verified.size() != 0 {
		t.Fatalf("remembered: a = %d, b = %d; want 2 and 0", a.verified.size(), b.verified.size())
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if a.verified.size() != 0 {
		t.Errorf("a closed Store still remembers %d rows", a.verified.size())
	}
}

func TestRecheck_ConcurrentReadersShareOneMemorySafely(t *testing.T) {
	s := newStore(t)
	const n, readers, rounds = 20, 8, 5
	approvedServer(t, s, n)

	run := func() {
		var wg sync.WaitGroup
		for g := 0; g < readers; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for r := 0; r < rounds; r++ {
					for name, read := range readPaths(s) {
						if err := read(); err != nil {
							t.Errorf("%s: %v", name, err)
							return
						}
					}
				}
			}()
		}
		wg.Wait()
	}
	// Cold: a reader may hash a row it finds unremembered, never more.
	run()
	if got := s.verified.hashCount(); got < n || got > n*readers {
		t.Fatalf("cold hashes = %d, want between %d and %d", got, n, n*readers)
	}
	if s.verified.size() != n {
		t.Fatalf("remembered = %d, want %d", s.verified.size(), n)
	}
	// Warm: nothing is hashed again.
	warm := s.verified.hashCount()
	run()
	wantHashes(t, s, warm, "warm concurrent reads hash nothing")
}
