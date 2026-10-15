package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// A file from the last pre-release schema is the live DDL without the two
// positive-id guards and user_version 5 (the version 7 objects the live DDL
// also holds do not matter: the version is read before any guard comparison).
// Every open mode refuses it with the re-initialise advice, before any guard
// comparison (so it is never mistaken for a corrupt file missing a trigger)
// and without writing to it, which is what docs/operations.md promises for a
// file another build wrote (eighth review).
func TestOpen_RefusesAPreReleaseSchemaFileUntouched(t *testing.T) {
	t.Parallel()
	path := dbPath(t)
	s := openStore(t, path, lifecycle.DefaultPolicy())
	approvedEcho(t, s)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	db := rawDB(t, path)
	mustExec(t, db, `DROP TRIGGER approvals_positive_id`)
	mustExec(t, db, `DROP TRIGGER tool_versions_positive_id`)
	mustExec(t, db, `PRAGMA user_version = 5`)
	_ = db.Close()
	before := fileDigest(t, path)

	for name, opts := range map[string]OpenOptions{
		"read-write": {Policy: lifecycle.DefaultPolicy()},
		"read-only":  {ReadOnly: true},
		"forensic":   {Forensic: true},
	} {
		_, err := OpenWith(path, opts)
		if !errors.Is(err, ErrSchema) {
			t.Fatalf("%s open of a v5 file = %v, want ErrSchema", name, err)
		}
		for _, want := range []string{"schema version 5 from an unreleased build", "this build uses 7", "delete the file and run init again"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s open error %q does not say %q", name, err, want)
			}
		}
		if strings.Contains(err.Error(), "guard trigger") {
			t.Errorf("%s open mistook the older schema for a corrupt file: %v", name, err)
		}
	}
	if after := fileDigest(t, path); after != before {
		t.Errorf("the refused opens changed the file: %s before, %s after", before, after)
	}
	// SQLite may leave an empty write-ahead log next to a WAL-mode file after
	// any open, so the content is re-read rather than the directory listed.
	db = rawDB(t, path)
	var version int
	if err := db.QueryRowContext(bg, `PRAGMA user_version`).Scan(&version); err != nil || version != 5 {
		t.Errorf("user_version after the refused opens = %d, %v; want 5", version, err)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND name IN ('approvals_positive_id', 'tool_versions_positive_id')`); n != 0 {
		t.Errorf("%d positive-id guards exist after the refused opens; a refused open must not migrate the file", n)
	}
}

// fileDigest is the SHA-256 of a file's bytes, for untouched-file assertions.
func fileDigest(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// The refusal advises deletion only for a schema below the first released one;
// a file written by a released build is named with the fix this build knows
// (D22 g: the first bump after v0.1.0 carried a migration, as the eighth
// review promised), so no message ever tells an operator to destroy an audit
// log. The schema the build migrates is told to back the file up and run init,
// and that every command but serve, audit verify and audit list migrates too;
// a released schema below the one the build migrates (reachable at the next
// bump, when migratableFrom moves to 7 and a v6 file is refused by a
// read-write open as well) is told to read the file with a build of its own
// schema or migrate it release by release, never to run the command that just
// refused it. The branches are reached through the parameters so that each
// can be pinned on its own, before the schema it describes exists.
func TestSchemaMessage_AdvisesDeletionOnlyForUnreleasedSchemas(t *testing.T) {
	t.Parallel()
	const migrate = `back the file up, then run "toolwarrant init" with this build to migrate it in place`
	cases := map[string]struct {
		version, first, migratable, current int
		want, wantNot                       string
	}{
		"unreleased build":              {5, 6, 6, 6, "delete the file and run init again", "do not delete"},
		"released, the migration":       {6, 6, 6, 7, "this build uses 7; " + migrate, "delete"},
		"released, below the migration": {6, 6, 7, 8, "this build uses 8 and migrates schema 7 only; do not delete it: read it with a build of schema 6, or migrate it with each release in turn", `run "toolwarrant init"`},
		"released, the next migration":  {7, 6, 7, 8, "this build uses 8; " + migrate, "delete"},
		"newer build":                   {99, 6, 6, 6, "this build supports 6", "delete"},
		"zero":                          {0, 6, 6, 6, "this build supports 6", "delete"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := schemaMessage(tc.version, tc.first, tc.migratable, tc.current)
			if !errors.Is(err, ErrSchema) {
				t.Fatalf("schemaMessage = %v, want ErrSchema", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("message %q does not say %q", err, tc.want)
			}
			if strings.Contains(err.Error(), tc.wantNot) {
				t.Errorf("message %q must not say %q", err, tc.wantNot)
			}
			if tc.version >= tc.first && strings.Contains(err.Error(), "delete the file") {
				t.Errorf("message %q advises deleting a released catalog", err)
			}
			if tc.version == tc.migratable && tc.version < tc.current {
				for _, want := range []string{"every command but serve, audit verify and audit list", "list and show included", "never migrate"} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("message %q does not say %q", err, want)
					}
				}
			}
		})
	}
	if firstReleasedSchema > schemaVersion {
		t.Errorf("firstReleasedSchema %d is above schemaVersion %d", firstReleasedSchema, schemaVersion)
	}
}
