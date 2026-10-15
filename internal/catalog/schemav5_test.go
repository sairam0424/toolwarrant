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
// a file written by a released build is named with the migration a read-write
// open runs (D22 g: the first bump after v0.1.0 carried one, as the eighth
// review promised), so no message ever tells an operator to destroy an audit
// log. The branches are reached through the parameters so that each can be
// pinned on its own.
func TestSchemaMessage_AdvisesDeletionOnlyForUnreleasedSchemas(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		version, first, current int
		want, wantNot           string
	}{
		"unreleased build":     {5, 6, 6, "delete the file and run init again", "do not delete"},
		"released older build": {6, 6, 7, `this build uses 7; run "toolwarrant init" with this build, or any writing command, to migrate it in place`, "delete"},
		"newer build":          {99, 6, 6, "this build supports 6", "delete"},
		"zero":                 {0, 6, 6, "this build supports 6", "delete"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := schemaMessage(tc.version, tc.first, tc.current)
			if !errors.Is(err, ErrSchema) {
				t.Fatalf("schemaMessage = %v, want ErrSchema", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("message %q does not say %q", err, tc.want)
			}
			if strings.Contains(err.Error(), tc.wantNot) {
				t.Errorf("message %q must not say %q", err, tc.wantNot)
			}
		})
	}
	if firstReleasedSchema > schemaVersion {
		t.Errorf("firstReleasedSchema %d is above schemaVersion %d", firstReleasedSchema, schemaVersion)
	}
}
