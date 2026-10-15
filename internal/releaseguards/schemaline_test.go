package releaseguards

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const (
	// schemaSource is, with goreleaserConfig (releasenotes_test.go), one of
	// the two files the schema-line recipe reads, relative to the Makefile.
	schemaSource = "internal/catalog/schema.go"
	// schemaLineTarget runs the recipe alone; release-check runs it after the
	// guards and before goreleaser check.
	schemaLineTarget = "release-schema-line"
	// schemaLinePrefix is how the release notes header names the catalog
	// schema; the recipe's sed reads the number after it, and the sentence
	// after the number is what an operator with an older catalog acts on.
	schemaLinePrefix = "; a catalog from an earlier build "
	// migrationSentence is what the header line must start with after the
	// number since the version 7 round (D22 g): a v6 file is migrated in
	// place, nothing else is; the Makefile's sed reads the number before it.
	migrationSentence = "is migrated in place when it is schema v6 (v0.1.0 to v0.3.x) and refused otherwise"
	// The messages the recipe prints.
	schemaLineAgrees   = ", as the code writes"
	schemaLineMismatch = "but internal/catalog/schema.go writes v"
)

var (
	// schemaVersionLine captures the number schema.go writes.
	schemaVersionLine = regexp.MustCompile(`(?m)^const schemaVersion = (\d+)`)
	// headerSchemaLine captures the header line the recipe reads, without
	// its indentation.
	headerSchemaLine = regexp.MustCompile(`(?m)^\s*(v(\d+)` + regexp.QuoteMeta(schemaLinePrefix) + `[^\n]*)$`)
)

// TestReleaseGuards_schemaLineNamesTheMigration pins the release notes
// header: the recipe passes on the tree and names the version schema.go
// writes, the header line says that a schema v6 file is migrated in place
// (the sentence an operator upgrading from v0.1.0 to v0.3.x reads first), a
// scratch copy whose header still names the previous version is refused with
// both numbers, a copy with no such line is refused, and release-check runs
// the recipe before goreleaser check.
func TestReleaseGuards_schemaLineNamesTheMigration(t *testing.T) {
	dir := scratchReleaseTree(t)
	version := schemaVersionOf(t, readFile(t, filepath.Join(dir, schemaSource)))
	out, err := runMake(dir, schemaLineTarget)
	if err != nil || !strings.Contains(out, "release notes name schema v"+version+schemaLineAgrees) {
		t.Fatalf("the schema line check failed on the tree as it is: %v\n%s", err, out)
	}
	header := readFile(t, filepath.Join(dir, goreleaserConfig))
	m := headerSchemaLine.FindStringSubmatch(header)
	if m == nil {
		t.Fatalf("%s has no header line of the form v<N>%s...", goreleaserConfig, schemaLinePrefix)
	}
	if m[2] != version {
		t.Errorf("the header names schema v%s, schema.go writes v%s", m[2], version)
	}
	if want := "v" + version + schemaLinePrefix + migrationSentence; !strings.HasPrefix(m[1], want) {
		t.Errorf("header line\n  %s\nmust start with\n  %s", m[1], want)
	}
	t.Run("stale version", func(t *testing.T) {
		dir := scratchReleaseTree(t)
		stale := strings.Replace(header, "v"+version+schemaLinePrefix, "v6"+schemaLinePrefix, 1)
		if version == "6" {
			stale = strings.Replace(header, "v6"+schemaLinePrefix, "v5"+schemaLinePrefix, 1)
		}
		writeFile(t, filepath.Join(dir, goreleaserConfig), stale)
		out, err := runMake(dir, schemaLineTarget)
		assertGuard(t, out, err, true, schemaLineMismatch+version)
	})
	t.Run("no schema line", func(t *testing.T) {
		dir := scratchReleaseTree(t)
		writeFile(t, filepath.Join(dir, goreleaserConfig), headerSchemaLine.ReplaceAllString(header, ""))
		out, err := runMake(dir, schemaLineTarget)
		assertGuard(t, out, err, true, "release notes name schema v "+schemaLineMismatch+version)
	})
	out, err = runMake(dir, "-n", releaseCheckTarget)
	if err != nil {
		t.Fatalf("make -n %s: %v\n%s", releaseCheckTarget, err, out)
	}
	line, goreleaser := strings.Index(out, "a catalog from an earlier build"), strings.Index(out, "goreleaser check")
	if line < 0 || goreleaser < 0 || line > goreleaser {
		t.Errorf("release-check must read the schema line before goreleaser check (line at %d, goreleaser at %d):\n%s", line, goreleaser, out)
	}
}

// scratchReleaseTree is scratchTree plus copies of .goreleaser.yaml and
// internal/catalog/schema.go, the two files the schema-line recipe reads.
func scratchReleaseTree(t *testing.T) string {
	t.Helper()
	dir := scratchTree(t)
	root := moduleRoot(t)
	for _, name := range []string{goreleaserConfig, schemaSource} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o700); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(dir, name), readFile(t, filepath.Join(root, name)))
	}
	return dir
}

// schemaVersionOf reads the number the schemaVersion constant holds.
func schemaVersionOf(t *testing.T, source string) string {
	t.Helper()
	m := schemaVersionLine.FindStringSubmatch(source)
	if m == nil {
		t.Fatalf("%s has no 'const schemaVersion = N' line", schemaSource)
	}
	return m[1]
}
