package export

import (
	"path/filepath"
	"strings"
	"testing"
)

// The sweep used to delete every regular file whose name started with ".tmp-"
// in the export root and the server directories, whether or not this package
// had created it, although the package promises that nothing outside the
// manifest is deleted. It now matches only the exact shape writeAtomic
// produces: the prefix and sixteen lower-case hex digits, nothing else.
func TestIsTempName_MatchesOnlyWriteAtomicsOwnShape(t *testing.T) {
	suffix, err := randomSuffix()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{tmpPrefix + suffix, tmpPrefix + "deadbeefdeadbeef", tmpPrefix + "0123456789abcdef"} {
		if !isTempName(name) {
			t.Errorf("isTempName(%q) = false, want true", name)
		}
	}
	bad := map[string]string{
		"empty":                   "",
		"prefix only":             tmpPrefix,
		"operator notes":          tmpPrefix + "notes",
		"backup":                  tmpPrefix + "backup",
		"fifteen digits":          tmpPrefix + strings.Repeat("a", 15),
		"seventeen digits":        tmpPrefix + strings.Repeat("a", 17),
		"upper-case hex":          tmpPrefix + "DEADBEEFDEADBEEF",
		"not hex":                 tmpPrefix + "ghijklmnopqrstuv",
		"hex then a suffix":       tmpPrefix + "deadbeefdeadbeef" + jsonSuffix,
		"right length, two bytes": tmpPrefix + "deadbeefdeadbe\u00e9",
		"other prefix":            ".tmq-deadbeefdeadbeef",
		"no leading dot":          "tmp-deadbeefdeadbeef",
		"digits only":             "deadbeefdeadbeef",
		"manifest":                manifestName,
	}
	for label, name := range bad {
		if isTempName(name) {
			t.Errorf("%s: isTempName(%q) = true, want false", label, name)
		}
	}
}

// Ported from the review's TestReview_WriteDeletesForeignTmpFilesItNeverCreated.
// A ".tmp-" file this package did not create survives a Write: in the export
// root when no manifest exists yet, and in a server directory on a later
// Write that rewrites a tool there. A real leftover next to each one is still
// swept, which proves the sweep ran and only the shape decided.
func TestWrite_ForeignTmpFilesSurviveTheSweep(t *testing.T) {
	dir := t.TempDir()
	const leftover = "cafecafecafecafe"
	foreign := []string{tmpPrefix + "my-notes", tmpPrefix + "DEADBEEFDEADBEEF", tmpPrefix + "deadbeefdeadbee", tmpPrefix + "deadbeefdeadbeef0"}
	for _, n := range foreign {
		writeFile(t, filepath.Join(dir, n), "the operator's own scratch file\n")
	}
	writeFile(t, filepath.Join(dir, tmpPrefix+leftover), "partial")
	writeFile(t, filepath.Join(dir, "notes", tmpPrefix+leftover), "partial")

	rep := mustWrite(t, dir, mkTool(t, "alpha", "echo", "v1"))
	wantReport(t, rep, 1, 0, 0)
	snap := snapshot(t, dir)
	for _, n := range foreign {
		if _, ok := snap[n]; !ok {
			t.Errorf("%s was deleted although this package never created it", n)
		}
	}
	if _, ok := snap[tmpPrefix+leftover]; ok {
		t.Error("control: a leftover of the exact shape in the root was not swept, so the sweep did not run")
	}
	if _, ok := snap["notes/"+tmpPrefix+leftover]; !ok {
		t.Error("a directory neither the manifest nor the plan names must not be swept, whatever the file is called")
	}

	alien := "alpha/" + tmpPrefix + "alien"
	writeFile(t, filepath.Join(dir, filepath.FromSlash(alien)), "x")
	writeFile(t, filepath.Join(dir, "alpha", tmpPrefix+leftover), "partial")
	rep = mustWrite(t, dir, mkTool(t, "alpha", "echo", "v2"))
	wantReport(t, rep, 1, 0, 0)
	snap = snapshot(t, dir)
	if _, ok := snap[alien]; !ok {
		t.Errorf("%s was deleted although this package never created it", alien)
	}
	if _, ok := snap["alpha/"+tmpPrefix+leftover]; ok {
		t.Error("control: the leftover in the server directory was not swept")
	}
	if got := readFile(t, filepath.Join(dir, "alpha", "echo.json")); !strings.Contains(got, "v2") {
		t.Fatal("the rewritten tool must hold the new definition")
	}
}
