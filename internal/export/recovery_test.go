package export

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/textdiff"
)

// Write used to put the manifest down last, so a process that died after the
// tool files were written and the stale ones removed left a new snapshot on
// disk that no manifest ever listed: no later Write could remove it and the
// next commit recorded it as approved. The pending manifest written first now
// covers every file, and the next Write finishes the clean-up.
func TestWrite_CrashBeforeTheFinalManifestIsRecovered(t *testing.T) {
	dir := t.TempDir()
	x := mkTool(t, "a", "x", "1")
	y := mkTool(t, "b", "y", "1")
	mustWrite(t, dir, x) // the manifest lists a/x.json

	// Write(dir, {y}) dying after the tool files and removals but before the
	// complete manifest: Write's own steps minus the last one.
	planned, skipped, err := planAll([]Tool{y})
	if err != nil || len(skipped) != 0 {
		t.Fatal(err, skipped)
	}
	root, err := openExportRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	prev, err := readPrevManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	act, err := planActions(root, prev, planned)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := renderManifest(unionEntries(prev.Tools, planned), statusPending, testOpts)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(root, manifestName, pending); err != nil {
		t.Fatal(err)
	}
	var rep Report
	if err := writeTools(root, planned, act.write, &rep); err != nil {
		t.Fatal(err)
	}
	if err := removeUnwanted(root, act.remove, &rep); err != nil {
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	// -- crash here --

	if doc := readManifest(t, dir); doc.Status != statusPending || !reflect.DeepEqual(doc.files(), []string{"a/x.json", "b/y.json"}) {
		t.Fatalf("after the crash the manifest must be pending and list both files, got %+v", doc)
	}
	// The approvals changed again before the retry: nothing is approved now.
	rep = mustWrite(t, dir)
	wantReport(t, rep, 0, 1, 0)
	snap := snapshot(t, dir)
	if _, orphan := snap["b/y.json"]; orphan {
		t.Fatal("b/y.json is orphaned: on disk, listed nowhere, and would be committed as approved")
	}
	if doc := readManifest(t, dir); doc.Status != statusComplete || len(doc.Tools) != 0 {
		t.Fatalf("manifest after the recovery = %+v", doc)
	}
}

// A pending manifest whose work turns out to be done already is completed
// without touching any tool file.
func TestWrite_PendingManifestWithNothingLeftToDoIsCompleted(t *testing.T) {
	dir := t.TempDir()
	one := mkTool(t, "s", "one", "1")
	mustWrite(t, dir, one)
	before := snapshot(t, dir)["s/one.json"]
	complete := readFile(t, filepath.Join(dir, manifestName))
	writeFile(t, filepath.Join(dir, manifestName), strings.Replace(complete, `"status": "complete"`, `"status": "pending"`, 1))
	if doc := readManifest(t, dir); doc.Status != statusPending {
		t.Fatal("test setup: manifest must be pending")
	}
	rep := mustWrite(t, dir, one)
	wantReport(t, rep, 0, 0, 1)
	if doc := readManifest(t, dir); doc.Status != statusComplete {
		t.Fatalf("status = %q", doc.Status)
	}
	if after := snapshot(t, dir)["s/one.json"]; after != before {
		t.Fatal("the tool file must not be touched")
	}
}

// A temp file left by a crash between OpenFile and Rename used to stay forever
// and be committed with the snapshots. Every Write now sweeps the temp files
// of the directories it touches, including the top level and the directories
// of files it removes. Only the exact name shape writeAtomic produces is
// swept, and only when it is a regular file: a directory or a symlink wearing
// it is left alone (sweep_test.go covers names that merely start with the
// prefix).
func TestWrite_SweepsLeftoverTemporaryFiles(t *testing.T) {
	dir := t.TempDir()
	one := mkTool(t, "s", "one", "v1")
	mustWrite(t, dir, one, mkTool(t, "b", "y", "1"))
	const inS, inRoot, inB = "deadbeefdeadbeef", "cafecafecafecafe", "feedfeedfeedfeed"
	const asDir, asLink = "0123456789abcdef", "fedcba9876543210"
	writeFile(t, filepath.Join(dir, "s", tmpPrefix+inS), "partial")
	writeFile(t, filepath.Join(dir, tmpPrefix+inRoot), "partial")
	writeFile(t, filepath.Join(dir, "b", tmpPrefix+inB), "partial")
	if err := os.Mkdir(filepath.Join(dir, "s", tmpPrefix+asDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "s", "one.json"), filepath.Join(dir, "s", tmpPrefix+asLink)); err != nil {
		t.Fatal(err)
	}

	rep := mustWrite(t, dir, one) // b/y.json is stale now
	wantReport(t, rep, 0, 1, 1)
	snap := snapshot(t, dir)
	for _, gone := range []string{"s/" + tmpPrefix + inS, tmpPrefix + inRoot, "b/" + tmpPrefix + inB, "b/y.json", "b"} {
		if _, ok := snap[gone]; ok {
			t.Errorf("%s must be swept", gone)
		}
	}
	for _, kept := range []string{"s/" + tmpPrefix + asDir, "s/" + tmpPrefix + asLink, "s/one.json"} {
		if _, ok := snap[kept]; !ok {
			t.Errorf("%s must be left alone", kept)
		}
	}
	if readFile(t, filepath.Join(dir, "s", "one.json")) != string(one.Canonical)+"\n" {
		t.Fatal("the symlink target was damaged")
	}
	if rep := mustWrite(t, dir, one); rep.Written != 0 || rep.Removed != 0 {
		t.Fatalf("second Write = %+v", rep)
	}
}

// Hostile names used to reach MANIFEST.json raw: an 8-bit CSI, a bidi
// override, a zero-width space and a tag character landed in a file people
// read with git diff. The manifest now holds only printable ASCII plus the
// escaped approver name.
func TestWrite_ManifestNeverCarriesSuspiciousCharacters(t *testing.T) {
	dir := t.TempDir()
	name := "safe\u009b2J\u202e\u200b" + string(rune(0xE0069)) + "x"
	tool := mkTool(t, "srv", name, "d")
	tool.ApprovedBy = "eve\u202e <x>"
	mustWrite(t, dir, tool)
	raw := readFile(t, filepath.Join(dir, manifestName))
	for i := 0; i < len(raw); i++ {
		if c := raw[i]; (c < 0x20 || c > 0x7e) && c != '\n' {
			t.Fatalf("manifest byte %d is 0x%02X, not printable ASCII:\n%s", i, c, raw)
		}
	}
	if fs := textdiff.Findings(raw); fs != nil {
		t.Fatalf("manifest carries a suspicious rune %+v", fs[0])
	}
	doc := readManifest(t, dir)
	wantTool := "safe%C2%9B2J%E2%80%AE%E2%80%8B%F3%A0%81%A9x"
	if doc.Tools[0].Tool != wantTool || doc.Tools[0].File != "srv/"+wantTool+".json" || doc.Tools[0].Server != "srv" {
		t.Fatalf("entry = %+v", doc.Tools[0])
	}
	if doc.Tools[0].ApprovedBy != `eve\u{202E} <x>` {
		t.Fatalf("approved_by = %q, want the escaped name", doc.Tools[0].ApprovedBy)
	}
	if _, err := os.Stat(filepath.Join(dir, "srv", wantTool+".json")); err != nil {
		t.Fatal(err)
	}
}

func TestParseManifest_AcceptsItsOwnOutputAndRejectsForgeries(t *testing.T) {
	planned, _, err := planAll([]Tool{mkTool(t, "s", "a.b", "1"), mkTool(t, "t", "x", "2")})
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{statusComplete, statusPending} {
		raw, err := renderManifest(planEntries(planned), status, testOpts)
		if err != nil {
			t.Fatal(err)
		}
		doc, ok := parseManifest(raw)
		if !ok || doc.Status != status || !reflect.DeepEqual(doc.files(), []string{"s/a%2Eb.json", "t/x.json"}) {
			t.Fatalf("own %s manifest rejected or misread: %v %+v", status, ok, doc)
		}
	}
	bad := map[string]string{
		"version 1":       `{"version":1,"status":"complete","tools":[]}`,
		"no status":       `{"version":2,"tools":[]}`,
		"other status":    `{"version":2,"status":"final","tools":[]}`,
		"raw name":        `{"version":2,"status":"complete","tools":[{"server":"s","tool":"a.b","file":"s/a.b.json"}]}`,
		"traversal":       `{"version":2,"status":"complete","tools":[{"server":"s","tool":"x","file":"../x.json"}]}`,
		"mismatched file": `{"version":2,"status":"complete","tools":[{"server":"s","tool":"x","file":"s/y.json"}]}`,
		"lower hex":       `{"version":2,"status":"complete","tools":[{"server":"s","tool":"a%2eb","file":"s/a%2eb.json"}]}`,
		"duplicate":       `{"version":2,"status":"complete","tools":[{"server":"s","tool":"x","file":"s/x.json"},{"server":"s","tool":"x","file":"s/x.json"}]}`,
		"empty server":    `{"version":2,"status":"complete","tools":[{"server":"","tool":"x","file":"/x.json"}]}`,
		"not an object":   `[]`,
		"garbage":         `{{{`,
	}
	for label, raw := range bad {
		if doc, ok := parseManifest([]byte(raw)); ok {
			t.Errorf("%s: accepted %+v", label, doc)
		}
	}
	if doc, ok := parseManifest([]byte(`{"version":2,"status":"complete","tools":[]}`)); !ok || len(doc.Tools) != 0 {
		t.Fatalf("an empty complete manifest is valid: %v %+v", ok, doc)
	}
}

func TestUnionEntries_KeepsPreviousFilesThePlanDoesNotClaim(t *testing.T) {
	planned, _, err := planAll([]Tool{mkTool(t, "s", "keep", "2"), mkTool(t, "s", "new", "1")})
	if err != nil {
		t.Fatal(err)
	}
	prev := []manifestEntry{
		{Server: "s", Tool: "keep", File: "s/keep.json", Digest: "old"},
		{Server: "s", Tool: "gone", File: "s/gone.json", Digest: "old"},
	}
	got := unionEntries(prev, planned)
	var files []string
	for _, e := range got {
		files = append(files, e.File)
	}
	if !reflect.DeepEqual(files, []string{"s/keep.json", "s/new.json", "s/gone.json"}) {
		t.Fatalf("union files = %v", files)
	}
	if got[0].Digest == "old" {
		t.Fatal("a file the plan claims must carry the plan's entry, not the previous one")
	}
}
