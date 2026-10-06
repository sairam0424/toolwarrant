package export

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// withDigest returns a Tool whose Digest matches raw, so only the property
// under test (validity, size) can make it fail.
func withDigest(t testing.TB, raw []byte) Tool {
	t.Helper()
	sum := sha256.Sum256(raw)
	return Tool{Server: "s", Name: "bad", Digest: hex.EncodeToString(sum[:]), Canonical: raw}
}

func TestWrite_StaleRemovalIsLimitedToManifestFiles(t *testing.T) {
	dir := t.TempDir()
	keep := mkTool(t, "s", "keep", "1")
	gone := mkTool(t, "s", "gone", "1")
	lone := mkTool(t, "solo", "only", "1")
	mustWrite(t, dir, keep, gone, lone)

	for _, f := range []string{filepath.Join(dir, "s", "notes.txt"), filepath.Join(dir, "README.md"), filepath.Join(dir, "solo", "mine.json")} {
		writeFile(t, f, "user")
	}
	if err := os.Mkdir(filepath.Join(dir, "userdir"), 0o755); err != nil {
		t.Fatal(err)
	}

	rep := mustWrite(t, dir, keep)
	wantReport(t, rep, 0, 2, 1)
	snap := snapshot(t, dir)
	for _, p := range []string{"s/keep.json", "s/notes.txt", "README.md", "solo/mine.json", "userdir"} {
		if _, ok := snap[p]; !ok {
			t.Errorf("%s must survive", p)
		}
	}
	for _, p := range []string{"s/gone.json", "solo/only.json"} {
		if _, ok := snap[p]; ok {
			t.Errorf("%s must be removed", p)
		}
	}
}

func TestWrite_EmptiedServerDirectoryIsRemoved(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, dir, mkTool(t, "a", "x", "1"), mkTool(t, "b", "y", "1"))
	mustWrite(t, dir, mkTool(t, "a", "x", "1"))
	if _, err := os.Stat(filepath.Join(dir, "b")); !os.IsNotExist(err) {
		t.Fatalf("empty server directory b should be gone: %v", err)
	}
}

func TestWrite_UntrustedPreviousManifestDeletesNothing(t *testing.T) {
	victimName := "victim.txt"
	head := `{"version":2,"status":"complete","tools":[`
	cases := map[string]string{
		"not json":                  "{{{",
		"old version":               `{"version":1,"tools":[{"server":"s","tool":"old","file":"s/old.json"}]}`,
		"unknown status":            `{"version":2,"status":"done","tools":[{"server":"s","tool":"old","file":"s/old.json"}]}`,
		"path traversal":            head + `{"server":"s","tool":"old","file":"../` + victimName + `"}]}`,
		"file does not match names": head + `{"server":"s","tool":"old","file":"s/other.json"},{"server":"s","tool":"old","file":"s/old.json"}]}`,
		"unencoded dot in server":   head + `{"server":"..","tool":"x","file":"../x.json"}]}`,
		"lower-case hex escape":     head + `{"server":"s","tool":"a%2eb","file":"s/a%2eb.json"}]}`,
		"needless escape":           head + `{"server":"s","tool":"%6Fld","file":"s/%6Fld.json"}]}`,
		"duplicate entries":         head + `{"server":"s","tool":"old","file":"s/old.json"},{"server":"s","tool":"old","file":"s/old.json"}]}`,
		"oversized":                 strings.Repeat(" ", maxManifestBytes+1),
	}
	for label, body := range cases {
		dir := t.TempDir()
		old := mkTool(t, "s", "old", "1")
		mustWrite(t, dir, old)
		victim := filepath.Join(filepath.Dir(dir), victimName)
		writeFile(t, victim, "v")
		writeFile(t, filepath.Join(dir, manifestName), body)
		mustWrite(t, dir, mkTool(t, "s", "new", "1"))
		if _, err := os.Stat(filepath.Join(dir, "s", "old.json")); err != nil {
			t.Errorf("%s: untrusted manifest must not cause deletions: %v", label, err)
		}
		if readFile(t, victim) != "v" {
			t.Errorf("%s: file outside dir was touched", label)
		}
		if err := os.Remove(victim); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWrite_StaleEntryThatIsNowASymlinkOrDirectoryIsNotFollowed(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.txt")
	writeFile(t, outside, "outside")
	mustWrite(t, dir, mkTool(t, "s", "link", "1"), mkTool(t, "d", "dir", "1"), mkTool(t, "s", "keep", "1"))
	link := filepath.Join(dir, "s", "link.json")
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	dirTarget := filepath.Join(dir, "d", "dir.json")
	if err := os.Remove(dirTarget); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dirTarget, 0o755); err != nil {
		t.Fatal(err)
	}

	rep := mustWrite(t, dir, mkTool(t, "s", "keep", "1"))
	if rep.Removed != 0 {
		t.Fatalf("report = %+v, nothing removable", rep)
	}
	if readFile(t, outside) != "outside" {
		t.Fatal("symlink target was modified")
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the symlink itself must be left alone: %v", err)
	}
}

func TestWrite_StaleServerDirectorySymlinkIsNotFollowed(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, dir, mkTool(t, "s", "old", "1"), mkTool(t, "k", "keep", "1"))
	outsideDir := t.TempDir()
	writeFile(t, filepath.Join(outsideDir, "old.json"), "outside")
	if err := os.RemoveAll(filepath.Join(dir, "s")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideDir, filepath.Join(dir, "s")); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, dir, mkTool(t, "k", "keep", "1"))
	if readFile(t, filepath.Join(outsideDir, "old.json")) != "outside" {
		t.Fatal("stale removal followed a directory symlink")
	}
}

func TestPlanActions_CaseInsensitiveKeepSet(t *testing.T) {
	dir := t.TempDir()
	root, err := openExportRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	writeFile(t, filepath.Join(dir, "Srv", "Tool.json"), "x")
	prev := manifestDoc{Version: manifestVersion, Status: statusComplete, Tools: []manifestEntry{{Server: "Srv", Tool: "Tool", File: "Srv/Tool.json"}}}
	planned := []plannedTool{{dirName: "srv", encTool: "tool", rel: "srv/tool.json", data: []byte("y")}}
	act, err := planActions(root, prev, planned)
	if err != nil {
		t.Fatal(err)
	}
	if len(act.remove) != 0 {
		t.Fatalf("a case-variant of a wanted file must not be deleted: %+v", act)
	}
}

func TestWrite_SymlinkRefusals(t *testing.T) {
	outside := t.TempDir()
	victim := filepath.Join(outside, "victim.json")
	writeFile(t, victim, "victim")
	tool := mkTool(t, "s", "t", "1")

	t.Run("export dir is a symlink", func(t *testing.T) {
		link := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(outside, link); err != nil {
			t.Fatal(err)
		}
		if _, err := Write(link, []Tool{tool}); err == nil {
			t.Fatal("want refusal")
		}
		if _, err := os.Stat(filepath.Join(outside, "MANIFEST.json")); !os.IsNotExist(err) {
			t.Fatal("wrote through a symlinked export dir")
		}
	})
	t.Run("export dir is a file", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "file")
		writeFile(t, f, "")
		if _, err := Write(f, []Tool{tool}); err == nil {
			t.Fatal("want refusal")
		}
	})
	t.Run("server dir is a symlink", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Symlink(outside, filepath.Join(dir, "s")); err != nil {
			t.Fatal(err)
		}
		if _, err := Write(dir, []Tool{tool}); err == nil {
			t.Fatal("want refusal")
		}
		if _, err := os.Stat(filepath.Join(outside, "t.json")); !os.IsNotExist(err) {
			t.Fatal("wrote through a symlinked server dir")
		}
		if _, err := os.Stat(filepath.Join(dir, manifestName)); !os.IsNotExist(err) {
			t.Fatal("a refused layout must not get a pending manifest")
		}
	})
	t.Run("server path is a file", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "s"), "")
		if _, err := Write(dir, []Tool{tool}); err == nil {
			t.Fatal("want refusal")
		}
	})
	t.Run("tool file is a symlink", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "s"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(victim, filepath.Join(dir, "s", "t.json")); err != nil {
			t.Fatal(err)
		}
		if _, err := Write(dir, []Tool{tool}); err == nil {
			t.Fatal("want refusal")
		}
		if readFile(t, victim) != "victim" {
			t.Fatal("wrote through a symlinked tool file")
		}
	})
	t.Run("tool file is a directory", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "s", "t.json"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := Write(dir, []Tool{tool}); err == nil {
			t.Fatal("want refusal")
		}
	})
	t.Run("manifest is a symlink", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Symlink(victim, filepath.Join(dir, manifestName)); err != nil {
			t.Fatal(err)
		}
		if _, err := Write(dir, []Tool{tool}); err == nil {
			t.Fatal("want refusal")
		}
		if readFile(t, victim) != "victim" {
			t.Fatal("wrote through a symlinked manifest")
		}
	})
}

// Simulated failure: a read-only server directory makes the temp file
// impossible to create. The old file must be intact, nothing partial or
// temporary may be visible, and the pending manifest, written before the
// attempt, still lists the file so a retry can finish.
func TestWrite_FailureLeavesNoPartialFileAndAPendingManifest(t *testing.T) {
	skipIfRoot(t)
	dir := t.TempDir()
	v1 := mkTool(t, "s", "t", "version one")
	mustWrite(t, dir, v1)
	lockDir(t, filepath.Join(dir, "s"))

	v2 := mkTool(t, "s", "t", "version two, longer")
	if _, err := Write(dir, []Tool{v2}); err == nil {
		t.Fatal("want an error from the read-only directory")
	}
	if err := os.Chmod(filepath.Join(dir, "s"), 0o755); err != nil {
		t.Fatal(err)
	}
	snap := snapshot(t, dir)
	if snap["s/t.json"].Content != string(v1.Canonical)+"\n" {
		t.Fatal("old file content was damaged")
	}
	for p := range snap {
		if strings.Contains(p, tmpPrefix) {
			t.Fatalf("temporary file left behind: %s", p)
		}
	}
	if doc := readManifest(t, dir); doc.Status != statusPending || !reflect.DeepEqual(doc.files(), []string{"s/t.json"}) {
		t.Fatalf("manifest after the failure = %+v, want pending and listing s/t.json", doc)
	}
	rep := mustWrite(t, dir, v2)
	wantReport(t, rep, 1, 0, 0)
	if doc := readManifest(t, dir); doc.Status != statusComplete {
		t.Fatalf("the retry must complete the manifest, got %q", doc.Status)
	}
}

func TestWrite_FailureCreatingServerDirectoryLeavesNothing(t *testing.T) {
	skipIfRoot(t)
	dir := t.TempDir()
	lockDir(t, dir)
	if _, err := Write(dir, []Tool{mkTool(t, "s", "t", "1")}); err == nil {
		t.Fatal("want an error from the read-only export directory")
	}
	if got := snapshot(t, dir); len(got) != 1 {
		t.Fatalf("export dir must stay empty, has %v", names(got))
	}
}

// A stale file that cannot be removed stays listed in the pending manifest, so
// it is never orphaned; the next Write removes it.
func TestWrite_RemovalFailureKeepsThePendingManifest(t *testing.T) {
	skipIfRoot(t)
	dir := t.TempDir()
	mustWrite(t, dir, mkTool(t, "s", "gone", "1"), mkTool(t, "k", "keep", "1"))
	lockDir(t, filepath.Join(dir, "s"))

	if _, err := Write(dir, []Tool{mkTool(t, "k", "keep", "1")}); err == nil {
		t.Fatal("want an error when a stale file cannot be removed")
	}
	if doc := readManifest(t, dir); doc.Status != statusPending || !slices.Contains(doc.files(), "s/gone.json") {
		t.Fatalf("manifest after the failure = %+v, want pending and still listing s/gone.json", doc)
	}
	if err := os.Chmod(filepath.Join(dir, "s"), 0o755); err != nil {
		t.Fatal(err)
	}
	rep := mustWrite(t, dir, mkTool(t, "k", "keep", "1"))
	wantReport(t, rep, 0, 1, 1)
	if _, err := os.Stat(filepath.Join(dir, "s", "gone.json")); !os.IsNotExist(err) {
		t.Fatal("the retry must remove the stale file")
	}
	if doc := readManifest(t, dir); doc.Status != statusComplete || !reflect.DeepEqual(doc.files(), []string{"k/keep.json"}) {
		t.Fatalf("manifest after the retry = %+v", doc)
	}
}

func TestWriteAtomic_TempFileNamesNeverCollideWithExports(t *testing.T) {
	for _, n := range []string{"a", ".", "..", ".hidden", ".tmp-x"} {
		enc, err := encodeName("tool", n)
		if err != nil || strings.HasPrefix(enc, ".") {
			t.Fatalf("encoded %q = %q (%v) could collide with %q temp files", n, enc, err, tmpPrefix)
		}
	}
}

func TestWrite_DirectoryTargetAndExistingUserFileAtToolPath(t *testing.T) {
	// A plain user file at a tool path is replaced only via atomic rename and
	// counted as written; here it already has identical bytes.
	dir := t.TempDir()
	tool := mkTool(t, "s", "t", "1")
	writeFile(t, filepath.Join(dir, "s", "t.json"), string(tool.Canonical)+"\n")
	rep := mustWrite(t, dir, tool)
	wantReport(t, rep, 0, 0, 1)
}
