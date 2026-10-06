package export

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
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

	userFile := filepath.Join(dir, "s", "notes.txt")
	topFile := filepath.Join(dir, "README.md")
	soloUser := filepath.Join(dir, "solo", "mine.json")
	for _, f := range []string{userFile, topFile, soloUser} {
		if err := os.WriteFile(f, []byte("user"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	userDir := filepath.Join(dir, "userdir")
	if err := os.Mkdir(userDir, 0o755); err != nil {
		t.Fatal(err)
	}

	rep := mustWrite(t, dir, keep)
	if rep != (Report{Unchanged: 1, Removed: 2}) {
		t.Fatalf("report = %+v", rep)
	}
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
	cases := map[string]func(dir string) string{
		"not json": func(string) string { return "{{{" },
		"wrong version": func(string) string {
			return `{"version":2,"tools":[{"server":"s","tool":"old","file":"s/old.json"}]}`
		},
		"path traversal": func(string) string {
			return `{"version":1,"tools":[{"server":"s","tool":"old","file":"../` + victimName + `"}]}`
		},
		"file does not match names": func(string) string {
			return `{"version":1,"tools":[{"server":"s","tool":"old","file":"s/other.json"},{"server":"s","tool":"old","file":"s/old.json"}]}`
		},
		"unencoded dot": func(string) string {
			return `{"version":1,"tools":[{"server":"..","tool":"x","file":"../x.json"}]}`
		},
		"duplicate entries": func(string) string {
			return `{"version":1,"tools":[{"server":"s","tool":"old","file":"s/old.json"},{"server":"s","tool":"old","file":"s/old.json"}]}`
		},
		"oversized": func(string) string { return strings.Repeat(" ", maxManifestBytes+1) },
	}
	for label, body := range cases {
		dir := t.TempDir()
		old := mkTool(t, "s", "old", "1")
		mustWrite(t, dir, old)
		victim := filepath.Join(filepath.Dir(dir), victimName)
		if err := os.WriteFile(victim, []byte("v"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, manifestName), []byte(body(dir)), 0o644); err != nil {
			t.Fatal(err)
		}
		mustWrite(t, dir, mkTool(t, "s", "new", "1"))
		if _, err := os.Stat(filepath.Join(dir, "s", "old.json")); err != nil {
			t.Errorf("%s: untrusted manifest must not cause deletions: %v", label, err)
		}
		if readFile(t, victim) != "v" {
			t.Errorf("%s: file outside dir was touched", label)
		}
		os.Remove(victim)
	}
}

func TestWrite_StaleEntryThatIsNowASymlinkOrDirectoryIsNotFollowed(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
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
	if err := os.WriteFile(filepath.Join(outsideDir, "old.json"), []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
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

func TestRemoveUnwanted_CaseInsensitiveKeepSet(t *testing.T) {
	dir := t.TempDir()
	root, err := openExportRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.MkdirAll(filepath.Join(dir, "Srv"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Srv", "Tool.json"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	var rep Report
	planned := []plannedTool{{rel: "srv/tool.json"}}
	if err := removeUnwanted(root, []string{"Srv/Tool.json"}, planned, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Removed != 0 {
		t.Fatalf("a case-variant of a wanted file must not be deleted: %+v", rep)
	}
}

func TestWrite_SymlinkRefusals(t *testing.T) {
	outside := t.TempDir()
	victim := filepath.Join(outside, "victim.json")
	if err := os.WriteFile(victim, []byte("victim"), 0o644); err != nil {
		t.Fatal(err)
	}
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
		if err := os.WriteFile(f, nil, 0o644); err != nil {
			t.Fatal(err)
		}
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
	})
	t.Run("server path is a file", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "s"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
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
// impossible to create. The old file must be intact and nothing partial or
// temporary may be visible.
func TestWrite_FailureLeavesNoPartialFile(t *testing.T) {
	skipIfRoot(t)
	dir := t.TempDir()
	v1 := mkTool(t, "s", "t", "version one")
	mustWrite(t, dir, v1)
	before := snapshot(t, dir)
	lockDir(t, filepath.Join(dir, "s"))

	if _, err := Write(dir, []Tool{mkTool(t, "s", "t", "version two, longer")}); err == nil {
		t.Fatal("want an error from the read-only directory")
	}
	if err := os.Chmod(filepath.Join(dir, "s"), 0o755); err != nil {
		t.Fatal(err)
	}
	after := snapshot(t, dir)
	if !reflectEqualContent(before, after) {
		t.Fatalf("state changed after failed write:\nbefore %v\nafter  %v", names(before), names(after))
	}
	if after["s/t.json"].Content != string(v1.Canonical)+"\n" {
		t.Fatal("old file content was damaged")
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

func TestWrite_RemovalFailureIsReportedAndManifestIsKept(t *testing.T) {
	skipIfRoot(t)
	dir := t.TempDir()
	mustWrite(t, dir, mkTool(t, "s", "gone", "1"), mkTool(t, "k", "keep", "1"))
	oldManifest := readFile(t, filepath.Join(dir, manifestName))
	lockDir(t, filepath.Join(dir, "s"))

	_, err := Write(dir, []Tool{mkTool(t, "k", "keep", "1")})
	if err == nil {
		t.Fatal("want an error when a stale file cannot be removed")
	}
	if readFile(t, filepath.Join(dir, manifestName)) != oldManifest {
		t.Fatal("manifest must not advance past a failed removal, or the stale file is orphaned")
	}
}

// reflectEqualContent compares snapshots ignoring directory mod times, which
// legitimately move when a temp file is created and removed.
func reflectEqualContent(a, b map[string]entry) bool {
	if len(a) != len(b) {
		return false
	}
	for k, ea := range a {
		eb, ok := b[k]
		if !ok || ea.Mode != eb.Mode || ea.Content != eb.Content {
			return false
		}
	}
	return true
}

func TestWriteAtomic_TempFileNamesNeverCollideWithExports(t *testing.T) {
	for _, n := range []string{"a", ".", "..", ".hidden"} {
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
	if err := os.Mkdir(filepath.Join(dir, "s"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "s", "t.json"), append(append([]byte{}, tool.Canonical...), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if rep := mustWrite(t, dir, tool); rep.Unchanged != 1 || rep.Written != 0 {
		t.Fatalf("identical pre-existing file should be unchanged: %+v", rep)
	}
}
