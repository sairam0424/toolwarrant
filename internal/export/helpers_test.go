package export

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fixedTime is a non-UTC instant so tests prove the manifest converts to UTC.
var fixedTime = time.Date(2026, 10, 7, 14, 30, 5, 0, time.FixedZone("CEST", 2*60*60))

// mkTool builds a Tool whose Canonical bytes and Digest agree. body varies the
// content so tests can produce "the definition changed" cases.
func mkTool(t testing.TB, server, name, body string) Tool {
	t.Helper()
	canon, err := json.Marshal(map[string]string{"description": body, "name": name})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canon)
	return Tool{
		Server:     server,
		Name:       name,
		Digest:     hex.EncodeToString(sum[:]),
		Canonical:  canon,
		ApprovedBy: "alice@example.com",
		ApprovedAt: fixedTime,
		VersionNo:  1,
	}
}

// entry is one file or directory in a tree snapshot.
type entry struct {
	Mode    fs.FileMode
	Content string
	ModTime time.Time
}

// snapshot records every path under dir (without following symlinks) with its
// mode and content, so tests can assert byte-identical directories.
func snapshot(t testing.TB, dir string) map[string]entry {
	t.Helper()
	out := map[string]entry{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		e := entry{Mode: info.Mode(), ModTime: info.ModTime()}
		if info.Mode().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			e.Content = string(b)
		}
		out[rel] = e
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot %s: %v", dir, err)
	}
	return out
}

// names lists the relative paths of a snapshot, for compact assertions.
func names(s map[string]entry) []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	return out
}

// readFile fails the test if the file cannot be read.
func readFile(t testing.TB, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// writeFile creates p, and its directory, with content.
func writeFile(t testing.TB, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// mustWrite runs Write and fails the test on error.
func mustWrite(t testing.TB, dir string, tools ...Tool) Report {
	t.Helper()
	rep, err := Write(dir, tools)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	return rep
}

// wantReport compares the counts of rep with the expected ones and requires
// that nothing was skipped. Report holds a slice, so == cannot compare it.
func wantReport(t testing.TB, rep Report, written, removed, unchanged int) {
	t.Helper()
	if rep.Written != written || rep.Removed != removed || rep.Unchanged != unchanged || len(rep.Skipped) != 0 {
		t.Fatalf("report = %+v, want written=%d removed=%d unchanged=%d and nothing skipped", rep, written, removed, unchanged)
	}
}

// readManifest parses MANIFEST.json in dir with the package's own parser.
func readManifest(t testing.TB, dir string) manifestDoc {
	t.Helper()
	doc, ok := parseManifest([]byte(readFile(t, filepath.Join(dir, manifestName))))
	if !ok {
		t.Fatalf("MANIFEST.json in %s does not parse", dir)
	}
	return doc
}

// appendGitConfig appends text to dir/.git/config, the way an operator or an
// attacker with write access to the repository would.
func appendGitConfig(t testing.TB, dir, text string) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(dir, gitDirName, "config"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(text); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// skipIfRoot skips permission-based tests when the process can ignore modes.
func skipIfRoot(t testing.TB) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("SKIP: running as root, file modes do not restrict writes")
	}
}

// lockDir makes dir read-only for the rest of the test and restores it on
// cleanup so t.TempDir can delete it.
func lockDir(t testing.TB, dir string) {
	t.Helper()
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
}
