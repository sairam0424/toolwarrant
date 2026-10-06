package export

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// headExists reports whether dir has at least one commit.
func headExists(t testing.TB, dir string) bool {
	t.Helper()
	cmd := exec.Command("git", "rev-parse", "--verify", "-q", "HEAD")
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"}
	return cmd.Run() == nil
}

// wantRefused runs Commit and requires an error naming want, with no commit
// made and the previous commit count unchanged.
func wantRefused(t testing.TB, dir, want string, commitsBefore int) {
	t.Helper()
	ok, err := Commit(context.Background(), dir, "approvals", alice)
	if err == nil || ok {
		t.Fatalf("Commit = %v, %v; want a refusal", ok, err)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q does not mention %q", err, want)
	}
	if commitsBefore == 0 {
		if headExists(t, dir) {
			t.Fatal("a refused Commit must not create a commit")
		}
		return
	}
	if got := commitCount(t, dir); got != commitsBefore {
		t.Fatalf("commits = %d, want %d", got, commitsBefore)
	}
}

// `git add -A` honours ignore rules, so a *.json pattern in .gitignore or
// .git/info/exclude used to drop every snapshot and MANIFEST.json from the
// commit while Commit returned committed=true. It now verifies the index.
func TestCommit_RefusesWhenAnIgnoreRuleDropsSnapshots(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".gitignore"), "*.json\n")
	mustWrite(t, dir, mkTool(t, "s", "one", "v1"))
	wantRefused(t, dir, "ignore rule", 0)

	dir2 := t.TempDir()
	mustWrite(t, dir2, mkTool(t, "s", "one", "v1"))
	mustCommit(t, dir2, "init")
	writeFile(t, filepath.Join(dir2, ".git", "info", "exclude"), "*.json\n")
	mustWrite(t, dir2, mkTool(t, "s", "one", "v2"), mkTool(t, "s", "two", "v1"))
	wantRefused(t, dir2, "ignore rule", 1)
	if got := git(t, dir2, "show", "HEAD:s/one.json"); !strings.Contains(got, "v1") {
		t.Fatalf("history moved past the refusal: %q", got)
	}

	// An ignore rule that matches nothing of ours is fine.
	dir3 := t.TempDir()
	writeFile(t, filepath.Join(dir3, ".gitignore"), "*.log\n")
	mustWrite(t, dir3, mkTool(t, "s", "one", "v1"))
	if !mustCommit(t, dir3, "ok") {
		t.Fatal("want a commit")
	}
}

// .git/config is read before every git command. Keys outside core, user,
// commit and init can run programs or point the repository elsewhere, so
// Commit refuses them instead of hoping a -c flag covers each one.
func TestCommit_RefusesRepositoryConfigOutsideTheAllowList(t *testing.T) {
	requireGit(t)
	elsewhere := t.TempDir()
	writeFile(t, filepath.Join(elsewhere, "secret.txt"), "s3cr3t")
	cases := map[string]string{
		"external diff":             "\n[diff]\n\texternal = /bin/echo\n\ttrustExitCode = true\n",
		"clean filter":              "\n[filter \"evil\"]\n\tclean = /bin/cat\n",
		"include":                   "\n[include]\n\tpath = /dev/null\n",
		"core.worktree":             "\n[core]\n\tworktree = " + elsewhere + "\n",
		"core.bare":                 "\n[core]\n\tbare = true\n",
		"core.sshCommand":           "\n[core]\n\tsshCommand = /bin/echo\n",
		"remote (outside the list)": "\n[remote \"origin\"]\n\turl = https://example.invalid/x.git\n",
		"extensions.worktreeConfig": "\n[extensions]\n\tworktreeConfig = true\n",
	}
	for label, cfg := range cases {
		t.Run(label, func(t *testing.T) {
			dir := t.TempDir()
			mustWrite(t, dir, mkTool(t, "s", "one", "v1"))
			mustCommit(t, dir, "init")
			appendGitConfig(t, dir, cfg)
			mustWrite(t, dir, mkTool(t, "s", "one", "v2"))
			wantRefused(t, dir, "refusing to use .git/config", 1)
			if got := git(t, dir, "ls-files"); strings.Contains(got, "secret.txt") {
				t.Fatalf("a foreign tree was staged: %q", got)
			}
		})
	}
}

// The reviewer's clean-filter attack: with the filter configured, the blob git
// stored read TAMPERED while the file on disk kept the approved bytes. The
// script must never run and the history must not move.
func TestCommit_CleanFilterNeverRunsAndHistoryIsIntact(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	mustWrite(t, dir, mkTool(t, "s", "one", "v1"))
	mustCommit(t, dir, "init")
	marker := filepath.Join(t.TempDir(), "marker")
	script := filepath.Join(t.TempDir(), "clean.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho ran >> "+marker+"\nsed 's/v2/TAMPERED/'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, ".gitattributes"), "*.json filter=evil\n")
	appendGitConfig(t, dir, "\n[filter \"evil\"]\n\tclean = "+script+"\n")
	mustWrite(t, dir, mkTool(t, "s", "one", "v2"))

	ok, err := Commit(context.Background(), dir, "second", alice)
	if err == nil || ok {
		t.Fatalf("Commit = %v, %v; want a refusal", ok, err)
	}
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatal("the clean filter ran")
	}
	if got := git(t, dir, "show", "HEAD:s/one.json"); !strings.Contains(got, "v1") || strings.Contains(got, "TAMPERED") {
		t.Fatalf("committed blob = %q", got)
	}
	if got := commitCount(t, dir); got != 1 {
		t.Fatalf("commits = %d", got)
	}
}

// Attributes rewrite bytes on the way into git (filters, ident, encodings).
// This package never writes an attributes file, so any one present is refused.
func TestCommit_RefusesAttributesFiles(t *testing.T) {
	requireGit(t)
	cases := map[string]string{
		"top-level .gitattributes":    ".gitattributes",
		"server-level .gitattributes": filepath.Join("s", ".gitattributes"),
		"upper-case spelling":         ".GITATTRIBUTES",
		".git/info/attributes":        filepath.Join(".git", "info", "attributes"),
	}
	for label, rel := range cases {
		t.Run(label, func(t *testing.T) {
			dir := t.TempDir()
			mustWrite(t, dir, mkTool(t, "s", "one", "v1"))
			mustCommit(t, dir, "init")
			writeFile(t, filepath.Join(dir, rel), "*.json ident\n")
			mustWrite(t, dir, mkTool(t, "s", "one", "v2"))
			wantRefused(t, dir, "attributes", 1)
		})
	}
}

// Commit verifies the export files from MANIFEST.json, so it needs a complete
// one: without it there is nothing whose presence in the commit can be
// checked, and a pending one would record a half-finished export.
func TestCommit_RefusesWithoutACompleteManifest(t *testing.T) {
	requireGit(t)
	t.Run("no manifest", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "notes.txt"), "x")
		wantRefused(t, dir, "MANIFEST.json not found", 0)
		if _, err := os.Stat(filepath.Join(dir, ".git")); !os.IsNotExist(err) {
			t.Fatal("nothing must be initialised without a manifest")
		}
	})
	t.Run("pending manifest", func(t *testing.T) {
		dir := t.TempDir()
		mustWrite(t, dir, mkTool(t, "s", "one", "v1"))
		mustCommit(t, dir, "init")
		complete := readFile(t, filepath.Join(dir, manifestName))
		writeFile(t, filepath.Join(dir, manifestName), strings.Replace(complete, `"status": "complete"`, `"status": "pending"`, 1))
		wantRefused(t, dir, "pending", 1)
	})
	t.Run("corrupt manifest", func(t *testing.T) {
		dir := t.TempDir()
		mustWrite(t, dir, mkTool(t, "s", "one", "v1"))
		writeFile(t, filepath.Join(dir, manifestName), "{{{")
		wantRefused(t, dir, "not a manifest", 0)
	})
}

func TestCheckConfigList_Table(t *testing.T) {
	ok := []string{
		"",
		"core.repositoryformatversion\n0\x00core.filemode\ntrue\x00core.bare\nfalse\x00core.logallrefupdates\ntrue\x00core.ignorecase\ntrue\x00core.precomposeunicode\ntrue\x00",
		"user.name\nA\x00user.email\na@b\x00commit.gpgsign\ntrue\x00init.defaultbranch\nmain\x00",
		"core.hookspath\n/x\x00core.fsmonitor\n/y\x00core.editor\nvim\x00",
		"core.bare\n False \x00",
	}
	for _, list := range ok {
		if err := checkConfigList(list); err != nil {
			t.Errorf("checkConfigList(%q) = %v, want nil", list, err)
		}
	}
	bad := map[string]string{
		"diff.external":           "diff.external\n/x\x00",
		"filter with subsection":  "filter.Evil.clean\ncat\x00",
		"core.worktree":           "core.worktree\n/x\x00",
		"core.bare true":          "core.bare\ntrue\x00",
		"core.bare without value": "core.bare\x00",
		"include.path":            "include.path\n/x\x00",
		"includeIf":               "includeif.gitdir:/x.path\n/y\x00",
		"core.sshcommand":         "core.sshcommand\nx\x00",
		"remote":                  "remote.origin.url\nx\x00",
		"extensions":              "extensions.worktreeconfig\ntrue\x00",
		"mixed case":              "Core.WorkTree\n/x\x00",
		"after allowed keys":      "user.name\nA\x00gc.auto\n0\x00",
	}
	for label, list := range bad {
		if err := checkConfigList(list); err == nil {
			t.Errorf("%s: checkConfigList(%q) = nil, want an error", label, list)
		}
	}
}

func TestExportFiles_ListsManifestAndExistingSnapshots(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, dir, mkTool(t, "s", "one", "1"), mkTool(t, "t", "two", "2"))
	if err := os.Remove(filepath.Join(dir, "t", "two.json")); err != nil {
		t.Fatal(err)
	}
	got, err := exportFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{manifestName, "s/one.json"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("exportFiles = %v, want %v", got, want)
	}
}
