package export

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

var alice = Identity{Name: "Alice Approver", Email: "alice@example.com"}

// requireGit skips loudly when git is unavailable, so a green run on a machine
// without git cannot be mistaken for a run that exercised Commit.
func requireGit(t testing.TB) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skipf("SKIPPED LOUDLY: git binary not found, Commit is NOT being tested: %v", err)
	}
}

// git runs git in dir with a hermetic environment (independent of the code
// under test) and returns trimmed stdout.
func git(t testing.TB, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(),
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v in %s: %v\n%s", args, dir, err, out)
	}
	return strings.TrimSpace(string(out))
}

func commitCount(t testing.TB, dir string) int {
	t.Helper()
	n, err := strconv.Atoi(git(t, dir, "rev-list", "--count", "HEAD"))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func mustCommit(t testing.TB, dir, msg string) bool {
	t.Helper()
	ok, err := Commit(context.Background(), dir, msg, alice)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return ok
}

func TestCommit_FirstNoopAndChangedContent(t *testing.T) {
	requireGit(t)
	dir := filepath.Join(t.TempDir(), "approved")
	mustWrite(t, dir, mkTool(t, "s", "one", "v1"))

	if !mustCommit(t, dir, "export: initial approvals") {
		t.Fatal("first commit must report committed=true")
	}
	if got := commitCount(t, dir); got != 1 {
		t.Fatalf("commits = %d, want 1", got)
	}
	if got := git(t, dir, "log", "-1", "--format=%s"); got != "export: initial approvals" {
		t.Fatalf("subject = %q", got)
	}
	if got := git(t, dir, "ls-files"); got != "MANIFEST.json\ns/one.json" {
		t.Fatalf("tracked files = %q", got)
	}

	if mustCommit(t, dir, "export: nothing changed") {
		t.Fatal("a no-op commit must report committed=false")
	}
	if got := commitCount(t, dir); got != 1 {
		t.Fatalf("no-op created a commit: %d", got)
	}

	mustWrite(t, dir, mkTool(t, "s", "one", "v2"))
	if !mustCommit(t, dir, "export: v2") {
		t.Fatal("changed content must commit again")
	}
	if got := commitCount(t, dir); got != 2 {
		t.Fatalf("commits = %d, want 2", got)
	}
	if got := git(t, dir, "status", "--porcelain"); got != "" {
		t.Fatalf("worktree not clean after commit: %q", got)
	}
}

func TestCommit_RemovedToolIsCommittedAsDeletion(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	mustWrite(t, dir, mkTool(t, "s", "a", "1"), mkTool(t, "s", "b", "1"))
	mustCommit(t, dir, "one")
	mustWrite(t, dir, mkTool(t, "s", "a", "1"))
	if !mustCommit(t, dir, "two") {
		t.Fatal("deletion must commit")
	}
	if got := git(t, dir, "show", "--name-status", "--format=", "HEAD"); !strings.Contains(got, "D\ts/b.json") {
		t.Fatalf("deletion missing from commit: %q", got)
	}
}

func TestCommit_AppliesIdentityAndIgnoresAmbientEnvironment(t *testing.T) {
	requireGit(t)
	home := t.TempDir()
	cfg := "[user]\n\tname = Evil Global\n\temail = evil@example.com\n[commit]\n\tgpgsign = true\n[gpg]\n\tprogram = /nonexistent/gpg\n"
	if err := os.WriteFile(filepath.Join(home, ".gitconfig"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("GIT_AUTHOR_NAME", "Evil Env")
	t.Setenv("GIT_AUTHOR_EMAIL", "env@example.com")
	t.Setenv("GIT_COMMITTER_NAME", "Evil Env")
	t.Setenv("GIT_COMMITTER_EMAIL", "env@example.com")
	t.Setenv("GIT_DIR", filepath.Join(t.TempDir(), "elsewhere.git"))
	t.Setenv("GIT_WORK_TREE", t.TempDir())
	t.Setenv("GIT_INDEX_FILE", filepath.Join(t.TempDir(), "index"))

	dir := t.TempDir()
	mustWrite(t, dir, mkTool(t, "s", "one", "1"))
	who := Identity{Name: "-Dash Name", Email: "dash@example.com"}
	ok, err := Commit(context.Background(), dir, "-n --amend not flags", who)
	if err != nil || !ok {
		t.Fatalf("Commit = %v, %v", ok, err)
	}
	got := git(t, dir, "log", "-1", "--format=%an|%ae|%cn|%ce|%s")
	if want := "-Dash Name|dash@example.com|-Dash Name|dash@example.com|-n --amend not flags"; got != want {
		t.Fatalf("ident = %q, want %q", got, want)
	}
	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		t.Fatal("repository must live in dir, not where GIT_DIR pointed")
	}
}

func TestCommit_MultilineMessageIsPreserved(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	mustWrite(t, dir, mkTool(t, "s", "one", "1"))
	msg := "export: approvals\n\nWhy: weekly review\n# not a comment"
	mustCommit(t, dir, msg)
	if got := git(t, dir, "log", "-1", "--format=%B"); got != msg {
		t.Fatalf("message = %q, want %q", got, msg)
	}
}

func TestCommit_ParentRepositoryIsNotTouched(t *testing.T) {
	requireGit(t)
	parent := t.TempDir()
	git(t, parent, "init", "-q")
	git(t, parent, "-c", "user.name=p", "-c", "user.email=p@example.com", "commit", "-q", "--allow-empty", "-m", "parent")
	headBefore := git(t, parent, "rev-parse", "HEAD")

	dir := filepath.Join(parent, "exports")
	mustWrite(t, dir, mkTool(t, "s", "one", "1"))
	if !mustCommit(t, dir, "nested") {
		t.Fatal("want a commit in the nested repository")
	}

	if got := git(t, parent, "rev-parse", "HEAD"); got != headBefore {
		t.Fatalf("parent HEAD moved: %s -> %s", headBefore, got)
	}
	if got := git(t, parent, "ls-files"); got != "" {
		t.Fatalf("parent index was modified: %q", got)
	}
	if got := git(t, parent, "rev-list", "--count", "HEAD"); got != "1" {
		t.Fatalf("parent gained commits: %s", got)
	}
	if got := git(t, dir, "rev-parse", "--show-toplevel"); !sameDir(t, got, dir) {
		t.Fatalf("nested repository top level = %q, want %q", got, dir)
	}
	if got := commitCount(t, dir); got != 1 {
		t.Fatalf("nested commits = %d", got)
	}
}

func sameDir(t testing.TB, a, b string) bool {
	t.Helper()
	ra, errA := filepath.EvalSymlinks(a)
	rb, errB := filepath.EvalSymlinks(b)
	return errA == nil && errB == nil && ra == rb
}

func TestCommit_HooksAndRepoLocalProgramsAreNotExecuted(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	mustWrite(t, dir, mkTool(t, "s", "one", "1"))
	mustCommit(t, dir, "first")

	marker := filepath.Join(t.TempDir(), "marker")
	script := "#!/bin/sh\necho ran >> " + marker + "\nexit 0\n"
	hooksDir := filepath.Join(dir, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil { // init uses an empty template, so none exists yet
		t.Fatal(err)
	}
	for _, h := range []string{"pre-commit", "prepare-commit-msg", "commit-msg", "post-commit", "pre-auto-gc"} {
		if err := os.WriteFile(filepath.Join(hooksDir, h), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	otherHooks := filepath.Join(t.TempDir(), "hooks")
	if err := os.MkdirAll(otherHooks, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(otherHooks, "pre-commit"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	fsmon := filepath.Join(t.TempDir(), "fsmon.sh")
	if err := os.WriteFile(fsmon, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	local := "\n[core]\n\thooksPath = " + otherHooks + "\n\tfsmonitor = " + fsmon + "\n[commit]\n\tgpgsign = true\n"
	cfg, err := os.OpenFile(filepath.Join(dir, ".git", "config"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.WriteString(local); err != nil {
		t.Fatal(err)
	}
	cfg.Close()

	mustWrite(t, dir, mkTool(t, "s", "one", "2"))
	if !mustCommit(t, dir, "second") {
		t.Fatal("want a commit")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("a hook or repo-local program ran (marker exists): %v", err)
	}
	if got := commitCount(t, dir); got != 2 {
		t.Fatalf("commits = %d", got)
	}
}

func TestCommit_RejectsBadInputBeforeTouchingTheDirectory(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	mustWrite(t, dir, mkTool(t, "s", "one", "1"))
	long := strings.Repeat("x", maxIdentityBytes+1)
	cases := map[string]struct {
		msg string
		who Identity
	}{
		"empty message":      {"", alice},
		"blank message":      {" \n\t", alice},
		"NUL in message":     {"a\x00b", alice},
		"invalid utf-8 msg":  {"a\xffb", alice},
		"huge message":       {strings.Repeat("m", maxMessageBytes+1), alice},
		"empty name":         {"m", Identity{"", "a@b"}},
		"blank name":         {"m", Identity{"  ", "a@b"}},
		"empty email":        {"m", Identity{"A", ""}},
		"newline in name":    {"m", Identity{"A\nB", "a@b"}},
		"newline in email":   {"m", Identity{"A", "a@b\nc"}},
		"CR in name":         {"m", Identity{"A\rB", "a@b"}},
		"NUL in name":        {"m", Identity{"A\x00", "a@b"}},
		"angle in name":      {"m", Identity{"A <x@y>", "a@b"}},
		"angle in email":     {"m", Identity{"A", "<a@b>"}},
		"space in email":     {"m", Identity{"A", "a b@c"}},
		"too long name":      {"m", Identity{long, "a@b"}},
		"invalid utf-8 name": {"m", Identity{"A\xff", "a@b"}},
	}
	for label, c := range cases {
		ok, err := Commit(context.Background(), dir, c.msg, c.who)
		if err == nil || ok {
			t.Errorf("%s: want an error, got committed=%v err=%v", label, ok, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, ".git")); !os.IsNotExist(err) {
		t.Fatal("rejected input must not initialise a repository")
	}
}

func TestCommit_RefusesUnsafeDirectories(t *testing.T) {
	requireGit(t)
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	gitfile := filepath.Join(base, "gitfile")
	if err := os.Mkdir(gitfile, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitfile, ".git"), []byte("gitdir: "+real+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitlink := filepath.Join(base, "gitlink")
	if err := os.Mkdir(gitlink, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(gitlink, ".git")); err != nil {
		t.Fatal(err)
	}
	for label, d := range map[string]string{
		"empty":           "",
		"missing":         filepath.Join(base, "missing"),
		"symlink":         link,
		"regular file":    file,
		".git is a file":  gitfile,
		".git is symlink": gitlink,
	} {
		if ok, err := Commit(context.Background(), d, "m", alice); err == nil || ok {
			t.Errorf("%s: want refusal, got committed=%v err=%v", label, ok, err)
		}
	}
	if entries, _ := os.ReadDir(real); len(entries) != 0 {
		t.Fatalf("the redirect target was modified: %v", entries)
	}
}

func TestCommit_CancelledContextFails(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	mustWrite(t, dir, mkTool(t, "s", "one", "1"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if ok, err := Commit(ctx, dir, "m", alice); err == nil || ok {
		t.Fatalf("want an error from a cancelled context, got %v, %v", ok, err)
	}
}

func TestCommit_NeverPushesOrAddsRemotes(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	mustWrite(t, dir, mkTool(t, "s", "one", "1"))
	mustCommit(t, dir, "m")
	if got := git(t, dir, "remote"); got != "" {
		t.Fatalf("remotes configured: %q", got)
	}
}

func TestGitEnv_HasNoInheritedGitVariables(t *testing.T) {
	t.Setenv("GIT_DIR", "/evil")
	t.Setenv("GIT_SSH_COMMAND", "evil")
	t.Setenv("GIT_AUTHOR_NAME", "evil")
	t.Setenv("PATH", "/usr/bin:/bin")
	env := gitEnv("/tmp/home")
	allowed := map[string]string{"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0", "GIT_EDITOR": "true"}
	seen := map[string]bool{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		seen[k] = true
		if strings.HasPrefix(k, "GIT_") && allowed[k] != v {
			t.Errorf("unexpected or altered %s=%s", k, v)
		}
	}
	for _, k := range []string{"PATH", "HOME", "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL"} {
		if !seen[k] {
			t.Errorf("%s missing from the environment", k)
		}
	}
	t.Setenv("PATH", "")
	if !strings.Contains(strings.Join(gitEnv("/h"), "\n"), "PATH="+defaultPath) {
		t.Error("empty PATH must fall back to a default")
	}
}

func TestGitConfigFlags_DisableHooksAndSigning(t *testing.T) {
	joined := strings.Join(gitConfigFlags(alice), " ")
	for _, want := range []string{"core.hooksPath=/dev/null", "commit.gpgsign=false", "user.name=Alice Approver", "user.email=alice@example.com", "core.fsmonitor=false"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %s", want, joined)
		}
	}
}

func TestGitRunner_ErrorPaths(t *testing.T) {
	requireGit(t)
	bin, _ := exec.LookPath("git")
	home := t.TempDir()
	notRepo := t.TempDir()
	g := gitRunner{bin: bin, dir: notRepo, env: gitEnv(home), args: gitConfigFlags(alice)}
	ctx := context.Background()

	if _, err := g.run(ctx, "", "bogus-subcommand"); err == nil || !strings.Contains(err.Error(), "bogus-subcommand") {
		t.Fatalf("unknown subcommand must fail and name itself: %v", err)
	}
	if staged, err := g.hasStagedChanges(ctx); err == nil || staged {
		t.Fatalf("outside a repository hasStagedChanges must error, got %v, %v", staged, err)
	}
	if own, err := g.isOwnToplevel(ctx); err != nil || own {
		t.Fatalf("a non-repository is not an own top level: %v, %v", own, err)
	}

	missing := gitRunner{bin: filepath.Join(home, "no-such-git"), dir: notRepo, env: gitEnv(home)}
	if _, err := missing.isOwnToplevel(ctx); err == nil {
		t.Fatal("a git binary that cannot start must be an error, not 'not a repo'")
	}
	if _, err := missing.commitAll(ctx, "m"); err == nil {
		t.Fatal("commitAll must propagate the start failure")
	}
}

func TestGitRunner_TimeoutIsEnforced(t *testing.T) {
	if gitTimeout != 30*time.Second {
		t.Fatalf("gitTimeout = %v, the contract is 30s", gitTimeout)
	}
	sleeper, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep binary")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	g := gitRunner{bin: sleeper, dir: t.TempDir(), env: gitEnv(t.TempDir())}
	start := time.Now()
	if _, err := g.run(ctx, "", "5"); err == nil {
		t.Fatal("want the process to be killed")
	}
	if time.Since(start) > 4*time.Second {
		t.Fatal("process was not killed promptly")
	}
}

func TestCappedBufferAndSubcommand(t *testing.T) {
	var c cappedBuffer
	big := make([]byte, maxGitOutputBytes+100)
	n, err := c.Write(big)
	if err != nil || n != len(big) || c.buf.Len() != maxGitOutputBytes {
		t.Fatalf("Write = %d, %v, len %d", n, err, c.buf.Len())
	}
	if n, _ := c.Write([]byte("more")); n != 4 || c.buf.Len() != maxGitOutputBytes {
		t.Fatal("buffer must stay capped")
	}
	if got := subcommand([]string{"-c", "a=b", "init", "-q"}); got != "init" {
		t.Fatalf("subcommand = %q", got)
	}
	if got := subcommand(nil); got != "command" {
		t.Fatalf("subcommand(nil) = %q", got)
	}
}
