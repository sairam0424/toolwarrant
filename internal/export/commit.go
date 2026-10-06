package export

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	// gitTimeout bounds each git invocation; a hung hook-free git on a dead
	// network file system must not hang the approval flow.
	gitTimeout = 30 * time.Second

	// gitWaitDelay is how long to wait for git's pipes to close after the
	// process was killed on timeout.
	gitWaitDelay = 2 * time.Second

	// maxGitOutputBytes caps captured git output; errors quote even less.
	maxGitOutputBytes = 64 << 10
	maxGitErrorQuote  = 1024

	gitDirName    = ".git"
	defaultPath   = "/usr/bin:/bin:/usr/local/bin"
	defaultBranch = "main"
)

// Identity is the author and committer recorded on an export commit. It is
// passed explicitly so the commit never depends on the operator's git config,
// and so the person recorded is the one who approved, not whoever runs the
// process.
type Identity struct {
	Name  string
	Email string
}

// gitRunner runs git with a sanitized environment inside one directory.
type gitRunner struct {
	bin  string
	dir  string
	env  []string
	args []string // -c flags placed before every subcommand
}

// gitEnv builds the only environment git ever sees: PATH (git needs it to find
// its helpers), a throw-away HOME, and switches that disable system and global
// configuration. No inherited GIT_* variable survives, so GIT_DIR,
// GIT_WORK_TREE, GIT_AUTHOR_* and friends cannot redirect or forge a commit.
func gitEnv(home string) []string {
	path := os.Getenv("PATH")
	if path == "" {
		path = defaultPath
	}
	return []string{
		"PATH=" + path,
		"HOME=" + home,
		"XDG_CONFIG_HOME=" + filepath.Join(home, ".config"),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_EDITOR=true",
		"LC_ALL=C",
	}
}

// gitConfigFlags are the per-invocation settings that make the commit
// reproducible and keep repository-local config from running programs or
// changing bytes: no hooks, no signing, no fsmonitor, no external diff, no
// per-user attributes or excludes files, no line-ending rewriting of approved
// bytes, no automatic gc or maintenance. They override .git/config; the keys
// that cannot be overridden safely are refused by checkRepoConfig instead.
func gitConfigFlags(who Identity) []string {
	return []string{
		"-c", "core.hooksPath=/dev/null",
		"-c", "commit.gpgsign=false",
		"-c", "core.fsmonitor=false",
		"-c", "core.autocrlf=false",
		"-c", "core.safecrlf=false",
		"-c", "core.attributesFile=/dev/null",
		"-c", "core.excludesFile=/dev/null",
		"-c", "diff.external=",
		"-c", "gc.auto=0",
		"-c", "maintenance.auto=false",
		"-c", "user.name=" + who.Name,
		"-c", "user.email=" + who.Email,
	}
}

// run executes git with the -c flags, then args, and optional stdin.
func (g gitRunner) run(ctx context.Context, stdin string, args ...string) (string, error) {
	full := append(append([]string{}, g.args...), args...)
	return g.execute(ctx, stdin, full)
}

// runPlain executes git without the -c flags. Listing the repository
// configuration needs it, or the flags would show up as configuration.
func (g gitRunner) runPlain(ctx context.Context, args ...string) (string, error) {
	return g.execute(ctx, "", args)
}

// execute runs one git command under gitTimeout. On a non-zero exit it returns
// an *exec.ExitError wrapped with a short quote of stderr.
func (g gitRunner) execute(ctx context.Context, stdin string, full []string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, gitTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, g.bin, full...)
	cmd.Dir = g.dir
	cmd.Env = g.env
	cmd.WaitDelay = gitWaitDelay
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr cappedBuffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		quote := strings.TrimSpace(stderr.buf.String())
		if len(quote) > maxGitErrorQuote {
			quote = quote[:maxGitErrorQuote]
		}
		return stdout.buf.String(), fmt.Errorf("export: git %s: %w: %s", subcommand(full), err, quote)
	}
	return stdout.buf.String(), nil
}

// resolveRepoDir returns the symlink-free absolute path of dir. dir itself may
// not be a symlink, matching Write, and a .git that is not a real directory is
// refused: a gitfile would point git at a repository elsewhere.
func resolveRepoDir(dir string) (string, error) {
	if dir == "" {
		return "", errors.New("export: directory is empty")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("export: resolve directory: %w", err)
	}
	fi, err := os.Lstat(abs)
	if err != nil {
		return "", fmt.Errorf("export: stat directory: %w", err)
	}
	if fi.Mode()&fs.ModeSymlink != 0 || !fi.IsDir() {
		return "", errors.New("export: directory is a symlink or not a directory")
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("export: resolve directory: %w", err)
	}
	gfi, err := os.Lstat(filepath.Join(resolved, gitDirName))
	if err == nil && (gfi.Mode()&fs.ModeSymlink != 0 || !gfi.IsDir()) {
		return "", errors.New("export: .git is a symlink or a file, refusing to use it")
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("export: stat .git: %w", err)
	}
	return resolved, nil
}

// isOwnToplevel reports whether dir is the top level of a repository of its
// own. An enclosing parent repository does not count: committing there would
// put an export into somebody else's history.
func (g gitRunner) isOwnToplevel(ctx context.Context) (bool, error) {
	out, err := g.run(ctx, "", "rev-parse", "--show-toplevel")
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return false, nil // not inside any repository
	}
	if err != nil {
		return false, err
	}
	top, err := filepath.EvalSymlinks(strings.TrimRight(out, "\r\n"))
	if err != nil {
		return false, nil //nolint:nilerr // an unresolvable top level cannot equal dir
	}
	return top == g.dir, nil
}

// Commit records the current contents of dir as one git commit and reports
// whether it created one. It never pushes and never configures remotes.
//
// The commit runs with a sanitized environment, hooks disabled and the given
// identity, inside a repository that must be dir's own: if dir is not the top
// level of a repository (an enclosing parent repository does not count) a new
// one is initialised there. dir must hold a complete MANIFEST.json from Write;
// a repository-local configuration outside the allow-list, an attributes file,
// or an ignore rule that would drop an export file from the commit is refused,
// because each could make the committed history differ from what was
// approved. Nothing staged means no commit and false.
func Commit(ctx context.Context, dir, message string, who Identity) (committed bool, err error) {
	if err := validateMessage(message); err != nil {
		return false, err
	}
	if err := validateIdentity(who); err != nil {
		return false, err
	}
	bin, err := exec.LookPath("git")
	if err != nil {
		return false, fmt.Errorf("export: find git: %w", err)
	}
	resolved, err := resolveRepoDir(dir)
	if err != nil {
		return false, err
	}
	expected, err := exportFiles(resolved)
	if err != nil {
		return false, err
	}
	home, err := os.MkdirTemp("", "toolwarrant-git-home-")
	if err != nil {
		return false, fmt.Errorf("export: temp home: %w", err)
	}
	defer func() { _ = os.RemoveAll(home) }()
	g := gitRunner{bin: bin, dir: resolved, env: gitEnv(home), args: gitConfigFlags(who)}
	return g.commitAll(ctx, message, expected)
}

// commitAll checks the repository, initialises it if needed, stages
// everything, verifies that the export files were staged and commits if
// anything is staged.
func (g gitRunner) commitAll(ctx context.Context, message string, expected []string) (bool, error) {
	if err := g.checkRepoConfig(ctx); err != nil {
		return false, err
	}
	if err := checkAttributes(g.dir); err != nil {
		return false, err
	}
	own, err := g.isOwnToplevel(ctx)
	if err != nil {
		return false, err
	}
	if !own {
		if _, err := g.run(ctx, "", "-c", "init.defaultBranch="+defaultBranch, "init", "-q", "--template="); err != nil {
			return false, err
		}
	}
	if _, err := g.run(ctx, "", "add", "-A", "--", "."); err != nil {
		return false, err
	}
	if err := g.verifyTracked(ctx, expected); err != nil {
		return false, err
	}
	staged, err := g.hasStagedChanges(ctx)
	if err != nil || !staged {
		return false, err
	}
	if _, err := g.run(ctx, message, "commit", "-q", "--no-verify", "--no-gpg-sign", "-F", "-"); err != nil {
		return false, err
	}
	return true, nil
}

// hasStagedChanges uses `git diff --cached --quiet`: exit 0 means nothing is
// staged, exit 1 means something is, anything else is a real failure. The
// external diff driver is switched off twice over, by flag and by config.
func (g gitRunner) hasStagedChanges(ctx context.Context) (bool, error) {
	_, err := g.run(ctx, "", "diff", "--cached", "--quiet", "--exit-code", "--no-ext-diff")
	if err == nil {
		return false, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return true, nil
	}
	return false, err
}

// subcommand names the git subcommand in args for error messages, skipping
// leading "-c key=value" pairs.
func subcommand(args []string) string {
	for i := 0; i < len(args); i++ {
		if args[i] == "-c" {
			i++
			continue
		}
		return args[i]
	}
	return "command"
}
