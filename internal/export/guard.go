package export

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	maxMessageBytes  = 64 << 10
	maxIdentityBytes = 256

	// lsFilesBatch is how many paths one ls-files call verifies; it keeps the
	// argument list far below any ARG_MAX while an export of ten thousand
	// tools still needs only a handful of calls.
	lsFilesBatch = 500

	// maxQuotedKey bounds a configuration key quoted in an error message.
	maxQuotedKey = 64

	attributesName = ".gitattributes"
)

// validateIdentity rejects values that could break out of a `-c key=value`
// argument or forge extra ident fields: control characters (including NUL and
// newlines), angle brackets, and for the address any whitespace.
func validateIdentity(who Identity) error {
	fields := []struct{ field, v string }{{"name", who.Name}, {"email", who.Email}}
	for _, f := range fields {
		field, v := f.field, f.v
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("export: identity %s is empty", field)
		}
		if len(v) > maxIdentityBytes || !utf8.ValidString(v) {
			return fmt.Errorf("export: identity %s is too long or not valid UTF-8", field)
		}
		for _, r := range v {
			if r < ' ' || r == 0x7f || r == '<' || r == '>' {
				return fmt.Errorf("export: identity %s contains a forbidden character", field)
			}
		}
	}
	if strings.ContainsAny(who.Email, " \t") {
		return errors.New("export: identity email contains whitespace")
	}
	return nil
}

// validateMessage rejects empty messages and NUL, which git would truncate at.
func validateMessage(msg string) error {
	if strings.TrimSpace(msg) == "" {
		return errors.New("export: commit message is empty")
	}
	if len(msg) > maxMessageBytes || !utf8.ValidString(msg) {
		return errors.New("export: commit message is too long or not valid UTF-8")
	}
	if strings.ContainsRune(msg, 0) {
		return errors.New("export: commit message contains NUL")
	}
	return nil
}

// cappedBuffer keeps at most maxGitOutputBytes and silently drops the rest, so
// a runaway git cannot exhaust memory.
type cappedBuffer struct{ buf bytes.Buffer }

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := maxGitOutputBytes - c.buf.Len(); room > 0 {
		c.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

// exportFiles returns the files Commit must find in the index after staging:
// MANIFEST.json, its signature and public key when the export was signed
// (signatureFiles, which refuses a signature that does not sign the current
// manifest), and every file the manifest lists that exists. The manifest must
// be complete, because a pending one means the last Write did not finish and
// the history would record a half state; it must also be one this package
// wrote, or there is nothing whose presence in the commit can be verified.
func exportFiles(dir string) ([]string, error) {
	p := filepath.Join(dir, manifestName)
	fi, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errors.New("export: MANIFEST.json not found, nothing to commit; run the export first")
	}
	if err != nil {
		return nil, fmt.Errorf("export: stat manifest: %w", err)
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxManifestBytes {
		return nil, errors.New("export: MANIFEST.json is not a regular file of a sane size")
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("export: read manifest: %w", err)
	}
	doc, ok := parseManifest(raw)
	if !ok {
		return nil, errors.New("export: MANIFEST.json is not a manifest this version wrote; run the export first")
	}
	if doc.Status != statusComplete {
		return nil, errors.New("export: MANIFEST.json is pending: the last export did not finish, run it again before committing")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("export: open directory: %w", err)
	}
	defer func() { _ = root.Close() }()
	sigFiles, err := signatureFiles(root, raw)
	if err != nil {
		return nil, err
	}
	files := append([]string{manifestName}, sigFiles...)
	for _, rel := range doc.files() {
		if fi, err := os.Lstat(filepath.Join(dir, filepath.FromSlash(rel))); err == nil && fi.Mode().IsRegular() {
			files = append(files, rel)
		}
	}
	return files, nil
}

// verifyTracked fails unless every expected file is in the index after `git
// add`. An ignore rule in .gitignore or .git/info/exclude would otherwise drop
// snapshots from the commit while Commit reported success, and the mirror
// would stop recording approvals without anyone being told.
func (g gitRunner) verifyTracked(ctx context.Context, expected []string) error {
	for start := 0; start < len(expected); start += lsFilesBatch {
		batch := expected[start:min(start+lsFilesBatch, len(expected))]
		args := append([]string{"ls-files", "-z", "--error-unmatch", "--"}, batch...)
		if _, err := g.run(ctx, "", args...); err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				return fmt.Errorf("export: an export file was not staged; an ignore rule (.gitignore or .git/info/exclude) is dropping snapshots from the commit: %w", err)
			}
			return err
		}
	}
	return nil
}

// checkRepoConfig lists the repository-local configuration, and nothing else
// (no -c flags, no includes), and fails closed on any key outside the
// allow-list. git reads .git/config before every command, and many sections
// can name a program to run (diff.external, filter.*.clean, core.sshCommand)
// or point the repository at another tree (core.worktree, include.path).
// Refusing everything but the sections an export repository needs is simpler
// and safer than enumerating the dangerous keys.
func (g gitRunner) checkRepoConfig(ctx context.Context) error {
	cfg := filepath.Join(g.dir, gitDirName, "config")
	fi, err := os.Lstat(cfg)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("export: stat .git/config: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return errors.New("export: .git/config is not a regular file")
	}
	out, err := g.runPlain(ctx, "config", "--local", "--list", "-z", "--no-includes")
	if err != nil {
		return err
	}
	if len(out) >= maxGitOutputBytes {
		return errors.New("export: .git/config is too large to check")
	}
	return checkConfigList(out)
}

// checkConfigList parses `git config --list -z` output, in which every entry
// ends in NUL and holds the key, a newline and the value (or just the key for
// a boolean written without a value).
func checkConfigList(list string) error {
	for _, entry := range strings.Split(list, "\x00") {
		if entry == "" {
			continue
		}
		key, value, _ := strings.Cut(entry, "\n")
		lower := strings.ToLower(key)
		section, _, _ := strings.Cut(lower, ".")
		if !configSectionAllowed(section) {
			return fmt.Errorf("export: refusing to use .git/config: key %s is outside the allowed sections (core, user, commit, init)", quoteKey(key))
		}
		if section == "core" {
			if err := checkCoreKey(lower, value); err != nil {
				return err
			}
		}
	}
	return nil
}

// configSectionAllowed names the sections `git init` writes or Commit sets:
// core.*, user.*, commit.* and init.*. The keys in these sections that still
// run programs are overridden by gitConfigFlags, and the ones that redirect
// the repository are refused by checkCoreKey.
func configSectionAllowed(section string) bool {
	switch section {
	case "core", "user", "commit", "init":
		return true
	}
	return false
}

// checkCoreKey refuses the core.* keys that point the repository at another
// tree or name a program, which a -c flag cannot neutralise safely.
func checkCoreKey(key, value string) error {
	switch key {
	case "core.worktree", "core.sshcommand", "core.gitproxy", "core.askpass", "core.alternaterefscommand":
		return fmt.Errorf("export: refusing to use .git/config: %s redirects the repository or runs a program", key)
	case "core.bare":
		if strings.EqualFold(strings.TrimSpace(value), "false") {
			return nil
		}
		return errors.New("export: refusing to use .git/config: core.bare is not false")
	}
	return nil
}

// quoteKey quotes a configuration key for an error message, bounded in length;
// it comes from a file other people can edit.
func quoteKey(k string) string {
	if len(k) > maxQuotedKey {
		k = k[:maxQuotedKey]
	}
	return strconv.Quote(k)
}

// checkAttributes refuses a .gitattributes anywhere in the export tree and a
// .git/info/attributes: attributes can rewrite the bytes git stores (clean
// filters, ident expansion, working-tree-encoding), so the committed snapshot
// would no longer be the approved definition. This package never writes
// either file, so their presence is somebody else's doing.
func checkAttributes(dir string) error {
	info := filepath.Join(dir, gitDirName, "info", "attributes")
	if _, err := os.Lstat(info); err == nil {
		return errors.New("export: refusing to commit: .git/info/attributes exists and could rewrite the approved bytes on the way into git")
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("export: stat .git/info/attributes: %w", err)
	}
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("export: scan for attributes files: %w", err)
		}
		if d.IsDir() {
			if p != dir && d.Name() == gitDirName {
				return fs.SkipDir
			}
			return nil
		}
		if strings.EqualFold(d.Name(), attributesName) {
			return errors.New("export: refusing to commit: a .gitattributes file in the export directory could rewrite the approved bytes on the way into git")
		}
		return nil
	})
}
