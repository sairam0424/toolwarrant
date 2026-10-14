package releaseguards

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const (
	// makefile, goMod and changelog are the three files the guards read; every
	// test copies them from the module root into a scratch directory and edits
	// the copies, never the tree.
	makefile  = "Makefile"
	goMod     = "go.mod"
	changelog = "CHANGELOG.md"
	// guardsTarget runs the three guards alone; releaseCheckTarget is what the
	// ci release-check job runs and must run the guards first.
	guardsTarget       = "release-guards"
	releaseCheckTarget = "release-check"
	// unreleasedHeading is the heading every tree must keep; unreleasedLine is
	// the heading as a whole line, which is what the tests edit, since the
	// file's opening paragraph also mentions the heading in prose.
	unreleasedHeading = "## [Unreleased]"
	unreleasedLine    = "\n" + unreleasedHeading + "\n"
	// maxParentDirs bounds the walk from the package directory to go.mod.
	maxParentDirs = 6
	// The messages the guards print. A refusal is pinned by its message so
	// that a guard failing for another reason does not pass for the right one.
	replaceMessage      = "go.mod carries a replace or exclude directive"
	unreadableMessage   = "go.mod could not be read"
	unreleasedMessage   = "CHANGELOG.md has no '## [Unreleased]' heading"
	versionMessage      = "YYYY-MM-DD' heading; the release commit adds it"
	versionShapeMessage = "VERSION must be the version as the changelog heading spells it"
	// releaseHeading matches a released entry's heading and captures the version.
	releaseHeading = `(?m)^## \[([^\]]+)\] - \d{4}-\d{2}-\d{2}$`
)

// TestReleaseGuards_runFirstInReleaseCheck pins the wiring: make -n prints the
// recipe lines release-check would run, and all three guards come before
// goreleaser check, so the ci release-check job runs them on every pull
// request under its unchanged name and without goreleaser having to be there
// for the guards to speak.
func TestReleaseGuards_runFirstInReleaseCheck(t *testing.T) {
	dir := scratchTree(t)
	out, err := runMake(dir, "-n", releaseCheckTarget)
	if err != nil {
		t.Fatalf("make -n %s: %v\n%s", releaseCheckTarget, err, out)
	}
	goreleaser := strings.Index(out, "goreleaser check")
	if goreleaser < 0 {
		t.Fatalf("make -n %s does not run goreleaser check:\n%s", releaseCheckTarget, out)
	}
	for _, guard := range []string{"'^[[:space:]]*(replace|exclude)", "'## [Unreleased]'", `"$VERSION"`} {
		at := strings.Index(out, guard)
		if at < 0 || at > goreleaser {
			t.Errorf("guard %s must be listed before goreleaser check (guard at %d, goreleaser at %d):\n%s", guard, at, goreleaser, out)
		}
	}
}

// TestReleaseGuards_passOnTheTreeAndOnEveryReleasedVersion runs the guards on
// copies of the tree's own files, without VERSION and then once with VERSION
// set to every version CHANGELOG.md has a dated heading for, so that the
// heading form the guard expects and the one the file uses cannot drift apart.
func TestReleaseGuards_passOnTheTreeAndOnEveryReleasedVersion(t *testing.T) {
	dir := scratchTree(t)
	out, err := runMake(dir, guardsTarget)
	if err != nil {
		t.Fatalf("the guards failed on the tree as it is: %v\n%s", err, out)
	}
	if !strings.Contains(out, "VERSION not set") {
		t.Fatalf("without VERSION the guards must say so:\n%s", out)
	}
	versions := releasedVersions(t, readFile(t, filepath.Join(dir, changelog)))
	if len(versions) == 0 {
		t.Fatal("CHANGELOG.md has no '## [x.y.z] - YYYY-MM-DD' heading to check against")
	}
	for _, v := range versions {
		out, err := runMake(dir, guardsTarget, "VERSION="+v)
		if err != nil {
			t.Errorf("VERSION=%s: %v\n%s", v, err, out)
			continue
		}
		if !strings.Contains(out, "entry for "+v) {
			t.Errorf("VERSION=%s: the guard did not report the entry:\n%s", v, out)
		}
	}
}

// TestReleaseGuards_refuseAReplaceOrExcludeDirectiveInGoMod plants each
// directive form the go.mod grammar allows and expects the refusal, leading
// blanks included since the go.mod parser skips them; a retract directive and
// a comment that mentions replace pass, because a retract is how a bad tag is
// withdrawn and a comment builds nothing. A go.mod that is not there is
// refused as well, under its own message: grep exits 2 for a file it cannot
// read, and a guard that took that for "no match" would pass a tree it never
// checked.
func TestReleaseGuards_refuseAReplaceOrExcludeDirectiveInGoMod(t *testing.T) {
	cases := map[string]struct {
		line    string
		missing bool
		refuse  bool
		message string
	}{
		"replace":          {line: "replace example.com/m => ../m", refuse: true, message: replaceMessage},
		"replace with tab": {line: "replace\texample.com/m => ../m", refuse: true, message: replaceMessage},
		"replace block":    {line: "replace (\n\texample.com/m => ../m\n)", refuse: true, message: replaceMessage},
		"indented replace": {line: "  replace example.com/m => ../m", refuse: true, message: replaceMessage},
		"exclude":          {line: "exclude example.com/m v1.0.0", refuse: true, message: replaceMessage},
		"exclude block":    {line: "exclude (\n\texample.com/m v1.0.0\n)", refuse: true, message: replaceMessage},
		"retract":          {line: "retract v0.1.0 // a bad tag"},
		"retract block":    {line: "retract (\n\tv0.1.0 // a bad tag\n)"},
		"comment":          {line: "// replace is refused here; see release-guards"},
		"go.mod missing":   {missing: true, refuse: true, message: unreadableMessage},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dir := scratchTree(t)
			path := filepath.Join(dir, goMod)
			if tc.missing {
				removeFile(t, path)
			} else {
				appendFile(t, path, "\n"+tc.line+"\n")
			}
			out, err := runMake(dir, guardsTarget)
			assertGuard(t, out, err, tc.refuse, tc.message)
		})
	}
}

// TestReleaseGuards_refuseAChangelogWithoutAnUnreleasedSection replaces the
// Unreleased heading line of a copy with every shape a careless release commit
// might leave and expects the refusal; the heading must be a whole line of its
// own, and a prose mention of it (the file's opening paragraph has one) does
// not count.
func TestReleaseGuards_refuseAChangelogWithoutAnUnreleasedSection(t *testing.T) {
	cases := map[string]struct {
		line   string
		empty  bool
		refuse bool
	}{
		"heading removed":  {line: "", refuse: true},
		"brackets dropped": {line: "## Unreleased", refuse: true},
		"trailing text":    {line: unreleasedHeading + " (next)", refuse: true},
		"wrong level":      {line: "#" + unreleasedHeading, refuse: true},
		"lower case":       {line: "## [unreleased]", refuse: true},
		"in prose only":    {line: "The " + unreleasedHeading + " heading was here.", refuse: true},
		"file empty":       {empty: true, refuse: true},
		"as it is":         {line: unreleasedHeading, refuse: false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dir := scratchTree(t)
			path := filepath.Join(dir, changelog)
			if tc.empty {
				writeFile(t, path, "")
			} else {
				writeFile(t, path, replaceHeadingLine(t, readFile(t, path), tc.line))
			}
			out, err := runMake(dir, guardsTarget)
			assertGuard(t, out, err, tc.refuse, unreleasedMessage)
		})
	}
}

// TestReleaseGuards_refuseAVersionWithoutADatedChangelogEntry runs the guards
// with VERSION set and expects the refusal unless the changelog carries the
// dated heading for exactly that version: a leading v, a prefix of a version
// and an undated heading all fail, and a VERSION that is not shaped like a
// version is refused before it reaches the comparison.
func TestReleaseGuards_refuseAVersionWithoutADatedChangelogEntry(t *testing.T) {
	cases := map[string]struct {
		version string
		heading string
		refuse  bool
		message string
	}{
		"unknown version":     {"9.9.9", "", true, versionMessage},
		"with the v":          {"v0.1.1", "", true, "pass VERSION without the v"},
		"prefix of a version": {"0.1", "", true, versionMessage},
		"undated heading":     {"9.9.9", "## [9.9.9]", true, versionMessage},
		"wrong date shape":    {"9.9.9", "## [9.9.9] - 14 Oct 2026", true, versionMessage},
		"dated heading":       {"9.9.9", "## [9.9.9] - 2026-12-31", false, ""},
		"candidate heading":   {"9.9.9-rc.1", "## [9.9.9-rc.1] - 2026-12-31", false, ""},
		"semicolon":           {"0.1.1;id", "", true, versionShapeMessage},
		"quote":               {"0.1.1'x", "", true, versionShapeMessage},
		"space":               {"0.1.1 x", "", true, versionShapeMessage},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dir := scratchTree(t)
			if tc.heading != "" {
				path := filepath.Join(dir, changelog)
				writeFile(t, path, replaceHeadingLine(t, readFile(t, path), unreleasedHeading+"\n\n"+tc.heading))
			}
			out, err := runMake(dir, guardsTarget, "VERSION="+tc.version)
			assertGuard(t, out, err, tc.refuse, tc.message)
		})
	}
}

// assertGuard checks a guard run against the expected outcome: a refusal must
// fail make and print the named message; a pass must exit 0.
func assertGuard(t *testing.T, out string, err error, refuse bool, message string) {
	t.Helper()
	if !refuse {
		if err != nil {
			t.Fatalf("the guards refused, want a pass: %v\n%s", err, out)
		}
		return
	}
	if err == nil {
		t.Fatalf("the guards passed, want the refusal %q:\n%s", message, out)
	}
	if !strings.Contains(out, message) {
		t.Fatalf("the guards failed for another reason than %q: %v\n%s", message, err, out)
	}
}

// replaceHeadingLine returns text with its one Unreleased heading line
// replaced by line (an empty line removes it), and fails when the heading is
// not there exactly once as a whole line, so that an edit can never miss and
// leave the original heading in place.
func replaceHeadingLine(t *testing.T, text, line string) string {
	t.Helper()
	if n := strings.Count(text, unreleasedLine); n != 1 {
		t.Fatalf("test setup: the Unreleased heading line occurs %d times, want 1", n)
	}
	with := "\n"
	if line != "" {
		with = "\n" + line + "\n"
	}
	return strings.Replace(text, unreleasedLine, with, 1)
}

// scratchTree copies the Makefile, go.mod and CHANGELOG.md of the module into
// a fresh directory, so that every case edits a copy and the tree is never
// touched. It fails, rather than skips, when make is not on PATH: the guards
// are make recipes, so there is nothing else to test them with.
func scratchTree(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("make"); err != nil {
		t.Fatalf("make is not on PATH; the release guards are make recipes: %v", err)
	}
	root := moduleRoot(t)
	dir := t.TempDir()
	for _, name := range []string{makefile, goMod, changelog} {
		writeFile(t, filepath.Join(dir, name), readFile(t, filepath.Join(root, name)))
	}
	return dir
}

// runMake runs make in dir and returns its combined output. VERSION is
// stripped from the inherited environment so that a VERSION exported by the
// developer's shell cannot turn a no-VERSION case into a version check; a
// case that wants it passes it as a command-line variable, which make exports
// to the recipe's environment.
func runMake(dir string, args ...string) (string, error) {
	cmd := exec.Command("make", append([]string{"--no-print-directory", "-C", dir}, args...)...)
	cmd.Env = withoutVersion(os.Environ())
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func withoutVersion(env []string) []string {
	kept := make([]string, 0, len(env))
	for _, kv := range env {
		if !strings.HasPrefix(kv, "VERSION=") {
			kept = append(kept, kv)
		}
	}
	return kept
}

// releasedVersions lists the versions CHANGELOG.md has a dated heading for,
// in file order.
func releasedVersions(t *testing.T, text string) []string {
	t.Helper()
	var versions []string
	for _, m := range regexp.MustCompile(releaseHeading).FindAllStringSubmatch(text, -1) {
		versions = append(versions, m[1])
	}
	return versions
}

// moduleRoot walks up from the package directory to the directory holding
// go.mod, so that the test reads the tree it is part of and nothing else.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for range maxParentDirs {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatalf("no go.mod within %d directories above the package", maxParentDirs)
	return ""
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func writeFile(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func appendFile(t *testing.T, path, text string) {
	t.Helper()
	writeFile(t, path, readFile(t, path)+text)
}

// removeFile deletes a scratch copy, for the case where a guard's input is
// not there at all.
func removeFile(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}
