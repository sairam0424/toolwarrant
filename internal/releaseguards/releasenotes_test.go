package releaseguards

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const (
	// notesScript is the script the release workflow runs before goreleaser;
	// the tests run the tree's own copy against scratch changelogs.
	notesScript = "scripts/release-notes.sh"
	// releaseWorkflow and goreleaserConfig are the two files whose wiring the
	// notes depend on: the workflow must hand the file to goreleaser and the
	// configuration must leave the changelog pipe enabled, since goreleaser
	// v2.18.2 reads --release-notes inside that pipe and a disabled pipe
	// publishes the header and footer around nothing.
	releaseWorkflow  = ".github/workflows/release.yml"
	goreleaserConfig = ".goreleaser.yaml"
	// The exit statuses the script documents: 1 for a changelog that has no
	// notes for the tag, 2 for a tag or a file it refuses before looking.
	exitNoNotes = 1
	exitUsage   = 2
	// The messages the script prints; a refusal is pinned by its message so
	// that a script failing for another reason does not pass for the right one.
	notAVersionMessage = "is not a version tag"
	cannotReadMessage  = "cannot read"
	noHeadingMessage   = "YYYY-MM-DD' heading; the release commit adds it"
	emptyMessage       = "section of"
	twiceMessage       = "appears 2 times"
	neitherMessage     = "has neither a"
)

// fixtureChangelog is a changelog in the shape CONTRIBUTING.md prescribes:
// an opening paragraph that mentions the headings in prose, lines under
// Unreleased, two released versions and the link references at the end.
const fixtureChangelog = `# Changelog

The prose mentions ## [Unreleased] and ## [1.0.0] - 2026-01-01 here.

## [Unreleased]

### Added

- the unreleased line (` + "`TestUnreleased`" + `).

## [1.0.0] - 2026-01-01

### Fixed

- the 1.0.0 line.

### Changed

- another 1.0.0 line.

## [0.9.0] - 2025-12-01

First release.

[Unreleased]: https://example.invalid/compare/v1.0.0...HEAD
[1.0.0]: https://example.invalid/compare/v0.9.0...v1.0.0
[0.9.0]: https://example.invalid/releases/tag/v0.9.0
`

// TestReleaseNotes_aFinalTagTakesItsOwnSectionAndStopsAtTheLinks runs the
// script on a changelog with two released versions: a final tag gets exactly
// the lines under its own dated heading, trimmed, and the last section of the
// file ends before the link reference definitions instead of carrying them.
func TestReleaseNotes_aFinalTagTakesItsOwnSectionAndStopsAtTheLinks(t *testing.T) {
	path := scratchChangelog(t, fixtureChangelog)
	out, stderr, err := runNotes(t, "v1.0.0", path)
	if err != nil {
		t.Fatalf("v1.0.0: %v\n%s", err, stderr)
	}
	want := "### Fixed\n\n- the 1.0.0 line.\n\n### Changed\n\n- another 1.0.0 line.\n"
	if out != want {
		t.Errorf("v1.0.0 notes:\n%q\nwant:\n%q", out, want)
	}
	if !strings.Contains(stderr, "takes the [1.0.0] section") {
		t.Errorf("stderr must name the section taken:\n%s", stderr)
	}
	out, stderr, err = runNotes(t, "v0.9.0", path)
	if err != nil {
		t.Fatalf("v0.9.0: %v\n%s", err, stderr)
	}
	if want := "First release.\n"; out != want {
		t.Errorf("v0.9.0 notes:\n%q\nwant:\n%q (the link references are not notes)", out, want)
	}
}

// TestReleaseNotes_aCandidateTakesUnreleasedUntilTheReleaseCommit pins the
// rule for a candidate: while the changelog has no dated heading for the
// version it is a candidate for, the Unreleased section is its notes; once
// the release commit has added that heading, the candidate and the final tag
// take the same section, so both orders of cutting a candidate work.
func TestReleaseNotes_aCandidateTakesUnreleasedUntilTheReleaseCommit(t *testing.T) {
	path := scratchChangelog(t, fixtureChangelog)
	out, stderr, err := runNotes(t, "v1.1.0-rc.1", path)
	if err != nil {
		t.Fatalf("v1.1.0-rc.1 before the release commit: %v\n%s", err, stderr)
	}
	if want := "### Added\n\n- the unreleased line (`TestUnreleased`).\n"; out != want {
		t.Errorf("candidate notes before the release commit:\n%q\nwant:\n%q", out, want)
	}
	if !strings.Contains(stderr, "takes the [Unreleased] section") {
		t.Errorf("stderr must say the Unreleased section was taken:\n%s", stderr)
	}
	released := strings.Replace(fixtureChangelog,
		"## [Unreleased]\n\n### Added\n\n- the unreleased line (`TestUnreleased`).\n",
		"## [Unreleased]\n\n## [1.1.0] - 2026-02-02\n\n### Added\n\n- the unreleased line (`TestUnreleased`).\n", 1)
	path = scratchChangelog(t, released)
	for _, tag := range []string{"v1.1.0-rc.2", "v1.1.0"} {
		out, stderr, err := runNotes(t, tag, path)
		if err != nil {
			t.Fatalf("%s after the release commit: %v\n%s", tag, err, stderr)
		}
		if want := "### Added\n\n- the unreleased line (`TestUnreleased`).\n"; out != want {
			t.Errorf("%s notes after the release commit:\n%q\nwant:\n%q", tag, out, want)
		}
		if !strings.Contains(stderr, "takes the [1.1.0] section") {
			t.Errorf("%s: stderr must name the version's section:\n%s", tag, stderr)
		}
	}
}

// TestReleaseNotes_refuseAnEmptySectionOrAMissingHeading runs the script on
// the changelogs a careless release leaves behind and expects exit 1 with the
// message that names the fix: a final tag without its dated heading, a
// candidate whose Unreleased section was emptied by the release commit before
// the version's heading exists, a heading with nothing under it, an undated
// heading and a heading that appears twice.
func TestReleaseNotes_refuseAnEmptySectionOrAMissingHeading(t *testing.T) {
	emptyUnreleased := strings.Replace(fixtureChangelog, "### Added\n\n- the unreleased line (`TestUnreleased`).\n\n", "", 1)
	cases := map[string]struct {
		changelog string
		tag       string
		message   string
	}{
		"final tag without a heading":          {fixtureChangelog, "v1.2.0", noHeadingMessage},
		"candidate with an emptied Unreleased": {emptyUnreleased, "v1.2.0-rc.1", emptyMessage},
		"heading with nothing under it": {strings.Replace(fixtureChangelog, "## [1.0.0] - 2026-01-01\n\n### Fixed\n\n- the 1.0.0 line.\n\n### Changed\n\n- another 1.0.0 line.\n",
			"## [1.0.0] - 2026-01-01\n\n\n", 1), "v1.0.0", emptyMessage},
		"undated heading":              {strings.Replace(fixtureChangelog, "\n## [1.0.0] - 2026-01-01\n", "\n## [1.0.0]\n", 1), "v1.0.0", noHeadingMessage},
		"heading twice":                {fixtureChangelog + "\n## [1.0.0] - 2026-01-02\n\n- again.\n", "v1.0.0", twiceMessage},
		"candidate without Unreleased": {strings.Replace(emptyUnreleased, "## [Unreleased]\n\n", "", 1), "v1.2.0-rc.1", neitherMessage},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			path := scratchChangelog(t, tc.changelog)
			out, stderr, err := runNotes(t, tc.tag, path)
			assertNotesRefusal(t, out, stderr, err, exitNoNotes, tc.message)
		})
	}
}

// TestReleaseNotes_refuseATagThatIsNotAVersion pins the usage refusals, exit
// 2: a tag without the v, a two-part version, a tag with a space or a
// shell character, a branch name, no tag at all, and a changelog that is not
// there. The tag is spliced into a pattern and into asset names, so anything
// that is not a version stops before the file is read.
func TestReleaseNotes_refuseATagThatIsNotAVersion(t *testing.T) {
	path := scratchChangelog(t, fixtureChangelog)
	for _, tag := range []string{"1.0.0", "v1.0", "v1.0.0 x", "v1.0.0;id", "main", "v1.0.0+build"} {
		t.Run(tag, func(t *testing.T) {
			out, stderr, err := runNotes(t, tag, path)
			assertNotesRefusal(t, out, stderr, err, exitUsage, notAVersionMessage)
		})
	}
	t.Run("no tag", func(t *testing.T) {
		out, stderr, err := runNotes(t)
		assertNotesRefusal(t, out, stderr, err, exitUsage, "usage:")
	})
	t.Run("changelog missing", func(t *testing.T) {
		out, stderr, err := runNotes(t, "v1.0.0", filepath.Join(t.TempDir(), "CHANGELOG.md"))
		assertNotesRefusal(t, out, stderr, err, exitUsage, cannotReadMessage)
	})
}

// TestReleaseNotes_everyReleasedVersionInTheTreeHasNotes runs the script on
// the tree's own CHANGELOG.md for every version that has a dated heading, so
// that a release whose section was left empty, or a heading form the script
// no longer recognises, fails here before a tag finds out.
func TestReleaseNotes_everyReleasedVersionInTheTreeHasNotes(t *testing.T) {
	root := moduleRoot(t)
	text := readFile(t, filepath.Join(root, changelog))
	versions := releasedVersions(t, text)
	if len(versions) == 0 {
		t.Fatal("CHANGELOG.md has no '## [x.y.z] - YYYY-MM-DD' heading to check")
	}
	for _, v := range versions {
		out, stderr, err := runNotes(t, "v"+v, filepath.Join(root, changelog))
		if err != nil {
			t.Errorf("v%s: %v\n%s", v, err, stderr)
			continue
		}
		if strings.TrimSpace(out) == "" {
			t.Errorf("v%s: the section is empty", v)
		}
		if strings.Contains(out, "\n## ") || strings.HasPrefix(out, "## ") {
			t.Errorf("v%s: the notes carry a level-two heading:\n%s", v, out)
		}
		if regexp.MustCompile(`(?m)^\[[^\]]+\]: `).MatchString(out) {
			t.Errorf("v%s: the notes carry the link references:\n%s", v, out)
		}
	}
}

// TestReleaseNotes_theWorkflowHandsTheFileToGoreleaserAndKeepsThePipe pins
// the wiring the notes depend on. release.yml runs the script into the
// runner's temp directory and passes that file as --release-notes; it
// attests the checksums file with attestations: write. .goreleaser.yaml has
// no changelog.disable line: goreleaser v2.18.2 reads --release-notes inside
// the changelog pipe, and a disabled pipe would publish the header and the
// footer with nothing between them.
func TestReleaseNotes_theWorkflowHandsTheFileToGoreleaserAndKeepsThePipe(t *testing.T) {
	root := moduleRoot(t)
	workflow := readFile(t, filepath.Join(root, releaseWorkflow))
	for _, want := range []string{
		notesScript + ` "${TAG}"`,
		"--release-notes ${{ runner.temp }}/release-notes.md",
		"attestations: write",
		"uses: actions/attest-build-provenance@",
		"subject-checksums: dist/toolwarrant_${{ steps.version.outputs.version }}_checksums.txt",
		"gh release upload",
		"_provenance.intoto.jsonl",
	} {
		if !strings.Contains(workflow, want) {
			t.Errorf("%s lacks %q", releaseWorkflow, want)
		}
	}
	config := readFile(t, filepath.Join(root, goreleaserConfig))
	if regexp.MustCompile(`(?m)^\s*disable:`).MatchString(config) {
		t.Errorf("%s disables a pipe; changelog.disable skips the pipe that reads --release-notes", goreleaserConfig)
	}
	if strings.Contains(config, "use: git") {
		t.Errorf("%s still lists the commits by type (use: git); the notes come from CHANGELOG.md", goreleaserConfig)
	}
}

// assertNotesRefusal checks a refusal: the script must exit with the given
// status, print nothing on stdout and name the reason on stderr.
func assertNotesRefusal(t *testing.T, out, stderr string, err error, status int, message string) {
	t.Helper()
	exit, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("want exit %d with %q, got err=%v\nstdout:\n%s\nstderr:\n%s", status, message, err, out, stderr)
	}
	if exit.ExitCode() != status {
		t.Errorf("exit %d, want %d\nstderr:\n%s", exit.ExitCode(), status, stderr)
	}
	if out != "" {
		t.Errorf("a refusal must print no notes, got:\n%s", out)
	}
	if !strings.Contains(stderr, message) {
		t.Errorf("stderr lacks %q:\n%s", message, stderr)
	}
}

// runNotes runs the tree's script with the given arguments (the tag, then the
// changelog path, as the workflow passes them) and returns stdout and stderr
// apart, so that a test can pin the notes and the message separately.
func runNotes(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	cmd := exec.Command(filepath.Join(moduleRoot(t), notesScript), args...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// scratchChangelog writes text as a CHANGELOG.md in a fresh directory.
func scratchChangelog(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), changelog)
	writeFile(t, path, text)
	return path
}
