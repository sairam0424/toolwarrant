package main

import (
	"regexp"
	"runtime/debug"
	"strings"
	"testing"
)

// commitLinePattern is the shape of the version command's third line: the
// prefix, then either unknownCommit or twelve hex characters with an optional
// dirty marker. Whether this test binary carries a revision depends on how go
// test was invoked (-buildvcs), so the live output is pinned to the shape and
// buildCommit is driven over fixed settings for the exact values.
var commitLinePattern = regexp.MustCompile(`^` + regexp.QuoteMeta(commitLinePrefix) + `(` + regexp.QuoteMeta(unknownCommit) + `|[0-9a-f]{12}(` + regexp.QuoteMeta(dirtyMarker) + `)?)$`)

// wantVersionLines pins the fixed shape of the version command's output: the
// program and version on the first line, the gateway pin on the second and
// the commit line, matching commitLinePattern, on the third and last.
func wantVersionLines(t *testing.T, out string) {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("version printed %d lines, want 3:\n%s", len(lines), out)
	}
	if !strings.HasPrefix(lines[0], programName+" ") {
		t.Errorf("version line 1 = %q, want %q and the version", lines[0], programName)
	}
	if lines[1] != gatewayVersion {
		t.Errorf("version line 2 = %q, want %q", lines[1], gatewayVersion)
	}
	if !commitLinePattern.MatchString(lines[2]) {
		t.Errorf("version line 3 = %q, want it to match %s", lines[2], commitLinePattern)
	}
}

// TestBuildCommit_NamesTheRevisionTheToolchainStamped drives the commit line's
// decision over every shape of build settings the version command meets: a
// release build cut to twelve characters, a build from a modified checkout
// with the dirty marker, a short revision printed whole, and the three shapes
// that carry no revision (no settings at all, settings of other kinds, a
// modified flag alone), which all read unknown. The live binary's own
// settings then go through the same function and the printed line keeps the
// pinned shape.
func TestBuildCommit_NamesTheRevisionTheToolchainStamped(t *testing.T) {
	t.Parallel()
	const full = "fc922a596bb9a5c3204d25e706675aa76c405569"
	stamp := func(revision, modified string) []debug.BuildSetting {
		s := []debug.BuildSetting{{Key: "CGO_ENABLED", Value: "0"}}
		if revision != "" {
			s = append(s, debug.BuildSetting{Key: vcsRevisionSetting, Value: revision})
		}
		if modified != "" {
			s = append(s, debug.BuildSetting{Key: vcsModifiedSetting, Value: modified})
		}
		return s
	}
	cases := []struct {
		name     string
		settings []debug.BuildSetting
		want     string
	}{
		{"a release build names the first twelve characters", stamp(full, "false"), "fc922a596bb9"},
		{"a modified checkout carries the dirty marker", stamp(full, "true"), "fc922a596bb9" + dirtyMarker},
		{"a revision with no modified setting is clean", stamp(full, ""), "fc922a596bb9"},
		{"a revision shorter than twelve characters is printed whole", stamp("abc123", "false"), "abc123"},
		{"a revision of exactly twelve characters is not cut", stamp("fc922a596bb9", "false"), "fc922a596bb9"},
		{"a modified flag without a revision is unknown", stamp("", "true"), unknownCommit},
		{"settings of other kinds alone are unknown", stamp("", ""), unknownCommit},
		{"no settings at all are unknown", nil, unknownCommit},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := buildCommit(tc.settings); got != tc.want {
				t.Errorf("buildCommit(%v) = %q, want %q", tc.settings, got, tc.want)
			}
		})
	}
	c := newCLI(t)
	out := c.ok("version")
	wantVersionLines(t, out)
	if got, want := strings.Split(out, "\n")[2], commitLinePrefix+buildCommit(embeddedBuildSettings()); got != want {
		t.Errorf("version line 3 = %q, want %q from this binary's own build settings", got, want)
	}
}
