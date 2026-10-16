package main

import "runtime/debug"

// The build settings the version command reads to name the commit a binary
// was built from. The go command stamps them into a main package built inside
// a version-controlled checkout (go build, go install of a local path, the
// release workflow's goreleaser run); a go install of module@version from the
// proxy, a go test binary and a go run binary carry no vcs.* setting.
const (
	// vcsRevisionSetting is the full revision of the checkout the binary was
	// built from, forty hex characters for git.
	vcsRevisionSetting = "vcs.revision"
	// vcsModifiedSetting is "true" when the checkout had uncommitted changes
	// at build time, so the revision alone does not name the source.
	vcsModifiedSetting = "vcs.modified"
	// vcsModifiedTrue is the value the go command writes for a modified
	// checkout; anything else reads as clean.
	vcsModifiedTrue = "true"
	// commitDisplayLen is how many characters of the revision the version
	// command prints: the twelve-character form git shows for large
	// repositories, which git show and the release page both resolve.
	commitDisplayLen = 12
	// dirtyMarker follows the commit of a build from a modified checkout, the
	// marker the go command itself appends to a pseudo-version.
	dirtyMarker = "+dirty"
	// unknownCommit is printed when the build carries no revision stamp.
	unknownCommit = "unknown"
	// commitLinePrefix starts the third line of the version command.
	commitLinePrefix = "commit "
)

// buildCommit names the commit a binary was built from, as the version
// command prints it: the revision cut to commitDisplayLen characters, with
// dirtyMarker when the checkout was modified, or unknownCommit when the build
// has no revision stamp (a modified flag without a revision is unknown too,
// since there is nothing to mark). It is a pure function of the settings so
// that the tests can hand it every shape; the binary's own settings come from
// embeddedBuildSettings.
func buildCommit(settings []debug.BuildSetting) string {
	revision, modified := "", false
	for _, s := range settings {
		switch s.Key {
		case vcsRevisionSetting:
			revision = s.Value
		case vcsModifiedSetting:
			modified = s.Value == vcsModifiedTrue
		}
	}
	if revision == "" {
		return unknownCommit
	}
	if len(revision) > commitDisplayLen {
		revision = revision[:commitDisplayLen]
	}
	if modified {
		return revision + dirtyMarker
	}
	return revision
}

// embeddedBuildSettings returns the build settings the Go toolchain recorded
// in this binary, or nil when the binary carries no build information.
func embeddedBuildSettings() []debug.BuildSetting {
	info, ok := debug.ReadBuildInfo()
	if !ok || info == nil {
		return nil
	}
	return info.Settings
}
