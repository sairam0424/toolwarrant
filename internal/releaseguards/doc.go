// Package releaseguards holds no code, only the tests of the three guards the
// Makefile's release-check target runs before goreleaser check (kept in their
// own target, release-guards): go.mod is there and carries no replace or
// exclude directive, so a release builds from published modules only (a
// retract is allowed, since that is how a bad tag is withdrawn, and a go.mod
// the guard cannot read is refused rather than passed as a no-match);
// CHANGELOG.md keeps a ## [Unreleased] heading for the next change to go
// under; and with VERSION=x.y.z the heading ## [x.y.z] - YYYY-MM-DD exists, so
// the release commit cannot be tagged before the changelog names the version.
// The tests copy the Makefile, go.mod and CHANGELOG.md into a scratch directory
// and run make there, so the tree is never edited and goreleaser is not needed;
// each refusal is pinned by the message the guard prints, so a guard failing
// for another reason is not mistaken for the right one.
//
// The package also holds the tests of scripts/release-notes.sh, the release
// workflow's notes step (decision D20 (d)): a final tag takes its own dated
// changelog section, a candidate takes the version's section once the release
// commit has added it and the Unreleased section until then, a section ends
// at the next level-two heading or the first link reference, and a missing
// heading, a heading that appears twice, an empty section or a tag that is not
// a version is refused with the exit status and message the script documents.
// The script runs against scratch changelogs written by the tests and once
// against the tree's own CHANGELOG.md for every released version; one more
// test reads release.yml and .goreleaser.yaml to pin that the workflow hands
// the file to goreleaser and that no changelog.disable line skips the pipe
// that reads it.
package releaseguards
