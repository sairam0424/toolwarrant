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
package releaseguards
