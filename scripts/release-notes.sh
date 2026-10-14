#!/usr/bin/env bash
# release-notes.sh prints the CHANGELOG.md section a tag publishes as its
# release notes, so that a release carries the prose the pull requests wrote
# under the keep-a-changelog headings and never the raw commit list (decision
# D20 (d) in docs/decisions.md).
#
# Why a script: the release workflow runs it before goreleaser and hands the
# output to `goreleaser release --release-notes`; a script beside the Makefile
# can be run by hand before a tag and is pinned by the tests of
# internal/releaseguards, where the same lines inside the workflow file could
# not be.
#
# Usage:
#   scripts/release-notes.sh vX.Y.Z [CHANGELOG.md]       the `## [X.Y.Z] - YYYY-MM-DD` section
#   scripts/release-notes.sh vX.Y.Z-rc.N [CHANGELOG.md]  the `## [X.Y.Z] - YYYY-MM-DD` section once the
#                                                        release commit has added it, else `## [Unreleased]`
#
# A candidate is cut either before the release commit, while the lines still
# sit under Unreleased, or on the release commit itself, when they sit under
# the version's heading; both orders give the candidate the notes the final
# tag will carry. The section runs from the line after its heading to the next
# `## ` heading or the first link reference definition (`[x.y.z]: https://...`
# at the end of the file), whichever comes first; blank lines at both ends are
# dropped. The script exits 1 when the heading is missing, is there more than
# once or has no text under it, and 2 for a tag that is not a version or a
# file it cannot read, so the workflow stops before goreleaser creates a draft
# with empty notes. The section is printed on stdout; which section was taken
# is said on stderr.
set -euo pipefail

usage="usage: $0 vX.Y.Z[-pre] [CHANGELOG.md]"

die() { # exit-status message
	local status=$1
	shift
	echo "release-notes: $*" >&2
	exit "$status"
}

tag="${1:-}"
changelog="${2:-CHANGELOG.md}"
[ -n "$tag" ] || die 2 "$usage"
[ "$#" -le 2 ] || die 2 "$usage"
# The tag is spliced into a pattern and into file names downstream, so it must
# be a version and nothing else: v, three numbers, an optional pre-release.
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || die 2 "tag '$tag' is not a version tag (vX.Y.Z or vX.Y.Z-rc.N); $usage"
[ -r "$changelog" ] || die 2 "cannot read $changelog"

version=${tag#v}
base=${version%%-*}
pre=${version#"$base"}

# dated_heading_count prints how many lines are the dated heading of a version.
dated_heading_count() { # version
	local pattern
	pattern="^## \\[${1//./\\.}\\] - [0-9]{4}-[0-9]{2}-[0-9]{2}\$"
	grep -cE "$pattern" "$changelog" || true
}

# dated_heading_line prints the one dated heading line of a version.
dated_heading_line() { # version
	local pattern
	pattern="^## \\[${1//./\\.}\\] - [0-9]{4}-[0-9]{2}-[0-9]{2}\$"
	grep -E "$pattern" "$changelog"
}

count=$(dated_heading_count "$base")
if [ "$count" -gt 1 ]; then
	die 1 "the heading '## [$base] - YYYY-MM-DD' appears $count times in $changelog; a version has one section"
fi
if [ "$count" -eq 1 ]; then
	heading=$(dated_heading_line "$base")
	label="[$base]"
elif [ -n "$pre" ]; then
	heading="## [Unreleased]"
	label="[Unreleased]"
	grep -qxF "$heading" "$changelog" || die 1 "$changelog has neither a '## [$base] - YYYY-MM-DD' heading nor the '## [Unreleased]' heading a candidate's notes come from (CONTRIBUTING.md, Before you open a pull request)"
else
	die 1 "$changelog has no '## [$version] - YYYY-MM-DD' heading; the release commit adds it above the Unreleased lines it moves (CONTRIBUTING.md); a candidate tag takes the Unreleased section until then"
fi

# The section: every line after the heading up to the next level-two heading
# or the first link reference definition, with blank lines trimmed at both
# ends. The heading is compared as a whole line, never as a pattern, so the
# text of the file cannot change what is matched.
section=$(awk -v h="$heading" '
	found && (/^## / || /^\[[^]]+\]: /) { exit }
	found { lines[++n] = $0; if (NF) { if (!first) first = n; last = n }; next }
	$0 == h { found = 1 }
	END { if (!first) exit; for (i = first; i <= last; i++) print lines[i] }
' "$changelog")

[ -n "$section" ] || die 1 "the $label section of $changelog is empty; the release commit moves the Unreleased lines under the version's heading (CONTRIBUTING.md), and a candidate needs text under Unreleased or under its version"

echo "release-notes: $tag takes the $label section of $changelog ($(printf '%s\n' "$section" | wc -l | tr -d ' ') lines)" >&2
printf '%s\n' "$section"
