#!/usr/bin/env bash
# gen-confusables.sh regenerates internal/textdiff/confusables_table.go, the
# table textdiff.Skeleton looks code points up in, from the unmodified UTS #39
# data file in third_party/unicode/confusables.txt.
#
# Why a script: the table is committed so that a build needs neither the data
# file nor a parser at start-up, and a committed generated file is only
# trustworthy when anyone can regenerate it byte for byte. The generator,
# internal/textdiff/gen_confusables.go (built with the ignore tag, so it is
# never part of the package), pins the data file's "Version:" header and
# refuses any other version, so the table cannot move without the pin, the
# licence vendored next to the data file (third_party/unicode/LICENSE) and
# the version test moving with it. The lint job of ci.yml runs the --check
# form on every pull request.
#
# Usage:
#   scripts/gen-confusables.sh          regenerate in place
#   scripts/gen-confusables.sh --check  regenerate into a temp dir and compare only
#
# No network is used and nothing but the Go toolchain is needed.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
data="$root/third_party/unicode/confusables.txt"
licence="$root/third_party/unicode/LICENSE"
pkg_dir="$root/internal/textdiff"
generator="gen_confusables.go"
table="confusables_table.go"

mode="generate"
case "${1:-}" in
"") ;;
--check) mode="check" ;;
*)
	echo "usage: $0 [--check]" >&2
	exit 2
	;;
esac

die() {
	echo "gen-confusables: $*" >&2
	exit 1
}

[ -f "$data" ] || die "the data file $data is missing"
[ -f "$licence" ] || die "the licence $licence must be vendored next to the data file"
[ -f "$pkg_dir/$generator" ] || die "the generator $pkg_dir/$generator is missing"
command -v go >/dev/null 2>&1 || die "go is not installed"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/gen-confusables.XXXXXX")
cleanup() {
	rm -f "$tmp/$table"
	rmdir "$tmp"
}
trap cleanup EXIT

# The generator runs from the package directory with the data file and the
# output named explicitly; GOFLAGS=-mod=readonly as everywhere in this module.
(cd "$pkg_dir" && GOFLAGS=-mod=readonly go run "$generator" -in "$data" -out "$tmp/$table")

if cmp -s "$tmp/$table" "$pkg_dir/$table"; then
	echo "gen-confusables: $table is up to date"
	exit 0
fi
echo "gen-confusables: $table differs from the committed file"
if [ "$mode" = check ]; then
	die "the committed table does not match the vendored data file; run scripts/gen-confusables.sh and review the diff"
fi
cp "$tmp/$table" "$pkg_dir/$table"
echo "gen-confusables: regenerated $pkg_dir/$table; review the diff before committing"
