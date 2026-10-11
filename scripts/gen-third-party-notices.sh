#!/usr/bin/env bash
# shellcheck disable=SC2016  # the single-quoted printf formats contain Markdown backticks on purpose
# gen-third-party-notices.sh writes THIRD_PARTY_NOTICES.md from go.mod, the
# module graph and the licence files in the Go module cache.
#
# Why a script: a notices file typed by hand drifts from go.mod the first time
# a dependency moves. This one is derived. Which modules exist comes from
# go.mod and `go list -m all`; which of them reach a binary comes from
# `go list -deps`; every licence text is copied verbatim from the module cache.
# The one step a program cannot do is read a licence and name it, so the names
# live in licence_row below, each pinned to the SHA-256 of the files it was
# read from. A module or file the table does not know, or a text that changed,
# stops the script with instructions instead of guessing.
#
# Usage:
#   scripts/gen-third-party-notices.sh          rewrite THIRD_PARTY_NOTICES.md
#   scripts/gen-third-party-notices.sh --check  regenerate to a temp file, compare
#
# The module cache must hold the modules in go.mod (any build has done that)
# and every package of the module, tests included, must load, because the
# classification comes from `go list -deps -test ./...`; a tree that does not
# compile stops the script. No network is used. Works with the bash 3.2 that
# macOS ships.
set -euo pipefail
export GOFLAGS=-mod=readonly LC_ALL=C

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
out="$root/THIRD_PARTY_NOTICES.md"
mode=generate
case "${1:-}" in
"") ;;
--check) mode=check ;;
*)
	echo "usage: $0 [--check]" >&2
	exit 2
	;;
esac

die() {
	echo "gen-third-party-notices: $*" >&2
	exit 1
}

# licence_row prints "<licence name>|<file>=<sha256>,<file>=<sha256>..." for a
# module at an exact version. The name was read from those files by a person;
# the digests let the script prove the files are still the ones that were read.
# Files are listed in C-locale sorted order, every licence-like file included.
licence_row() { # module@version
	case "$1" in
	github.com/dustin/go-humanize@v1.0.1) echo 'MIT|LICENSE=a973b4498c13eb74baa2a8e5c351426a6826f2fcdd909916dbe53ee2e755fd71' ;;
	github.com/google/jsonschema-go@v0.4.3) echo 'MIT|LICENSE=2d56c53449691d85d9aea245eb8dac12713e9075d70d5557b82ae1e94805b357' ;;
	github.com/google/uuid@v1.6.0) echo 'BSD-3-Clause|LICENSE=0a8d61ed3cbfd5312326e8126c31ce9c627a283adc99131b56896d29ada04b2d' ;;
	github.com/gowebpki/jcs@v1.0.2) echo 'Apache-2.0|LICENSE=cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30' ;;
	github.com/mattn/go-isatty@v0.0.24) echo 'MIT|LICENSE=08eab1118c80885fa1fa6a6dd7303f65a379fcb3733e063d20d1bbc2c76e6fa1' ;;
	github.com/modelcontextprotocol/go-sdk@v1.8.0) echo 'Apache-2.0 and MIT, per contribution (transition notice; MIT attribution applies)|LICENSE=af679003d933f045393a6a029f43da113f9ae364eac651d9ae268392985580f5' ;;
	github.com/ncruces/go-strftime@v1.0.0) echo 'MIT|LICENSE=38ae43959daf953a393a585b2988672cb65a5a541aca0d0be5e72595a0a16883' ;;
	github.com/remyoudompheng/bigfft@v0.0.0-20230129092748-24d4a6f8daec) echo 'BSD-3-Clause|LICENSE=dd26a7abddd02e2d0aba97805b31f248ef7835d9e10da289b22e3b8ab78b324d' ;;
	github.com/segmentio/asm@v1.1.3) echo 'MIT|LICENSE=e2a78de21d6d8ded2dff0f3189cd32e011630d785da127ebfbc8949012c0947b' ;;
	github.com/segmentio/encoding@v0.5.4) echo 'MIT|LICENSE=d6d71a1f7dc6539e371120cc7af6e3257e55ca79634d473211f217b8965b0f16' ;;
	github.com/yosida95/uritemplate/v3@v3.0.2) echo 'BSD-3-Clause|LICENSE=0761aadfb1921103752869ee942d4a71bdd54494697684d4b13dc17ad9781191' ;;
	golang.org/x/net@v0.60.0) echo 'BSD-3-Clause, with the Go patent grant|LICENSE=911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad,PATENTS=96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc' ;;
	golang.org/x/oauth2@v0.36.0) echo 'BSD-3-Clause|LICENSE=911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad' ;;
	golang.org/x/sync@v0.23.0) echo 'BSD-3-Clause, with the Go patent grant|LICENSE=911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad,PATENTS=96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc' ;;
	golang.org/x/sys@v0.48.0) echo 'BSD-3-Clause, with the Go patent grant|LICENSE=911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad,PATENTS=96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc' ;;
	golang.org/x/text@v0.42.0) echo 'BSD-3-Clause, with the Go patent grant|LICENSE=911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad,PATENTS=96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc' ;;
	golang.org/x/time@v0.15.0) echo 'BSD-3-Clause, with the Go patent grant|LICENSE=911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad,PATENTS=96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc' ;;
	google.golang.org/genproto/googleapis/rpc@v0.0.0-20260817212433-ac3dfec99bb1) echo 'Apache-2.0|LICENSE=cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30' ;;
	google.golang.org/grpc@v1.86.0-dev) echo 'Apache-2.0, with a NOTICE file|LICENSE=cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30,NOTICE.txt=693ff28ec216d5112ac1bbfe64ef539005867d1c7bd427b57d579683293b947f' ;;
	google.golang.org/protobuf@v1.36.12) echo 'BSD-3-Clause, with the Go patent grant|LICENSE=4835612df0098ca95f8e7d9e3bffcb02358d435dbb38057c844c99d7f725eb20,PATENTS=96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc' ;;
	modernc.org/libc@v1.77.1) echo 'BSD-3-Clause; carries notices for Go (BSD-3-Clause), musl libc (MIT), go-netdb (MIT) and NixOS/nixpkgs (MIT)|LICENSE=95ff867eb55a56935fa7492406cfa953fb7c13ca73f4c0a86ae05756b4605600,LICENSE-3RD-PARTY.md=f597097efe3d97021f89170746bd3a0fb9a8b6fb26b82043ed68a4e0283bee6c' ;;
	modernc.org/mathutil@v1.7.1) echo 'BSD-3-Clause|LICENSE=bfa9bf72a72ca009fd62a8f84fca3dca67e51d93af96352723646599898b6cf5' ;;
	modernc.org/memory@v1.12.1) echo 'BSD-3-Clause; carries notices for Go (BSD-3-Clause) and mmap-go (BSD-3-Clause)|LICENSE=59895e669f48f168b6b858358f6005779cdf40a265f7828813061b56af67b496,LICENSE-GO=2d36597f7117c38b006835ae7f537487207d8ec407aa9d9980794b2030cbc067,LICENSE-LOGO=5ae5bee3072a841376451b48d8cfcec7188e10543926d5870828d36c8a750dc5,LICENSE-MMAP-GO=c2eba69f20d05414538c3a5df7694dde392e065ff70882e1625e90f5d6659fff' ;;
	modernc.org/sqlite@v1.60.1) echo 'BSD-3-Clause; carries the SQLite public-domain dedication and the MIT notice of sqlite-vec|LICENSE=c6fe05491a60ae13bcd223088d2705e36dede24e5587226231d2459ada5c4822,LICENSE-3RD-PARTY.md=b4366b9c27a9364633e015011a231913ed19bf1228f335bf617e50a6f7b168a6,LICENSE-SQLITE=8438c9c89b849131ead81d5435cb97fcf052df5b0b286dda8a2d4c29e6cb3fd0,LICENSE-SQLITE_VEC=6ce72bbe12d975bd5286e5ab0a064c069693300c47bccbc57bec18485f1621ea' ;;
	pgregory.net/rapid@v1.3.0) echo 'MPL-2.0|LICENSE=66a3107d5ad6a058aab753eaac2047ccb2ed0e39465dd0fe5844da3e300d5172' ;;
	# Modules below are in the module graph only; no package of theirs is built.
	github.com/golang-jwt/jwt/v5@v5.3.1) echo 'MIT|LICENSE=fe26ca41577b9b2b4448050a24b25e5753af66b5d5945d5d36094e7790bfcb2f' ;;
	github.com/golang/protobuf@v1.5.4) echo 'BSD-3-Clause|LICENSE=8778a9fc1eaffb03ab873caae251df2d224f6b5502be8777d3cd573a4dd43903' ;;
	github.com/google/go-cmp@v0.7.0) echo 'BSD-3-Clause|LICENSE=17b5d209ba8f9684257ecfcff87df6ceda6194143a8fbd074f29727cff6f0c40' ;;
	github.com/google/pprof@v0.0.0-20260802141513-ef3492d7dac3) echo 'Apache-2.0|LICENSE=cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30' ;;
	github.com/hashicorp/golang-lru/v2@v2.0.7) echo 'MPL-2.0|LICENSE=6c7088eb877b5d7e6e0e9d27e822ea25fcda2e83f9eba59bb5f1418a656796e0' ;;
	github.com/stretchr/testify@v1.12.1) echo 'MIT|LICENSE=f8e536c1c7b695810427095dc85f5f80d44ff7c10535e8a9486cf393e2599189' ;;
	go.yaml.in/yaml/v3@v3.0.5) echo 'MIT and Apache-2.0, by file, with a NOTICE file|LICENSE=d18f6323b71b0b768bb5e9616e36da390fbd39369a81807cca352de4e4e6aa0b,NOTICE=f6c2dd3a67b576eafb89b80200b8b1627230bf3821a0c14cb99a22ac19107d00' ;;
	golang.org/x/mod@v0.41.0) echo 'BSD-3-Clause, with the Go patent grant|LICENSE=911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad,PATENTS=96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc' ;;
	golang.org/x/tools@v0.50.0) echo 'BSD-3-Clause, with the Go patent grant|LICENSE=911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad,PATENTS=96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc' ;;
	gonum.org/v1/gonum@v0.17.0) echo 'BSD-3-Clause|LICENSE=b44d9e394ba3efc15de4e5a8ebd843bd8d6325f6ffbb0a4ff6db7181aa15dda3' ;;
	modernc.org/cc/v4@v4.29.7) echo 'BSD-3-Clause|LICENSE=1c77905db36f407e0fdb513f97f1f2a3f2282049ca273637841face982d5d003' ;;
	modernc.org/ccgo/v4@v4.36.1) echo 'BSD-3-Clause|LICENSE=343748b20da2ceb739c1ab7b85fe16f6fe4b67fad88fea40c5835a08383d8ffe' ;;
	modernc.org/fileutil@v1.4.0) echo 'BSD-3-Clause|LICENSE=7dc07397727fc500d5ce768d724e4d555eee8fb7687f421fd40d72249868b0ca' ;;
	modernc.org/gc/v2@v2.6.5) echo 'BSD-3-Clause (two notices: GC Authors and Go Authors)|LICENSE=4719790df5e9d33b1cef3a67df8264fb1e3e7f54f3ca900c562e84a951de62d9' ;;
	modernc.org/gc/v3@v3.1.5) echo 'BSD-3-Clause (two notices: GC Authors and Go Authors)|LICENSE=4719790df5e9d33b1cef3a67df8264fb1e3e7f54f3ca900c562e84a951de62d9' ;;
	modernc.org/goabi0@v0.2.0) echo 'BSD-3-Clause|LICENSE=6d33428c98f9d7113dfc86e17fca00f81aeaac33e02f79c8a5afafb0a5fd33c6' ;;
	modernc.org/opt@v0.2.0) echo 'BSD-3-Clause|LICENSE=7a0dd90f1d1c8fa80d03c1806bdd8e4dca7285fae9b4a34f2c4a8a2552fdd77c' ;;
	modernc.org/sortutil@v1.2.1) echo 'BSD-3-Clause|LICENSE=7bc9df688c16dd8e64463ec0ad66728730a0e1a70a1dbda3dcbcd8a9b45bfaab' ;;
	modernc.org/strutil@v1.2.1) echo 'BSD-3-Clause|LICENSE=0f594b710bedb0335b15155204150cb1aac98e76144b52b852b43ce6a65eaaad' ;;
	modernc.org/token@v1.1.0) echo 'BSD-3-Clause|LICENSE=2d36597f7117c38b006835ae7f537487207d8ec407aa9d9980794b2030cbc067' ;;
	*) return 1 ;;
	esac
}

# not_reproduced names the files of section 1 modules that are listed with
# their digest but not copied into Appendix A, with the reason.
not_reproduced() { # module@version/file
	case "$1" in
	modernc.org/sqlite@v1.60.1/LICENSE-3RD-PARTY.md) echo "the driver's own flattened account of its whole module graph, 1614 lines; every item of it that reaches a toolwarrant binary is covered by the files reproduced here" ;;
	modernc.org/memory@v1.12.1/LICENSE-LOGO) echo "a URL to a logo image, not code" ;;
	*) return 1 ;;
	esac
}

# files_of prints "<file>=<sha256>,..." for the licence-like files in a module
# directory, in the same order and format licence_row uses (the glob expands in
# C-locale order because LC_ALL=C is exported above).
files_of() { # dir
	local f name upper acc=""
	for f in "$1"/*; do
		[ -f "$f" ] || continue
		name=${f##*/}
		upper=$(printf '%s' "$name" | tr '[:lower:]' '[:upper:]')
		case "$upper" in
		LICEN[CS]E* | COPYING* | NOTICE* | PATENTS*) ;;
		*) continue ;;
		esac
		acc="$acc,$name=$(shasum -a 256 "$f" | cut -d' ' -f1)"
	done
	printf '%s\n' "${acc#,}"
}

# checked_name verifies a module against its licence_row and prints the name.
checked_name() { # module@version dir
	local row have
	row=$(licence_row "$1") || die "no licence_row for $1: read the licence files in $2, then add a row with their SHA-256 digests"
	have=$(files_of "$2")
	[ "$have" = "${row#*|}" ] || die "licence files of $1 changed (now: $have); read them again and update licence_row"
	printf '%s\n' "${row%%|*}"
}

tmp=$(mktemp -d "${TMPDIR:-/tmp}/third-party-notices.XXXXXX")
cleanup() {
	rm -f "$tmp/gomod" "$tmp/all" "$tmp/linked" "$tmp/tested" "$tmp/cmdlinked" \
		"$tmp/labels" "$tmp/carriers" "$tmp/digests" "$tmp/out.md"
	rmdir "$tmp"
}
trap cleanup EXIT
tab=$(printf '\t')

main_module=$(go list -m)
awk '/^require[[:space:]]*\(/ { f = 1; next } /^\)/ { f = 0 } f && NF { print $1 } /^require[[:space:]]+[^(]/ { print $2 }' go.mod | sort -u >"$tmp/gomod"
go list -m -f '{{.Path}}{{"\t"}}{{.Version}}{{"\t"}}{{.Dir}}' all | awk -F'\t' '$2 != ""' >"$tmp/all"

# module_pkgs lists the modules whose packages the given build needs.
module_pkgs() { # go list args...
	go list -deps -f '{{with .Module}}{{.Path}}{{end}}' "$@" | awk -v main="$main_module" 'NF && $0 != main' | sort -u
}
module_pkgs ./... >"$tmp/linked"
module_pkgs -test ./... >"$tmp/tested"
cmds=""
for d in cmd/*/; do
	d=${d%/}
	cmds="$cmds ${d#cmd/}"
done
: >"$tmp/cmdlinked"
for c in $cmds; do
	module_pkgs "./cmd/$c" | awk -v c="$c" '{ print c "\t" $0 }' >>"$tmp/cmdlinked"
done

in_list() { grep -qxF "$1" "$2"; }

# label_for registers a text by digest and prints its label (A1, A2, ...);
# the registry also remembers every module file that carries the text.
label_for() { # sha256 module@version/file
	local n
	if ! grep -q "^$1$tab" "$tmp/labels"; then
		n=$(($(wc -l <"$tmp/labels") + 1))
		printf '%s\t%s\n' "$1" "A$n" >>"$tmp/labels"
	fi
	printf '%s\t%s\n' "$1" "$2" >>"$tmp/carriers"
	awk -F'\t' -v s="$1" '$1 == s { print $2 }' "$tmp/labels"
}
: >"$tmp/labels"
: >"$tmp/carriers"
: >"$tmp/digests"

# text_cell lists a module's files with the first 12 digest characters and,
# when register is 1 (section 1), registers each text for Appendix A.
text_cell() { # module@version files register
	local item f sha cell="" reason label
	for item in $(printf '%s' "$2" | tr ',' ' '); do
		f=${item%%=*}
		sha=${item#*=}
		printf '%s/%s\t%s\n' "$1" "$f" "$sha" >>"$tmp/digests"
		if [ "$3" != 1 ]; then
			cell="$cell, $f (${sha:0:12})"
		elif reason=$(not_reproduced "$1/$f"); then
			cell="$cell, $f (${sha:0:12}; not reproduced: $reason)"
		else
			label=$(label_for "$sha" "$1/$f")
			cell="$cell, $f (${sha:0:12}; $label)"
		fi
	done
	printf '%s\n' "${cell#, }"
}

linked_into() { # module path
	local c acc=""
	for c in $cmds; do in_list "$c$tab$1" "$tmp/cmdlinked" && acc="$acc, $c"; done
	printf '%s\n' "${acc#, }"
}

write_header() {
	cat <<'HDR'
# Third-party notices

toolwarrant itself is licensed under the Apache License, Version 2.0 (see
LICENSE). This file accounts for every other module in its build. The licence
of each module is stated as it was read from the module's own licence files in
the Go module cache (`go env GOMODCACHE`), never from a package index or a web
page, and the SHA-256 of every file read is listed in Appendix B so that the
statement can be re-checked at any time:

    shasum -a 256 "$(go list -m -f '{{.Dir}}' <module>)/<file>"

Modules are classified by what they do to a toolwarrant binary, because "a
dependency" and "code in the binary" are different questions: section 1 is what
a redistribution of the binaries must carry, section 2 is test scaffolding that
no binary contains, section 3 is the rest of the module graph, which contributes
no code at all.

Generated by `scripts/gen-third-party-notices.sh` from go.mod, `go list -m all`
and `go list -deps`; `scripts/gen-third-party-notices.sh --check` fails when
go.mod or a licence text changed and this file was not regenerated. Do not edit
by hand. The output carries no timestamp, so a diff here means the third-party
content really changed.

HDR
}

write_section1() {
	local path ver dir key name files
	cat <<'S1'
## 1. Modules compiled into the toolwarrant binaries

Every module below contributes code to at least one binary under cmd/
(mockupstream, seamclient, seamgate and seamprocessor are the spike's seam
tools; toolwarrant is the control plane and processor). A redistribution of
those binaries must carry the texts marked in the fourth column; they are
reproduced verbatim in Appendix A. The digests are the first twelve characters
of the SHA-256 given in full in Appendix B.

| Module | Version | Licence | Files (SHA-256 prefix; text) | Linked into |
| --- | --- | --- | --- | --- |
S1
	while IFS="$tab" read -r path ver dir; do
		in_list "$path" "$tmp/gomod" || continue
		in_list "$path" "$tmp/linked" || continue
		key="$path@$ver"
		name=$(checked_name "$key" "$dir")
		files=$(text_cell "$key" "$(files_of "$dir")" 1)
		printf '| `%s` | %s | %s | %s | %s |\n' "$path" "$ver" "$name" "$files" "$(linked_into "$path")"
	done <"$tmp/all"
	cat <<'S1B'

Notices inherited through the modernc.org packages: `modernc.org/sqlite` is the
SQLite C library transpiled to Go (SQLite is public domain, LICENSE-SQLITE);
`modernc.org/libc` carries code from Go, musl libc, go-netdb and NixOS/nixpkgs
(LICENSE-3RD-PARTY.md); `modernc.org/memory` carries code from Go and mmap-go
(LICENSE-GO, LICENSE-MMAP-GO). All of those files are reproduced in Appendix A.
The sqlite-vec extension (LICENSE-SQLITE_VEC) and the demo VFS are linked only
when `modernc.org/sqlite/vec` or `modernc.org/sqlite/vfs` is imported; no
toolwarrant package imports either, so the only sqlite packages in the binaries
are `modernc.org/sqlite`, `modernc.org/sqlite/lib` and `modernc.org/sqlite/vtab`.
S1B
}

write_section2() {
	local path ver dir key name files any=0
	cat <<'S2'

## 2. Modules used only by the test suite

| Module | Version | Licence | Files (SHA-256 prefix) |
| --- | --- | --- | --- |
S2
	while IFS="$tab" read -r path ver dir; do
		in_list "$path" "$tmp/gomod" || continue
		in_list "$path" "$tmp/linked" && continue
		in_list "$path" "$tmp/tested" || continue
		any=1
		key="$path@$ver"
		name=$(checked_name "$key" "$dir")
		files=$(text_cell "$key" "$(files_of "$dir")" 0)
		printf '| `%s` | %s | %s | %s |\n' "$path" "$ver" "$name" "$files"
	done <"$tmp/all"
	[ "$any" = 1 ] || echo '| (none) | | | |'
	cat <<'S2B'

`pgregory.net/rapid` is the property-testing library behind the `*_test.go`
files that use it. It is imported by test files only, so no toolwarrant binary
contains any of its code and nothing built here is a "Larger Work" under the
Mozilla Public License 2.0. It is used unmodified, so the MPL's source
availability terms are met by the module itself. Its licence text is the file
`pgregory.net/rapid@v1.3.0/LICENSE` in the module cache (digest in Appendix B);
it is not reproduced here because nothing distributed from this repository
contains the covered software.
S2B
	write_section2b
}

write_section2b() {
	local path ver dir any=0
	while IFS="$tab" read -r path ver dir; do
		in_list "$path" "$tmp/gomod" || continue
		in_list "$path" "$tmp/linked" && continue
		in_list "$path" "$tmp/tested" && continue
		[ "$any" = 1 ] || printf '\nModules required by go.mod but compiled into nothing (should be empty):\n\n'
		any=1
		printf -- '- `%s` %s\n' "$path" "$ver"
	done <"$tmp/all"
}

write_section3() {
	local path ver dir key name files
	cat <<'S3'

## 3. Modules in the module graph only

These appear in `go list -m all` because a dependency's go.mod names them, but
no package of theirs is compiled into any toolwarrant binary or test. They are
listed so that the account of the graph is complete. Where the module is in the
local module cache its licence was read and is stated; where it is not, nothing
is stated, because nothing was read.

| Module | Version | In module cache | Licence as read | Files (SHA-256 prefix) |
| --- | --- | --- | --- | --- |
S3
	while IFS="$tab" read -r path ver dir; do
		in_list "$path" "$tmp/gomod" && continue
		key="$path@$ver"
		if [ -z "$dir" ]; then
			printf '| `%s` | %s | no | not inspected | |\n' "$path" "$ver"
		elif licence_row "$key" >/dev/null; then
			name=$(checked_name "$key" "$dir")
			files=$(text_cell "$key" "$(files_of "$dir")" 0)
			printf '| `%s` | %s | yes | %s | %s |\n' "$path" "$ver" "$name" "$files"
		else
			printf '| `%s` | %s | yes | not recorded (no code of it is built) | |\n' "$path" "$ver"
		fi
	done <"$tmp/all"
}

write_section4() {
	cat <<'S4'

## 4. Third-party material in the repository

- `third_party/agentgateway/ext_mcp.proto` is an unmodified copy of
  `crates/protos/proto/ext_mcp.proto` from agentgateway v1.6.0, licensed under
  the Apache License 2.0; `third_party/agentgateway/NOTICE` next to it records
  the origin and is reproduced below. `internal/extmcpv1` is generated from it
  by `scripts/gen-proto.sh`.
- The test suite runs the agentgateway v1.6.0 release binary from `.cache/`,
  which is git-ignored and is not part of the repository or of any artefact
  built from it.

````text
S4
	awk 1 third_party/agentgateway/NOTICE
	echo '````'
}

# module_dir looks a module@version up in the module list written above.
module_dir() { # module@version
	awk -F'\t' -v p="${1%@*}" -v v="${1##*@}" '$1 == p && $2 == v { print $3 }' "$tmp/all"
}

write_appendix_a() {
	local sha label carriers first dir
	cat <<'AA'

## Appendix A. Licence texts for section 1, verbatim

Each text appears once, under the module files that carry it (identical files
are listed together). The texts are copied byte for byte from the module cache;
the heading gives the SHA-256 of the file.
AA
	while IFS="$tab" read -r sha label; do
		carriers=$(awk -F'\t' -v s="$sha" '$1 == s { print $2 }' "$tmp/carriers" | sort -u | tr '\n' ' ')
		first=${carriers%% *}
		dir=$(module_dir "${first%/*}")
		[ -n "$dir" ] || die "no module directory for $first"
		printf '\n### %s. %s\n\nSHA-256 %s\n\n````text\n' "$label" "$(printf '%s' "$carriers" | sed 's/ $//; s/ /, /g')" "$sha"
		awk 1 "$dir/${first##*/}"
		echo '````'
	done <"$tmp/labels"
}

write_appendix_b() {
	cat <<'AB'

## Appendix B. SHA-256 of every licence file read

Paths are relative to the module cache: `module@version/file`.

AB
	sort -u "$tmp/digests" | awk -F'\t' '{ printf "    %s  %s\n", $2, $1 }'
}

{
	write_header
	write_section1
	write_section2
	write_section3
	write_section4
	write_appendix_a
	write_appendix_b
} >"$tmp/out.md"

if [ "$mode" = check ]; then
	if cmp -s "$tmp/out.md" "$out"; then
		echo "gen-third-party-notices: THIRD_PARTY_NOTICES.md is up to date"
		exit 0
	fi
	die "THIRD_PARTY_NOTICES.md is stale or hand-edited; run scripts/gen-third-party-notices.sh and review the diff"
fi
cp "$tmp/out.md" "$out"
echo "gen-third-party-notices: wrote ${out#"$root"/} ($(wc -l <"$out" | tr -d ' ') lines)"
