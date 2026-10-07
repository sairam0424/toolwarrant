#!/usr/bin/env bash
# gen-proto.sh regenerates the ExtMCP gRPC stubs in internal/extmcpv1 from the
# unmodified agentgateway proto in third_party/agentgateway/ext_mcp.proto.
#
# Why a script: the stubs are committed so that a build needs no protoc, and a
# committed generated file is only trustworthy when anyone can regenerate it
# byte for byte. The generated headers record the exact protoc, protoc-gen-go
# and protoc-gen-go-grpc versions that produced them; this script refuses any
# other version, because a different generator version changes the output and
# the resulting diff would hide a real change in the proto.
#
# Usage:
#   scripts/gen-proto.sh          regenerate in place (refused if versions differ)
#   scripts/gen-proto.sh --check  regenerate into a temp dir and compare only
#
# No network is used: protoc and both plugins must already be installed. The
# plugins are looked up in PATH first and then in $(go env GOPATH)/bin.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
proto_dir="$root/third_party/agentgateway"
proto_file="ext_mcp.proto"
out_dir="$root/internal/extmcpv1"
go_file="ext_mcp.pb.go"
grpc_file="ext_mcp_grpc.pb.go"

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
	echo "gen-proto: $*" >&2
	exit 1
}

# recorded_version prints the version a generated header records for a tool,
# for example v1.36.12 from "// <tab>protoc-gen-go v1.36.12" or v7.36.2 from
# "// - protoc             v7.36.2". The tool name must be followed by spaces
# so that protoc does not match protoc-gen-go and protoc-gen-go does not match
# protoc-gen-go-grpc.
recorded_version() { # file tool
	local v
	v=$(grep -m1 -E "^//[[:space:]-]*$2[[:space:]]+v[0-9]" "$1" | awk '{print $NF}') || true
	[ -n "$v" ] || die "no $2 version is recorded in ${1##*/}"
	printf '%s\n' "$v"
}

# installed_version prints "v<version>" from a tool's --version output, which
# is "protoc-gen-go v1.36.12", "protoc-gen-go-grpc 1.6.2" or "libprotoc 36.2".
installed_version() { # tool
	local v
	v=$("$1" --version 2>/dev/null | awk '{print $NF}') || die "cannot run $1 --version"
	[ -n "$v" ] || die "$1 --version printed nothing"
	printf 'v%s\n' "${v#v}"
}

# require_same fails loudly, naming both versions, unless they are equal.
require_same() { # tool recorded installed
	if [ "$2" != "$3" ]; then
		die "$1: the committed stubs were generated with $2 but the installed $1 is $3; install the recorded version (or regenerate everything on purpose and commit the new headers)"
	fi
}

gobin=$(go env GOPATH)/bin
export PATH="$PATH:$gobin"
for tool in protoc protoc-gen-go protoc-gen-go-grpc; do
	command -v "$tool" >/dev/null 2>&1 || die "$tool is not installed (looked in PATH and $gobin)"
done

want_gen_go=$(recorded_version "$out_dir/$go_file" protoc-gen-go)
want_gen_grpc=$(recorded_version "$out_dir/$grpc_file" protoc-gen-go-grpc)
want_protoc=$(recorded_version "$out_dir/$go_file" protoc)
have_gen_go=$(installed_version protoc-gen-go)
have_gen_grpc=$(installed_version protoc-gen-go-grpc)
have_protoc=$(installed_version protoc)

require_same protoc-gen-go "$want_gen_go" "$have_gen_go"
require_same protoc-gen-go-grpc "$want_gen_grpc" "$have_gen_grpc"
# protoc reports itself to plugins as v<api-major>.<minor>.<patch> (v7.36.2) but
# prints the release number, libprotoc 36.2, to --version. Compare the release
# number here; the header comparison below is the exact check.
require_same protoc "${want_protoc#v*.}" "${have_protoc#v}"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/gen-proto.XXXXXX")
cleanup() {
	rm -f "$tmp/$go_file" "$tmp/$grpc_file"
	rmdir "$tmp"
}
trap cleanup EXIT

protoc -I "$proto_dir" \
	--go_out="$tmp" --go_opt=paths=source_relative \
	--go-grpc_out="$tmp" --go-grpc_opt=paths=source_relative \
	"$proto_file"

# The exact check: the headers the generator just wrote must record the same
# versions as the committed files, whatever --version printed.
same_header() { # file tool
	require_same "$2 (header of $1)" "$(recorded_version "$out_dir/$1" "$2")" "$(recorded_version "$tmp/$1" "$2")"
}
same_header "$go_file" protoc-gen-go
same_header "$go_file" protoc
same_header "$grpc_file" protoc-gen-go-grpc
same_header "$grpc_file" protoc

changed=0
for f in "$go_file" "$grpc_file"; do
	if cmp -s "$tmp/$f" "$out_dir/$f"; then
		echo "gen-proto: $f is up to date"
	else
		changed=1
		echo "gen-proto: $f differs from the committed file"
	fi
done

if [ "$mode" = check ]; then
	[ "$changed" -eq 0 ] || die "the committed stubs do not match the proto; run scripts/gen-proto.sh and review the diff"
	exit 0
fi
if [ "$changed" -eq 0 ]; then
	echo "gen-proto: nothing to do"
	exit 0
fi
cp "$tmp/$go_file" "$out_dir/$go_file"
cp "$tmp/$grpc_file" "$out_dir/$grpc_file"
echo "gen-proto: regenerated $out_dir; review the diff before committing"
