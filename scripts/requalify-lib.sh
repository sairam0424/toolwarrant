# shellcheck shell=sh
# requalify-lib.sh: the helpers of scripts/requalify-gateway.sh, sourced by
# it after it defined die. Kept apart so that each file stays readable; the
# functions that keep temporaries run in a subshell (parenthesised bodies) so
# that POSIX sh needs no local variables. Nothing here runs the gateway.

# platform_asset prints the release asset name for this host, or dies: the
# release ships linux/amd64, linux/arm64 and darwin/arm64 binaries only.
platform_asset() (
	case "$(uname -s)/$(uname -m)" in
	Darwin/arm64) echo agentgateway-darwin-arm64 ;;
	Linux/x86_64) echo agentgateway-linux-amd64 ;;
	Linux/aarch64 | Linux/arm64) echo agentgateway-linux-arm64 ;;
	*) die "no agentgateway release asset is known for $(uname -s)/$(uname -m); run on linux/amd64, linux/arm64 or darwin/arm64" ;;
	esac
)

# fetch downloads url into dest through a temporary name, so a failed
# download never leaves a partial file where a later run would trust it. With
# a non-empty description a failure is fatal and names what was wanted; with
# an empty one the caller decides.
fetch() { # url dest description
	if curl -fsSL --retry 3 -o "$2.part" "$1"; then
		mv "$2.part" "$2"
		return 0
	fi
	rm -f "$2.part"
	[ -z "$3" ] || die "cannot fetch $3 ($1)"
	return 1
}

# sha256_of prints the SHA-256 of a file with whichever tool the host has.
sha256_of() (
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	else
		shasum -a 256 "$1" | awk '{print $1}'
	fi
)

# extract_block prints one object of the pretty-printed schema: from the line
# `<indent>"<name>": {` to the first `<indent>}` or `<indent>},` after it.
# The schema is written by a JSON pretty-printer with two-space indentation,
# so a definition's closing brace is the first one back at its own indent.
# Nothing is printed when the name is absent.
extract_block() ( # file indent name
	awk -v open="$2\"$3\": {" -v end1="$2}" -v end2="$2}," '
		$0 == open { p = 1 }
		p { print }
		p && ($0 == end1 || $0 == end2) { exit }' "$1"
)

# count_keys prints how many object members the named block has one level
# in, or ? when the block is absent.
count_keys() ( # file indent name
	block=$(extract_block "$1" "$2" "$3")
	[ -n "$block" ] || {
		echo "?"
		exit 0
	}
	printf '%s\n' "$block" | grep -c "^$2  \"[^\"]*\": {\$" || true
)

# count_props prints how many properties a definition declares, or ? when the
# definition or its properties block is absent.
count_props() ( # file name
	block=$(extract_block "$1" "    " "$2")
	[ -n "$block" ] || {
		echo "?"
		exit 0
	}
	printf '%s\n' "$block" | awk '
		$0 == "      \"properties\": {" { q = 1; next }
		q && /^        "[^"]+": \{/ { n++ }
		q && ($0 == "      }" || $0 == "      },") { print n + 0; found = 1; exit }
		END { if (!found) print "?" }'
)

# enum_values prints the enum of a string definition as a comma-separated
# list, or nothing when it has none.
enum_values() ( # file name
	extract_block "$1" "    " "$2" | tr -d ' \n' | sed -n 's/.*"enum":\[\([^]]*\)\].*/\1/p' | tr -d '"'
)

# enums_of prints the three enumerations item 4 compares: the processor kinds
# (the const values inside Processor), the failure modes and the phases.
enums_of() ( # file
	kind=$(extract_block "$1" "    " Processor | sed -n 's/^ *"const": "\([^"]*\)",*$/\1/p' | sort -u | tr '\n' ',' | sed 's/,$//')
	echo "kind ${kind:-?}; failureMode $(enum_values "$1" FailureMode); phases $(enum_values "$1" Phase)"
)

# rmcp_versions prints every version of the rmcp crate a Cargo.lock resolves,
# sorted, on one line.
rmcp_versions() ( # file
	awk '$0 == "name = \"rmcp\"" { getline; sub(/^version = /, ""); gsub(/"/, ""); print }' "$1" | sort | awk '{ printf "%s%s", sep, $0; sep = " " } END { print "" }'
)

# tests_passed succeeds when every named top-level test has a PASS line in a
# go test -v log; otherwise it prints the names that have none and fails. A
# test that did not run counts as not passed: a renamed test must be renamed
# here too, which internal/requalifypolicy enforces.
tests_passed() ( # log name...
	log=$1
	shift
	missing=""
	for n in "$@"; do
		grep -q "^--- PASS: $n " "$log" || missing="$missing $n"
	done
	[ -z "$missing" ] && exit 0
	printf '%s' "${missing# }"
	exit 1
)

# scenario_passed succeeds when the named e2e subtest has a PASS line.
scenario_passed() { # TestEndToEnd/Name
	grep -q "^ *--- PASS: $1 " "$e2e_log"
}

# words prints how many words a string holds.
words() {
	printf '%s\n' "$1" | wc -w | tr -d ' '
}

# report prints one item line and records its status for the summary.
report() { # status number title detail
	printf '%s %2s/%s %s: %s\n' "$1" "$2" "$items_total" "$3" "$4"
	printf '%s\n' "$1" >>"$results"
}

# report_run prints how a test run ended, naming every failed test, so that a
# failure no item reads is never hidden; a failed run fails the whole script.
report_run() { # title log
	code=$(cat "$2.exit")
	if [ "$code" = 0 ]; then
		echo "RUN $1: exit 0 (${2#"$root"/})"
		return 0
	fi
	echo "RUN $1: exit $code; failed: $(grep '^ *--- FAIL: ' "$2" | awk '{print $3}' | tr '\n' ' ')(${2#"$root"/})"
	echo RUNFAIL >>"$results"
}

# summarise prints the counts and exits as the header of the script states.
summarise() {
	pass=$(grep -c '^PASS$' "$results" || true)
	changed=$(grep -c '^CHANGED$' "$results" || true)
	skipped=$(grep -c '^SKIPPED$' "$results" || true)
	pending=$(grep -c '^PENDING$' "$results" || true)
	failed=$(grep -c '^RUNFAIL$' "$results" || true)
	echo "requalify-gateway: $candidate against the pin $pinned: $pass PASS, $changed CHANGED, $skipped SKIPPED, $pending PENDING; the pin may move only when every item is PASS and item 15 has landed; artefacts under ${out#"$root"/}"
	if [ "$changed" -gt 0 ] || [ "$failed" -gt 0 ]; then
		exit 1
	fi
	[ "$skipped" -eq 0 ] || exit 3
	exit 0
}
