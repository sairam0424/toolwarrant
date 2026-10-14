#!/bin/sh
# requalify-gateway.sh: the re-qualification checklist for moving the
# agentgateway pin (known limit L7), run against one candidate release.
#
# Why a script: agentgateway is pinned to one release because its config
# schema is unversioned and the ExtMCP protocol is young; every other release
# is unqualified until the seventeen items of docs/operations.md, "Moving the
# gateway pin (L7)", have been checked against it. Checking them by hand is
# slow and forgetful, so this script fetches what the items compare, runs the
# binary-backed tests and (with --e2e) the end-to-end test against the
# candidate, and prints one PASS or CHANGED line per item. CHANGED is work to
# do before the pin moves, not a verdict on the release.
#
# Usage:
#   scripts/requalify-gateway.sh vX.Y.Z SHA256 [--e2e]
#   scripts/requalify-gateway.sh vX.Y.Z SHA256 --reuse
#
# SHA256 is the SHA-256 of the candidate release's agentgateway-linux-amd64
# asset, the value AGENTGATEWAY_SHA256 in .github/workflows/ci.yml takes when
# the pin moves; the script checks it against the digest the release
# publishes beside that asset and, on a linux/amd64 host, against the
# downloaded binary itself, as the e2e job does. The binary for the host's
# own platform is downloaded into .cache/candidate/<version>/ (or used from
# there when already present) and checked against its own published digest.
# --e2e also runs make e2e with the candidate; without it the items that need
# a running gateway are SKIPPED. --reuse runs nothing and re-reads the
# artefacts of an earlier run. The gateway binary is run only through the
# binary-backed tests (--validate-only) and, with --e2e, inside make e2e.
#
# Exit status: 0 when every item that ran is PASS, 1 when any item is CHANGED
# or a test run failed, 2 for a usage error, 3 when nothing is CHANGED but
# items were SKIPPED (run again with --e2e).
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
ci_file="$root/.github/workflows/ci.yml"
upstream_repo="agentgateway/agentgateway"
raw_base="https://raw.githubusercontent.com/$upstream_repo"
release_base="https://github.com/$upstream_repo/releases/download"
schema_path="schema/config.json"
proto_path="crates/protos/proto/ext_mcp.proto"
lock_path="Cargo.lock"
vendored_proto="$root/third_party/agentgateway/ext_mcp.proto"
linux_asset="agentgateway-linux-amd64"
laptop_asset="agentgateway-darwin-arm64"
items_total=17
# The schema definitions the emitted file writes into or the canary reads
# (item 2): the config block, a gateway, a route and its match, the route
# policies, the two MCP policies, the processor with its failure mode,
# phases, header filter, metadata and backend policies, and the mcp backend
# with its targets; the root section list is compared beside them. A change
# outside them is reported by size only.
schema_defs="RawConfig LocalGateway LocalAttachedRoute LocalGatewayRefs RouteMatch PathMatch FilterOrPolicy McpAuthorization RuleSet RuleSerde McpGuardrails Processor FailureMode Phase HeaderFilter HeaderOrPseudo Expression SimpleLocalBackendPolicies LocalBackendTLS LocalRouteBackend LocalMcpBackend LocalMcpTarget NamespacedHostname"
# The tests behind items 8, 10, 12, 13, 14 and 15, by exact name; the policy
# test in internal/requalifypolicy fails when one of them no longer exists.
tests_dollar="TestGatewaySubstitutesEnvironmentIntoTheRawFile TestGoldenFilesValidateWithRealGateway TestDollarEscapeIsPinned TestDollarSignNeverReachesTheFile"
tests_admin="TestVerifyGatewayComparesTheLiveConfigurationWithTheEmittedFile TestLiveComparisonCatchesAnAddedOpenGateway TestVerifyGatewayLiveComparisonFailsClosed"
tests_headers="TestGatewayParsesTheRequestHeaderFilter TestGatewayAcceptsEachHalfOfTheFilterAlone"
tests_listeners="TestGatewayReadsListenerPinsExactly TestGatewayParsesListenerAddresses TestGatewayParsesBindAddress TestEveryBindAddressClassValidates"
tests_lenient="TestGatewayAcceptsAProcessorOnItsOwnSocket TestGatewayAcceptsAProcessorNamedForItsOwnSocket TestGatewayAcceptsAmbiguousProcessorSpellings TestEmitterBindRulesAreStricterThanTheGateway TestEmitterNameRuleIsStricterThanTheGateway TestEmitterURLRuleIsStricterThanTheGateway TestGatewayAcceptsTheShadowRouteDocument TestGatewayAcceptsAMixedGatewaysAndBindsDocument TestGatewayAcceptsExtraRoutePoliciesAndBackends"
tests_tls="TestGatewayParsesBackendTLS TestGatewayValidateOnlyOpensBackendTLSFiles TestEmitWithTheGatewayBinaryNeedsTheTLSFilesOnThisHost"
# The e2e scenario each running-gateway item reads, as go test -v names it.
scenario_probe="TestEndToEnd/O_UnhookedCallProbe"
scenario_golden="TestEndToEnd/L_VendorExtensionMismatch"
scenario_admin="TestEndToEnd/P_LiveConfigComparison"
scenario_shared="TestEndToEnd/H_SharedSecret"
scenario_cross="TestEndToEnd/J_CrossServerAndDuplicatePage"
scenario_tls="TestEndToEnd/Q_ProcessorTLS"
# oversized_bytes is e2e's oversizedPadBytes (9 << 20), the page the gateway
# answers 500 before the hook (item 11).
oversized_bytes=9437184

usage() {
	echo "usage: $0 vX.Y.Z SHA256 [--e2e|--reuse]" >&2
	exit 2
}

die() {
	echo "requalify-gateway: $*" >&2
	exit 1
}

# shellcheck source-path=SCRIPTDIR
# shellcheck source=requalify-lib.sh
. "$root/scripts/requalify-lib.sh"

[ $# -ge 2 ] && [ $# -le 3 ] || usage
candidate=$1
given_digest=$(printf '%s' "$2" | tr 'A-F' 'a-f')
mode=run
case "${3:-}" in
"") ;;
--e2e) mode=e2e ;;
--reuse) mode=reuse ;;
*) usage ;;
esac
printf '%s\n' "$candidate" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$' || die "the version must look like vX.Y.Z, got $(printf '%s' "$candidate" | tr -c 'A-Za-z0-9.-' '?')"
printf '%s\n' "$given_digest" | grep -Eq '^[0-9a-f]{64}$' || die "the SHA-256 must be 64 hex digits"

pinned=$(sed -n 's/^ *AGENTGATEWAY_VERSION: *\(v[0-9][0-9.]*\) *$/\1/p' "$ci_file" | head -1)
[ -n "$pinned" ] || die "cannot read AGENTGATEWAY_VERSION from $ci_file"
asset=$(platform_asset)
out="$root/.cache/candidate/$candidate"
up="$out/upstream"
diffs="$out/diffs"
results="$out/results.txt"
tests_log="$out/tests.log"
e2e_log="$out/e2e.log"
e2e_report="$out/e2e-report.log"
e2e_work="$out/e2e-work"
binary="$out/$asset"
mkdir -p "$up/$pinned" "$up/$candidate" "$diffs"
: >"$results"
echo "requalify-gateway: candidate $candidate ($asset) against the pin $pinned; artefacts under ${out#"$root"/}"

# fetch_upstream puts the three compared files of one tag under upstream/.
fetch_upstream() { # tag
	for p in "$schema_path" "$proto_path" "$lock_path"; do
		fetch "$raw_base/$1/$p" "$up/$1/$(basename "$p")" "$p at $1 (the file moved; adjust the path constants of this script)"
	done
}

# check_release fetches the published digests, refuses a SHA256 argument the
# release does not publish for the linux asset, and leaves the candidate
# binary for this platform at $binary, downloaded unless already present and
# checked against its own published digest either way.
check_release() {
	fetch "$release_base/$candidate/$linux_asset.sha256" "$out/$linux_asset.sha256" "the published digest of $linux_asset at $candidate (is the tag released, and is that still the asset's name?)"
	published=$(awk '{print $1}' "$out/$linux_asset.sha256")
	[ "$published" = "$given_digest" ] || die "the SHA-256 given is not the one the release publishes for $linux_asset at $candidate ($published); check the release page, nothing was run"
	fetch "$release_base/$candidate/$asset.sha256" "$out/$asset.sha256" "the published digest of $asset at $candidate"
	if [ ! -f "$binary" ]; then
		echo "requalify-gateway: downloading $asset at $candidate into ${out#"$root"/}/"
		fetch "$release_base/$candidate/$asset" "$binary" "$asset at $candidate"
	fi
	want=$(awk '{print $1}' "$out/$asset.sha256")
	got=$(sha256_of "$binary")
	[ "$want" = "$got" ] || die "$binary hashes to $got but the release publishes $want for $asset at $candidate; remove the file and run again"
	chmod +x "$binary"
}

# run_tests runs the two packages whose tests drive the gateway binary with
# --validate-only, every test of them so that none is left out by name, and
# refuses a run in which a gateway test skipped: a skip means the binary was
# not exercised.
run_tests() {
	echo "requalify-gateway: go test -race ./internal/emit/ ./cmd/toolwarrant/ with the candidate binary (about two minutes)"
	code=0
	(cd "$root" && GOFLAGS=-mod=readonly TOOLWARRANT_AGENTGATEWAY="$binary" TOOLWARRANT_GATEWAY_BIN="$binary" go test -race -count=1 -timeout 1500s -v ./internal/emit/ ./cmd/toolwarrant/) >"$tests_log" 2>&1 || code=$?
	echo "$code" >"$tests_log.exit"
	if grep -q "NOT VALIDATED AGAINST THE REAL GATEWAY\|the real agentgateway binary is not at" "$tests_log"; then
		die "a gateway test skipped, so the candidate binary was not exercised; see $tests_log"
	fi
}

# run_e2e runs make e2e with the candidate, keeping the process logs under
# e2e-work/ and the scenario notes in e2e-report.log for the items to read.
run_e2e() {
	echo "requalify-gateway: make e2e with the candidate binary (about a minute)"
	rm -rf "$e2e_work" "$e2e_report"
	mkdir -p "$e2e_work"
	code=0
	(cd "$root" && TOOLWARRANT_GATEWAY_BIN="$binary" TOOLWARRANT_E2E_WORKDIR="$e2e_work" TOOLWARRANT_E2E_REPORT_FILE="$e2e_report" make e2e) >"$e2e_log" 2>&1 || code=$?
	echo "$code" >"$e2e_log.exit"
	if grep -q -- '--- SKIP: TestEndToEnd ' "$e2e_log"; then
		die "the end-to-end test skipped instead of running against $binary; see $e2e_log"
	fi
}

case "$mode" in
reuse)
	for f in "$up/$pinned/config.json" "$up/$candidate/config.json" "$tests_log" "$tests_log.exit"; do
		[ -f "$f" ] || die "--reuse needs the artefacts of an earlier run; $f is missing"
	done
	;;
*)
	fetch_upstream "$pinned"
	fetch_upstream "$candidate"
	check_release
	run_tests
	[ "$mode" = e2e ] && run_e2e
	;;
esac
have_e2e=no
[ -f "$e2e_log.exit" ] && have_e2e=yes

# The test runs come first, so that a failing test is never hidden behind the
# items that happened not to read it.
report_run "binary-backed tests (go test -race ./internal/emit/ ./cmd/toolwarrant/)" "$tests_log"
if [ "$have_e2e" = yes ]; then
	report_run "end-to-end test (make e2e)" "$e2e_log"
fi

# Item 1: the unhooked-call probe. Scenario O notes which shape it saw.
item_probe() (
	if [ "$have_e2e" = no ]; then
		report SKIPPED 1 "unhooked-call probe answers 202 (L17)" "needs --e2e ($scenario_probe)"
	elif scenario_passed "$scenario_probe" && grep -q '^O: the hostile upstream.s request log gained .* the gateway forwarded the id-less call' "$e2e_report"; then
		report PASS 1 "unhooked-call probe answers 202 (L17)" "scenario O saw the id-less tools/call forwarded to the upstream without the hook, as the documents say of $pinned"
	else
		report CHANGED 1 "unhooked-call probe answers 202 (L17)" "scenario O no longer records the forwarded id-less call ($(grep '^O: ' "$e2e_report" | head -1 | cut -c1-160)); rewrite the L17 text in README.md (canary step), SECURITY.md (hardening checklist), docs/operations.md (Running the canary), docs/threat-model.md (L17 and row 25) and the --no-probe help in cmd/toolwarrant/verify.go"
	fi
)

# Item 2: the schema, filtered to the definitions toolwarrant writes or reads.
item_schema() (
	a="$up/$pinned/config.json"
	b="$up/$candidate/config.json"
	changed=""
	for name in properties $schema_defs; do
		indent="    "
		[ "$name" = properties ] && indent="  "
		extract_block "$a" "$indent" "$name" >"$diffs/$name.pinned"
		extract_block "$b" "$indent" "$name" >"$diffs/$name.candidate"
		if ! cmp -s "$diffs/$name.pinned" "$diffs/$name.candidate"; then
			changed="$changed $name"
			diff -u "$diffs/$name.pinned" "$diffs/$name.candidate" >"$diffs/config.json.$name.diff" || true
		fi
		rm -f "$diffs/$name.pinned" "$diffs/$name.candidate"
	done
	counts="sections $(count_keys "$a" "  " properties)>$(count_keys "$b" "  " properties), route policies $(count_props "$a" FilterOrPolicy)>$(count_props "$b" FilterOrPolicy), config fields $(count_props "$a" RawConfig)>$(count_props "$b" RawConfig) (pinned>candidate; cmd/toolwarrant/liveshape.go and liveadmin.go state them)"
	whole="the whole schema is identical"
	if ! cmp -s "$a" "$b"; then
		diff -u "$a" "$b" >"$diffs/config.json.diff" || true
		whole="the whole schema differs in $(grep -c '^[-+][^-+]' "$diffs/config.json.diff") lines (${diffs#"$root"/}/config.json.diff)"
	fi
	if [ -z "$changed" ]; then
		report PASS 2 "config.json" "the $(words "$schema_defs") definitions the emitted file and the canary read, and the root section list, are identical at $pinned and $candidate; $whole; $counts"
	else
		report CHANGED 2 "config.json" "changed at $candidate:${changed} (${diffs#"$root"/}/config.json.<name>.diff); $whole; $counts; re-check internal/emit and the shapes of cmd/toolwarrant/liveshape.go"
	fi
)

# Item 3: the ExtMCP protocol definition.
item_proto() (
	a="$up/$pinned/ext_mcp.proto"
	b="$up/$candidate/ext_mcp.proto"
	cmp -s "$a" "$vendored_proto" || die "third_party/agentgateway/ext_mcp.proto is not the file at the $pinned tag; the vendored copy must be unmodified"
	if cmp -s "$a" "$b"; then
		report PASS 3 "ext_mcp.proto" "identical at $pinned and $candidate and to third_party/agentgateway/ext_mcp.proto"
	else
		diff -u "$a" "$b" >"$diffs/ext_mcp.proto.diff" || true
		touched=$(grep '^[-+]' "$diffs/ext_mcp.proto.diff" | grep -o 'McpRequest\|headers\|metadata_context\|service_names\|McpResponse' | sort -u | tr '\n' ' ')
		report CHANGED 3 "ext_mcp.proto" "differs at $candidate (${diffs#"$root"/}/ext_mcp.proto.diff; touches: ${touched:-no field the processor reads}); copy it into third_party/agentgateway/, record the tag's commit in NOTICE, run go generate ./internal/extmcpv1 and scripts/gen-proto.sh --check, and review McpRequest.headers and metadata_context in internal/processor"
	fi
)

# Item 4: the enumerations the emitted processor entry depends on.
item_enums() (
	a=$(enums_of "$up/$pinned/config.json")
	b=$(enums_of "$up/$candidate/config.json")
	if [ "$a" = "$b" ]; then
		report PASS 4 "processor enums" "$a at both tags"
	else
		report CHANGED 4 "processor enums" "$pinned: $a; $candidate: $b; re-check internal/emit/route.go, cmd/toolwarrant/liveshape.go processorShape and the methods phases the emitter writes"
	fi
)

# Item 5: the rmcp crate the gateway speaks MCP with (it drives L2).
item_rmcp() (
	a=$(rmcp_versions "$up/$pinned/Cargo.lock")
	b=$(rmcp_versions "$up/$candidate/Cargo.lock")
	if [ "$a" = "$b" ]; then
		report PASS 5 "rmcp version in Cargo.lock" "$a at both tags"
	else
		report CHANGED 5 "rmcp version in Cargo.lock" "$pinned: $a; $candidate: $b; the typed model that drops keys (L2) changed, so scenario L's golden decides"
	fi
)

# Item 6: scenario L against the L2 golden.
item_golden() (
	if [ "$have_e2e" = no ]; then
		report SKIPPED 6 "scenario L against the L2 golden" "needs --e2e ($scenario_golden)"
	elif scenario_passed "$scenario_golden"; then
		report PASS 6 "scenario L against the L2 golden" "the key paths the gateway drops, keeps and adds equal e2e/testdata/gateway_tool_keys.json"
	else
		report CHANGED 6 "scenario L against the L2 golden" "scenario L failed ($e2e_log); re-record e2e/testdata/gateway_tool_keys.json from the observed lists it names, then docs/threat-model.md L2 and L9, docs/decisions.md D10 and docs/operations.md"
	fi
)

# Item 7: the MCP revision the probe and the crawler send against the one the
# gateway negotiates (scenario L notes it); the revisions the hostile upstream
# saw in initialize requests are printed too, since the gateway relays each
# client's own (the hostile upstream's request log).
item_revision() (
	probe=$(sed -n 's/^[[:space:]]*probeProtocolVersion *= *"\([^"]*\)".*/\1/p' "$root/cmd/toolwarrant/probe.go")
	crawl=$(sed -n 's/^[[:space:]]*requestedProtocolVersion *= *"\([^"]*\)".*/\1/p' "$root/internal/crawl/crawl.go")
	sent="the probe sends ${probe:-?} (cmd/toolwarrant/probe.go) and the crawler ${crawl:-?} (internal/crawl/crawl.go)"
	if [ "$have_e2e" = no ]; then
		report SKIPPED 7 "MCP revision" "$sent; the negotiated one needs --e2e (scenario L)"
		return
	fi
	negotiated=$(sed -n 's/^L: the gateway negotiated MCP protocol version \([^ ]*\) .*/\1/p' "$e2e_report" | sort -u | tr '\n' ' ')
	upstream=$(cat "$e2e_work"/logs/*.requests.log 2>/dev/null | grep 'POST initialize' | grep -o '"protocolVersion":"[^"]*"' | cut -d'"' -f4 | sort -u | tr '\n' ' ')
	if [ -n "$probe" ] && [ "$probe" = "$crawl" ] && [ "$negotiated" = "$probe " ]; then
		report PASS 7 "MCP revision" "$sent; the gateway negotiated $probe with scenario L's raw client; the upstream received initialize requests naming ${upstream:-?}(each client's own revision, relayed by the gateway)"
	else
		report CHANGED 7 "MCP revision" "$sent; the gateway negotiated ${negotiated:-nothing noted }with scenario L's raw client; the upstream received initialize requests naming ${upstream:-?}(relayed); update both constants and the documents that name the revision"
	fi
)

# Items 8, 13 and 14: binary-backed tests that must still pass.
item_tests() ( # number title names detail-on-change
	n=$1 title=$2 names=$3 advice=$4
	# shellcheck disable=SC2086
	if missing=$(tests_passed "$tests_log" $names); then
		report PASS "$n" "$title" "$(words "$names") tests passed against the candidate"
	else
		report CHANGED "$n" "$title" "did not pass: $missing (${tests_log#"$root"/}); $advice"
	fi
)

# Item 9: the reload log markers e2e/stack_test.go waits for.
item_reload() (
	if [ "$have_e2e" = no ]; then
		report SKIPPED 9 "reload log markers" "needs --e2e (every scenario that re-emits waits for them)"
	elif grep -q 'did not reload\|refused the configuration' "$e2e_log"; then
		report CHANGED 9 "reload log markers" "a reload was not seen ($(grep -m1 'did not reload\|refused the configuration' "$e2e_log" | cut -c1-160)); check loadedMarker and failedMarker in e2e/stack_test.go against the candidate's log lines"
	else
		report PASS 9 "reload log markers" "$(grep -c 'gateway reloaded' "$e2e_log") reloads were seen through the markers e2e/stack_test.go names"
	fi
)

# Item 10: the admin API as the canary and scenario P use it (L18).
item_admin() (
	# shellcheck disable=SC2086
	missing=$(tests_passed "$tests_log" $tests_admin) || {
		report CHANGED 10 "admin API shape (L18)" "did not pass: $missing; re-record cmd/toolwarrant/testdata/admin_config.json from scenario P"
		return
	}
	if [ "$have_e2e" = no ]; then
		report SKIPPED 10 "admin API shape (L18)" "the cmd tests against testdata/admin_config.json passed; the running API needs --e2e ($scenario_admin)"
	elif scenario_passed "$scenario_admin" && grep -q '^P: GET /api/config renders the top-level sections \[config gateways routes\]' "$e2e_report" && grep -q '^P: POST /api/config with [0-9]* bytes of JSON -> status 200' "$e2e_report" && grep -q '^P: POST /api/config with Content-Type application/yaml -> status 415' "$e2e_report" && grep -q '^P: GET /config_dump -> status 200' "$e2e_report"; then
		report PASS 10 "admin API shape (L18)" "GET /api/config renders config, gateways and routes; POST takes JSON (200) and refuses YAML (415); GET /config_dump answers 200 without authentication, as L18 says"
	else
		report CHANGED 10 "admin API shape (L18)" "scenario P's notes differ from $pinned ($(grep '^P: GET /config_dump\|^P: POST /api/config with Content-Type' "$e2e_report" | tr '\n' ';' | cut -c1-200)); re-record testdata/admin_config.json and rewrite L18 in SECURITY.md, docs/threat-model.md (row 26) and the admin warning in internal/emit/listeners.go"
	fi
)

# Item 11: an oversized tools/list page is answered 500 before the hook.
item_oversized() (
	if [ "$have_e2e" = no ]; then
		report SKIPPED 11 "oversized page answered 500 before the hook" "needs --e2e (scenario J)"
	elif grep -A1 "^J: page with a $oversized_bytes-byte description" "$e2e_report" | grep -q 'Internal Server Error' && grep -A1 "^J: page with a $oversized_bytes-byte description" "$e2e_report" | grep -q 'the processor logged no line'; then
		report PASS 11 "oversized page answered 500 before the hook" "scenario J: the $oversized_bytes-byte page was refused with Internal Server Error and the processor logged nothing, as D15 (f) records"
	else
		report CHANGED 11 "oversized page answered 500 before the hook" "scenario J's notes differ ($(grep -A1 "^J: page with a $oversized_bytes-byte description" "$e2e_report" | cut -c1-200 | tr '\n' ';')); re-read D15 (f) and threat-model row 2's note"
	fi
)

# Item 12: the request-header filter, the target name and metadata on both hooks.
item_hooks() (
	# shellcheck disable=SC2086
	missing=$(tests_passed "$tests_log" $tests_headers) || {
		report CHANGED 12 "requestHeaders filter, service_names and metadata_context" "did not pass: $missing; the gateway reads the header filter differently"
		return
	}
	if [ "$have_e2e" = no ]; then
		report SKIPPED 12 "requestHeaders filter, service_names and metadata_context" "the header-filter tests passed; the hooks need --e2e ($scenario_shared, $scenario_cross, $scenario_admin)"
	elif scenario_passed "$scenario_shared" && scenario_passed "$scenario_cross" && grep -q '^H: .*metadata_context is delivered on both hooks' "$e2e_report" && grep -q "^P: .*carries the requestHeaders filter: true" "$e2e_report"; then
		report PASS 12 "requestHeaders filter, service_names and metadata_context" "the gateway parses the filter, delivers metadata_context on both hooks (scenario H), names the target (scenario J) and renders the filter in the live document (scenario P)"
	else
		report CHANGED 12 "requestHeaders filter, service_names and metadata_context" "scenarios H, J or P differ from $pinned ($e2e_log); re-read internal/processor and D8"
	fi
)

# Item 15: the backendTLS block (D19, L11): what the binary's --validate-only
# does with the block's fields and files, and the handshake scenario Q drives
# between the running gateway and a processor started with the three flags.
item_tls() (
	# shellcheck disable=SC2086
	missing=$(tests_passed "$tests_log" $tests_tls) || {
		report CHANGED 15 "backendTLS fields and the scenario Q handshake" "did not pass: $missing (${tests_log#"$root"/}); the gateway reads the block or opens its files differently; re-read internal/emit/tls.go, cmd/toolwarrant/emittls.go and D19"
		return
	}
	if [ "$have_e2e" = no ]; then
		report SKIPPED 15 "backendTLS fields and the scenario Q handshake" "the --validate-only tests against the block passed; the handshake needs --e2e ($scenario_tls)"
	elif scenario_passed "$scenario_tls" && grep -q '^Q: .*the first handshake between agentgateway' "$e2e_report" && grep -q '^Q: .*so the gateway.s client offered h2' "$e2e_report"; then
		report PASS 15 "backendTLS fields and the scenario Q handshake" "the binary reads the block and opens its three files as D19 records; scenario Q listed and called through the TLS link with the gateway's client certificate, refused a client certificate from another authority, both downgrades and a garbage root, and found verify-gateway --admin healthy on the TLS entry"
	else
		report CHANGED 15 "backendTLS fields and the scenario Q handshake" "scenario Q differs from $pinned ($(grep '^Q: ' "$e2e_report" | head -1 | cut -c1-160)); re-read D19 and its observations in docs/decisions.md, threat-model.md L11 and docs/operations.md (Running the processor, Re-emitting the gateway configuration)"
	fi
)

# Item 16: the release asset names toolwarrant's files depend on.
item_assets() (
	missing=""
	assets=$(printf '%s\n' "$linux_asset" "$laptop_asset" "$asset" | sort -u)
	for a in $assets; do
		[ -f "$out/$a.sha256" ] && continue
		fetch "$release_base/$candidate/$a.sha256" "$out/$a.sha256" "" || missing="$missing $a"
	done
	digests=$(for a in $assets; do [ -f "$out/$a.sha256" ] && printf '%s %s\n' "$a" "$(awk '{print $1}' "$out/$a.sha256")"; done | awk '{ printf "%s%s %s", sep, $1, $2; sep = "; " } END { print "" }')
	if [ -z "$missing" ]; then
		report PASS 16 "release asset names and checksum" "published at $candidate: $digests; the given SHA-256 is $linux_asset's (ci.yml AGENTGATEWAY_SHA256) and $asset hashes to its own"
	else
		report CHANGED 16 "release asset names and checksum" "no published digest for${missing} at $candidate; the asset names changed: update ci.yml AGENTGATEWAY_ASSET, README.md, e2e/main_test.go, internal/emit/binary_test.go and cmd/toolwarrant/emit_validate_test.go"
	fi
)

# Item 17: every tracked file that spells the pinned version.
item_bump() (
	table=$(cd "$root" && git ls-files -z | xargs -0 grep -c -- "$pinned" 2>/dev/null | grep -v ':0$' | sort | tr '\n' ' ')
	files=$(words "$table")
	total=$(echo "$table" | tr ' ' '\n' | awk -F: '{n+=$2} END{print n+0}')
	if [ "$candidate" = "$pinned" ]; then
		report PASS 17 "the bump list" "the pin is already $pinned ($total mentions in $files tracked files); nothing to bump"
	else
		report CHANGED 17 "the bump list" "$total mentions of $pinned in $files tracked files to move to $candidate: ${table}plus AGENTGATEWAY_SHA256 in ci.yml and the tag's commit in third_party/agentgateway/NOTICE"
	fi
)

item_probe
item_schema
item_proto
item_enums
item_rmcp
item_golden
item_revision
# shellcheck disable=SC2016 # the title names a literal $NAME
item_tests 8 'a raw $NAME is refused and the escaped $ is accepted' "$tests_dollar" "the gateway's environment substitution changed; re-read internal/emit/dollar.go and testdata/README.md"
item_reload
item_admin
item_oversized
item_hooks
item_tests 13 "listener defaults" "$tests_listeners" "re-read internal/emit/listeners.go: the addresses the gateway parses and the exact spelling of off"
item_tests 14 "the lenient acceptances the binary tests pin" "$tests_lenient" "the gateway now refuses or accepts something else; rewrite internal/emit/testdata/README.md and the emitter refusals it explains"
item_tls
item_assets
item_bump
summarise
