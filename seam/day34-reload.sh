#!/usr/bin/env bash
# Days 3-4, part 3: does the gateway watch its config file, and what happens on a bad reload?
# Loopback only. Only the PIDs started here are stopped.
#
#   R0  good config               -> guarded (2 tools)
#   R1  garbage YAML written      -> previous state must be kept
#   R2  schema-invalid value      -> previous state must be kept
#   R3  valid config, no processor -> does the file reload at all, and does the guard vanish?
#   R4  good config restored      -> guarded again
set -uo pipefail
cd "$(dirname "$0")/.."

GW=.cache/agentgateway-darwin-arm64
LOG=.cache/logs
APPROVED=.cache/approved.json
CFG=.cache/reload.yaml
WAIT=${RELOAD_WAIT:-4}
mkdir -p "$LOG"; rm -f "$APPROVED"
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
wait_port() { for _ in $(seq 1 50); do nc -z 127.0.0.1 "$1" 2>/dev/null && return 0; sleep 0.2; done; echo "port $1 did not open" >&2; return 1; }
list() { ./bin/seamclient -all 2>&1 | sed 's/^/    /'; }

cp seam/gateway.yaml "$CFG"
./bin/mockupstream >"$LOG/upstream.log" 2>&1 & PIDS+=($!); wait_port 3001
./bin/seamgate -approved "$APPROVED" -learn echo,add >"$LOG/gate.log" 2>&1 & PIDS+=($!); wait_port 9001
"$GW" -f "$CFG" >"$LOG/gateway.log" 2>&1 & PIDS+=($!); wait_port 3000

echo "### R0  good config"; list
LINES0=$(wc -l <"$LOG/gateway.log")

echo; echo "### R1  garbage YAML"
printf 'binds: [this is: not: valid\n  - }\n' >"$CFG"; sleep "$WAIT"
list
echo "    gateway log since the write:"; tail -n +$((LINES0+1)) "$LOG/gateway.log" | cut -c1-220 | sed 's/^/      /'
LINES1=$(wc -l <"$LOG/gateway.log")

echo; echo "### R2  schema-invalid value (failureMode: bogus)"
sed 's/failClosed/bogus/' seam/gateway.yaml >"$CFG"; sleep "$WAIT"
list
echo "    gateway log since the write:"; tail -n +$((LINES1+1)) "$LOG/gateway.log" | cut -c1-220 | sed 's/^/      /'
LINES2=$(wc -l <"$LOG/gateway.log")

echo; echo "### R3  valid config with the processor removed"
cp seam/gateway-baseline.yaml "$CFG"; sleep "$WAIT"
list
echo "    gateway log since the write:"; tail -n +$((LINES2+1)) "$LOG/gateway.log" | cut -c1-220 | sed 's/^/      /'
LINES3=$(wc -l <"$LOG/gateway.log")

echo; echo "### R4  good config restored"
cp seam/gateway.yaml "$CFG"; sleep "$WAIT"
list
echo "    gateway log since the write:"; tail -n +$((LINES3+1)) "$LOG/gateway.log" | cut -c1-220 | sed 's/^/      /'
