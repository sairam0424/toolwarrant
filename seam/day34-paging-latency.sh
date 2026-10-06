#!/usr/bin/env bash
# Days 3-4, part 1: pagination and added latency. Loopback only.
#
#   P1  26 tools over 6 pages (page size 5); only echo+add approved
#       -> the client must still walk every page and see exactly 2 tools
#   P2  the same, with every tool approved -> all 26 come through
#   L   tools/list and tools/call latency, baseline (no processor) vs guarded
#
# Only the PIDs started here are stopped.
set -uo pipefail
cd "$(dirname "$0")/.."

GW=.cache/agentgateway-darwin-arm64
LOG=.cache/logs
APPROVED=.cache/approved.json
N=${BENCH_N:-300}
mkdir -p "$LOG"
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
wait_port() { for _ in $(seq 1 50); do nc -z 127.0.0.1 "$1" 2>/dev/null && return 0; sleep 0.2; done; echo "port $1 did not open" >&2; return 1; }
stop_one() { kill "$1" 2>/dev/null || true; wait "$1" 2>/dev/null || true; }

./bin/mockupstream -page-size 5 -extra 23 >"$LOG/upstream.log" 2>&1 & PIDS+=($!); wait_port 3001

run_guarded() { # $1 = learn list
  rm -f "$APPROVED"
  ./bin/seamgate -approved "$APPROVED" -learn "$1" >"$LOG/gate.log" 2>&1 & GATE=$!; PIDS+=($GATE); wait_port 9001
  "$GW" -f seam/gateway.yaml >"$LOG/gateway.log" 2>&1 & GWPID=$!; PIDS+=($GWPID); wait_port 3000
}

echo "### P1  26 tools, 6 pages of 5; only echo+add approved"
run_guarded echo,add
./bin/seamclient -all
echo "    processor saw $(grep -c 'tools/list filtered' "$LOG/gate.log") tools/list page responses"
stop_one "$GWPID"; stop_one "$GATE"

echo; echo "### P2  everything approved"
ALL=echo,add,wipe_database,$(seq -f 't%g' -s, 1 23 | sed 's/,$//')
run_guarded "$ALL"
./bin/seamclient -all
echo "    processor saw $(grep -c 'tools/list filtered' "$LOG/gate.log") tools/list page responses"
stop_one "$GWPID"; stop_one "$GATE"

echo; echo "### L  latency, n=$N sequential list+call pairs on one session (loopback, one machine)"
for round in 1 2; do
  "$GW" -f seam/gateway-baseline.yaml >"$LOG/gateway.log" 2>&1 & GWPID=$!; PIDS+=($GWPID); wait_port 3000
  printf 'baseline r%s  ' "$round"; ./bin/seamclient -bench "$N"
  stop_one "$GWPID"
  run_guarded echo,add
  printf 'guarded  r%s  ' "$round"; ./bin/seamclient -bench "$N"
  stop_one "$GWPID"; stop_one "$GATE"
done
