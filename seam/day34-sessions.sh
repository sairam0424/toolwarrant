#!/usr/bin/env bash
# Days 3-4, part 2: session reuse across routes/binds and crawl-route reachability.
# Loopback only. Only the PIDs started here are stopped.
#
# Routes on the test gateway (seam/gateway-twoway.yaml):
#   :3000/mcp    guarded      :3000/crawl  unguarded      :3002/mcp  unguarded
#
#   S0  what each route serves to a fresh session
#   S1  session created on an unguarded route, replayed on the guarded one (list + call)
#   S2  same across binds (3002 -> 3000)
#   S3  session created on the guarded route, replayed on the unguarded one
#   R   which interfaces the gateway actually listens on
set -uo pipefail
cd "$(dirname "$0")/.."

GW=.cache/agentgateway-darwin-arm64
LOG=.cache/logs
APPROVED=.cache/approved.json
T=$(mktemp -d)
mkdir -p "$LOG"; rm -f "$APPROVED"
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done; rm -rf "$T"; }
trap cleanup EXIT
wait_port() { for _ in $(seq 1 50); do nc -z 127.0.0.1 "$1" 2>/dev/null && return 0; sleep 0.2; done; echo "port $1 did not open" >&2; return 1; }

cat >"$T/sum.py" <<'PY'
import json, sys
raw = open(sys.argv[1], encoding="utf-8", errors="replace").read().strip()
msg = None
for chunk in ([raw] + [l[5:].strip() for l in raw.splitlines() if l.startswith("data:")]):
    try:
        msg = json.loads(chunk); break
    except Exception:
        pass
if msg is None:
    print("no-json: " + raw[:100].replace("\n", " ")); sys.exit()
if "error" in msg:
    print("JSON-RPC error %s: %s" % (msg["error"].get("code"), str(msg["error"].get("message"))[:90])); sys.exit()
r = msg.get("result", {})
if "tools" in r:
    print("tools=%d %s" % (len(r["tools"]), ",".join(sorted(t["name"] for t in r["tools"]))))
elif "content" in r:
    txt = " ".join(c.get("text", "") for c in r["content"])
    print(("TOOL ERROR: " if r.get("isError") else "OK: ") + txt[:80])
else:
    print(json.dumps(r)[:100])
PY

H=(-H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream')
init() { # url -> SID
  curl -s -D "$T/h" -o "$T/b" -X POST "${H[@]}" --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}' "$1"
  SID=$(awk 'tolower($1)=="mcp-session-id:"{print $2}' "$T/h" | tr -d '\r')
  curl -s -o /dev/null -X POST "${H[@]}" -H "Mcp-Session-Id: $SID" --data '{"jsonrpc":"2.0","method":"notifications/initialized"}' "$1"
}
rpc() { # label url sid body
  local code; code=$(curl -s -o "$T/b" -w '%{http_code}' -X POST "${H[@]}" -H "Mcp-Session-Id: $3" --data "$4" "$2")
  printf '  %-46s HTTP %s  %s\n' "$1" "$code" "$(python3 "$T/sum.py" "$T/b")"
}
LIST='{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
WIPE='{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"wipe_database","arguments":{"confirm":true}}}'
ECHO='{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"echo","arguments":{"message":"hi"}}}'

./bin/mockupstream >"$LOG/upstream.log" 2>&1 & PIDS+=($!); wait_port 3001
./bin/seamgate -approved "$APPROVED" -learn echo,add >"$LOG/gate.log" 2>&1 & PIDS+=($!); wait_port 9001
"$GW" -f seam/gateway-twoway.yaml >"$LOG/gateway.log" 2>&1 & PIDS+=($!); wait_port 3000; wait_port 3002

echo "### S0  fresh session per route"
init http://127.0.0.1:3000/mcp;   G=$SID;  rpc "guarded   :3000/mcp   list"         http://127.0.0.1:3000/mcp   "$G" "$LIST"
init http://127.0.0.1:3000/crawl; C=$SID;  rpc "unguarded :3000/crawl list"         http://127.0.0.1:3000/crawl "$C" "$LIST"
init http://127.0.0.1:3002/mcp;   B=$SID;  rpc "unguarded :3002/mcp   list"         http://127.0.0.1:3002/mcp   "$B" "$LIST"
rpc "unguarded :3000/crawl call wipe_database" http://127.0.0.1:3000/crawl "$C" "$WIPE"
rpc "guarded   :3000/mcp   call wipe_database" http://127.0.0.1:3000/mcp   "$G" "$WIPE"

echo; echo "### S1  session from the unguarded route (:3000/crawl) replayed on the guarded route (:3000/mcp)"
rpc "replay list"                http://127.0.0.1:3000/mcp "$C" "$LIST"
rpc "replay call wipe_database"  http://127.0.0.1:3000/mcp "$C" "$WIPE"
rpc "replay call echo (approved)" http://127.0.0.1:3000/mcp "$C" "$ECHO"

echo; echo "### S2  session from the unguarded bind (:3002) replayed on the guarded route (:3000/mcp)"
rpc "replay list"                http://127.0.0.1:3000/mcp "$B" "$LIST"
rpc "replay call wipe_database"  http://127.0.0.1:3000/mcp "$B" "$WIPE"

echo; echo "### S3  session from the guarded route replayed on the unguarded ones"
rpc "guarded sid on :3000/crawl list"       http://127.0.0.1:3000/crawl "$G" "$LIST"
rpc "guarded sid on :3002/mcp   list"       http://127.0.0.1:3002/mcp   "$G" "$LIST"

echo; echo "### R  listening sockets of the gateway"
GWPID=$(pgrep -f "agentgateway-darwin-arm64 -f seam/gateway-twoway.yaml" | head -1)
lsof -nP -a -p "$GWPID" -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR==1||/LISTEN/{print "  "$0}'
