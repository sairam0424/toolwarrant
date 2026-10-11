#!/usr/bin/env bash
# demo/run.sh: the unattended end-to-end demo of toolwarrant on the real
# agentgateway v1.6.0 binary.
#
# It builds the module, runs the e2e test (go test -tags e2e ... -v ./e2e),
# tees everything to demo/last-run.log under a timestamp header, prints a
# one-line verdict and exits with the test's exit code. The test needs the
# gateway binary at .cache/agentgateway-darwin-arm64 (or TOOLWARRANT_GATEWAY_BIN)
# and skips loudly without it. Everything runs on loopback ports picked at
# run time, the gateway's admin, stats and readiness listeners included (the
# test passes them through emit --admin-addr, --stats-addr and
# --readiness-addr), so nothing on the host has to be stopped first.
#
# Processes the test starts are stopped by the test. As a safety net for a
# run that was killed, anything whose command line still names this run's
# work directory is killed at the end; nothing else is touched.
set -euo pipefail
cd "$(dirname "$0")/.."

export GOFLAGS=-mod=readonly
LOG=demo/last-run.log
GATEWAY="${TOOLWARRANT_GATEWAY_BIN:-.cache/agentgateway-darwin-arm64}"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/toolwarrant-e2e.XXXXXX")"
# Resolved through symbolic links (macOS keeps TMPDIR under /var, a link to
# /private/var): init refuses a catalog path whose directory is reached through
# a link (decision D14), and the harness resolves the directory the same way,
# so the path the processes carry on their command lines is this one.
WORKDIR="$(cd "$WORKDIR" && pwd -P)"
export TOOLWARRANT_E2E_WORKDIR="$WORKDIR"
export TOOLWARRANT_E2E_REPORT_FILE="$PWD/$LOG"
START=$(date +%s)

{
  echo "# toolwarrant end-to-end demo"
  echo "# started:  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# commit:   $(git rev-parse --short HEAD 2>/dev/null || echo unknown)$(git diff --quiet 2>/dev/null || echo ' (uncommitted changes)')"
  echo "# gateway:  $GATEWAY"
  echo "# workdir:  $WORKDIR"
  echo "# command:  go test -tags e2e -count=1 -timeout 900s -v ./e2e"
} > "$LOG"

if [ ! -x "$GATEWAY" ]; then
  echo "demo: WARNING: no agentgateway binary at $GATEWAY; the end-to-end test will skip" | tee -a "$LOG"
fi

echo "# go build ./..." | tee -a "$LOG"
go build ./... 2>&1 | tee -a "$LOG"

echo "# go test -tags e2e -count=1 -timeout 900s -v ./e2e" | tee -a "$LOG"
set +e
go test -tags e2e -count=1 -timeout 900s -v ./e2e 2>&1 | tee -a "$LOG"
code=${PIPESTATUS[0]}
set -e

if pgrep -f "$WORKDIR" >/dev/null 2>&1; then
  echo "demo: killing processes still running from $WORKDIR" | tee -a "$LOG"
  pkill -f "$WORKDIR" || true
fi

ELAPSED=$(( $(date +%s) - START ))
if [ "$code" -ne 0 ]; then
  verdict="FAIL (go test exit $code); process logs kept in $WORKDIR"
elif grep -q -- '--- SKIP: TestEndToEnd ' "$LOG"; then
  verdict="SKIPPED: the end-to-end test did not run (see the skip message above); nothing was proven"
  rm -rf "$WORKDIR"
else
  verdict="PASS: every scenario passed against the real gateway"
  rm -rf "$WORKDIR"
fi
echo "# finished: $(date -u +%Y-%m-%dT%H:%M:%SZ) after ${ELAPSED}s" | tee -a "$LOG"
echo "toolwarrant e2e demo: $verdict (${ELAPSED}s, full output in $LOG)" | tee -a "$LOG"
exit "$code"
