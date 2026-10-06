# Seam results: days 1-5 of the spike

Everything below ran on one Mac (arm64), loopback only, against the sha256-verified
agentgateway v1.6.0 release binary, a go-sdk mock upstream (echo, add, wipe_database,
plus t1..t23 for paging) and `cmd/seamgate`, a hash-bound ExtMCP processor.
Scripts: `seam/day5.sh`, `seam/day34-paging-latency.sh`, `seam/day34-sessions.sh`,
`seam/day34-reload.sh`. Re-run any of them to reproduce.

## Results

| # | Test | Result | Evidence |
|---|---|---|---|
| 1 | tools/list filtered to an approved set | PASS | wipe_database hidden, echo and add served |
| 2 | tools/call denied for an unapproved name | PASS | `TOOL ERROR: tool wipe_database is not approved` |
| 3 | Upstream changes echo's description (drift) | PASS | echo disappears from the list; its call is denied |
| 4 | Drift denied at call time from last-seen snapshot | PASS, with a limit (F1) | denied after a list; allowed by a client that never re-lists |
| 5 | Rollback (upstream restores the description) | PASS | tool returns on the next list |
| 6 | Disable (approval removed) | PASS | effective on the next request; client round trip including connect, list and call was 114 ms |
| 7 | Processor stopped, `failClosed` | PASS | list and call both fail |
| 8 | Pagination: 26 tools, 6 pages of 5, 2 approved | PASS | client walks all 6 pages, sees exactly `add,echo`; the processor saw 6 page responses, including pages the filter emptied |
| 9 | Pagination with everything approved | PASS | all 26 tools, 6 pages |
| 10 | Session from an unguarded route replayed on the guarded one (same bind and across binds), list and call | PASS | HTTP 404 `session not found` in every direction |
| 11 | Session from the guarded route replayed on the unguarded ones | PASS | 404 |
| 12 | Crawl route reachable by clients | FAIL by construction (F2) | an unguarded route or bind serves wipe_database and runs it; gateway binds listen on `*` |
| 13 | Bad config on reload (garbage YAML, schema-invalid value) | PASS | error logged, previous state kept, still guarded |
| 14 | Valid config without the processor | NOTE (F3) | reloaded in under 0.5 s, the guard silently vanished, wipe_database served |
| 15 | Added latency (n=300 list+call pairs, one session, two rounds) | PASS | below |

### Added latency (ms, loopback, 5-tool page, 300 pairs per round)

| | baseline p50 | guarded p50 | added p50 | baseline p95 | guarded p95 | added p95 |
|---|---|---|---|---|---|---|
| tools/list, round 1 | 1.09 | 2.25 | +1.16 | 3.42 | 9.69 | +6.27 |
| tools/list, round 2 | 0.92 | 1.96 | +1.04 | 4.03 | 8.88 | +4.85 |
| tools/call, round 1 | 0.99 | 1.85 | +0.86 | 3.48 | 7.63 | +4.15 |
| tools/call, round 2 | 0.86 | 1.68 | +0.82 | 3.81 | 7.85 | +4.04 |

Worst added p95 is 6.3 ms against the 50 ms budget. Single-sample maxima reached 60 ms on
a shared laptop and are noise, not the criterion. Digest cost per tool definition
(`BenchmarkDigest`, about 0.9 KB): 65 microseconds and 334 allocations.

## Findings that shape v0.1

- **F1. The call hook carries no tool definition.** A client that has not re-listed can
  call a tool that changed upstream until the processor's snapshot is refreshed. Closing it
  needs the control plane to crawl upstream itself and push fresh digests.
- **F2. There must be no crawl route on the serving gateway.** Any unguarded route or bind
  is a complete bypass, and bind sockets listen on all interfaces (`*:3000`, `*:3002`).
  The control plane crawls the upstream directly. Upstreams must be unreachable except from
  the gateway and the control plane. Only the intended ports should be exposed.
- **F3. The guard is config-presence-based.** A valid config that omits the processor fails
  open with no error. Needed: a deploy-time self-test that lists through the gateway and
  compares against the approved set, a single owner of the config file, and tight file
  permissions.
- **F4. Digest cost is linear in catalog size.** About 6.5 ms per 100 tools, so roughly 65 ms
  for a 1,000-tool unpaginated list. Cache digests keyed by the SHA-256 of the raw tool
  bytes, which skips canonicalisation for unchanged tools.
- **F5. Sessions are route-scoped on v1.6.0.** The cross-route replay class is not
  reproducible here. Keep tests 10 and 11 as a regression suite pinned to the gateway
  version, since this is version-specific behaviour.

## Decision (written, technical tests only)

**GO on Architecture A.** List filtering, call denial and drift hide all work on v1.6.0;
A-lite is not needed. Against the six-condition rule, conditions 1 (list filter, call denial,
drift hide), 2 (rollback within the next request) and 3 (p95 added latency at most 50 ms)
hold. Conditions 4 to 6 are not yet evaluable: the unattended demo (day 10), the hours
limit, and the competitor watch (days 11-14).

Limits of this evidence: one machine, loopback, mock upstream, happy-path crawl, a 5-tool
latency page, and the `-learn` flag standing in for a real approval workflow.

## Plan hours (fixed here, as the plan requires)

Plan 60 h (range 50-70), end-of-week-2 limit 90 h, day-10 check about 65 h. The time log is
the user's to keep; this file does not record hours worked.
