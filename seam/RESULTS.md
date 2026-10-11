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

## Post-review changes (2026-10-07)

Two review waves ran against the code the spike grew into, and five commits
answered them on 7 October 2026: b9e4533 (core: gate, lifecycle, audit),
29dd670 (processor), f2a3e5a (emit), c728172 (crawl, fetch) and 20e32b4
(textdiff, export). This section records the design decisions those commits
state, corrects the statements above that the review showed to be wrong or
incomplete, and adds a cost caveat. The results table and the findings F1 to
F5 are left exactly as they were written on day 5; every correction is given
as "was" (the text above) and "is" (what holds after the five commits).
Statements about the tree refer to commit 20e32b4; wiring that the commit
messages list as a "known knock-on" for cmd and catalog is the following wave's
work and is called out as such.

### Design decisions D1 to D10 as the commit messages state them

- D1 (b9e4533, gate): DigestProfile "full-v1": the whole object, no exclusions.
  _meta is part of the digest. CanonicalTool canonicalises the original bytes
  and refuses invalid UTF-8 and lone surrogate escapes (ErrNotUTF8) and numbers
  that are not exact doubles (ErrNumberPrecision). VolatileKeys stays exported
  but is empty.
- D2 (29dd670, processor; f2a3e5a, emit): deny any hook whose service_names is
  not exactly [Config.Target]; refuse a ProcessorAddr used by more than one
  server. One processor address belongs to exactly one upstream.
- D3 (29dd670, processor; c728172, crawl; b9e4533, lifecycle): two-pass list
  filtering: a repeated name denies the page and marks the name as conflicting
  until a clean page shows the approved digest. At crawl time a tool that fails
  validation, and every copy of a repeated name, goes to Result.Unusable with a
  reason and a safe detail string while the valid tools are kept. In the
  lifecycle, UnusableDigest marks a live definition that was invalid or
  duplicated.
- D4 (b9e4533, lifecycle): Version.Proposers is an append-only history and
  approve refuses every proposer; Enable adds no proposer.
- D5 (b9e4533, lifecycle): every change of LastSeen or MissingCrawls emits an
  event (drifted, reverted, returned, missing).
- D6 (29dd670, processor): caps: 8 MiB payload, 10000 tools per page, tools
  over 512 KiB hidden unhashed, 32 concurrent hooks, context checked every 256
  tools.
- D7: not stated in any of the five commit messages. One wave-1 fixer report
  refers to "D4/D7 work" in the lifecycle without saying what D7 is. It is not
  restated here; the commit that lands it must state it.
- D8 (29dd670, processor; f2a3e5a, emit): an optional shared secret, written by
  emit under processors[].metadata as a CEL string literal (Server.Secret) and
  read by the processor from the metadata context.
- D9 (29dd670, processor): the call rule: allow only when every piece of
  evidence equals the approved digest; a LastSeen marker that is not a digest
  denies; no evidence denies.
- D10 (29dd670, processor): digest mismatches are counted and logged
  separately. The processor report adds the context: v0.1 does not hash the
  projection that agentgateway re-serialises (the gateway drops unknown
  top-level and annotations keys before the hook), so a tool carrying such a
  field is hidden as a mismatch and reported, not served.

### Corrections to the text above

- F1, was: "Closing it needs the control plane to crawl upstream itself and
  push fresh digests." Is: the control plane does crawl upstream itself, so the
  call-time gap is bounded by the crawl cadence, and that bound holds only when
  a crawl can actually record the upstream state. The review showed two ways an
  upstream could keep LastSeen equal to the approved digest for ever: one tool
  with a hostile name made the catalog refuse the whole crawl, so nothing was
  recorded, and the crawler announced itself as clientInfo "toolwarrant", so an
  upstream could serve the crawler a different definition from the one it
  serves clients. After the five commits the first way is closed: an invalid or
  duplicated definition is quarantined in Result.Unusable while the valid tools
  are still recorded (D3), the lifecycle marks the tool UnusableDigest and emits
  an event for the change (D3, D5), and the processor denies a call whose
  LastSeen is not a digest (D9), so a hostile name can no longer freeze the
  evidence. The second way remains a known limit: the crawl library's default
  clientInfo is now neutral, but cmd/toolwarrant still passes its own program
  name and version, and request shape, timing and source address identify a
  crawler anyway. The processor's live-listing check, not the crawl, is the
  defence against an upstream that serves the crawler something else. At
  20e32b4 the catalog and the CLI do not yet consume Result.Unusable; that
  wiring is the next wave's work.
- F3, was: "Needed: a deploy-time self-test that lists through the gateway and
  compares against the approved set, a single owner of the config file, and
  tight file permissions." Is: the self-test exists as the CLI's verify-gateway
  subcommand (cmd/toolwarrant/verify.go). It opens a new MCP session through
  the gateway route like a client would, lists the tools and compares each
  served definition with the catalog's serving policy, printing LEAK for a tool
  the catalog would hide, MISSING for an approved and current tool the gateway
  does not serve, and OK otherwise. The emitted gateway file carries a fourth
  header line, "# toolwarrant-sha256: <hex>", the SHA-256 of the YAML body, and
  emit.Verify checks a file against it; at 20e32b4 nothing calls emit.Verify
  yet, so an edit to the file on disk is detected by verify-gateway's listing,
  not by the header. The nuance the spike missed: the gateway binds the
  processor chain per MCP session, so removing or adding the processor on a
  reload affects only new sessions. Sessions that existed before the reload keep
  calling the processor, its statistics keep moving and nothing looks wrong,
  which is why processor statistics cannot detect a chain removal and why a
  canary must open a new session on every run, as verify-gateway does. A single
  owner of the file and tight file permissions remain operator duties; the
  emitter cannot set them.
- Test 14, was: "reloaded in under 0.5 s, the guard silently vanished,
  wipe_database served." Is: the guard vanished for new sessions. seamclient
  opened a fresh session for every request, which is why the spike saw the
  loss at once; a session opened before the reload stayed guarded until it
  ended.
- F2, unchanged for route binds: the v1.6.0 schema has no address key under
  binds[], so route sockets still listen on all interfaces. What changed: the
  emitted config now pins the gateway's admin, stats and readiness listeners to
  127.0.0.1 (adminAddr, statsAddr, readinessAddr); the review had found the
  stats and readiness listeners on all interfaces by default.
- Other statements the review found wrong: _meta is no longer described as
  volatile, it is in the digest (D1); ProposedBy is no longer rewritten by a
  re-proposal or by Enable (D4). Still open at 20e32b4 and owned by the next
  wave: schema.go's "digest re-check on every read" (the Snapshot read path has
  none), catalog.go's "the processor only reads" (Store.Open needs write
  access), and Approve, Reject and Rollback accepting a system actor.

### Cost caveat: the latency table predates the five commits

The latency table above was measured with cmd/seamgate, a single-pass list
filter and the spike's digest. Two deliberate changes now sit on the tools/list
hot path: the processor parses every page twice, names first, so that a
repeated name is known before any observation is recorded (D3), and the digest
checks every number token for exactness before canonicalising (D1). The wave-1
processor report measured BenchmarkCheckResponse100Tools at 14.7 ms per
operation, "roughly double the single pass", and the core report notes that
checkNumbers adds a second parse of each definition, so the per-definition
digest cost "roughly doubles" from the 65 microseconds and 334 allocations per
0.9 KB definition recorded above. The processor report also measured the D6
per-tool cap: 15 oversized catalog-named tools (7.5 MiB) now cost 371 ms for
the page where one 16 MiB tool cost 1.75 s before, because an oversized tool is
hidden without being hashed. Taken together, the per-page processor cost is
roughly twice what the table reflects; the added p95 must be re-measured with
cmd/toolwarrant serve, with pages of realistic size, before v0.1 relies on the
50 ms budget. A digest cache keyed by the SHA-256 of the raw tool bytes (F4)
is being added in the post-review wave so that an unchanged definition is
neither canonicalised nor number-checked again; until it lands, read the table
as a lower bound.

### Repository hygiene added with this section

THIRD_PARTY_NOTICES.md states the licence of every module in go.mod as read
from the module cache (pgregory.net/rapid is MPL-2.0 and test-only; the go-sdk
licence is a mixed MIT and Apache-2.0 transition text) and is regenerated by
scripts/gen-third-party-notices.sh. scripts/gen-proto.sh regenerates
internal/extmcpv1 from third_party/agentgateway/ext_mcp.proto with the exact
protoc, protoc-gen-go and protoc-gen-go-grpc versions recorded in the generated
headers, and refuses any other; go generate ./internal/extmcpv1 runs it. The
root .golangci.yml pins the lint set. go.mod says go 1.27 with toolchain
go1.27.1, so a 1.27.0 toolchain no longer triggers a download. The three
textdiff tests that walk all of Unicode skip under go test -short.

## Corrections after the end-to-end run and the second review (2026-10-11)

The end-to-end test (e2e/, commit 21164fd; its run of 2026-10-07 is kept in
demo/last-run.log, which is gitignored) and the second hostile review ran the
code the post-review section above describes against the real agentgateway
v1.6.0 binary. This section records what they changed in the statements above.
Every statement of the day-5 results table and of the post-review section was
true of the tree it names (20e32b4); the corrections below say what holds now.
The results table and findings F1 to F5 are again left exactly as written.

### Corrections to the post-review section

- F1 correction, was: "cmd/toolwarrant still passes its own program name and
  version". Is: the CLI passes no client name; the initialize request on the
  wire carries the library default clientInfo `mcp-client`. Request shape,
  timing, source address and Go's default User-Agent still identify a crawler
  (README limit L4). Was: "At 20e32b4 the catalog and the CLI do not yet
  consume Result.Unusable". Is: `crawl` prints rejected entries with their
  reason and `crawl --strict` exits 1 (cmd test
  TestCrawlReportsAnInvisibleToolNameAsRejected); the e2e scenario J denies a
  duplicate page through the gateway as a whole.
- F3 correction, was: "at 20e32b4 nothing calls emit.Verify yet". Is:
  `verify-gateway --config FILE` calls it and prints CONFIG-EDITED, exit 1, on
  a one-byte edit and on a missing header (e2e scenario F). The hash is an
  unkeyed SHA-256, so an edit that recomputes the header line passes `Verify`
  and the gateway's `--validate-only` (README limit L19); the controls against
  that are the canary's listing in a fresh session and, since the third round,
  its comparison of the gateway's live configuration (`GET /api/config` on the
  admin listener) with the emitted file (`--admin`, LIVE-CONFIG-MISMATCH).
  The second review also showed that the verdicts of 21164fd were too lenient:
  a route without its processor printed OK while nothing had drifted (the
  allow rule hides unapproved names), MISMATCH with exit 0 while a poisoned
  and later rejected definition was being served, and LEAK only after a crawl
  had recorded the drift. Decision D12 (docs/decisions.md) makes LEAK mean any
  served tool the catalog would not serve, exit 1, with MISMATCH kept only as
  a diagnostic sub-label of a LEAK line.
- F2 correction, was: "unchanged for route binds: the v1.6.0 schema has no
  address key under binds[], so route sockets still listen on all
  interfaces". Is: the emitter moved to the gateways form in 611e081 and
  writes `gateways.toolwarrant.bindAddress: "127.0.0.1"` by default; the real
  binary parses it and binds only 127.0.0.1 (e2e scenario I: connections to
  the gateway port and to the admin, stats and readiness listeners on the
  host's LAN address were not accepted). `emit --bind-address ADDR` chooses
  another address, a wildcard also needs `--allow-all-interfaces`, and `emit`
  prints a warning for any address other hosts can reach. The admin, stats and
  readiness addresses became emitter inputs in the third round, with an off
  switch for the admin API (`DisableAdmin`, the gateway's `adminAddr: off`).
  The admin listener is loopback but its API is unauthenticated
  (`GET /config_dump` returns the shared secret, `POST /api/config` replaces
  the running configuration), so it is part of the trusted computing base
  (README limit L18).
- Test 14 and L3 stand as corrected: the second review reproduced that a
  session opened before the reload kept calling the processor after the
  processor was removed from its route.
- "Still open at 20e32b4", was: schema.go's digest re-check, catalog.go's
  "the processor only reads", and Approve, Reject and Rollback accepting a
  system actor. Is: every read path re-hashes the approved bytes it hands out
  (with the verified-version memory of 4dce1c1); `serve` opens the catalog
  read-only (cmd test TestServeOpensTheCatalogReadOnly); the system actor is
  refused with exit 2 (decision D7, commit 8b7a574, which also states D7 that
  this section recorded as unstated). The third round added to the integrity
  checks: guard objects are compared by their DDL text rather than by name (a
  same-named no-op trigger had passed), the serving snapshot requires an
  approve or rollback record for every approved version (a forged approval
  through the mutable `tools` and `tool_versions.status` columns had been
  served), and `Store.Integrity` cross-checks the registry against the
  approvals table and the audit log (`audit verify` runs it after the chain
  check and exits 1 on any problem).
- D1 as stated above, was: "refuses invalid UTF-8 and lone surrogate escapes
  (ErrNotUTF8)". The second review found that at 21164fd a lone or ill-paired
  surrogate escape was refused by the RFC 8785 step with only the
  canonicaliser's own error, so `errors.Is(err, ErrNotUTF8)` was false (no
  caller depended on it: crawler and catalog classify every canonicalisation
  failure as `not-canonical`). Is, since the third round: both cases are
  reported as `ErrNotUTF8`, and for a surrogate escape the step's own error is
  wrapped alongside, so the statement above holds again.
- D10 as stated above, was: "the gateway drops unknown top-level and
  annotations keys before the hook". Is, as observed: the e2e scenario L
  recorded the gateway dropping `x-vendor` (with `x-vendor.tier`) and
  `annotations.x-risk` and keeping `annotations.title`,
  `annotations.readOnlyHint` and the `_meta` member `vendor/ui`; the second
  review's lab, not pinned by a test in this tree, also saw a `_meta` member
  named `ui` and a top-level `execution` key dropped. With the processor in
  place such a tool is hidden and `verify-gateway` reports it as MISSING;
  MISMATCH appears only as the sub-label of a LEAK line when a route without
  its processor serves the re-serialised bytes (README limit L2).
- Decisions added since: D11 (no data plane of its own; the seam is hardened
  instead) and D12 (LEAK semantics and the two canary probes, including the
  probe for a `tools/call` sent without a JSON-RPC id, which agentgateway
  v1.6.0 forwards without the hook and without the allow rule, README limit
  L17). Both are in docs/decisions.md.

### Cost caveat, resolved

Was: "A digest cache keyed by the SHA-256 of the raw tool bytes (F4) is being
added in the post-review wave ... until it lands, read the table as a lower
bound." Is: the cache landed in c311115 (internal/processor/digestcache.go),
and the e2e scenario M re-measured the added latency with `toolwarrant serve`
on the real gateway, loopback, a 3-tool page and 100 list and call pairs per
mode. demo/last-run.log of 2026-10-07: tools/list p50 2.07 ms with the
processor against 1.11 ms with the CEL rule alone (+0.95 ms), p95 7.08 against
3.25 (+3.83); tools/call p50 1.77 against 0.90 (+0.87), p95 5.50 against 2.15
(+3.35). The commit message of 21164fd records +0.3 ms list and +0.2 ms call at
p50 from other runs; p95 on a shared laptop is noise. The table at the top of
this file remains the spike's measurement with cmd/seamgate and is read as
history; pages of 100 tools and more are still not measured (README limit L12).
