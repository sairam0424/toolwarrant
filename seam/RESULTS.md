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

## Week-2 decision (2026-10-11 22:51 IST)

Written at the end of the two-week spike against the six-condition rule of the
plan (report section 7.4). Code tree: commit 75ab299 on main (local, not pushed;
the commits after it on 2026-10-11 touch documents only). Evidence: the seam
results above, the end-to-end harness (`make e2e`, scenarios A to P on the real
agentgateway v1.6.0 binary), the unattended demo (`demo/run.sh`) and the two
competitor-watch logs in the workspace scratch-pad (2026-10-07 and 2026-10-11).
A third hostile review of 75ab299 starts right after this section is written;
v0.1 is published only after its findings are triaged.

| # | Condition | Result | Evidence |
|---|---|---|---|
| 1 | List filtering, call denial and drift hide work on the pinned gateway | HOLDS | seam tests 1 to 3 (day 5); e2e A (nothing approved serves nothing), B (approve serves exactly), C (drift hides and denies), J (two servers, duplicate-name page, service_names check), K (CEL rule alone); `make e2e` on 75ab299: 16.0 s, exit 0 |
| 2 | A rollback takes effect within the next request | HOLDS | seam test 5; e2e D (re-approve and rollback: listed again on the next tools/list; tools/call allowed again once the next crawl records the revert, D9) |
| 3 | Added p95 latency at most 50 ms | HOLDS | seam: worst added p95 6.3 ms (5-tool page, 300 pairs); e2e M on 75ab299 (3-tool page, 100 list+call pairs, loopback): added p50 +0.23 ms list, +0.18 ms call; added p95 +0.46 ms list, +0.26 ms call. The same scenario on 21164fd under a loaded machine measured +3.83 and +3.35 ms p95, still far inside the budget |
| 4 | The demo runs unattended twice | HOLDS | `demo/run.sh` by the maintainer on 75ab299: run 1 exit 0 in 25 s, run 2 exit 0 in 22 s (2026-10-11); before that, five green harness runs and one demo run by the e2e builder on the same scenarios, and four runs on 21164fd |
| 5 | Hours worked at most 90 h (1.5 x the 60 h plan) | OWNER'S CALL | the time log is the owner's; this file records no hours |
| 6 | No competing open-source project shipped K4 (i), (ii) or (iii) | HOLDS | competitor-watch-2026-10-07.md (baseline 2026-10-05) and competitor-watch-2026-10-11.md: K4 not tripped; nearest miss LiteLLM PR #44245 (open); LiteLLM's admin pin and drift alert, GA in v1.105.0, is none of the three clauses |

**Decision on the technical conditions: GO to v0.1.** Conditions 1, 2, 3, 4
and 6 hold on evidence in this repository and the two watch logs. Condition 5
is decided by the owner's time log, not here; if it fails, the plan's own rule
applies and this GO does not override it.

**What the technical evidence does not cover.**

- agentgateway v1.6.0 forwards a `tools/call` sent without a JSON-RPC id to
  the upstream without running the ExtMCP processor or the mcpAuthorization
  rule. e2e scenario O records it on every run (HTTP 202, the probe arrives in
  the hostile upstream's request log, `verify-gateway` prints UNHOOKED-CALLS
  and exits 1). The control is the canary's probe; the fix is upstream, and the
  upstream report is the owner's hand-written action. The 2026-10-11 watch
  found no existing public report of it (eleven searches), so the report would
  be new.
- The gateway's admin API on the loopback admin listener accepts
  `POST /api/config` without authentication, applies the document and rewrites
  the watched file (header lines kept). e2e scenario P records it: the canary
  prints LIVE-CONFIG-MISMATCH against a byte-identical copy of the emitted file
  and CONFIG-EDITED against the rewritten file. The emitter can move or disable
  the admin listener; the host remains part of the trusted computing base (D12,
  threat model rows 19 and 26).
- The call-time window for a client that never re-lists is bounded by the crawl
  cadence (F1, L1). e2e scenario C on 75ab299: such a session was denied 3.7 ms
  after the drift when another session listed the drifted definition, and
  21.7 ms after a second drift that no session listed, when the crawl recorded
  it; in production the second case is the crawl interval.
- Everything was measured on one Mac, loopback, mock upstreams, pages of three
  to twenty-six tools. Pages of realistic size are not measured.
- On v1.6.0 the probe fails every canary run by design; operators pass
  `--no-probe` once they have recorded the limit, as the harness does for every
  scenario but O.

**What changes with GO.** The publish gate stays in front of v0.1: project name
and registration, SBOM and signing (syft, goreleaser, cosign), the first push
and CI run (the action SHAs in `.github/workflows/ci.yml` and the linux gateway
asset checksum are the owner's to verify and fill in), the hand-written
upstream report, the SECURITY.md contact. Stay pinned at agentgateway v1.6.0;
before the first move to a newer tag run the contract tests and re-check the
items the 2026-10-11 watch lists (the `processors[]` shape after #3711, `_meta`
merged back into `params` for request-phase processors, CEL header semantics
after #3778, gRPC status mapping after #3793).



**Note added 2026-10-12 00:37 IST.** The third review's findings were fixed after this
decision was written (commits 9cc8f28 to a96672e, decisions D13 in
docs/decisions.md): the serving path now requires the newest decision about
the tool, Integrity covers every mutable column and refuses foreign triggers,
per-server growth caps exist, an unreadable page marks every servable tool,
the live-configuration comparison covers the whole document, the canary and
the crawl schedule exit 1 on any failure, the emitted file is 0600 and its
processor entries filter client headers, and the schema is v4. The technical
conditions were re-checked on a96672e: `make e2e` 17 to 23 s exit 0;
`demo/run.sh` twice, 23 s and 29 s, both exit 0 (condition 4 still holds);
scenario M added p50 +0.07 ms list and +0.06 ms call, with p95 inside the
run-to-run noise on a loaded machine (condition 3 still holds by a wide
margin). The whole-system review of the third round never completed (one
usage-policy refusal, then two server-side failures of the model API); it is
part of the fourth review, which starts on a96672e. The GO stands; v0.1 waits
for that review's triage.

**Note added 2026-10-12 03:07 IST.** The fourth review (26 findings on a96672e) was fixed
as the fifth round (commits 369a0ba to 53e96b9, decisions D14): the serving
path is anchored to the audit chain and a Store pins the chain prefix it has
verified; Integrity covers subjects, orphans, proposers and version statuses
and the tools table cannot be deleted from; the audit log has a per-crawl cap
on rejected entries; a replaced catalog file is detected and every hook denied;
the live comparison covers every top-level section, the header filter and the
processor metadata; processor addresses live in the catalog; the schema is v5.
The trust boundary is stated once in D14: controls inside the file detect
rewrites of history, and a forged sealed append by whoever can write the file
is detected only by anchors outside it. Re-checked on 53e96b9: the full race
suite (not -short) green on every package; `make e2e` 19.8 s exit 0;
`demo/run.sh` twice, 25 s and 24 s, both exit 0 (condition 4 holds); scenario
M added p50 +0.18 ms list, +0.14 ms call. The whole-system LLM review could not
be run (two usage-policy refusals); the e2e harness on the real gateway is the
system-level evidence. A fifth review of this round follows; the GO stands and
v0.1 waits for its triage.

**Note added 2026-10-12 05:25 IST.** The fifth review (15 findings on a369090, three high)
was fixed as the sixth round (commits 01673cf to f392ab1, decisions D15): a
Store verifies the whole audit chain when it opens and afterwards trusts an
entry only when the hash computed from its fields is the one its own walk
recorded, so an entry rewritten in place is refused on every serving and
decision path; Integrity verifies seals and links as it streams; tables and
automatic indexes are compared like the other guards; a page the gRPC
transport refuses for size marks the snapshot; listing evidence is kept for
unservable tools and during a pause; the live comparison fails closed on every
field a route, backend or the config block carries that the emitted file does
not, and runs even when the canary's own listing fails; a 400 with any JSON
body is PROBE-INCONCLUSIVE. The remaining limit is stated once: a chain
rewritten completely before a Store opens is caught only by the head the
operator recorded. Two assumptions of the round were corrected on the real
gateway and written down: agentgateway v1.6.0 answers the client HTTP 500 on
tools/list before the ExtMCP hook for a page over its own limit (6 MiB and
9 MiB in scenario J), so such a page marks nothing and the call window stays at
the crawl cadence (L1); and a requestMirror policy posted on the route through
the admin API breaks the route for new sessions, the canary's own listing
included, which is why the comparison now runs regardless. Re-checked on
f392ab1: the full race suite (not -short) green on every package; `make e2e`
twice, 25.5 s and 27.7 s, exit 0; `demo/run.sh` twice, 30 s and 33 s, both
exit 0 (condition 4 holds); scenario M added p50 +0.24 ms list, +0.22 ms call.
The GO stands; the owner decides whether a further review round precedes v0.1.

### Corrections after the third review (2026-10-11)

The third hostile review ran against d28e0e3 and 9cc8f28, the tree the week-2
decision above describes; its fixes are the fourth round, recorded as decision
D13 in docs/decisions.md. Every statement above was true of the tree it names.
What the round changed in the statements of this file:

- "Still open at 20e32b4" as corrected above, was: "the serving snapshot
  requires an approve or rollback record for every approved version". Is: the
  serving path requires the newest decision about the tool: among all versions
  of a tool, the approvals row with the highest id whose decision is approve or
  rollback must point at the approved version and carry hash_seen equal to its
  digest (D13 a). The third review had flipped a tools row back to a
  superseded version with plain UPDATE statements, and rewritten an approved
  definition after dropping and re-creating a guard trigger with its original
  DDL; both were served by Snapshot and Approved because some historic approve
  row about the version existed, and only Store.Integrity named them.
- Same bullet, was: "Store.Integrity cross-checks the registry against the
  approvals table and the audit log". Is: it compares every mutable column the
  log describes (approved digest, last-seen digest, tools.state,
  proposals_since_decision, servers.paused, servers.allow_private and a hash of
  servers.url) with the latest entry about the subject, and any trigger or view
  in sqlite_master that the schema did not create is ErrCorrupt at Open and on
  every Snapshot and Approved load (D13 b; the audit detail format gained
  fields, so the schema version is 4). The third review had re-enabled a
  disabled tool and un-paused a server with one UPDATE each, and installed a
  foreign trigger that undid every later disable, with Integrity clean.
- Week-2 decision, "What the technical evidence does not cover", second
  bullet, was: the canary "prints LIVE-CONFIG-MISMATCH against a byte-identical
  copy of the emitted file". Still true, and insufficient: at 75ab299 the
  comparison read the one route named after the server, so a route added
  through the admin API that owned the client's path, a second route on
  another path and a second gateway on 0.0.0.0:3001 all compared healthy, and
  each loaded in --validate-only. Is: the comparison covers the whole document
  (every emitted gateway and route present exactly once with the same fields
  and match path, nothing extra, no path twice, the --url path on the emitted
  route; D13 e).
- Same section, last bullet, was: "operators pass --no-probe once they have
  recorded the limit". Is: the documents now say so in the places that
  promised an OK line the pinned gateway cannot print with the probe on (README
  step 7, the SECURITY.md canary item, the operations guide's example); the
  probe also gained PROBE-INCONCLUSIVE for a 2xx answer with a body that is not
  a plain 202 (D13 h), since any JSON-RPC error in such an answer had counted
  as the gateway's own refusal, whoever produced it.
- The canary's exit under --keep-going, stated as "exited 1 on SIGTERM after
  reporting both" for scenario F: the third review stopped a run while the
  admin fetch that followed a LEAK was in flight and got exit 0, because the
  check was not tallied once the stop signal was set. Is: every check is
  tallied before the stop signal is looked at, verdict lines are printed before
  the network calls that follow the listing, and a run that printed any
  failing verdict line exits 1 (D13 f). crawl --every gained the matching rule
  (stop on a catalog error; exit 1 when no crawl completed or any was refused).
- The emitted file: was 0644 unless it carried a secret or a query string; is
  always 0600, with the operator making it readable by the gateway's user (D13
  g). Processor addresses are stable across re-emits (an existing emitted file
  is read first; a new server takes the next free port; changes are printed),
  a processor address on one of the gateway's own sockets is refused, and
  verify-gateway --expect-body-hash HEX compares the body hash emit printed,
  which closes the "unkeyed hash, record it elsewhere" statement of the F3
  correction with a command that does the comparison (README limit L19).
- The processor-level rule of D3 as the third round stated it, "a denied page
  leaves the conflict marker on every catalog tool it listed, whatever denied
  it": the third review placed an unreadable decoy in front of a changed tool
  and the collector stopped at the decoy, so the changed tool kept its older
  evidence. Is: a page the processor cannot read through to the end marks
  every catalog tool of the snapshot, and the observed-evidence table is sized
  from the snapshot, records only servable catalog tools and never evicts a
  contradiction (D13 d). README limit L6, "it cannot grow the database", was
  false for an upstream that lists fresh names on every crawl; per-server caps
  on tool rows and stored bytes bound it now (D13 c).
- Decisions added since: D13, in docs/decisions.md, with the document
  corrections of the round (D9 no longer says that what is listed is exactly
  what is callable; CLAUDE.md names schema v4; the CI trigger is stated as
  every pull request and every push to main; .golangci.yml names golangci-lint
  v2.14.0).

### Corrections after the fourth review (2026-10-12)

The fourth hostile review ran against a96672e, the tree the note of 00:37 IST
above describes; its fixes are the fifth round, recorded as decision D14 in
docs/decisions.md. Every statement above was true of the tree it names. What
the round changed in the statements of this file:

- "Still open at 20e32b4" as corrected twice above, was: the serving path
  "requires the newest decision about the tool ... carry hash_seen equal to
  its digest (D13 a)". Is: it also requires the newest version.approved or
  version.rolled_back audit entry about the tool to carry after_hash equal to
  the approved digest and to re-seal from its predecessor, and a Store pins
  the newest audit entry it has verified and refuses a file in which that
  entry or the suffix since it changed (D14 a and b). The fourth review
  dropped and re-created approvals_no_update together with
  tool_versions_immutable, rewrote a definition and its hash_seen
  consistently, and Snapshot, Approved and Versions served it while only
  Store.Integrity saw it: the approvals table was the only evidence, and it
  is as rewritable as the versions table.
- Same bullet, was: "Store.Integrity ... compares every mutable column the
  log describes". Is: it also compares every subject the log describes with
  the rows that exist (a deleted tools row, a tool the log never discovered,
  a second tool.discovered for one subject, orphaned tool_versions rows),
  each version's proposers with its version.proposed entries and each
  version's status with the status the log implies; a UNIQUE index the schema
  did not create is a foreign object; guard triggers refuse DELETE on tools,
  tool_versions, tool_version_proposers and approvals; and the schema version
  is 5 (D14 c and k). The fourth review laundered the proposer rule with one
  DELETE of the tools row and flipped a rejected version back to pending, each
  with Integrity clean.
- The trust boundary that every bullet above left implicit is now stated once
  (D14, README limit L19, threat-model row 21): the controls inside the
  catalog file detect rewrites of history; whoever can write the 0600 file can
  append a new, correctly sealed audit entry that approves a definition, and
  nothing inside the file can refute it; the recorded audit head, the git
  export of approved definitions and backups are the anchors that do.
- "Processor addresses are stable across re-emits (an existing emitted file
  is read first ...)" in the corrections after the third review. Is: the
  addresses live in the catalog (servers.processor_addr, written by emit and
  by --processor with the audit entry server.processor_set, shown by server
  list) and emit never reads addresses from the file at --out; --out and the
  canary's --config must be regular files (D14 i). The fourth review re-sealed
  a file with a forged processor address (the unkeyed header hash, L19) and
  planted a symbolic link at --out, and the documented CONFIG-EDITED remedy,
  running emit again, wrote the forged address back with no change line and
  an OK canary; a FIFO at --config blocked the canary in open() with no
  verdict and no exit.
- "The comparison covers the whole document" in the same corrections. Is: the
  live document is decoded as a map of top-level sections and every section
  other than config, gateways and routes is a LIVE-CONFIG-MISMATCH of its own;
  the listener addresses, each processor's requestHeaders filter and a hash of
  its metadata are compared as well (D14 i). The fourth review loaded the
  emitted file plus a binds listener and plus a top-level mcp section in
  --validate-only, and the comparison, which decoded two sections, called both
  a match; a stripped header filter compared healthy too. The end-to-end
  scenario P now posts each of the three through the admin API of the running
  gateway (demo/last-run.log of 2026-10-12): the gateway accepted the binds
  section and the mcp shortcut with status 200, rendered each in GET
  /api/config, and through each new listener a fresh session listed every
  tool of the upstream, unapproved wipe_database included, with tools/call
  echo allowed; the comparison printed "section binds: not in the emitted
  file; it may bind ports and routes the comparison cannot see" (and the mcp
  twin) and, for the stripped filter, "processor requestHeaders allowed:
  emitted :method, live (none)" with its disallowed twin, exit 1 each time.
- The probe rule of D13 h, "HTTP 400 healthy". Is: a 400 is healthy only when
  its body is not a JSON-RPC error; a JSON-RPC error on a 400 is
  PROBE-INCONCLUSIVE, since a forwarding gateway relays the upstream's
  refusal, status included; and the error for every other answer names the
  status and whether a body was present (D14 i). Not reachable on v1.6.0,
  which answers 202.
- "The processor reloads only when the catalog generation moves, so decisions
  take effect without a restart" (operations guide, README). Is: while the
  file is the same file. init writes a random catalog identity, a Store
  records it with the file's device and inode, and Generation refuses a
  replaced or removed file, which the processor turns into a source-error
  denial and an Error log line; every recovery procedure that deletes the
  file now says to stop the processors first and start them after init
  (D14 e). The fourth review followed the growth-cap recovery of the
  operations guide and a running processor kept serving the deleted file's
  approvals, including a tool the new catalog did not approve, with source
  errors at zero. The end-to-end scenario N now deletes and re-initialises
  the catalog under two running processors: 23 and 26 ms later both denied
  every list and call with "catalog unavailable" and logged "catalog
  unavailable, denying", and a processor started on the new file served the
  re-approved tool while a tool approved only in the deleted file was denied
  as not approved.
- README limit L6 as corrected after the third review, "per-server caps on
  tool rows and stored bytes bound it now". Is: the caps bound rows and
  bytes; the audit log grows with observed changes, bounded by the crawl
  cadence and a per-crawl cap on rejected entries
  (catalog.MaxRejectedPerCrawl) past which the crawl is recorded as failed
  under its own class and adds no entries (D14 d). The fourth review listed
  fresh unusable names on every crawl and grew the log by about 2.6 MB per
  crawl at the per-crawl cap with no row added and no cap tripped.
- The processor-level rule of D3 and D13 d, "a page the processor cannot read
  through to the end marks every servable tool of the snapshot". Is: a page
  over the payload cap is marked the same way before it is denied, and the
  observed-evidence table is pruned only against a non-empty snapshot and
  never loses a contradiction, so a pause and resume keeps every marker
  (D14 g); mcpwire counts a page's entries with a streaming decoder and stops
  at the per-page cap before the array is materialised, so the per-hook memory
  is the raw page plus at most 10000 parsed entries (threat-model row 15; the
  fourth review measured about eighteen times the payload for a 1 MiB page of
  tiny entries under the old order).
- The emitter's socket rule of D13 g, "a processor address on one of the
  gateway's own sockets (a loopback, localhost or wildcard host ...) is
  refused". Is: a host that is all digits, dotted digits or hex-looking must
  parse with netip.ParseAddr or is refused, and the rule compares the
  processor address with the input's own bind address and listener addresses
  (D14 h). The fourth review passed 127.1, 0x7f.0.0.1, 2130706433 and 0,
  which the resolver reads as loopback or the wildcard, and a processor on the
  very address the input named for the bind.
- Smaller corrections of the round: list and show apply the same evidence as
  the serving path and refuse a tampered file, so the operations guide no
  longer presents list as a check; a forensic open accepts a file whose
  journal mode is not WAL (mode=ro with immutable=1); audit verify prints the
  integrity report when the chain is broken as well; without --keep-going the
  canary ends at the first check that printed a failing verdict whatever a
  later step did; init refuses a database path whose directory is reached
  through a symbolic link that root does not own; the three processor
  comments that still said listed equals callable state the one-way rule of
  D9 (D14 f, i); and textdiff escapes a quotation mark inside a quoted
  changed span (D14 j; `TestTool_changedTextSpanEscapesQuotationMarks`, landed
  in the commit after this round's documents). The finding that
  unlisted deprecated tools kept a stale unusable marker was fixed in 15eba5e
  before this round and re-verified with the reviewer's recorded seed.
- Decisions added since: D14, in docs/decisions.md, with the trust boundary of
  the catalog file stated once and the document corrections of the round
  (README L1, L6, L17, L18 and L19; threat-model rows 4, 7, 10, 11, 15, 16,
  18, 20, 21, 22, 25 and 26; the operations guide's processor, canary, audit,
  recovery and re-emit sections; CLAUDE.md names schema v5).

### Corrections after the fifth review (2026-10-12)

The fifth hostile review ran against a369090, the tree the corrections after
the fourth review describe; its fixes are the sixth round, recorded as
decision D15 in docs/decisions.md. Every statement above was true of the tree
it names. What the round changed in the statements of this file:

- "The trust boundary that every bullet above left implicit is now stated
  once ... the controls inside the catalog file detect rewrites of history",
  and the first bullet of the fourth-review corrections, "a Store pins the
  newest audit entry it has verified and refuses a file in which that entry
  or the suffix since it changed (D14 a and b)". Is: the anchor of D14 a
  re-sealed the newest approval entry against its predecessor only, the pin
  verified the head and the suffix after it only, and the verifier memory was
  keyed by the hash column the forger writes, so the fifth review rewrote one
  approval entry in place below the head (a new after_hash or actor with the
  hash recomputed from the real prev_hash; after_hash alone while the memory
  was warm), kept the head unchanged, and a running Store, a fresh read-only
  Store and a fresh read-write Store all served it with Integrity clean, while
  only the full chain walk of audit verify broke at the successor; the same
  rewrite of version.proposed entries laundered the proposer rule. Since D15 a
  Store verifies the whole chain once when it opens and pins the head, keeps
  the hash it computed itself for every decision entry and for the head,
  verifies the suffix after the pin on every reload, and the serving path and
  the decision path trust an entry only when the hash computed from its fields
  equals the one that walk recorded; the stored hash column is never consulted
  for trust. A forger must rewrite every entry from the forged one to the
  head, which changes the head a running Store pinned and the head the
  operator recorded; a chain rewritten completely before a Store opens is
  caught only by the recorded head (the pin-bootstrap limit). Store.Integrity
  verifies every entry's seal and link as it streams the log (D15 c), the
  catalog identity is compared on every read, not only by Generation (D15 d),
  every table's DDL is compared with the schema's, an automatic index the
  schema's tables do not account for is a foreign object, and the ErrCorrupt
  for a constraint failure names the table and the constraint (D15 e).
- "The processor-level rule ... a page over the payload cap is marked the
  same way before it is denied (D14 g)". Is: over the gRPC transport such a
  page is refused for size before the hook runs, so the marking inside the
  hook was unreachable in the shipped runtime (the fifth review's padded page
  left a changed tool's older evidence alive with nothing counted or logged);
  since D15 f the processor observes the transport's refusal of a
  CheckResponse call and marks every servable tool of the snapshot from it.
  README L1 and threat-model row 11 listed "more than 10000 tools" among the
  pages read to the end; since the fifth round the survey stops at the
  per-page cap, so such a page is unreadable and marks every servable tool,
  and the documents now say so. Listing evidence is recorded for every
  catalog tool a page names, servable or not, and a page seen while the
  snapshot is empty is judged against the names already tracked (D15 g; the
  fifth review listed a changed definition during a pause and the processor,
  judging against the empty snapshot, discarded it).
- "The emitter's socket rule ... (D14 h)". Is: the rule knew one name,
  localhost; the loopback aliases common resolvers map without DNS
  (localhost.localdomain, localhost4, localhost4.localdomain4, localhost6,
  localhost6.localdomain6, ip6-localhost, ip6-loopback) passed with the
  serving and the admin port, warned about as non-loopback. Since D15 h a
  processor whose host is a name rather than an IP literal is refused on any
  port the gateway binds, and the aliases count as loopback in the emitter
  and in serve.
- "The comparison covers the whole document ... every top-level section, the
  header filter and the metadata (D14 i)". Is: the comparison decoded the
  known fields of each route and of config only, so an extProc policy, a
  requestMirror, a response transformation, a urlRewrite, a second host
  backend and a config.mcp block, each accepted by the pinned binary's
  --validate-only, compared as a match. Since D15 i every live route, backend
  and config field is decoded generically and anything the emitted file
  cannot carry (a route key other than name, gateways, matches, policies and
  backends; a policy other than mcpAuthorization and mcpGuardrails; a match
  that is not a single exact path; a backend that is not the one mcp backend
  with the emitted target; a config field other than the three listener
  addresses) is a LIVE-CONFIG-MISMATCH line of its own; a top-level section
  counts only when it is non-empty, which the code always did and the
  documents now say.
- "Processor addresses live in the catalog ... written by emit (D14 i)". Is:
  emit recorded them before the file was validated and written, so a refused
  emit left the address and its server.processor_set entry behind for a file
  that never existed and the next emit printed no "is new" line; since D15 j
  the addresses are recorded only after the file was renamed into place.
- "The probe rule of D13 h ... a 400 is healthy only when its body is not a
  JSON-RPC error (D14 i)". Is: a 400 is healthy only when its body is empty
  or is not JSON; a body that parses as JSON, object or array (a JSON-RPC
  batch of errors included, which the old check did not recognise), is
  PROBE-INCONCLUSIVE (D15 k).
- Smaller corrections of the round: the CI test-full job runs
  internal/processor as well, because TestServe_AcceptsAPageOverGRPCsDefaultLimit
  is the sixth test -short skips, and CLAUDE.md names all six (D15 l); three
  sentences that over-stated a rule were corrected: init tolerates a
  root-owned symbolic link in the directory part of the database path, the
  live comparison reports every non-empty extra section, and the printed
  serve command's --allow-non-loopback is accepted with --secret-env or the
  explicit --insecure-no-secret (D15 m).
- Decisions added since: D15, in docs/decisions.md, with the chain rule
  stated exactly (README "Trust model", "The audit log" and L19; threat-model
  row 21 and L19; the operations guide's audit and recovery sections) and the
  document corrections of the round (README "Pause and resume", L1, L17 and
  L18; threat-model rows 4, 7, 10, 11, 15, 18, 20, 25 and 26 and limits L1,
  L17 and L18; the operations guide's processor, canary, pause and re-emit
  sections; SECURITY.md's scope and checklist; CLAUDE.md and ci.yml).
