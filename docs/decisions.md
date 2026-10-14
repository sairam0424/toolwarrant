# Design decisions D1 to D20

These records are taken from the commit messages that state each decision: the
five wave-1 commits of 2026-10-07 (b9e4533 core, 29dd670 processor, f2a3e5a
emit, c728172 crawl and fetch, 20e32b4 textdiff and export), the catalog
commit 8b7a574, the emitter commit 611e081, the end-to-end commit 21164fd, the
commits of the third round (2026-10-11, the fixes after the second review),
which state D11 and D12 and the catalog integrity changes recorded in
[threat-model.md](threat-model.md) rows 20 and 21, and the commits of the fourth
round (2026-10-11, the fixes after the third review), which state D13, and
the commits of the fifth round (2026-10-12, the fixes after the fourth review),
which state D14, the commits of the sixth round (2026-10-12, the fixes
after the fifth review), which state D15, the release design of 2026-10-12,
which is D16, and the commits of the seventh round (2026-10-12, the fixes
after the seventh review, scoped to the catalog chain and the canary), which
state D17, and the L17 decision of 2026-10-14 (owner decision O-1 of the
post-v0.1 plan, taken after the research of that day), which is D18, and the
TLS decision of 2026-10-14 (owner decision O-2 of the same plan, landed as
the processor's listener TLS, the canary's reader and the emitter's block),
which is D19, and the v0.2 release round of 2026-10-14 (the plan's PR 1.4 with owner decisions O-4
and O-5, landed as pull requests #15, #16, #20 and the release workflow
change), which is D20. The
post-review sections of [../seam/RESULTS.md](../seam/RESULTS.md) quote the same
decisions and record the corrections they forced to the spike's findings. Each
record gives the context (what a review found), the decision, its consequences
for operators and for other packages, and where it lives in code with the tests
that pin it. Where a decision is proven on the real gateway, the end-to-end
scenario is named: `TestEndToEnd` in `e2e/` runs scenarios A to Q against the
agentgateway v1.6.0 binary (`make e2e`; `demo/run.sh` keeps the last run in
`demo/last-run.log`).

## D1. The digest covers the whole definition: profile `full-v1`

- Context. The review found `_meta` excluded from the digest although hosts act
  on it (MCP Apps `ui.resourceUri`, OpenAI Apps SDK `openai/*` members), so
  unapproved `_meta` content rode on an approved tool. It also found that
  invalid UTF-8 and lone-surrogate object keys hashed as their U+FFFD twins, and
  that numbers beyond double precision (2^53 + 1 and 2^53, 1e-400 and 0) shared
  a digest, so one definition could be served as another.
- Decision (b9e4533). `gate.DigestProfile` is `"full-v1"`: the SHA-256 of the
  RFC 8785 canonical form of the whole tool object, no key excluded.
  `CanonicalTool` canonicalises the original bytes, refuses invalid UTF-8 and
  lone or ill-paired surrogate escapes (both reported as `ErrNotUTF8`; for a
  surrogate escape the RFC 8785 step's own refusal is wrapped alongside, since
  the third round: the second review found that at 21164fd a surrogate escape
  failed with only the canonicaliser's error, so `errors.Is(err, ErrNotUTF8)`
  was false, which no caller depended on because the crawler and the catalog
  classify every canonicalisation failure as `not-canonical`), and refuses a
  number whose token does not denote exactly the value its canonical rendering
  denotes (`ErrNumberPrecision`; 2^53 + 1 and 1e-400 are refused, while 1e23
  and 2^53 + 2 are accepted because their shortest rendering is their own
  value, so no two values can share a digest). `VolatileKeys` stays exported
  but is empty.
- Consequence. Every digest of a definition that carries `_meta` changed; an
  approval made before D1 reads as drifted until re-approved. A definition with
  an inexact number can be neither approved nor served (fail closed). A tool
  whose upstream rewrites a volatile `_meta` member on every listing drifts on
  every crawl and cannot be kept approved (limit L9). The number check parses
  every definition a second time, which roughly doubled the digest cost on the
  processor's hot path; the raw-byte digest cache (c311115) removes that cost
  for unchanged definitions. The catalog records the profile on every version
  (`VersionView.DigestProfile`) so a later profile can coexist with approvals
  made under this one.
- Where. `internal/gate/digest.go`, `internal/gate/numbers.go`,
  `internal/gate/surrogates.go`; `internal/catalog/schema.go` (the
  `digest_profile` column). Tests:
  `TestDigestProfile_IsFullV1WithNoExclusions`, `TestDigest_MetaIsPartOfTheDigest`,
  `TestCanonicalTool_RejectsNumbersBeyondDoublePrecision`,
  `TestCanonicalTool_RejectsLoneSurrogateEscapes`,
  `TestCanonicalTool_RejectsInvalidUTF8`; catalog
  `TestRecordCrawl_ChangedMetaIsANewDefinition`.

## D2. One processor address belongs to exactly one upstream

- Context. A HIGH finding reproduced on the real gateway: the processor never
  read `service_names`, and the emitter accepted one processor address for
  several servers, so a definition approved for server A was served and
  executed on route B, which had a different approved digest for the same name.
- Decision (29dd670 processor, f2a3e5a emit). The processor denies any hooked
  `tools/list` or `tools/call` whose `service_names` is not exactly
  `[Config.Target]`; `Target` defaults to the server name, which is what the
  emitted configuration names the backend. The emitter refuses a
  `ProcessorAddr` used by more than one server.
- Consequence. One processor process per upstream. The first mismatching hook
  is logged once at Warn (`hook names another backend`, with the quoted
  `service_names` value) and counted in `Stats.WrongBackend`, so `serve` shows
  the exact name to pass to `--target`; the line was at Debug, which the CLI's
  logger does not print, until the third round. The end-to-end test confirmed
  the value: `service_names` carries the backend name, which is the server
  name in the emitted file, and a route pointed by hand at another server's
  processor was denied as `wrong backend` on every list and call (scenario J;
  the counter appeared in scenario N). Tests that send hooks must carry
  `ServiceNames`. Since the fourth round the emitter also refuses a processor
  address on one of the gateway's own sockets (the serving port, the admin,
  stats or readiness listener), which the gateway's `--validate-only` accepts
  and which would make the gateway dial itself on every hook (D13).
- Where. `internal/processor/guard.go` (the admit check),
  `internal/processor/processor.go` (`Config.Target`);
  `internal/emit/validate.go`. Tests: `TestAdmit_HooksAboutAnotherBackendAreDenied`,
  `TestAdmit_AnotherRoutesCallNeverRidesOnThisServersApproval`,
  `TestAdmit_TargetMayDifferFromTheServerName`, `TestAdmit_FirstWrongBackendIsLoggedOnce`;
  emit `TestDuplicateProcessorAddrNamesBothServers`; e2e scenario J.

## D3. Quarantine the bad tool, keep the crawl, deny the conflicting name

- Context. Two reproduced findings. A page that listed the same name twice, the
  approved definition first, left the approved digest as evidence, so a later
  call passed (HIGH). And one tool with a hostile name (a zero-width space, a
  non-breaking space, a tab, over 256 bytes) made the catalog refuse the whole
  crawl before its transaction, recording nothing and freezing `LastSeen` on
  the approved digest while the upstream served something else (MEDIUM); the
  crawler also accepted definitions the gate and the catalog reject.
- Decision (29dd670 processor, c728172 crawl, b9e4533 lifecycle, 8b7a574
  catalog). The processor filters a page in two passes, names first: a repeated
  name denies the page and marks the name as conflicting until a clean page
  shows the approved digest. The crawler vets every listed tool with exactly
  the gate's and catalog's rules (shared name rule, 256 KiB, depth 32, RFC 8785
  canonicalisation) and puts a tool that fails, and every copy of a repeated
  name, in `Result.Unusable` with a reason and a safe detail while the valid
  tools are kept. The lifecycle marks a live definition that was invalid or
  duplicated as `UnusableDigest` in `LastSeen`: never served, no version
  created. The catalog records every crawl of a registered, unpaused server:
  a known tool with an unusable definition gets an unusable observation, an
  unknown one becomes a `tool.rejected` audit entry and `CrawlReport.Rejected`.
- Consequence. A decoy can no longer freeze the evidence that protects an
  approved tool. `list` flags such a tool `UNUSABLE`, `crawl` prints rejected
  entries with their reason (the name withheld), and `crawl --strict` exits 1
  when any tool was rejected or unusable. The unusable marker hides the tool
  from listings as well as from calls: the second review showed the processor
  listing a tool whose catalog `LastSeen` was the marker while the gateway
  happened to show the approved bytes (calls were denied by D9, so a client
  saw a tool it could never call); since the third round the list filter also
  hides a tool whose `LastSeen` is the marker (counted as `unverified`,
  `Stats.ToolsUnverified`), so an `UNUSABLE` tool is neither listed nor
  callable until a clean crawl records the approved digest, and since the
  fourth round the canary applies the same rule through the shared predicate
  `lifecycle.LastSeenVerifiable` (D13). A page the processor reads to the end
  but denies as a whole (a repeated name, a tool it cannot hash) leaves the
  conflict marker on every catalog tool it listed, and a page it cannot read
  through to the end (an entry without a string name, a `tools` member that is
  not an array, more than 10000 tools since the fifth round, when the survey
  began to stop at the per-page cap before reading the entry past it) is
  evidence about nothing, so every
  catalog tool of the snapshot gets the marker (D13; the third round's rule
  marked only the tools read before the failure, so the third review placed an
  unreadable decoy in front of a changed tool and that tool kept its older
  evidence). So a decoy in any position cannot keep a changed tool's older
  evidence alive: its calls are denied as changed until a clean page shows the
  approved digest. The crawl package's `ErrDuplicateTool` is never returned any
  more. The processor parses every page twice.
- Where. `internal/processor/filter.go`, `internal/processor/list.go`,
  `internal/processor/observed.go`; `internal/crawl/vet.go`,
  `internal/crawl/list.go`; `internal/lifecycle/observe.go`
  (`UnusableDigest` in `internal/lifecycle/lifecycle.go`); `internal/catalog/crawlprep.go`,
  `internal/catalog/crawl.go`. Tests:
  `TestCheckResponse_RepeatedNameDeniesThePageAndTheCallsUntilACleanPage`,
  `TestCheckResponse_DeniedPageMarksEveryCatalogToolOnIt`,
  `TestJudgeCall_NonDigestLastSeenMarkersHideTheToolAndDenyCalls`,
  `TestUnusableToolsDoNotFailTheCrawl`, `TestRepeatedNamesMakeEveryCopyUnusable`,
  `TestObserveUnusable_MarksLastSeenAndChangesNothingElse`,
  `TestRecordCrawl_PoisonNameIsQuarantined`, `TestRecordCrawl_DuplicateNamesAreUnusable`;
  cmd `TestCrawlReportsAnInvisibleToolNameAsRejected`; e2e scenario J (a
  duplicate page through the gateway is denied as a whole). The fourth round's
  tests are listed under D13.

## D4. Proposers are an append-only history and none of them may approve

- Context. The approver-differs-from-proposer rule compared against the last
  proposer, and both a re-proposal and `Enable` overwrote `ProposedBy`, so the
  person who introduced a digest could approve it after a crawler flip-flop or
  a colleague's `enable`.
- Decision (b9e4533 lifecycle; persisted by 8b7a574 catalog).
  `Version.Proposers` is an append-only history: a re-proposal adds a name,
  `Enable` adds nobody, nothing removes one; `Approve` refuses every proposer.
  The catalog persists the history in `tool_version_proposers`, an append-only
  table with its own guard triggers; `proposed_by` is immutable and must equal
  position 0 on load, else `ErrCorrupt`.
- Consequence. `ErrSelfApproval` now reads "approver must differ from every
  proposer". `show` lists every proposer of a version. The second-proposer
  protection survives a restart. `--allow-self-approval` relaxes the rule for
  every proposer at once, for a lab. `Rollback` does not apply the rule: its
  target was approved by someone before, so a proposer may roll back to it;
  that is deliberate and SECURITY.md's scope says so.
- Where. `internal/lifecycle/proposers.go`, `internal/lifecycle/decide.go`,
  `internal/lifecycle/toggle.go`; `internal/catalog/schema.go`,
  `internal/catalog/load.go`, `internal/catalog/guards.go`. Tests:
  `TestApprove_EveryProposerIsRefused`,
  `TestSelfApproval_ReproposalByAnotherCrawlerDoesNotLaunder`,
  `TestSelfApproval_EnableDoesNotRenameTheProposer`,
  `TestSelfApproval_FirstProposerIsRememberedAcrossReproposals`; catalog
  `TestProposers_ArePersistedAndEveryOneIsRefused`.

## D5. Every change of LastSeen or MissingCrawls is an audit event

- Context. After a reject or a missed crawl, a tool flipped between served and
  hidden with nothing in the log but `crawl.completed changes=0`, contradicting
  the catalog's own promise that no state change happens without an audit
  entry.
- Decision (b9e4533 lifecycle; mapped by 8b7a574 catalog). `ObserveCrawl`
  emits an event for every change of `LastSeen` or `MissingCrawls`:
  `tool.drifted` on every move to a non-approved digest (whether or not
  anything is approved), `tool.reverted` on every move back to the approved
  digest, `tool.returned` when a missing tool is listed again, `tool.missing`
  on a miss, `tool.unusable` when the live definition cannot be used. The
  catalog maps the new events to crawl change kinds (`returned`, `unusable`;
  drift classifies as `changed`).
- Consequence. Audit volume rises: an unapproved tool whose pending digest
  changes also emits `tool.drifted`. The crawl report gained the kinds
  `returned` and `unusable`. An observation that changes nothing emits nothing.
- Where. `internal/lifecycle/observe.go`; `internal/catalog/crawl.go`
  (`classify`). Tests: `TestAuditEvents_EveryVisibleChangeHasAnEventAndNoChangeHasNone`,
  `TestAuditEvents_FlipsAfterRejectAreEvents`,
  `TestAuditEvents_ReturnAfterMissingIsAnEvent`,
  `TestAuditEvents_RevertIsReportedInEveryState`; catalog
  `TestRecordCrawl_ReturnAfterMissIsReportedAndAudited`, `TestClassify`.

## D6. Caps everywhere, and a proposal budget

- Context. A hostile upstream could make the gate expensive (a 32 MiB page cost
  about 2.4 s of CPU and 200 to 250 MiB of heap per hook, one 16 MiB tool took
  1.75 s to hash, and gRPC had no stream limit) and could fill the catalog
  (versions grew without bound; a 60 by 1 MB crawl held the write lock for
  17.6 s and an operator's decision failed with SQLITE_BUSY).
- Decision (29dd670 processor; 8b7a574 catalog; c728172 crawl). Processor:
  8 MiB payload cap equal to the gRPC receive limit, 10000 tools per page,
  tools over 512 KiB hidden unhashed, 32 concurrent hooks with surplus denied
  as RESOURCE_EXHAUSTED, the hook context checked every 256 tools. Catalog:
  256 KiB per tool, 32 MiB per crawl, nesting depth 32, 10000 tools per crawl,
  and a proposal budget of 20 new digests per tool between decisions, past
  which a crawl that brings yet another digest marks the live definition
  unusable instead of storing it. Crawler: `MaxToolBytes`, `MaxTotalBytes`
  (32 MiB) and `Timeout` (5 min). The caps are exported so every component
  vets with the same numbers.
- Budget reset (third round). The budget is reset only by an explicit human
  decision. Approve, reject and rollback reset it, and so does
  `Store.ResetProposalBudget`, a decision that changes nothing but the budget
  and writes one audit entry, `tool.budget_reset`, by a human actor (D7). It
  exists for the state the second review found deadlocked: after an upstream
  revert the budget stayed exhausted with no pending proposal and nothing to
  roll back to, so no approve, reject or rollback was accepted and the tool
  could never take a new definition (limit L6). A budget that is already zero
  is refused, so the reset is never a silent no-op. The CLI command for the
  reset is `budget reset SERVER TOOL [--by NAME]`, a human decision with one
  audit entry; the system actor is refused as a usage error. A revert alone never
  resets the budget, because a hostile upstream could then cycle twenty garbage
  digests and a revert to grow the file.
- Per-server growth caps (fourth round). The budget is per tool, so it never
  bounded an upstream that lists fresh names on every crawl; D13 adds a fixed
  cap on tool rows per server and on stored canonical bytes per server, under
  which a crawl that would exceed either is recorded as failed under its own
  class and adds no rows, and makes crawl cost follow the live set.
- Consequence. Excess becomes a denial or a hidden tool, never a pass. A tool
  over 256 KiB can never be approved. A tool that changes faster than people
  decide is hidden until someone decides (limit L6). A listing over a cap is
  recorded as a failed crawl with a class. Fifteen oversized tools (7.5 MiB)
  cost 371 ms for the page where one 16 MiB tool cost 1.75 s before.
- Where. `internal/processor/limits.go`, `internal/processor/serve.go`;
  `internal/catalog/catalog.go` (exported caps), `internal/catalog/crawlprep.go`,
  `internal/catalog/tooldef.go`, `internal/catalog/ops.go`
  (`ResetProposalBudget`); `internal/crawl/config.go`. Tests:
  `TestCheckResponse_OversizedPayloadIsDenied`, `TestServe_RecvLimitIsThePayloadCap`,
  `TestConcurrency_HooksBeyondTheSlotLimitAreDeniedNotQueued`,
  `TestCheckResponse_OversizedToolIsHiddenUnhashedAndDeniesCalls`;
  catalog `TestRecordCrawl_ProposalBudgetCapsVersions`,
  `TestRecordCrawl_RejectResetsTheBudget`, `TestResetProposalBudget_Refusals`,
  `TestRecordCrawl_ListingOverACapIsRecordedAsFailed`,
  `TestRecordCrawl_LargeCrawlDoesNotBlockADecision`; crawl
  `TestTotalByteBudgetAcrossPages`.

## D7. Only a named person decides, and names are normalised

- Context. `Approve`, `Reject` and `Rollback` accepted a system actor, and
  approvals compared actor names byte for byte, so `Alice` and `alice` were two
  people and a look-alike spelling defeated the two-person rule. RESULTS.md
  recorded D7 as stated in none of the five wave-1 commits; the catalog commit
  8b7a574 states it.
- Decision (8b7a574 catalog). Approve, reject, roll back, disable, enable,
  pause and resume return `ErrHumanRequired` for a system actor. Every actor
  name is NFKC-normalised, lower-cased and must then match
  `^[a-z0-9][a-z0-9._@-]{0,63}$`; the normalised name is what is stored and
  compared.
- Consequence. Names with accents, spaces or other scripts are `ErrInvalid` in
  every method. The CLI reserves the name `crawler` for the system actor, lets
  a crawl without `--as` run as the system actor, and refuses a decision by the
  system actor with exit code 2 and advice to pass `--as`. `TOOLWARRANT_ACTOR`
  counts as an explicit `--as`, so a person whose environment names them
  proposes as themselves when they crawl and therefore cannot approve that
  crawl's proposals.
- Where. `internal/catalog/ops.go`, `internal/catalog/validate.go`;
  `cmd/toolwarrant/global.go`, `cmd/toolwarrant/decide.go`. Tests:
  `TestDecisions_RequireAHumanActor`, `TestActors_AreNormalisedBeforeStorageAndComparison`,
  `TestOperations_RejectAnInvalidActorBeforeTakingTheLock`; cmd
  `TestSelfApprovalAndSystemActorRefusals`, `TestActorNamesAreValidatedAndLowerCased`.

## D8. An optional shared secret between gateway and processor

- Context. ExtMCP hooks are unauthenticated and the processor accepted any
  listener, so anyone who could reach the port could poison the observed
  evidence, deny approved tools and enumerate approval state.
- Decision (29dd670 processor, f2a3e5a emit). The emitter writes an optional
  secret (`emit.Server.Secret`, 16 to 256 printable ASCII characters) under
  `processors[].metadata` as a CEL string literal with the key
  `toolwarrant_secret`; the processor reads that key from `metadata_context` on
  every hook and compares it in constant time; `Serve` refuses a non-loopback
  TCP listener unless `Config.AllowRemoteListener`.
- Consequence. The secret stands in the gateway file in clear, so a file that
  carries one must be readable by the gateway alone; since the fourth round the
  CLI writes every emitted file 0600, secret or not, and still warns when the
  file carries a secret (D13). The CLI exposes `--secret-env` on `emit` and
  `serve`. The end-to-end test settled the open question of this decision: the
  live gateway delivers `metadata_context` on both hooks, so with the shared
  value in the file and in the processor's environment every list and call
  works, and with another value every hook is denied as `wrong or missing
  processor secret` and counted in `Stats.Unauthenticated` (scenario H). `serve`
  refuses to listen on a TCP address other hosts can reach with
  `--allow-non-loopback` unless `--secret-env` is given or `--insecure-no-secret`
  is passed as well, so an exposed processor without a secret is an explicit
  choice; a `--secret-env` always wins over `--insecure-no-secret`. What the
  secret does not do: it is confidential against other hosts only. The
  gateway's admin API on the loopback admin listener hands the loaded
  configuration, secret included, to any local user (`GET /config_dump`, second
  review), so the admin listener is part of the trusted computing base (limit
  L18) and the gateway must run on a host without other local users, or in its
  own container or network namespace, or with the admin API turned off by the
  emitter. The two packages' key constants are pinned equal by a test.
- Where. `internal/processor/guard.go`, `internal/processor/serve.go`,
  `internal/processor/processor.go` (`Config.Secret`, `SecretMetadataKey`);
  `internal/emit/emit.go`, `internal/emit/quote.go`; `cmd/toolwarrant/serve.go`
  (the listen policy). Tests:
  `TestAdmit_SharedSecretIsRequiredOnEveryHook`, `TestServe_SharedSecretIsCheckedOverGRPC`,
  `TestWire_SecretIsReadFromMetadataContextOnBothHooks`,
  `TestWire_SecretMetadataKeyIsTheOneEmitWrites`,
  `TestServe_RefusesAListenerReachableFromOtherHosts`; emit
  `TestSecretWrittenAsCELStringLiteral`, `TestHostileSecretsAreValidCEL`; cmd
  `TestEmitWithASecretWritesAPrivateFileAndWiresServe`, `TestCheckListenAddrPolicy`,
  `TestServeAcceptsTheExposureFlagsOnLoopback`; e2e scenario H.

## D9. The call rule: every piece of evidence must equal the approved digest

- Context. The `tools/call` hook carries no definition (finding F1). The
  processor judged a call from whatever evidence it had, and the review showed
  evidence that could be stale or poisoned: a duplicate-name page left the
  approved digest in place, and `LastSeen` could be a marker rather than a
  digest.
- Decision (29dd670 processor). A call is allowed only when every piece of
  evidence equals the approved digest: the digest observed in the latest
  gateway listing and the digest the latest crawl recorded in `LastSeen`. A
  `LastSeen` that is not a 64-character lowercase hex digest (the
  `UnusableDigest` marker) denies as unverified. No evidence at all denies. An
  empty `LastSeen` with a matching observed digest allows, so a tool the gateway
  listed correctly is callable even if the last crawl missed it. Observed
  evidence can expire (`Config.MaxEvidenceAge`).
- Consequence. A client that never re-lists is caught by the crawl's
  `LastSeen` within the crawl cadence (limit L1); the end-to-end scenario C
  measured both paths (denied 1.5 ms after another session listed the drifted
  definition through the gateway, and otherwise as soon as the crawl recorded
  the drift). A tool that was never listed through the gateway and never
  crawled is denied. The rule is one-directional on purpose: after an upstream
  revert, or after a rollback, the tool is listed again on the very next
  `tools/list` because the live bytes hash to the approved digest, but
  `tools/call` is denied as `changed since approval` until the next crawl
  records the revert in `LastSeen` (scenario D). Crawl right after a rollback.
  A `LastSeen` that is the unusable marker hides the tool from listings as well
  as from calls (D3), so a tool hidden for a marker is also uncallable; the
  reverse does not hold. A `LastSeen` that is another real digest (a stale
  crawl, a rollback not yet followed by a crawl, an upstream that shows the
  crawler something else, limit L4) still lists the tool while the live bytes
  hash to the approved digest and denies its calls until the next crawl
  records the revert, which is the rule above. The third review found the
  earlier wording of this record, "what is listed is exactly what is callable",
  contradicted by this very paragraph; the marker direction is the one that
  holds. `MaxEvidenceAge` also ages conflict markers (limit L15).
- Label note. The catalog commit 8b7a574 also labels `PauseServer` and
  `ResumeServer` "(D9)". To keep the numbering of RESULTS.md, that decision is
  recorded here as D9a: a paused server refuses crawls (`ErrPaused`), its
  snapshot is empty so nothing of it is served, and decisions keep working
  until `ResumeServer`. Pause and resume write `server.paused` and
  `server.resumed` audit entries and require a human actor (scenario E).
- Where. `internal/processor/call.go` (`judgeCall`); D9a in
  `internal/catalog/servers.go`. Tests: `TestJudgeCall_RuleTable`,
  `TestJudgeCall_NonDigestLastSeenMarkersHideTheToolAndDenyCalls`,
  `TestCheckRequest_AbsentOrUncrawledToolsNeedOnePieceOfEvidence`,
  `TestCheckRequest_DeniesWhenTheLatestCrawlDiffersEvenIfNeverListed`,
  `TestEvidence_ObservedDigestsExpire`; catalog `TestPauseAndResumeServer`; cmd
  `TestPauseBlocksCrawlingAndServing`; e2e scenarios C, D and E.

## D10. Digest mismatches are counted and reported, not hashed around

- Context. agentgateway v1.6.0 re-serialises tool definitions before the ExtMCP
  hook and drops keys it does not know (MEDIUM). A tool carrying such a key is
  permanently "changed since approval": the crawler's digest can never equal
  the gateway's. Before D10 such a tool was indistinguishable from an
  unapproved one.
- Decision (29dd670 processor). Mismatches are counted apart from unapproved
  tools (`Stats.ToolsMismatched` against `Stats.ToolsUnapproved` and
  `Stats.ToolsOversized`) and logged at Info as `digest mismatch` with quoted
  names. v0.1 does not hash a projection of what the gateway re-serialises; it
  detects the case and reports it, so the tool stays hidden.
- What the gateway strips. The end-to-end scenario L lists a tool carrying the
  top-level members MCP revision 2025-11-25 names (`title`, `outputSchema`,
  `icons`, `execution`), three `_meta` members (`vendor/ui`, `ui`,
  `openai/outputTemplate`), a vendor member inside `inputSchema`, an unknown
  `annotations` member and an unknown top-level key through the gateway,
  derives from what a raw client received the key paths the gateway dropped,
  kept and added, and compares the three sorted lists exactly with the golden
  `e2e/testdata/gateway_tool_keys.json`, recorded on 2026-10-14 from one run on
  the pinned binary. Dropped: `x-vendor` (with `x-vendor.tier`),
  `annotations.x-risk`, `execution` (with `execution.taskSupport`) and the
  `_meta` member `ui` (with `_meta.ui.resourceUri`). Kept: `name`, `title`,
  `description`, `inputSchema` with every member under it,
  `inputSchema.x-vendor` included, `outputSchema` with every member under it,
  `icons[0].src`, `icons[0].mimeType`, `icons[0].sizes`, `annotations.title`,
  `annotations.readOnlyHint`, `_meta.vendor/ui` and
  `_meta.openai/outputTemplate`. Added: nothing. This agrees with the first
  recording of scenario L (`x-vendor` and `annotations.x-risk` dropped;
  `annotations.title`, `annotations.readOnlyHint` and `_meta.vendor/ui` kept)
  and pins what the second review's lab saw and this tree did not (`_meta.ui`
  and `execution` dropped; `openai/outputTemplate` under `_meta`, `title`,
  `outputSchema`, `icons` and vendor keys inside `inputSchema` kept); the
  lab's number observation (`1e2` re-serialised as `100.0`, harmless under RFC
  8785) is about values, which the golden does not compare. The logs do not
  show the rule behind the `_meta` member named `ui`, so a `_meta` member must
  still be assumed droppable until the golden shows otherwise (limits L2 and
  L9). A run whose lists differ fails scenario L naming the list and the
  entries on each side and writes the lists it derived to
  `gateway_tool_keys.observed.json` next to the process logs; a move of the
  gateway pin (L7) re-records the golden by copying that file and reviewing
  the diff. `TestToolKeysGoldenRefusesWhatItCannotCompare` pins that a golden
  naming another release, carrying an unknown field or holding an unsorted
  list is refused rather than compared.
- Consequence. Limit L2: such a tool cannot be served in v0.1 at all, because
  the catalog can only approve what the crawl saw and the gateway never serves
  those bytes. With the processor in place the tool is hidden, so
  `verify-gateway` reports it as MISSING (approved, the latest crawl saw the
  approved digest, the gateway does not list it; scenario L printed `MISSING
  vendor_tool`), and the processor's `digest mismatch` log line and the
  `mismatched` counter in the `serve` stats line say why. MISMATCH is not a
  verdict of its own: it is the sub-label of a LEAK line for an approved,
  enabled tool whose live digest differs from the approved one, which a client
  can only see when the route has lost its processor (D12). A mismatch counted
  by the processor on a tool that was just approved is this case, not drift.
- Where. `internal/processor/results.go`, `internal/processor/list.go`,
  `internal/processor/processor.go` (`Stats`); the known limit is also stated in
  the package comments of `internal/gate` and `internal/processor`. Tests:
  `TestCheckResponse_MismatchedAndUnapprovedAreCountedApart`,
  `TestCheckResponse_LogNamesTheBrokenToolButTheClientReasonDoesNot`; e2e
  scenario L (`e2e/toolkeys_test.go`) against the golden
  `e2e/testdata/gateway_tool_keys.json`.

## D11. No data plane of its own: the seam is hardened instead

The spike (findings F1 to F3) and both review rounds found every weak point of
v0.1 at the seam with the gateway rather than in the catalog: the call hook
carries no definition (F1), the guard is config-presence-based (F3), the gateway
binds the processor chain per session (limit L3), re-serialises definitions
before the hook (L2), forwards an id-less `tools/call` without the hook (L17)
and exposes an unauthenticated admin API on the gateway host (L18). Each of
these is a property of agentgateway v1.6.0, not of toolwarrant, and each raised
the same question: should toolwarrant proxy MCP traffic itself, so that the
bytes a client receives are the bytes toolwarrant judged? The decision of this
round is no. toolwarrant keeps no data plane of its own, the non-goal in
README.md stands beyond v0.1, and the seam is hardened instead. A proxy of our
own would have to reimplement the gateway's transport, session, authentication
and streaming work, would turn a control plane for MCP into an MCP product
(which the project's naming rule forbids), and would move the class of bugs
found at the seam into code nobody has reviewed rather than remove it. The
gateway is the data plane the operator chose; the job of toolwarrant is to make
what the gateway serves provably equal to what a person approved, and to make
every way the gateway could fail open visible.

The consequence is a method rather than a feature: every gateway behaviour that
weakens the guarantee is recorded as a known limit with a control on our side
and, where the behaviour is a defect, a report to the gateway project as the
owner's pending action. The controls so far are the loopback bind by
configuration (611e081, `gateways.bindAddress`), the explicit allow rule and
`failureMode: failClosed` on every route, the shared secret (D8), the canary
with its live-configuration comparison and its unhooked-call probe (D12, widened
to the whole configuration document and to the recorded body hash by D13), the
emitter's listener inputs with an off switch for the admin API and its option
to validate the file with the gateway binary (`emit --gateway-binary`), and the
pin to one gateway version with re-qualification by the emitter's binary tests
and the end-to-end test before every move (L7). The decision is revisited only
if a gateway behaviour appears that no control on our side can make visible.
Where: `internal/emit` (the gateways form and the listener inputs),
`cmd/toolwarrant/verify.go` and `cmd/toolwarrant/verdicts.go` (the canary),
`e2e/` (every scenario runs through the real gateway). Tests: `TestEndToEnd`
scenarios F, I, K, L, O and P; emit `TestGatewayParsesBindAddress`,
`TestGoldenFilesValidateWithRealGateway`.

## D12. LEAK means served but not approved, and the canary probes the gateway

- Context. The second review ran `verify-gateway` against a route whose
  processor had been removed, the F3 case the canary exists for, and got exit
  0 three times over: OK while nothing had drifted (the allow rule hides
  unapproved names, so the listing looked right), MISMATCH while the upstream
  served a poisoned description that fresh sessions were reading, and MISMATCH
  again after the operator had rejected that digest. LEAK appeared only after
  a crawl had recorded the drift. The same review found that the gateway
  forwards a `tools/call` sent as a JSON-RPC notification (no `id`, or
  `id: null`) without invoking the processor and without applying the allow
  rule, and that any local user can replace the live configuration through the
  unauthenticated admin API on the loopback admin listener.
- Decision (third round). LEAK is any tool the gateway serves that the catalog
  would not serve (`lifecycle.Serves` is false for the live digest), and it
  fails the check with exit 1. The old MISMATCH verdict is kept only as a
  diagnostic sub-label on a LEAK line for the approved, enabled tool whose live
  digest differs from the approved one, with both digests printed so the owner
  can see whether the served definition is legitimate. Exit 0 is reserved for
  OK and MISSING. The canary gains two probes. With `--admin ADDR` it fetches
  the gateway's live configuration from the admin API (`GET /api/config`) and
  compares it with the file named by `--config`; a difference is
  LIVE-CONFIG-MISMATCH, exit 1, and it is what a processor-less route looks
  like in steady state, when no listing can show the loss. Unless `--no-probe`
  is given, every check also sends an id-less `tools/call` for a name that no
  catalog can hold; a gateway that forwards it (HTTP 202) instead of rejecting
  it is UNHOOKED-CALLS, exit 1. The probe reaches the upstream when the gateway
  is unhooked, which is why it can be switched off.
- Consequence. A supervisor that treats exit 1 as an incident now fires for a
  poisoned or rejected definition the moment a fresh session can read it, for
  a live configuration that is not the emitted file, and for a gateway build
  that forwards unhooked calls. The L2 re-serialisation case shows as MISSING
  with the processor present (D10), never as a verdict of its own. The admin
  listener's address becomes an emitter input, as do the stats and readiness
  addresses (`emit --admin-addr`, `--stats-addr`, `--readiness-addr`), and the
  admin API can be turned off (`emit --disable-admin` writes the gateway's own
  `adminAddr: off`); with it off the live-configuration
  comparison has nothing to query, so the operator chooses between a gateway
  host without other local users, the admin API on loopback and the comparison
  on, or no admin API and no comparison (L18). The id-less call is a gateway
  defect: the probe is the control on our side, the report to the gateway
  project is the owner's pending action (L17), and the probe is re-run on every
  move of the gateway pin (L7). The e2e scenario L's assertion that MISMATCH
  alone exits 0 encoded the old behaviour and changed with this decision: on
  the CEL-only variant scenario L now expects `LEAK vendor_tool` with the
  MISMATCH sub-label and exit 1, with or without `--config`. The third review
  found four gaps in these probes, and D13 closes them: the live comparison
  read one route by name, the probe called any JSON-RPC error in a 2xx answer
  the gateway's refusal, the LEAK rule ignored the unusable marker the
  processor enforces (now the UNVERIFIED sub-label), and a `--keep-going` run
  stopped during a check that had printed a LEAK exited 0.
- Where. `cmd/toolwarrant/verdicts.go` (`compare`, the LEAK rule),
  `cmd/toolwarrant/verify.go` (`--admin`, the probe, `--no-probe`),
  `internal/emit/listeners.go` (the listener inputs). Tests: cmd
  `TestCompareSortsLiveToolsIntoVerdicts`,
  `TestVerifyGatewayReportsLeaksAgainstAPassThroughUpstream`,
  `TestVerifyGatewayChecksTheEmittedConfig`,
  `TestVerifyGatewayProbesForUnhookedCalls`; e2e scenarios F (CONFIG-EDITED and
  LEAK across a hand edit, and the `--every 1s --keep-going` canary that
  exited 1 on SIGTERM after reporting both), O (UNHOOKED-CALLS, exit 1, from
  the pinned binary's HTTP 202, with the probe in the hostile upstream's
  request log; `--no-probe` reports the probe as skipped) and P
  (LIVE-CONFIG-MISMATCH, exit 1, after the processors were removed through
  `POST /api/config`, against a byte-identical copy of the emitted file; the
  gateway rewrote the watched file with the header lines kept, so that file
  reported CONFIG-EDITED).

## D13. The fourth round: the serving path, the integrity report, the caps, the canary and the emitter

- Context. The third hostile review (2026-10-11, four reviewers over the areas
  core, processor and emit, ingest, CLI and documents, each finding re-run by
  an independent verifier against d28e0e3 and 9cc8f28) confirmed twenty-five
  findings and raised one of them, the serving path's approval evidence, from
  medium to high. The code findings, in the order of the sub-decisions below:
  a tools row pointed back at a superseded version by three plain `UPDATE`
  statements, and a definition rewritten after dropping and re-creating a
  guard trigger with its original DDL, were both served by `Snapshot` and
  `Approved` because any historic approve row about the version counted as
  evidence; `UPDATE tools SET state = 'enabled'` re-served a disabled,
  deprecated or paused tool with `Integrity` clean, a foreign `AFTER UPDATE`
  trigger undid every later disable inside the operator's own transaction, and
  a raw `UPDATE` of the proposal budget left no `tool.budget_reset` entry; an
  upstream that listed 1500 fresh names on every crawl grew the catalog by
  18 MB in six crawls and made every later crawl slower while README L6 said it
  could not grow the database; an unreadable decoy listed in front of a changed
  tool denied the page without marking the changed tool, and a full
  observed-evidence table dropped the changed digest of a servable tool and
  allowed its call; the live-configuration comparison read the one route named
  after the server, so a shadow route that owned the path, a second route on
  another path and a second gateway on `0.0.0.0:3001` all compared healthy and
  each loaded in `--validate-only`; a `--keep-going` canary stopped while the
  admin fetch that followed a LEAK was in flight exited 0, and `crawl --every`
  kept recording crawls into a catalog whose guard trigger was gone and exited
  0, as did a schedule in which every crawl failed; `emit` wrote a URL with a
  credential in its path into a 0644 file in silence, renumbered every later
  server's processor port when a server was added, accepted a processor address
  on one of the gateway's own sockets, and no command compared the body hash
  it printed; the probe called any JSON-RPC error in a 2xx answer the gateway's
  refusal, whoever produced it; the canary counted a tool whose latest crawl
  left the unusable marker as approved and current while the processor hides
  it; and `audit verify --expect-head` with a mismatching head returned before
  the integrity report. The document findings are listed at the end.
- Decision (a): the serving path's approval evidence is the newest decision
  about the tool. Among all versions of a tool, the approvals row with the
  highest id whose decision is `approve` or `rollback` must point at the
  approved version and carry `hash_seen` equal to its digest; `Snapshot`,
  `Approved` and every version load apply the rule and report `ErrCorrupt`
  otherwise. The rule reads the append-only approvals table only, so it costs
  no pass over the log and closes both variants: a pointer flipped back to a
  superseded version has an older row, not the newest, and a rewritten
  definition no longer hashes to the `hash_seen` the newest row carries. The
  cross-check against the audit log remains `Store.Integrity`'s.
- Decision (b): `Store.Integrity` compares every mutable column the log
  describes with the latest entry about the subject: `tools.state`,
  `servers.paused`, `tools.proposals_since_decision`, `servers.allow_private`
  and a SHA-256 of `servers.url` (a hash, so no credential enters the log),
  next to the approved digest and the last-seen digest it compared before; and
  any trigger or view in `sqlite_master` that the schema did not create is
  `ErrCorrupt` at `Open`, on every `Snapshot` and `Approved` load and at the end
  of every write transaction, because a foreign trigger on `tools` cannot be
  benign and a long-lived writer must never commit into a file every other
  command refuses (indexes that are not guards are left alone: an index cannot
  change what a query returns). A forensic open tolerates it so that
  `audit verify` can run, and `Integrity` reports it as `unexpected trigger X`
  or `unexpected view X`. `audit verify` runs the integrity report whether or
  not `--expect-head` matched and reports both findings together, withholding
  the head reminder when either fails.
- Decision (c): per-server growth caps. A fixed cap on tool rows per server,
  live and deprecated together (`catalog.MaxToolsPerServer`, five full crawls
  of fresh names, 50000), and on the canonical bytes stored across every
  version of every tool of a server (`catalog.MaxServerBytes`, thirty-two
  crawls at the per-crawl cap, 1 GiB; the raw definition is stored next to the
  canonical form, so the file can hold about twice that per server), next to
  the per-crawl caps of D6. A crawl that would push the server over either is
  recorded as a failed crawl under its own class (`server-tools-cap`,
  `server-bytes-cap`) and adds no row, like a listing over a per-crawl cap;
  only a crawl that adds rows or bytes pays for the counts. Crawl cost follows
  the live set: deprecated rows are not loaded on every crawl, except a
  deprecated tool that still carries the unusable marker, which the first crawl
  that does not list it loads once more to clear the marker. The recovery is
  `server pause`, then a fresh `init` and a re-crawl; there is no prune in
  v0.1, because versions are immutable and the log is append-only.
- Decision (d): a `tools/list` page the processor cannot read through to the
  end is evidence about nothing, so every servable catalog tool of the snapshot
  gets the conflict marker (a page read to the end but denied still marks every
  catalog tool it listed, as before). The observed-evidence table is sized from
  the snapshot at every reload (the snapshot's tool count plus a small margin,
  at most `DefaultMaxTracked`), records only catalog tools the catalog could
  serve (never-servable names cannot fill it), and when full evicts an entry
  whose digest equals its approved digest, never a contradiction; when no
  agreeing entry is left the new evidence is dropped and counted
  (`Stats.EvidenceDropped`), and from then on a servable tool with no listing
  evidence is denied as not yet verified until a listing records it, because
  the missing entry may be the contradiction that was lost.
- Decision (e): the live-configuration comparison covers the whole document.
  Every emitted gateway and route must be present exactly once with the same
  fields and the same match path, nothing the file does not carry may exist,
  no path may appear twice, and the path of `--url` must be the emitted
  route's match. Any violation is LIVE-CONFIG-MISMATCH, exit 1, and the line
  names the route or gateway (`route X: not in the emitted file (gateway G,
  path P); the gateway serves it without the emitted guards`, `gateway G: not
  in the emitted file ...`, `path P: matched by N live routes`). The end-to-end
  scenario P gained the two steps: a route added through the admin API and a
  shadow route owning the client's path with the server's route parked
  elsewhere, each reported as LIVE-CONFIG-MISMATCH with exit 1 and the live
  configuration restored afterwards.
- Decision (f): the canary tallies a check before it looks at the stop signal,
  prints its verdict lines before any network call that follows the listing
  (the admin fetch and the probe), and fails the run at the end if any verdict
  line was printed, so a `--keep-going` run that printed a LEAK cannot exit 0.
  `crawl --every` re-checks the catalog before every crawl (a snapshot load,
  which verifies the guard objects), stops at once with exit 1 on a catalog
  error (`ErrCorrupt`, `ErrSchema`, an unknown server), and exits 1 when it is
  stopped if no crawl completed or the catalog refused any crawl as a whole
  (a per-crawl or per-server cap); an upstream that was down for a while is
  printed and counted but does not fail the run.
- Decision (g): the emitted gateway file is always 0600; the operator makes it
  readable by the gateway's user with `chown` or an ACL, and the warning for a
  server URL with a query string stays. Processor addresses are stable across
  re-emits: an existing file at `--out` that is `emit`'s own output (header and
  body hash intact) is read first and each server keeps its address, a
  `--processor` override wins, a new server takes the next free port above
  every port in use, and every change is printed (`processor address of server
  X is new: ADDR`, `processor address of server X changed from A to B; restart
  its processor on the new address`); a file at `--out` that is not what `emit`
  wrote is not trusted for addresses, with a warning, because whoever wrote it
  would otherwise choose where the processors listen. The end-to-end scenario J
  re-emits a side file as servers are added in an order that would have
  renumbered them and checks that no address moves. A processor address on one
  of the gateway's own sockets (a loopback, localhost or wildcard host with the
  serving port or a listener port; since D15 (h) any host that is a name rather
  than an IP literal) is refused by the emitter; the gateway's
  `--validate-only` accepts such a file. `verify-gateway` gains
  `--expect-body-hash HEX` (needs `--config`), mirroring `audit verify
  --expect-head`: the body hash `emit` printed, recorded off the host, is
  compared with the file and a difference is CONFIG-EDITED, exit 1, header
  recomputed or not (limit L19).
- Decision (h): the unhooked-call probe calls HTTP 400 healthy, HTTP 202
  UNHOOKED-CALLS, and any other 2xx answer with a body PROBE-INCONCLUSIVE, which
  fails the check with exit 1: a JSON-RPC error in such an answer may be an
  upstream's reply relayed by a forwarding gateway, and the probe must not
  report health it did not see. On the pinned gateway, which answers 202, the
  classification is unchanged; the case is a re-qualification item for every
  move of the pin (L7).
- Decision (i): the schema version moves from 3 to 4, because the audit detail
  format gains the fields (b) compares (the state, the budget, the paused and
  allow-private flags, the URL hash). A v3 file from an unreleased build is
  refused with `ErrSchema` and must be re-initialised, as every earlier version
  was. Extended after the eighth review: when both the canary's host and the emitted address are IP literals they must be equal (a gateway bound to 127.0.0.1 does not listen on 127.0.0.2 or ::1, so a stand-in there with the emitted ports is not the emitted gateway); the loopback-class rule remains for names; an unspecified emitted address is compared by port alone.
- Decision (j): the digest-shape rule is shared. `internal/lifecycle` exports
  `IsDigest` and `LastSeenVerifiable` (9cc8f28); the processor and the canary
  use them instead of private copies, so a served tool whose latest crawl left
  the unusable marker is a LEAK with the sub-label UNVERIFIED (the marker is
  printed) and is not counted MISSING when a working processor hides it. The
  state machine's own looser rule (any non-empty value other than
  `UnusableDigest`) is unchanged, so the property tests keep their short
  stand-in digests.
- Request headers (finding processor-emit-6 of the third review). The ExtMCP
  request carries the client's HTTP request headers after the gateway's own
  filtering, and with no filter agentgateway v1.6.0 forwards every header and
  pseudo-header, so a client's bearer token or cookie rode each hook across the
  plaintext gateway-to-processor link (limit L11). The processor reads no
  header, so every processor entry `emit` writes now carries a `requestHeaders`
  filter: the allow list names the one pseudo-header `:method` (an empty allow
  list means "forward everything", so a non-empty one is the only way to say
  "nothing"), and the deny list names `authorization`, `cookie` and
  `proxy-authorization` as well, so the file states what must never cross even
  if a later gateway read the allow list differently. The pinned binary loads
  the filter and each half of it alone. What the gateway puts on the wire with
  the filter in place was not observed in this tree.
- Consequence. Operators: record the `body sha256` line `emit` prints the way
  the audit head is recorded and pass it as `--expect-body-hash`; make the
  emitted file readable by the gateway's user (it is 0600 whatever it carries);
  re-emitting after adding a server no longer darkens the other routes; a
  server that hit a growth cap is paused and re-initialised; `audit verify`
  reports a state, budget, pause, URL or egress-policy edit and a foreign
  trigger or view; a database from the third round (schema v3) must be
  re-initialised. On agentgateway v1.6.0 the probe still fails every check
  (L17), so the documents now say to run it once, record the limit and pass
  `--no-probe` until the pin moves, instead of promising an OK line the pinned
  gateway cannot print. Document corrections of the round: D9 no longer says
  that what is listed is exactly what is callable (the marker direction holds,
  the digest direction does not); CLAUDE.md names schema v4; README.md and
  SECURITY.md say the CI workflow runs on every pull request and every push to
  main, which is what `.github/workflows/ci.yml` triggers on; `.golangci.yml`
  names golangci-lint v2.14.0; README step 7, the SECURITY.md canary item and
  the operations guide show the OK line as it is printed, with the
  live-configuration and probe clauses. The fourth review re-attacked this
  round and D14 records what did not hold: the newest-decision rule of (a)
  trusted `approvals.hash_seen`, a column the same drop-and-re-create technique
  rewrites; the whole-document comparison of (e) decoded two of the fourteen
  top-level sections the gateway loads and compared neither the
  `requestHeaders` filter nor the processor metadata; the stable addresses of
  (g) were read from the file at `--out`, which L19 says an attacker can
  re-seal; the probe rule of (h) called an HTTP 400 healthy whoever produced
  it; and the per-server caps of (c) bound rows and bytes but not the audit
  log.
- Where. In `docs/threat-model.md` this round changed rows 4, 11, 16, 18, 20,
  21, 22, 25 and 26 and limits L1, L6, L11, L17, L18 and L19. In the code:
  `internal/catalog/snapshot.go` and `internal/catalog/load.go` (a),
  `internal/catalog/integrity.go`, `internal/catalog/integrity_audit.go` and
  `internal/catalog/guards.go` (b), `internal/catalog/crawl.go` and
  `internal/catalog/tooldef.go` (c), `internal/catalog/schema.go` (i);
  `internal/processor/filter.go` and `internal/processor/observed.go` (d);
  `cmd/toolwarrant/liveadmin.go` and `cmd/toolwarrant/liveconfig.go` (e),
  `cmd/toolwarrant/verifyloop.go` and `cmd/toolwarrant/crawl.go` (f),
  `cmd/toolwarrant/emit.go`, `internal/emit/validate.go` and
  `cmd/toolwarrant/verify.go` (g), `cmd/toolwarrant/probe.go` (h),
  `cmd/toolwarrant/verdicts.go` and `internal/lifecycle/digestshape.go` (j);
  `internal/emit/route.go` (the request-header filter). Tests: processor
  `TestCheckResponse_UnreadablePageMarksEveryServableToolOfTheSnapshot`,
  `TestCheckResponse_FullObservedTableEvictsAgreeingEvidenceNeverAContradiction`,
  `TestCheckResponse_EvidenceIsKeptForEveryCatalogTool` (renamed in the sixth round, when evidence began to be kept for every catalog tool, D15 g),
  `TestCheckRequest_DroppedEvidenceDeniesUnlistedToolsUntilListed`,
  `TestReload_SizesTheObservedTableFromTheSnapshot` (d); emit
  `TestProcessorOnAGatewaySocketIsRefused`,
  `TestProcessorSocketRuleAppliesToEveryServer`,
  `TestProcessorSocketRuleFollowsTheListenerInputs`,
  `TestProcessorSocketRuleLeavesOtherRefusalsAlone`,
  `TestProcessorOnAnotherHostMayShareAGatewayPort`,
  `TestGatewayAcceptsAProcessorOnItsOwnSocket` (g, the binary accepts what the
  emitter refuses), `TestEveryProcessorEntryFiltersClientHeaders`,
  `TestHeaderFilterNamesArePinned`, `TestGatewayParsesTheRequestHeaderFilter`,
  `TestGatewayAcceptsEachHalfOfTheFilterAlone` (request headers); cmd
  `TestLiveComparisonCatchesAShadowRouteThatOwnsThePath`,
  `TestLiveComparisonCatchesAnAddedOpenGateway`,
  `TestLiveComparisonReportsAnAddedRoute`, `TestLiveComparisonChecksTheURLPath`,
  `TestCompareDocumentsNamesEveryDifference`,
  `TestCompareRoutesEscapesAndFailsClosed`, `TestEmittedConfigReadsWhatEmitWrites`,
  `TestGatewayAcceptsTheShadowRouteDocument` (e); lifecycle
  `TestIsDigestAndLastSeenVerifiable` (j); catalog
  `TestSnapshot_PointerFlipToASupersededVersionIsCorrupt`,
  `TestSnapshot_DropEditRecreateGuardIsCaughtByTheNewestDecision`,
  `TestSnapshot_NewestDecisionRuleAcceptsEveryStoreWrittenHistory` (a),
  `TestIntegrity_StateFlipReenablingADisabledToolIsReported`,
  `TestIntegrity_StateFlipRevivingADeprecatedToolIsReported`,
  `TestIntegrity_PausedFlagFlipUnpausingAServerIsReported`,
  `TestIntegrity_BudgetColumnResetByRawSQLIsReported`,
  `TestOpen_ForeignTriggerIsCorrupt`, `TestOpen_ForeignViewIsCorrupt`,
  `TestRecordCrawl_RefusesToCommitAfterAGuardWasDropped`,
  `TestDecisions_RefuseToCommitAfterAGuardWasDroppedOrRedefined` (b),
  `TestRecordCrawl_RenamedToolsStopAtTheServerCap`,
  `TestRecordCrawl_NewDefinitionsStopAtTheServerByteCap`,
  `TestRecordCrawl_DeprecatedToolsAreLoadedOnlyWhenListed`,
  `TestServerCaps_Constants` (c); cmd
  `TestKeepGoingExits1WhenStoppedDuringACheckThatFoundALeak`,
  `TestLoopTallyOutcome`, `TestCrawlEveryStopsAtOnceOnACorruptCatalog`,
  `TestCrawlEveryExits1WhenNoCrawlCompleted`, `TestCrawlTallyOutcome` (f),
  `TestEmitAlwaysWritesAnOwnerOnlyFile`,
  `TestEmitKeepsProcessorAddressesAcrossReEmits`,
  `TestPlanEmitKeepsPreviousAddresses` (its previous-file reader and that
  reader's test were removed in the fifth round, since addresses now come from
  the catalog, D14), `TestPortAllocator`,
  `TestVerifyGatewayComparesTheRecordedBodyHash` (g),
  `TestProbeReportsARelayedUpstreamAnswerAsInconclusive` (h),
  `TestVerifyGatewayReportsAnUnverifiedToolAsALeak` (j),
  `TestAuditVerifyReportsIntegrityWhenTheHeadMismatches` (the integrity report
  under a mismatching head); e2e scenarios J
  (stable processor addresses on the side file) and P (the added route and the
  shadow route).

## D14. The fifth round: the trust boundary of the catalog file, the chain on the serving path, the replaced file, the live comparison and the processor addresses

- Context. The fourth hostile review (2026-10-12, four reviewers over the
  areas ingest, CLI and documents, core, and processor and emit, each finding
  re-run by an independent verifier against a96672e) confirmed twenty-six
  findings, two of them reported from two areas, four of them high after
  verification. In the order of the sub-decisions below: the newest-decision
  rule of D13 (a) read `approvals.hash_seen`, a column that one guard trigger
  protects, so the drop-and-re-create technique applied to
  `approvals_no_update` together with `tool_versions_immutable` rewrote a
  definition and its `hash_seen` consistently, and `Snapshot`, `Approved` and
  `Versions` served the rewritten bytes under the approver's name while only
  `Integrity` saw it; one `DELETE` of a `tools` row with foreign keys off (the
  `sqlite3` shell's default), or a rewrite of the proposer tables under
  re-created guards, laundered the proposer rule of D4: the next crawl
  discovered the tool afresh with the system actor as proposer and the person
  whose crawl had proposed the bytes approved them with `Integrity` and
  `audit verify` clean; a rejected version flipped back to pending by one
  `UPDATE` was approvable and unreported; a `UNIQUE` index the schema did not
  create broke every write with a plain constraint error while `audit verify`
  printed `integrity ok`; an upstream that listed fresh unusable names on every
  crawl added one `tool.rejected` entry per name (258 bytes of log columns
  each, about 2.6 MB per crawl at the per-crawl cap) and no cap counted them,
  while README L6 said the caps bounded the file; after the documented
  growth-cap recovery (pause, delete the file, `init`, re-register,
  re-approve) a running processor kept reading the deleted file through its
  open handle, its generation never moved, and it listed and allowed calls to
  a tool the catalog on disk no longer approved, with `source errors` at zero
  and nothing logged; `list` printed a forged approved pointer as fact while
  `Snapshot`, `Approved` and `Versions` refused the file, and the operations
  guide told the operator to run `list` against a suspect database;
  `PRAGMA journal_mode = DELETE` on a tampered file locked out the forensic
  open, whose error suggested a read-write open that the guard check refused;
  a page over the payload cap was denied before the marking step, so a changed
  tool kept its older evidence; a pause followed by a resume emptied the
  observed-evidence table, contradictions included; one `tools/list` hook
  allocated about eighteen times its payload before the per-page count ran;
  three code comments still said that what is listed is exactly what is
  callable; loopback spellings the resolver accepts (`127.1`, `0x7f.0.0.1`,
  `2130706433`, `0`) passed the socket rule and were warned about as
  non-loopback, and a processor on the very bind or listener address the input
  named was accepted; the live comparison decoded the `gateways` map and the
  `routes` list only, so a `binds` listener or a top-level `mcp` section, both
  of which the pinned binary loads in `--validate-only`, compared as a match,
  and the processor `requestHeaders` filter and metadata were not compared; a
  FIFO at `--config` blocked the canary in `open()` with no verdict, no exit
  and no reaction to SIGTERM or SIGINT, and a FIFO at `--out` blocked `emit`;
  a re-emit took processor addresses from a file whose header had been
  recomputed, or that was reached through a symbolic link at `--out`, and the
  documented CONFIG-EDITED remedy (run `emit` again) re-sealed the forged
  address with no change line and an OK canary; without `--keep-going` a check
  that printed a LEAK and then hit a probe error did not end the run;
  `audit verify` returned at a broken chain without the integrity report; the
  probe called an HTTP 400 healthy whoever produced it, and its error said
  "without a body" whatever the body was; `init` followed a symbolic link in
  the directory part of the database path; the Changed text section of `diff`
  printed a raw quotation mark inside a quoted span, so a span could appear to
  close early. The finding that unlisted deprecated tools kept a stale unusable
  marker was fixed in 15eba5e before this round (D13 (c) as corrected) and was
  re-verified: `TestModel_StoreFollowsTheLifecycleModel` passes with the
  reviewer's recorded seed and
  `TestRecordCrawl_DeprecatedToolWithAMarkerIsClearedOnce` pins the clearing.
- The trust boundary, stated once. The controls inside the catalog file (the
  guard triggers, the newest-decision rule, the chain anchor and the pin below,
  `Store.Integrity`) detect rewrites of history. Whoever can write the 0600
  file can also append a new, correctly sealed audit entry that approves a
  definition, and nothing inside the file can refute it; that is detected only
  by anchors outside the file: the audit head the operator records, the git
  export of approved definitions, and backups. This round therefore anchors
  the serving path to the chain, so that a forger must re-chain the log suffix
  (which the recorded head betrays), lets a running processor pin the chain
  prefix it has verified, so that history cannot change under it, and states
  the remaining limit in one sentence in README L19, threat-model row 21 and
  here. Corrected by D15: re-sealing one entry against its predecessor does
  not force a re-chain, because the forger recomputes that one hash from the
  real `prev_hash` and leaves the head alone; since the sixth round an entry
  is trusted only when it is part of the chain the `Store` verified, and the
  forger must rewrite every entry from the forged one to the head. Corrected
  again by D17 (k): that rewrite is caught by a running `Store` through the
  head it pinned, and when no `Store` holds a pin (the CLI between commands,
  the processors while stopped) it is caught by the recorded head alone; the
  pin never protected the CLI. And by D17 (a) and (c): the columns a decision
  or a server view acts on were still trusted through the tables; since the
  seventh round they are trusted only through the chain too.
- Decision (a): the serving-path evidence reaches the chain. For every
  approved version, `Snapshot`, `Approved` and `Versions` read the newest
  `version.approved` or `version.rolled_back` audit entry about the tool,
  require its `after_hash` to equal the approved digest, and require the entry
  to re-seal from its predecessor (`audit.Seal`), next to the newest-decision
  rule of D13 (a). The verifier memory of `RecheckTTL` caches the result by
  entry hash, so the price is one indexed read and one seal per approved tool
  per ten minutes per `Store`. A forger who rewrites a definition and its
  `hash_seen` under re-created guards must now also rewrite and re-chain the
  log suffix, which `audit verify --expect-head` betrays. Corrected by D15 (a)
  and (b): the re-seal against the predecessor alone accepted an entry
  rewritten in place (a new `after_hash` or actor, the hash recomputed from
  the real `prev_hash`) with the head unchanged, and the verifier memory keyed
  by the stored hash column accepted a rewritten `after_hash` alone while the
  memory was warm; the fifth review served such an entry from a long-lived
  `Store` and from a fresh one, with `Integrity` clean. Since the sixth round
  the entry must be part of the chain the `Store` verified.
- Decision (b): chain pinning. A `Store` remembers the sequence number and
  hash of the newest audit entry it has verified; every `Snapshot` verifies
  that the entry still has that hash and that the suffix since it re-seals,
  then advances the pin. A mismatch is `ErrCorrupt`, which the processor turns
  into a source-error denial of every hook, so the log cannot be rewritten
  under a running processor without every list and call being denied. The
  first pin is the head as the `Store` finds it at open, verified to re-seal
  from its predecessor only, because verifying the whole chain on every start
  of a processor or a canary would cost a full read of the log; a rewrite
  before the `Store` opened is what `audit verify` with the recorded head is
  for. Corrected by D15 (a): verifying the head's seal alone at open left
  every entry below the head unverified, so the pin caught nothing rewritten
  below it; since the sixth round the `Store` verifies the whole chain once at
  open (the read `audit verify` already pays) and keeps the hash it computed
  for every decision entry, and the limit that remains is a chain rewritten
  completely before the `Store` opens, which only the recorded head catches.
- Decision (c): `Store.Integrity` gains passes that the log makes possible: a
  subject the log describes whose `tools` row is gone; a `tools` row with no
  `tool.discovered` entry; a second `tool.discovered` entry for one subject
  (the catalog never deletes a row, so a second discovery is impossible);
  `tool_versions` rows whose tool is gone; each version's proposer list
  against the actors of its `version.proposed` entries; and each version's
  status reconstructed from the log (`version.proposed`, `version.superseded`,
  `version.rejected`, `version.approved`, `version.rolled_back`) against
  `tool_versions.status`. A `UNIQUE` index the schema did not create is a
  foreign object, like a foreign trigger or view (an ordinary index cannot
  change what a query returns; a unique one changes what every write does).
  New guard triggers refuse `DELETE` on `tools`, `tool_versions`,
  `tool_version_proposers` and `approvals`, so the laundering `DELETE` is
  refused outright and a dropped guard is a missing guard. A constraint
  failure on a guarded table inside a write transaction is reported as
  `ErrCorrupt`, so a crawl schedule stops instead of treating it as an
  upstream failure.
- Decision (d): audit-log growth. The per-server caps of D13 (c) bound rows
  and bytes; the log grows with observed changes. A per-crawl cap on rejected
  entries (`catalog.MaxRejectedPerCrawl`, a named constant) bounds the one
  shape that added entries without adding rows: a crawl that would exceed it
  is recorded as failed under its own class and adds no entries. The documents
  say it as it is: the caps bound rows and bytes, and the log grows with
  observed changes, bounded by the crawl cadence and this cap.
- Decision (e): replaced-file detection. `init` writes a random catalog
  identity into the `meta` table; a `Store` records it and the file's device
  and inode at open; `Generation` re-checks both and returns `ErrReplaced`,
  which wraps `ErrCorrupt`, when the file at the path was replaced or removed.
  The processor turns that into a source error that denies everything with the
  reason `catalog unavailable` and logs `catalog unavailable, denying` at
  Error. The end-to-end scenario N deletes and re-initialises the catalog
  under two running processors: 23 and 26 ms after the re-init both denied
  every list and call with that reason and logged the line, and a processor
  started on the new file served the re-approved tool while a tool approved
  only in the deleted file was denied as not approved. The recovery procedures
  say to stop every processor of the file before deleting it, and README no
  longer says that the processors need no restart without the qualification
  "while the file is the same".
- Decision (f): `Tools` and `Tool`, the queries behind `list` and `show`,
  apply the same evidence as the serving path and return `ErrCorrupt`, so the
  operations guide no longer presents `list` as a check against a suspect
  database. A forensic open accepts a database whose journal mode is not WAL
  (it opens with `mode=ro` and `immutable=1`), so `audit verify` and
  `audit list` work on a file whose tamperer also switched the journal mode.
- Decision (g): processor. An oversized page marks every catalog tool of the
  snapshot, servable or not, before it is denied, like every other page the processor cannot
  read through to the end. The observed-evidence table is pruned only against
  a non-empty snapshot and never loses a contradiction, so a pause followed by
  a resume keeps every conflict marker and changed digest the gateway's
  listings recorded. `internal/mcpwire` counts the entries of a `tools/list`
  page with a streaming decoder and stops at the per-page cap before the array
  is materialised, so a page of tiny entries cannot allocate many times its
  bytes. The three comments that still said listed equals callable now state
  the one-way rule of D9. Corrected by D15 (f) and (g): over the gRPC
  transport a page over the payload cap is refused for size before the hook
  runs, so the marking inside the hook was unreachable in the shipped runtime
  (the fifth review's padded page left a changed tool's older evidence alive
  with nothing counted or logged); since the sixth round the processor
  observes the transport's refusal of a `CheckResponse` call and marks every
  catalog tool of the snapshot from it, which applies to a gateway that
  forwards such a page; agentgateway v1.6.0 answers the client HTTP 500 before
  the hook for a page over its own limit (e2e scenario J, 6 MiB and 9 MiB), so
  there nothing is marked and the window is the crawl cadence (L1). The pause rule kept only the evidence
  recorded before the pause: a listing during the pause was judged against
  the empty snapshot and discarded, and so was a listing about a disabled
  tool; since the sixth round evidence is recorded for every catalog tool a
  page names, servable or not, and a page seen while the snapshot is empty is
  judged against the names already tracked.
- Decision (h): emit. A processor host that is all digits, dotted digits or
  hex-looking must parse with `netip.ParseAddr` or is refused, so a loopback
  spelling the resolver would accept cannot pass the socket rule as a name;
  the socket rule compares the processor address with the input's own bind
  address and listener addresses, not only with the loopback class. Corrected
  by D15 (h): the rule knew one name, `localhost`, so the loopback aliases
  common resolvers map without DNS (`localhost.localdomain`, `localhost4`,
  `localhost4.localdomain4`, `localhost6`, `localhost6.localdomain6`,
  `ip6-localhost`, `ip6-loopback`) passed with the serving or the admin port
  and were warned about as non-loopback; since the sixth round a processor
  whose host is a name rather than an IP literal is refused on any port the
  gateway binds, and those aliases count as loopback in the emitter and in
  `serve`.
- Decision (i): CLI. The live comparison decodes `GET /api/config` into a map
  of top-level sections and fails closed on any non-empty section other than
  `config`, `gateways` and `routes`, one LIVE-CONFIG-MISMATCH line per extra
  section (`section binds: not in the emitted file; it may bind ports and
  routes the comparison cannot see`); it compares the `config` block's admin,
  stats and readiness addresses, the `requestHeaders` filter of every
  processor (the allowed and the disallowed list), and the processor metadata
  by equality of a hash of its canonical form, never printing a value. The
  end-to-end scenario P pins what the pinned gateway does with such a
  document: on the emitted file `GET /api/config` rendered the sections
  `config`, `gateways` and `routes` with the header filter in the processor
  entry; a `binds` section with a listener on another port and a top-level
  `mcp` shortcut were each accepted by `POST /api/config` with status 200 and
  rendered, and through each new listener a fresh session listed every tool
  of the upstream, unapproved `wipe_database` included, and `tools/call echo`
  was allowed, so each is a route with no processor and no allow rule; the
  comparison reported each as LIVE-CONFIG-MISMATCH naming the section, and a
  stripped header filter as `processor requestHeaders allowed: emitted
  :method, live (none)` with its `disallowed` twin. Processor addresses live
  in the catalog: a `servers.processor_addr` column written by `emit` and by
  `emit --processor` with the audit entry `server.processor_set`, shown in
  the PROCESSOR column of `server list` (`-` before the first emit); `emit`
  never reads addresses from the file at `--out`, so a file an attacker wrote
  or re-sealed lends nothing to the next emit. `--config` and `--out` must be
  regular files: a symbolic link, directory, device, socket or named pipe is
  refused by `Lstat` before anything is opened, and the open itself never
  follows a link and never blocks. Without `--keep-going` the run exits 1 at
  a check that found a failing verdict even if a later step errored, while a
  listing failure alone is printed, counted and does not stop the run.
  `audit verify` runs the integrity report even when the chain is broken and
  reports both; a broken chain is not compared with `--expect-head`, since
  the head is then meaningless. The probe treats an HTTP 400 as healthy only
  when its body is not a JSON-RPC error (a JSON-RPC error on a 400 is
  PROBE-INCONCLUSIVE, since a forwarding gateway relays the upstream's
  refusal), and its error text names the status and whether a body was
  present (`the gateway answered http status N with a body of M bytes`).
  `init` walks the directory of the database path and refuses a component
  that is a symbolic link not owned by root (links the operating system
  installs in its own directories, such as `/var` on macOS, are tolerated),
  so a link planted in a shared working directory cannot redirect where the
  private file is created. Corrected by D15 (i), (j), (k) and (m): the live
  comparison decoded the known fields of each route and of `config` only, so
  a route policy, backend or `config` field the emitted file cannot carry
  compared as a match (the fifth review's `extProc`, `requestMirror`,
  transformation, `urlRewrite`, second host backend and `config.mcp` block,
  each accepted by `--validate-only`); since the sixth round every live route,
  backend and `config` field is decoded generically and anything the file
  cannot carry is a mismatch, and the documents say "every non-empty
  top-level section", which is what the code always compared. `emit` recorded
  the processor addresses before the file was validated and written, so a
  refused emit left the address and its audit entry behind and the next emit
  printed no `is new` line; since the sixth round the addresses are recorded
  after the rename. The probe recognised a single JSON-RPC error object only,
  so a JSON-RPC batch of errors on a 400 was healthy; since the sixth round a
  400 whose body parses as JSON, object or array, is PROBE-INCONCLUSIVE and
  only an empty or non-JSON body is healthy. SECURITY.md said `init` refuses
  every linked directory, which omits the root-owned exception above, and the
  `emit --processor` help and the operations guide said `serve` accepts
  `--allow-non-loopback` only with `--secret-env`, which omits the explicit
  `--insecure-no-secret`; both sentences were corrected.
  The comparison runs even when the canary's own listing failed: a policy
  posted through the admin API can break the route for new sessions (a
  `requestMirror` did, on agentgateway v1.6.0, in e2e scenario P); the
  LIVE-CONFIG-MISMATCH lines are printed and named next to the listing failure
  and the run exits 1
  (`TestVerifyGatewayComparesTheLiveConfigurationWhenTheListingFails`).
- Decision (j): `textdiff` escapes a quotation mark inside a quoted changed
  span as `\"`, the way it already did inside a key, so a span can only end at
  the renderer's own closing quote. Landed in the commit after this round's
  documents; pinned by `TestTool_changedTextSpanEscapesQuotationMarks`.
- Decision (k): the schema version moves from 4 to 5 (the new column, the
  meta key and the no-delete guards). A v4 file from the fourth round is
  refused with `ErrSchema` and must be re-initialised, as every earlier
  version was.
- Decision (l): how the round was run. Each area was fixed by one agent that
  edited only its own paths and reported to the lead in its final message; no
  agent messaged another, and the documents were written against the
  decisions above and checked against the tree at the end.
- Consequence. Operators: a database from the fourth round (schema v4) must be
  re-initialised; stop every processor of a catalog file before deleting or
  replacing it and start them after `init`, because a processor that detects a
  replaced file denies every hook and logs an error until it is restarted;
  record the audit head, keep the git export and keep backups, because they
  are the only anchors against an appended, correctly sealed approval; after a
  CONFIG-EDITED the remedy is still to run `emit` again, and the addresses it
  writes come from the catalog (`server list` shows them), not from the file;
  `list` and `show` refuse a tampered file like every other command, so use
  `audit verify` and `audit list` on a suspect database; a canary without
  `--keep-going` ends at the first check that printed a failing verdict even
  when a later step of that check errored; the growth of the audit log is
  bounded by the crawl cadence and the rejected-entries cap, not by the
  per-server caps. The processor's `source errors` counter rises when the
  file was replaced under it. Document corrections of the round are listed in
  the corrections subsection of [../seam/RESULTS.md](../seam/RESULTS.md).
- Where. In `docs/threat-model.md` this round changed rows 4, 7, 10, 11, 15, 16,
  18, 20, 21, 22, 25 and 26 and limits L1, L6, L17, L18 and L19, and states
  the trust boundary of the catalog file in row 21. In the code:
  `internal/catalog/anchor.go` and `internal/catalog/approved.go` (a),
  `internal/catalog/pin.go` and `internal/audit/audit.go` (`VerifyFrom`, b),
  `internal/catalog/integrity_versions.go`, `internal/catalog/integrity.go`,
  `internal/catalog/guards.go` and `internal/catalog/store.go` (c),
  `internal/catalog/crawl.go` and `internal/catalog/crawlprep.go`
  (`MaxRejectedPerCrawl`, the `rejected-cap` class, d),
  `internal/catalog/identity.go` (e), `internal/catalog/views.go` and
  `internal/catalog/openmodes.go` (f), `internal/catalog/processoraddr.go`
  and `internal/catalog/schema.go` (i, k); `internal/processor/list.go`,
  `internal/processor/filter.go`, `internal/processor/observed.go`,
  `internal/processor/snapshot.go` and `internal/mcpwire/mcpwire.go` (g);
  `internal/emit/socket.go` and `internal/emit/validate.go` (h);
  `cmd/toolwarrant/liveadmin.go`, `cmd/toolwarrant/livecompare.go`,
  `cmd/toolwarrant/liveconfig.go`, `cmd/toolwarrant/paths.go`,
  `cmd/toolwarrant/verify.go`, `cmd/toolwarrant/verifyloop.go`,
  `cmd/toolwarrant/audit.go`, `cmd/toolwarrant/probe.go`,
  `cmd/toolwarrant/global.go`, `cmd/toolwarrant/emit.go`,
  `cmd/toolwarrant/emitports.go` and `cmd/toolwarrant/server.go` (i);
  `internal/textdiff/tool.go` (j, pending). Tests: catalog
  `TestSnapshot_RewritingHashSeenUnderRecreatedGuardsIsCorrupt`,
  `TestSnapshot_AppendedApprovalRowIsCaughtByTheChainAnchor`,
  `TestSnapshot_AnchorAcceptsStoreWrittenHistoryAndRemembersEntries` (a),
  `TestSnapshot_LegitimateAppendsAdvanceThePin`,
  `TestSnapshot_ReChainedLogIsCaughtByThePinAndTheRecordedHead`,
  `TestSnapshot_LogChangedAfterThePinIsCorrupt` (b), audit
  `TestVerifyFrom_AcceptsEverySuffixOfAValidChain`,
  `TestVerifyFrom_ZeroPrevIsVerify`,
  `TestVerifyFrom_RefusesASuffixThatDoesNotContinueFromPrev` (b); catalog
  `TestIntegrity_DeletedToolRowIsRefusedAndReported`,
  `TestIntegrity_ProposerHistoryRewrittenUnderRecreatedGuardsIsReported`,
  `TestIntegrity_RejectedVersionFlippedToPendingIsReported`,
  `TestIntegrity_ProposerAndStatusReconstructionAcceptsStoreWrittenHistory`,
  `TestIntegrity_RowsTheLogDoesNotDescribeAreReported`,
  `TestOpen_ForeignUniqueIndexIsCorrupt`, `TestOpen_PlainForeignIndexIsTolerated`,
  `TestInTx_ConstraintFailureIsCorrupt` (c),
  `TestRecordCrawl_RejectedEntriesStopAtTheCap`,
  `TestRecordCrawl_RejectedCapConstant` (d),
  `TestGeneration_DetectsADeletedAndReinitialisedFile`,
  `TestGeneration_DetectsARenamedFileAndRecoversWhenItReturns`,
  `TestGeneration_DetectsAnotherIdentityInMeta`,
  `TestOpen_WritesAndKeepsACatalogIdentity` (e),
  `TestTools_ForgedApprovedPointerIsCorrupt`,
  `TestTools_ApplyTheServingPathEvidence`,
  `TestOpenWith_ForensicOpensANonWALFile` (f),
  `TestSetProcessorAddr_RecordsTheAddressAndTheEntry`,
  `TestIntegrity_ProcessorAddrRewrittenIsReported` (i),
  `TestOpen_RefusesOtherSchemaVersions` (k); processor
  `TestCheckResponse_OversizedPageMarksEveryServableToolBeforeDenial`,
  `TestCheckResponse_OversizedPageWithAnUnreadableCatalogIsASourceError`,
  `TestCache_PauseAndResumeKeepTheListingEvidence`,
  `TestCheckResponse_OverCapPageIsRefusedBeforeNamesAreRead`,
  `TestCheckResponse_ReplacedCatalogFileDeniesEveryHook`,
  `TestCache_CorruptGenerationDiscardsTheCacheUntilASnapshotReloads` (e, g),
  mcpwire `TestParseToolsList_StopsAtTheCapBeforeReadingTheEntryPastIt`,
  `TestToolsList_WalkRejectsEntriesWithoutAStringName`,
  `TestToolsList_EntriesAliasTheInput`,
  `TestInternals_DecoderDisagreementsFailClosed` (g); emit
  `TestAmbiguousProcessorHostSpellingsAreRefused`,
  `TestNumericHostRuleLeavesNamesAndCanonicalAddressesAlone`,
  `TestIsNumericHost`, `TestGatewayAcceptsAmbiguousProcessorSpellings` (the
  binary accepts what the emitter refuses),
  `TestProcessorOnTheGatewaysOwnSpecificAddressIsRefused`,
  `TestProcessorBesideTheGatewaysOwnAddressIsAccepted`, `TestIsGatewayHost`
  (h); cmd `TestLiveComparisonReportsASectionTheFileDoesNotCarry`,
  `TestLiveComparisonComparesTheConfigListeners`,
  `TestLiveComparisonComparesTheRequestHeaderFilter`,
  `TestCompareDocumentsSeesAMissingRequestHeaderFilter`,
  `TestLiveComparisonComparesTheProcessorMetadataWithoutShowingIt`,
  `TestEmittedConfigReadsTheHeaderFilterAndHashesTheMetadata`,
  `TestGatewayAcceptsAMixedGatewaysAndBindsDocument` (the binary loads the
  `binds` document), `TestReEmitIgnoresAForgedAddressInTheFileAtOut`,
  `TestPlanEmitKeepsPreviousAddresses`,
  `TestEmitKeepsProcessorAddressesAcrossReEmits`,
  `TestVerifyGatewayReportsAFIFOAtConfigAsEdited`, `TestEmitRefusesAnIrregularOut`,
  `TestReadRegularFile`, `TestInitRefusesADirectorySymlink`,
  `TestEveryWithoutKeepGoingStopsAtALeakWhenTheProbeErrors`,
  `TestEveryWithoutKeepGoingStopsAtAnEditedConfigWhenTheListingFails`,
  `TestAuditVerifyReportsIntegrityWhenTheChainIsBroken`,
  `TestProbeReportsARelayed400WithAJSONRPCErrorAsInconclusive`,
  `TestProbeErrorSaysWhetherTheAnswerHadABody` (i); e2e scenario P (the
  header filter, the `binds` section and the `mcp` section through the admin
  API of the running gateway) and scenario N (the catalog deleted and
  re-initialised under two running processors). The fixed finding about the
  stale unusable marker is pinned by `TestModel_StoreFollowsTheLifecycleModel`
  and `TestRecordCrawl_DeprecatedToolWithAMarkerIsClearedOnce`.

## D15. The sixth round: the verified chain, the whole-route live comparison, the transport-refused page and the pin-bootstrap limit

- Context. The fifth hostile review (2026-10-12, four reviewers over the
  areas ingest, CLI and documents, core, and processor and emit, each finding
  re-run by an independent verifier against a369090) confirmed fifteen
  findings, three of them high and three medium after verification; the
  in-place rewrite of an audit entry was reported from two areas and the
  over-cap page from two. In the order of the sub-decisions below: the chain
  anchor of D14 (a) re-sealed the newest approval entry against its
  predecessor only, the pin of D14 (b) verified the head and the suffix after
  the pin only, and the verifier memory of `RecheckTTL` was keyed by the hash
  column the forger writes, so a forger with file write access rewrote one
  approval entry in place below the head (a new `after_hash` or actor with
  the hash recomputed from the real `prev_hash`, or `after_hash` alone while
  the memory was warm), kept the head unchanged, and a long-lived `Store`, a
  fresh read-only `Store` and a fresh read-write `Store` all served the
  rewritten digest under the approver's name, `Approved` exported the
  poisoned bytes, the decision path accepted it, and `Store.Integrity`
  reported nothing, while only the full chain walk of `VerifyAudit` broke at
  the successor; the same rewrite of every `version.proposed` entry about a
  tool, together with the proposer tables under re-created guards, laundered
  the proposer rule of D4 with `Integrity` clean, so the proposer approved;
  `Store.Integrity` read the audit entries without verifying them, so its
  cross-checks agreed with a rewritten log; the documents' sentence "a forger
  must re-chain the log suffix, which the recorded head betrays" was
  therefore false; the stored catalog identity was compared by `Generation`
  alone while `Snapshot`, `Approved`, `Versions`, `Tools` and `Tool` compared
  the device and inode only, so an identity changed in `meta` gave
  `ErrReplaced` from one read and success from the others; the guard check
  and `Integrity` compared triggers, indexes and views but never a table's
  DDL and ignored an index without DDL text, so `audit_log` re-created with an
  extra `UNIQUE (event)` passed every check while every later `RecordCrawl`
  failed with an `ErrCorrupt` that named no cause; over the gRPC transport a
  `tools/list` page over the payload cap was refused with `ResourceExhausted`
  before `CheckResponse` ran (the receive limit equals the cap and the message
  is larger than its payload), so the marking D14 (g) added to the hook was
  unreachable in the shipped runtime, nothing was counted or logged, and a
  padded page next to a changed tool kept the older evidence alive, which is
  the fourth review's finding one layer down; listing evidence seen while a
  tool could not be served was discarded (a paused server's empty snapshot
  made every name a catalog miss, and `record` skipped a disabled tool), so a
  listing during a pause or while disabled that showed the changed definition
  left the pre-pause agreeing digest in place and the call passed after the
  resume or the enable; the socket rule knew one host name, `localhost`, so
  `localhost.localdomain`, `localhost4`, `localhost4.localdomain4`,
  `localhost6`, `localhost6.localdomain6`, `ip6-localhost` and `ip6-loopback`,
  which resolvers map to loopback from the hosts file without DNS, passed with
  the serving or the admin port, were warned about as non-loopback, and the
  gateway loaded the file; the live comparison read a fixed set of fields
  inside the three known sections and `json.Unmarshal` dropped every other
  key, so the emitted document plus an `extProc` policy, a `requestMirror` to
  another host at percentage 100, a response transformation, a `urlRewrite`,
  a second host backend next to the `mcp` one and a `config.mcp` block, each
  of which agentgateway v1.6.0 accepts (it lists thirty-two route policies and
  thirty-seven config fields), compared as a match and the canary printed OK;
  `emit` recorded the processor addresses and their `server.processor_set`
  entries before the file was validated and written, so a refused emit left
  them behind for a file that never existed and the next emit printed no
  `is new` line; the probe recognised a single JSON-RPC error object only, so
  a 400 carrying a JSON-RPC batch of errors was called healthy; the CI
  `test-full` job ran `internal/textdiff` and `internal/catalog` only while
  `TestServe_AcceptsAPageOverGRPCsDefaultLimit` also skips under `-short`, and
  CLAUDE.md counted five skips where there are six; three sentences stated a
  rule more strongly than the code enforces it (SECURITY.md's `init` and
  symbolic links, "every top-level section" where the code compares non-empty
  ones, the printed `serve` command needing `--secret-env` where
  `--insecure-no-secret` is also accepted); and the documents listed the
  over-cap page of more than 10000 tools among the pages read to the end,
  which the fifth round's streaming survey had stopped doing.
- The trust boundary, restated. Whoever can write the 0600 file can append a
  new, correctly sealed audit entry that approves a definition, and nothing
  inside the file can refute it (D14). Inside the file, an audit entry is
  trusted only when it is part of the chain the `Store` verified: a forger
  who rewrites an entry must rewrite every entry from the forged one to the
  head, which changes the head a running `Store` pinned and the head the
  operator recorded. A chain rewritten completely, head included, before any
  `Store` opens it is caught only by the recorded head: the pin-bootstrap
  limit. README "The audit log" and L19, threat-model row 21 and L19 and the
  operations guide state the rule in these words. Corrected by D17 (k): the
  limit is wider than "completely". Any rewrite from the forged entry to the
  head made while no `Store` holds a pin verifies clean on the next open and
  is caught by the recorded head alone; the entries before the forged one
  stay byte for byte what they were (the seventh review left 6 of 13
  unchanged). The pin protects a running `Store` only, so a processor while
  it runs and never the CLI, whose `Store`s open and close with each command.
  The documents now state the limit in those words and tell operators to
  record the head after every verify and compare it before every decision
  made after processors were stopped.
- Decision (a): the whole chain, once, at open. A `Store` verifies the whole
  audit chain when it opens (`audit.VerifyFrom` from the first entry over a
  streamed read, the read `audit verify` already pays) and pins the head. It keeps in memory the hash
  it computed itself for every decision entry it walked (`version.proposed`,
  `version.superseded`, `version.rejected`, `version.approved`,
  `version.rolled_back`, `tool.budget_reset`, `server.processor_set`) and for
  the head. Every reload verifies the suffix after the pin with
  `audit.VerifyFrom` and extends the memory. `audit.HashOf` exposes the seal
  computation over an entry's fields alone, ignoring the hash column it was
  stored with.
- Decision (b): trust comes from the walk. The serving path (`Snapshot`,
  `Approved`, `Versions`, `Tools`, `Tool`) and the decision path (every
  `Apply`, the proposer list `Approve` consults included) trust an audit entry
  only when the hash computed locally from its fields equals the hash the
  verified walk recorded for its sequence number. The stored hash column is
  never consulted for trust and never keys a memory. A mismatch is
  `ErrCorrupt`, which the processor turns into a source-error denial of every
  hook. Corrected by D17 (a): this covered the audit entries the decision
  path reads, but the decision path still trusted the `status` and
  `ever_approved` columns of `tool_versions` through the approvals table (any
  approve or rollback row, at any id), so the seventh review flipped the
  flag with one `UPDATE`, added an approvals row at id -2 and rolled back to
  an unapproved digest as its sole proposer with the chain untouched; since
  the seventh round every version's status and ever-approved flag used by a
  decision and by `Versions` is reconstructed from the verified `version.*`
  entries, a column that disagrees is `ErrCorrupt`, and `Rollback` accepts a
  target only when a verified `version.approved` or `version.rolled_back`
  entry names its digest.
- Decision (c): `Store.Integrity` verifies every entry's seal from its
  predecessor and its link to its successor as it streams the log and reports
  each break as a problem, so its cross-checks are meaningful on their own.
- Decision (d): the stored catalog identity is compared in `checkFile` too,
  so every read compares it, as the documents said.
- Decision (e): the guard check and `Integrity` compare the stored DDL of
  every table with the schema (the same normalisation as for triggers and
  indexes) and account for every automatic index (`sql IS NULL`) that the
  schema's own tables create, reporting any other as a foreign object; the
  `ErrCorrupt` raised for a constraint failure names the table and the
  constraint when SQLite reports them.
- Decision (f): processor. A `CheckResponse` call whose message the gRPC
  transport refuses for size (`ResourceExhausted` from the length prefix) is
  observed on the call's request decoder, within the same handler call, and
  the processor marks every catalog tool of the snapshot (every tracked entry
  while the snapshot is empty), counts the denial and logs it, exactly as it
  does for an oversized page it reads itself. The order on the wire, found by
  the first ci run after the eighth review: grpc-go's server stream writes the
  status to the client before it returns the error to the decoder, so the
  gateway sees the failed hook a moment before the marking lands, and a
  `tools/call` in that moment is judged against the evidence the previous
  listing left, as one an instant earlier would have been (the test that read
  the statistics inside that moment now waits for the marking); marking needs no payload, so the
  refused message's secret and service names, which were never read, cannot
  gate it. The documents say what the shipped runtime does: on agentgateway v1.6.0
  a page over the gateway's own limit never reaches the processor at all (HTTP
  500 to the client before the hook; e2e scenario J with 6 MiB and 9 MiB
  pages), so the refusal marks only for a gateway that forwards such a page.
- Decision (g): listing evidence is recorded for every catalog tool the page
  names, servable or not (a contradiction costs one slot and the table is
  sized from the snapshot's whole tool count with a margin), never for a name
  the catalog does not know. A page seen while the snapshot is empty (a paused
  server) is judged against the names already in the observed table: a
  readable page records its digests for the tracked names and an unreadable
  page marks every tracked entry.
- Decision (h): emit. A processor whose host is a name rather than an IP
  literal is refused when its port is one the gateway binds, because a name
  may resolve to this host (`processor address NAME:PORT has a host that is
  not an IP literal and may resolve to this host, so it may be the gateway's
  own SOCKET socket (port N): the gateway would dial its own listener for
  every hook; write the processor's IP address or use a port the gateway does
  not bind`). The loopback aliases common resolvers map without DNS
  (`localhost.localdomain`, `localhost4`, `localhost4.localdomain4`,
  `localhost6`, `localhost6.localdomain6`, `ip6-localhost`, `ip6-loopback`)
  count as loopback in `isThisHost`, in the emitter's warning
  (`emit.IsLoopbackName`) and in the CLI's `isLoopbackHost`, one list for
  both; any other name is not resolved.
- Decision (i): the live comparison decodes every live route, backend and
  `config` field generically against the shape the emitted file can carry and
  fails closed on anything else: a route key other than `name`, `gateways`,
  `matches`, `policies` and `backends`; a policy other than
  `mcpAuthorization` and `mcpGuardrails`; a match that is not a single exact
  path; a backend that is not the one `mcp` backend with the emitted target;
  a `config` field other than the three listener addresses; one
  LIVE-CONFIG-MISMATCH line per item with names escaped and values never
  shown (`policy requestMirror: not in the emitted file; the gateway applies
  it to this route`, `field KEY: not in the emitted file`, `match 1: field
  KEY: not in the emitted file`, `backend 2: field host: not in the emitted
  file`, `config KEY: not in the emitted file`, `gateway NAME: field KEY: not
  in the emitted file`; a place that is not the object or list the file has
  there is reported as a whole). A top-level section counts only when it is
  non-empty, which the code always did and the documents now say. Extended
  by D17 (i): "the one `mcp` backend with the emitted target" compared the
  target host only, so the seventh review renamed the target through the
  admin API and the canary printed OK while the processor denied every hook
  about the renamed backend; the name is compared on both sides since the
  seventh round, and so are the ports of `--url` and `--admin` against the
  emitted gateway port and `adminAddr` port.
- Decision (j): `emit` records processor addresses in the catalog only after
  the file was validated and renamed into place, so a refused or failed emit
  records nothing and the next emit still prints its change lines.
- Decision (k): the probe treats a 400 as healthy only when its body is empty
  or is not JSON; a 400 whose body parses as JSON (an object or an array, a
  JSON-RPC error or a batch of them, a bare scalar included) is
  PROBE-INCONCLUSIVE, because the probe cannot tell who wrote it. Corrected
  by D17 (h): the probe cannot tell who wrote an empty or plain-text 400
  either, since a go-sdk upstream behind a forwarding gateway writes exactly
  that; since the seventh round no answer is called the gateway's refusal,
  a bare 400 is reported as not accepted as a notification, by the gateway
  or by the upstream, with exit 0, and a JSON body behind a
  byte-order mark, a JSON-RPC error split over the `data:` lines of one SSE
  event and a body truncated at the probe's cap are PROBE-INCONCLUSIVE too.
- Decision (l): CI. The `test-full` job runs `./internal/processor/` next to
  `./internal/textdiff/` and `./internal/catalog/`, and CLAUDE.md names the
  six tests `-short` skips.
- Decision (m): the three over-stated sentences are corrected (SECURITY.md:
  `init` refuses a directory component that is a symbolic link not owned by
  root; "every non-empty top-level section"; the printed `serve` command's
  `--allow-non-loopback` is accepted with `--secret-env` or the explicit
  `--insecure-no-secret`), and the over-cap page of more than 10000 tools is
  listed among the unreadable shapes everywhere.
- Decision (n): README "The audit log", D14 (a) and (b) as corrected above,
  threat-model row 21 and the operations guide state the rule exactly: an
  entry is trusted only when it is part of the chain the `Store` verified; a
  forger must rewrite every entry from the forged one to the head, which
  changes the head a running `Store` pinned and the head the operator
  recorded; a chain rewritten completely before a `Store` opens is caught only
  by the recorded head (the pin-bootstrap limit). Corrected by D17 (k): the
  words "rewritten completely" are too narrow; the documents now say that any
  rewrite from the forged entry to the head made while no `Store` holds a pin
  is caught by the recorded head alone.
- How the round was run. Each area was fixed by one agent that edited only its
  own paths and reported to the lead in its final message; no agent messaged
  another, and the documents were written against the decisions above and
  checked against the tree at the end.
- Consequence. Operators: opening a `Store` (every command, every processor
  start, every canary run) now reads the whole audit log once, the cost
  `audit verify` already had; the schema stays v5 and no file needs
  re-initialising; record the audit head after every verify, because a
  rewrite made while no `Store` holds a pin is caught by that head alone
  (D17 (k) corrected the earlier wording, "a chain rewritten completely");
  expect a `tools/call` denial with the reason `changed since
  approval` after a page the transport refused, until a clean page shows the
  approved digest, and expect the processor's `lists denied` counter to count
  such a page; a listing during a pause now counts as evidence; `emit`
  refuses a processor host that is a name on a port the gateway binds (write
  the IP address or move the port) and no longer warns about the loopback
  aliases; `verify-gateway --admin` reports any route policy, match, backend,
  route key or `config` field the emitted file cannot carry, so a gateway
  whose live document carries one on purpose cannot pass the canary; a
  refused `emit` records no address; a 400 probe answer with any JSON body
  fails the check. Document corrections of the round are listed in the
  corrections subsection of [../seam/RESULTS.md](../seam/RESULTS.md).
- Where. In `docs/threat-model.md` this round changed rows 4, 7, 10, 11, 15, 18,
  20, 21, 25 and 26 and limits L1, L17, L18 and L19, and restates the chain
  rule of row 21: an audit entry is trusted only when it is part of the chain
  the `Store` verified. In the code:
  `internal/catalog/chain.go`, `internal/catalog/anchor.go`,
  `internal/catalog/approved.go`, `internal/catalog/load.go`,
  `internal/catalog/recheck.go`, `internal/catalog/snapshot.go` and
  `internal/catalog/proposers.go` (a, b; `pin.go` is gone; `proposers.go`
  became `versionhistory.go` in D17),
  `internal/audit/audit.go` (`HashOf`), `internal/catalog/integrity_audit.go`
  (c), `internal/catalog/chain.go` (`checkFile`) and
  `internal/catalog/identity.go` (d), `internal/catalog/schemaobjects.go`,
  `internal/catalog/guards.go` and `internal/catalog/store.go` (e);
  `internal/processor/serve.go` (`watchRefusal`, `pageRefused`),
  `internal/processor/list.go`, `internal/processor/filter.go` and
  `internal/processor/observed.go` (f, g); `internal/emit/socket.go` and
  `internal/emit/warning.go` (`IsLoopbackName`, h);
  `cmd/toolwarrant/liveshape.go`,
  `cmd/toolwarrant/liveadmin.go`, `cmd/toolwarrant/livecompare.go` and
  `cmd/toolwarrant/liveconfig.go` (i), `cmd/toolwarrant/emit.go` and
  `cmd/toolwarrant/emitports.go` (j), `cmd/toolwarrant/probe.go` (k),
  `cmd/toolwarrant/serve.go` (h), `.github/workflows/ci.yml` and CLAUDE.md
  (l). Tests: catalog `TestOpen_VerifiesTheWholeChainAndPagesThroughIt`,
  `TestSnapshot_InPlaceRewriteOfTheApprovalEntryBelowTheHeadIsCorrupt` (a
  long-lived `Store` with a warm memory and a fresh open),
  `TestSnapshot_InPlaceEditOfAfterHashUnderAWarmMemoryIsCorrupt`,
  `TestOpen_RewrittenHeadEntryIsCaughtOnlyByThePinAndTheRecordedHead` (the
  pin-bootstrap limit), `TestInTx_RefusesToAppendAfterTheChainWasEdited` (a),
  `TestApprove_ProposerLaunderedByInPlaceRewriteIsCorrupt`,
  `TestDecisions_TrustEntriesAnotherHandleAppended` (b),
  `TestIntegrity_ReportsEveryChainBreak` (c),
  `TestSnapshot_ComparesTheStoredIdentityOnEveryRead` (d),
  `TestOpen_TableRecreatedWithAnExtraConstraintIsCorrupt`,
  `TestSchema_AutomaticIndexesArePinned`,
  `TestDisable_CheckConstraintFromARecreatedTableIsNamed` (e); audit
  `TestHashOf_IsTheSealComputationAndIgnoresTheHashField`
  (a); processor `TestServe_OversizedPageOverTheWireMarksEveryCatalogTool`,
  `TestServe_RefusedPageWithAnUnreadableCatalogIsASourceError` (f),
  `TestCheckResponse_EvidenceIsKeptForEveryCatalogTool`,
  `TestCache_ListingWhileDisabledDeniesTheEnabledCallUntilACleanListing`,
  `TestCache_PauseAndResumeKeepTheListingEvidence` (g); emit
  `TestProcessorNameOnAGatewayPortIsRefused`,
  `TestProcessorNameRuleFollowsTheListenerInputs`,
  `TestLoopbackAliasOnAGatewaySocketIsRefused`,
  `TestLoopbackAliasOnAFreePortIsQuiet`, `TestIsLoopbackName`,
  `TestGatewayAcceptsAProcessorNamedForItsOwnSocket` (the binary loads the
  name; h); cmd `TestLiveComparisonReportsWhatTheFileCannotCarryInsideAKnownSection`,
  `TestCompareDocumentsReportsAPolicyOrBackendTheFileCannotCarry`,
  `TestShapeWalkFailsClosedOnWhatItCannotRead`,
  `TestGatewayAcceptsExtraRoutePoliciesAndBackends` (the binary loads the
  extra policies and the second backend; i),
  `TestEmitRecordsProcessorAddressesOnlyAfterTheFileIsWritten` (j),
  `TestProbeReportsA400WithABatchOfJSONRPCErrorsAsInconclusive` (k),
  `TestCheckListenAddrPolicy` (h); e2e scenario J (a page padded past the
  payload cap next to a changed tool is refused by the gateway itself with
  HTTP 500 before the hook, at 6 MiB as at 9 MiB, so the processor marks
  nothing and the earlier session's next call stays allowed, recorded as the
  shipped runtime's behaviour), scenario N (a processor restarted on a long log walks the whole chain
  at open and serves exactly what the stopped one served) and scenario P (a
  `requestMirror` policy and a second backend posted through the admin API,
  each LIVE-CONFIG-MISMATCH, with what the running gateway did recorded
  against a mirror target).

## D16. The release: a tagged GitHub release with signed binaries, built by goreleaser, private first

- Context. The week-2 decision is GO on all six conditions (seam/RESULTS.md,
  2026-10-12). The repository has never been pushed, has no release pipeline,
  and the CLI's `version` is set by `-ldflags -X main.version=...` with the
  default `dev`. The owner decided on 2026-10-12, in the brainstorm recorded
  in the daily log, what v0.1 means: a public repository under the name
  toolwarrant (free on GitHub, npm, PyPI and crates.io, with the .dev, .io,
  .com and .org domains unregistered as of that day), a `v0.1.0` tag, binaries
  for the operator and the processor with a software bill of materials and
  signatures, and release notes grouped from the conventional commits; no
  container image and no Homebrew tap in v0.1. The repository goes public only
  at the tag: it is pushed private first so the CI workflow can run and be
  fixed where a runner differs from the laptop without anything half-working
  being visible. The three action SHAs in `ci.yml` were verified against their
  tags on 2026-10-12 (match); `gitleaks/gitleaks-action` is pinned by tag only
  and gets a SHA here.
- Decision (a): goreleaser drives the release. One `.goreleaser.yaml` with a
  single build of `./cmd/toolwarrant` (CGO off, `-trimpath`, `-ldflags "-s -w
  -X main.version={{.Version}}"`) for darwin/arm64, darwin/amd64, linux/amd64
  and linux/arm64; the seam and mock binaries are never released. Archives are
  tar.gz carrying LICENSE, README.md, SECURITY.md and THIRD_PARTY_NOTICES.md;
  a checksums file lists every archive. goreleaser 2.18, syft 1.54 and cosign
  3.1 are installed on the owner's machine, so the pipeline is dry-run locally
  before any push.
- Decision (b): one SBOM per archive, produced by syft through goreleaser's
  `sboms`, so the modules the notices file attributes are also machine
  readable per artefact.
- Decision (c): keyless signing. The checksums file is signed with cosign
  through GitHub's OIDC identity of the release workflow, so no signing key
  exists anywhere and the signature binds to
  `https://github.com/sairam0424/toolwarrant/.github/workflows/release.yml@refs/tags/vX.Y.Z`.
  A user verifies the checksums file with `cosign verify-blob` against that
  identity and the GitHub issuer, then the checksum of the binary they run.
  The signature is a sigstore bundle, `<checksums>.sigstore.json`, verified
  with `--bundle`: cosign v3, which the pinned cosign-installer provides,
  writes bundles by default and ignores the `--output-signature` and
  `--output-certificate` files of cosign v2, so the first configuration, which
  named those files, would have signed nothing (the review of 2026-10-12
  found it before v0.1.0-rc.3; the local proof of (g) ran on cosign v3.1).
- Decision (d): the changelog is generated from the conventional commits
  between tags, grouped by type (feat, fix, perf, refactor, test, build, ci,
  docs), and the release notes open with a fixed header naming the pinned
  gateway version (agentgateway v1.6.0) and the catalog schema version, since
  both decide whether an operator can upgrade in place. The previous tag is
  the newest other tag by version, release candidates included, so the
  candidate tags and their drafts are deleted before a final tag is cut (the
  Releasing section says so). goreleaser's `smartsemver` sort, which would
  skip them, is a GoReleaser Pro feature: the open-source build passes the
  value to `git tag --sort`, git rejects it, and goreleaser reports "git
  doesn't contain any tags", which is how v0.1.0-rc.2 failed on 2026-10-12
  after `goreleaser check` had accepted the value.
- Decision (e): the workflow `.github/workflows/release.yml` runs on `v*` tags
  only, with permissions `contents: write` and `id-token: write` and nothing
  else (the gate job that checks the ci run has `actions: read` and
  `contents: read`; the first release candidate, v0.1.0-rc.1 on 2026-10-12,
  failed with HTTP 403 when the gate had `actions: read` alone, since a
  permissions block zeroes everything it does not name), after the existing
  CI jobs have passed on the same commit; every
  action is SHA-pinned (resolved on 2026-10-12: goreleaser-action v7.2.3,
  cosign-installer v4.1.2, sbom-action v0.24.3, checkout v7.0.1, setup-go
  v7.0.0, each re-verified against its tag with the GitHub API on
  2026-10-12 when the file was written, as was gitleaks-action v3.0.0). Go
  comes from go.mod through setup-go.
- Decision (f): failure handling. goreleaser aborts on any failed build,
  missing SBOM or failed signature and leaves no partial release; a tag whose
  CI failed never reaches the release job; the release is created as a draft
  and published by the owner after inspecting the artefacts, so nothing
  unsigned or unexpected goes public without a person looking.
- Decision (g): proof before the tag, in this order: `goreleaser check`;
  `make release-snapshot` (goreleaser `release --snapshot --clean`, which
  builds every target and SBOM locally and skips signing); a local
  `cosign sign-blob` and `verify-blob` of the snapshot checksums with the
  owner's own identity to prove the verification command in the documents;
  the full race suite, `make e2e` and `demo/run.sh` on the tagged commit; the
  first tag on the private repository, inspection of the draft release, then
  the repository is made public and the release published.
- Decision (h): the publish gate the owner completes before the tag, all of it
  recorded in SECURITY.md's pending-actions section until done (the section
  went with the v0.1.0 wording, its items complete or carried by the Releasing
  section of docs/operations.md): fill the
  SECURITY.md contact (GitHub private vulnerability reporting enabled on the
  repository, or an address); record the linux gateway asset checksum for the
  e2e CI job; write and file the upstream report on the id-less tools/call
  forwarding by hand (no public report existed on 2026-10-11); register the
  domain if wanted (not needed for v0.1).
- Consequence. Operators: a release is one tag; the binary prints the tag
  without its v prefix as its version (goreleaser's version template strips
  it; a snapshot built before the first push names its commit `none`, since
  goreleaser reads it from the remote); an archive is verified by the checksums file's signature, not
  by a key the project would have to protect. Maintainers: adding a platform
  or an archive member is a line in `.goreleaser.yaml`; the release workflow
  shares no secret with anyone. What D16 does not do: no container image, no
  package-manager formula, no automatic publication (a draft needs a person),
  no release of the seam or mock binaries.
- Where. `.goreleaser.yaml` (new), `.github/workflows/release.yml` (new),
  `Makefile` (`release-snapshot`), `.github/workflows/ci.yml` (gitleaks SHA
  pin), `docs/operations.md` ("Releasing": the owner's steps and the user's
  verification command), SECURITY.md (reporting mechanism, Release integrity).
- Tests and proof. `goreleaser check` and `make release-snapshot` green on the
  owner's machine; the verification command exercised once against a locally
  signed checksums file; the existing CI jobs on the private repository green
  before the first tag; the draft release inspected before publication. No
  Go test is added: the pipeline is configuration, and its proof is the
  snapshot build and the signature verification.

## D17. The seventh round: columns trusted only through the chain, rows below the first, the unattributed probe, the live comparison's target and ports, emit's refusals and the pin limit as the code has it

- Context. The seventh hostile review (2026-10-12, scoped to two areas, the
  catalog chain and the canary, each finding re-run by an independent verifier
  against eda2077) confirmed twelve findings, two of them high, four medium
  and six low. In the order of the sub-decisions below: `lifecycle` exempts a
  rollback from the self-approval rule because its target was approved
  before, and it learned that from `Version.EverApproved`, which `loadTool`
  took from the `tool_versions.ever_approved` column (not in the column list
  of `tool_versions_immutable`) backed by `approvalRecorded`, an `EXISTS` over
  any approve or rollback row of the approvals table; neither was anchored to
  a verified `version.approved` or `version.rolled_back` entry, although D15
  (b) said the decision path trusts the verified chain, so with file write
  access and no trigger dropped, one `UPDATE` of the column and one `INSERT`
  of an approvals row at id -2 (`approvals_no_replace` refused only an
  existing id, and a negative id is never the newest decision) let the sole
  proposer of a digest roll back to her own bytes: the `Store` wrote a genuine
  `version.rolled_back` entry, `Snapshot`, `Approved` and fresh read-only and
  read-write `Store`s served the digest under her name, `Versions` showed it
  as approved before, `Integrity` afterwards printed one line about the
  orphan row, and the recorded head, the git export and backups did not
  betray it (the same root cause made a rejected version flipped to pending
  approvable, which D14 had documented as detection only); SQLite evaluates
  `NEW.id` as -1 in a `BEFORE INSERT` trigger when the row id is not
  supplied, so one row inserted at id -1 with plain SQL made
  `approvals_no_replace` refuse every later approve and reject with `a guard
  refused the write (approvals cannot be replaced)`, a message that named the
  wrong cause (a disable writes no approvals row and was unaffected; the
  `tool_versions` twin refused the next crawl); `Server` and `Servers` were
  the only views that ran neither `checkFile` nor any evidence check, the
  servers table has no update guard, and nothing anchored `processor_addr`,
  `url` or `allow_private` to the verified `server.processor_set` and
  `server.added` entries (the chain memory recorded the `server.processor_set`
  hashes and never consulted them), so one `UPDATE servers SET
  processor_addr = '127.0.0.1:9999'` was returned as fact by a long-lived
  `Store` and by a fresh one, `Server` and `Servers` also answered with a
  guard trigger dropped and with another identity in `meta` where `Snapshot`
  returned `ErrCorrupt` and `ErrReplaced`, `server list` showed the forged
  address, the next `emit`, the documented remedy after a CONFIG-EDITED,
  wrote `host: "127.0.0.1:9999"` into the gateway configuration, which the
  pinned binary validated, with no `changed from` line and no
  `server.processor_set` entry, and `audit verify --expect-head` printed
  `audit log ok` with the recorded head before the one integrity line (the
  gateway would dial the forger's processor for every hook of the route,
  which can allow any definition under the approved names and receives the
  shared secret header; the same path gave the crawl loop a rewritten URL and
  allow-private flag); every chain walk, `Integrity.readLog` and the genesis
  page started at seq 0 (`WHERE seq > ?` from the zero pin) and
  `audit_log.seq` has no `CHECK (seq >= 1)`, so a `version.proposed` row
  about a tool inserted at seq 0 or -7 under a re-created
  `audit_log_sequential` was invisible to `audit verify` (the recorded head
  and the old count), to `Integrity` (no problem) and to `audit list`, while
  `proposersFromLog` (now `versionsFromLog`) read it (no lower bound) and `chainMemory.verify`
  refused it, so `Approve`, `Reject`, `Disable` and `Versions` on the tool
  were `ErrCorrupt` for ever, on a long-lived `Store` and on a fresh one, and
  the ErrCorrupt procedure sent the operator to an `audit verify` that said
  ok (nothing was served wrongly); `scanApproved` took `ApprovedBy` and
  `ApprovedAt` from the approvals row and `anchorApproved` verified the entry
  without comparing its actor and timestamp, so under a re-created
  `approvals_no_update` one `UPDATE` made the git export say alice approved a
  tool while the verified entry said bob, with the chain and the recorded
  head clean; a read transaction's snapshot is fixed at its first statement
  (`checkStoredIdentity`) while the pin it is compared with is read later in
  `verifyChain` under `walkMu`, so when a commit landed between the two and
  another `verifyChain` of the same `Store` walked past it first,
  `checkPinnedEntry` looked for the pinned seq in the stale snapshot, found
  nothing and returned `ErrCorrupt` `audit entry N, which this store
  verified, is gone; the log was truncated or the file replaced under a
  running reader` for an untouched file (deterministic with the `Store`'s own
  primitives in `Snapshot`'s order; under load, six readers and one writer on
  one `Store`, 1249 of 6902 `Snapshot` calls failed this way in 4 s, 4836 of
  22243 for the verifier; no shipped runtime calls `Snapshot` concurrently
  with a writer on one `Store` today, so the defect was latent in a type
  documented as safe for concurrent use); `classifyProbe` called a 400 with
  an empty or non-JSON body healthy and the summary read `id-less tools/call
  rejected by the gateway`, but that is the shape any upstream writes: a
  go-sdk upstream behind the repository's own forwarding stand-in received
  the probe (its name in the upstream's log) and relayed its plain-text 400,
  and the canary attributed the refusal to the gateway with exit 0, which is
  the condition the probe exists to detect, while SECURITY.md's scope, README
  L17, threat-model row 25 and the operations guide all reasoned that a
  non-JSON 400 is the gateway's refusal; `carriesJSONAnswer` validated each
  SSE data line on its own and the body as one value, so a JSON-RPC error
  split over two `data:` lines of one event (the SSE specification joins
  them with a newline), a JSON body behind a UTF-8 byte-order mark and a JSON
  body longer than `probeMaxBody` (1 MiB), which the limited reader truncates
  into invalid JSON, each passed as non-JSON (neither reachable on
  agentgateway v1.6.0, which answers 202 before forwarding; both matter on
  every move of the pin, when the healthy shapes are meant to be re-derived);
  the live comparison read `targets[].mcp.host` on the live side and the
  `host:` line on the emitted side, and the shape walk listed the target
  `name` key as one the file carries, so a live document with the backend
  target renamed compared as a match and the canary printed OK, exit 0, while
  the pinned binary accepted the document with `--validate-only` and the
  processor, whose target rule denies a hook about another backend, served
  nothing on the route (the operator saw MISSING lines, which the documents
  explained by a stale allow rule or limit L2); `compareURLPath` compared the
  path of `--url` and nothing else, so a canary that listed through two
  stand-ins on other loopback ports and asked an admin stand-in on a third
  printed `live configuration matches the emitted file` for each, binding one
  gateway's configuration to a listing made through another; `emit --out`
  accepted any regular file, the catalog database included: `emit --out <the
  --db path>` opened the catalog, staged the YAML next to it, renamed it over
  the database while the store held the old inode, wrote the addresses into
  the unlinked inode, printed `wrote <db>` and the `is new` line and exited
  0, after which every later command refused the file (`file is not a
  database`), and the same held for the `-wal` and `-shm` siblings and any
  other regular file; and seven places (README L373 and L670, SECURITY.md L93
  and L248, threat-model L88, operations.md L574 and L618) and the `chain.go`
  comment stated the pin limit as "a chain rewritten completely before any
  `Store` opens it is caught only by the recorded head", when with no `Store`
  open, which is the CLI's normal state between commands and the processors'
  state during the ErrCorrupt procedure, the pin catches nothing and the
  condition is not "completely": with another server's whole history first
  in the log, the forger rewrote the version and approval of one tool and the
  detail of every entry about it naming the benign digest and re-chained from
  the first of them, 6 of 13 entries stayed byte for byte what they were,
  fresh read-only and read-write `Store`s served the poison approved by
  nobody, `VerifyAudit` was clean with the same count and `Integrity`
  reported nothing; only the recorded head differed.
- The trust boundary, as the code has it. Whoever can write the 0600 file can
  append a new, correctly sealed audit entry that approves a definition, and
  nothing inside the file can refute it (D14). Inside the file an audit
  entry, and since this round every column a decision or a view acts on, is
  trusted only through the chain the `Store` verified (D15, D17 (a), (c) and
  (e)). A forger who rewrites an entry must rewrite every entry from it to
  the head. A running `Store` catches that through the head it pinned; while
  no `Store` holds a pin, which is the CLI between commands and the
  processors while they are stopped, any such rewrite verifies clean on the
  next open and is caught by the recorded head alone. The processor's pin
  protects only while a processor runs; the CLI is never protected by a pin.
  Operators record the head after every verify and compare it before every
  decision made after processors were stopped (D17 (k)).
- Decision (a): the decision path reconstructs from the chain. Every
  version's status and ever-approved flag used by a decision (`Approve`,
  `Reject`, `Rollback`, `Disable`, `Enable`, `ResetProposalBudget`) and by
  `Versions` is reconstructed from the verified `version.*` entries about the
  subject with the same rule `Integrity` uses (`noteVersionEvent`), and a
  `tool_versions` column that disagrees is `ErrCorrupt`. `Rollback` accepts a
  target only when a verified `version.approved` or `version.rolled_back`
  entry names its digest. The approvals table remains the newest-decision
  evidence of D13 (a); it no longer carries status or history on its own.
- Decision (b): an approvals row or a history row with id below 1 is corrupt.
  Every checked read and every write transaction refuses a file that holds
  one before it trusts or writes anything (`checkGhostRows`, run by
  `checkFile` and `inTx`; the error reads `TABLE holds a row whose COLUMN is
  below 1, which the catalog never assigns; the file was edited outside
  toolwarrant, run audit verify`), two positive-id guards refuse the insert
  (`approvals_positive_id` and `tool_versions_positive_id`, `AFTER INSERT ...
  WHEN NEW.id < 1`), and `Integrity` reports such rows. The decision as
  stated for the round said the no-replace guards would gain `WHEN NEW.id < 1
  OR ...`; the implementation adds guards of their own instead, because in a
  `BEFORE INSERT` trigger SQLite evaluates an unsupplied id as -1, so a
  `BEFORE` guard on `NEW.id < 1` would refuse every insert the `Store` makes,
  while an `AFTER INSERT` trigger sees the id the row got and `RAISE(ABORT)`
  there backs the row out again.
- Decision (c): `Server` and `Servers` run `checkFile` like every other view
  and anchor `processor_addr` to the newest verified `server.processor_set`
  entry about the server and `url` (by `url_sha256`) and `allow_private` to
  the verified `server.added` entry, else `ErrCorrupt`. `emit` refuses to
  emit on `ErrCorrupt` and prints a change line whenever the address it
  writes differs from that entry, so a re-emit cannot adopt an address the
  catalog's audit log does not carry in silence. Extended by the lead after
  the round, with the same rule: the paused flag is anchored to the newest
  verified `server.paused` or `server.resumed` entry about the server (no
  entry means not paused) by `Server`, `Servers`, `Snapshot`, `RecordCrawl`,
  `PauseServer` and `ResumeServer`, so an un-pause by one `UPDATE` serves
  nothing, is refused as a crawl and turns the operator's resume into
  `ErrCorrupt` rather than `ErrInvalid`; the chain memory records both
  events for it. Extended again after the eighth review (the whole-branch
  review before the first push): every tool's state column is anchored to the
  newest verified lifecycle entry about the tool (`anchorStates`, on
  `Snapshot`, `Tools`, `Tool`, `Approved`, every decision and the crawl),
  since `Disable` keeps the approved pointer and one `UPDATE tools SET state
  = 'enabled'` served a disabled tool again while every approval anchor held;
  the chain memory therefore records every lifecycle event about a tool.
  Extended once more after the verification of the released v0.1.0 binary
  (2026-10-13): `Approved` had anchored only the rows its state-filtered query
  returned and `Snapshot` only the non-deprecated rows, so an approved tool
  whose state column was edited to `disabled` vanished from the export and
  `emit` wrote a smaller allow list from a catalog that `list` and `audit
  verify` refused, and a flip to `deprecated` dropped a tool from the served
  policy without an error; both now anchor every tool row of their scope
  before leaving one out (`TestApproved_ToolHiddenByAColumnFlipIsCorrupt`,
  `TestSnapshot_ToolDeprecatedByAColumnFlipIsCorrupt`,
  `TestEmitRefusesACatalogWhoseToolStateColumnWasEdited`). The
  server row is anchored to the first `server.added` entry, not the newest,
  because a server is registered once and an appended sealed second entry
  (the access D14 admits) must not re-register it; `Integrity` names a second
  one.
- Decision (d): every chain walk, `Integrity.readLog` and the genesis page
  start at the smallest possible seq, bound included (the query reads
  `seq >= math.MinInt64` from the zero pin; the first cut read `seq >` and so
  could not reach that one value, which the eighth review planted a row at),
  so a row at seq 0 or below is a chain
  break (expected seq 1) at open, in `audit verify` and in `Integrity`, which
  also compares `COUNT(*)` of `audit_log` with the entries it walked;
  `AuditEntries` shows such rows in forensic mode so `audit list` can name
  them.
- Decision (e): `Approved` takes `ApprovedBy` and `ApprovedAt` from the
  verified entry and reports a disagreement with the approvals row as
  `ErrCorrupt`, so the git export carries the name the chain carries.
- Decision (f): a stale read snapshot cannot be mistaken for a truncation
  because it cannot occur: `checkFile` takes `walkMu` before the read
  transaction's first statement, so the snapshot is fixed after the pin it
  is compared with was read, and `checkPinnedEntry` treats an absent pinned
  entry as a truncation and nothing else. The first cut of this record named
  a second mechanism, accepting the snapshot's head by its recorded hash,
  which was considered and not implemented (it would accept a prefix
  truncation ending at a decision entry); the eighth review corrected the
  record. A concurrent-writer test fails on the old code.
- Decision (g): the positive-id guards, `checkGhostRows` and `Integrity`
  refuse and report an id below 1 (the same rule as (b)), so a ghost row at
  id -1 cannot block the `Store`'s own inserts under the no-replace guards'
  message: the file is refused with its cause named before the insert is
  tried. A forensic open (read-only) reads past such a row, as it reads past
  a missing guard, so `list`, `show` and `audit list` can inspect the file
  while `audit verify` names the row (eighth review).
- Decision (h): the probe attributes nothing it cannot attribute. HTTP 202
  stays UNHOOKED-CALLS, exit 1: it is the fail-open shape of agentgateway
  v1.6.0. A 400 whose body is empty or is not JSON, read to the end, is
  reported as `the id-less tools/call was not accepted as a notification
  (HTTP 400, by the gateway or by the upstream)` with exit 0 and a summary
  that never says `rejected by the gateway`; a 400 whose body is JSON, an SSE
  event whose joined `data:` lines are JSON, a body with a UTF-8 byte-order
  mark before JSON and a body cut at `probeMaxBody`, like a 2xx other than
  202 that carries a body, are PROBE-INCONCLUSIVE, exit 1; a 2xx without a
  body and every other status stay a `check failed` line that names the
  status and whether a body was present (D14), since the probe then proved
  nothing either way. The decision as stated for the round said "any other
  answer" would be reported as not accepted; the implementation keeps that
  sentence for the 400 alone, which is the only status the pinned gateway and
  the go-sdk write for a refused notification, and keeps every other status
  as the error it was, so that the pass sentence can name the one status it
  is written for. The documents say what the probe proves: the fail-open
  shape of v1.6.0, and that it cannot prove the hook, because an answer other
  than 202 may have been written by the gateway or by the upstream behind a
  forwarding gateway and the probe cannot tell which. D15 (k) is corrected:
  there is no healthy shape the probe can attribute to the gateway.
- Decision (i): the live comparison compares the MCP backend target name on
  both sides (the `- name:` item inside the emitted backends block, the
  `Name` of the live target) and the ports of `--url` and `--admin` with the
  emitted gateway port and the emitted `adminAddr` port, the hosts too when
  the emitted bind is loopback; each difference is one LIVE-CONFIG-MISMATCH
  line. The name is the server name, so it may be shown.
- Decision (j): `emit` refuses `--out` that is the catalog database, its
  `-wal` or `-shm` sibling or the `--gateway-binary` path (compared by
  canonical path and, when the file exists, with `os.SameFile`; the first
  cut compared by `os.SameFile` alone, and the runtime drive after the round
  saw `emit --out <db>-wal` accepted while the sibling was absent, SQLite
  removing the written configuration at the next open), and refuses to
  replace an existing regular file whose
  header lines are not emit's (a file the gateway rewrote keeps the header
  lines and stays replaceable, so the documented re-emit after a
  CONFIG-EDITED still works), each as a usage error naming the fix.
- Decision (k): the documents state the pin limit as the code has it: any
  rewrite from the forged entry to the head made while no `Store` holds a pin
  is caught by the recorded head alone; the processor's pin protects only
  while a processor runs; the CLI is never protected by a pin; operators
  record the head after every verify and compare it before every decision
  made after processors were stopped. The same correction is made to README
  L95, threat-model row 21 and D15 (b), which said the decision path trusts
  entries through the chain while it still trusted the status and
  ever-approved columns through the approvals table; since this round it
  trusts columns only through the chain too. The re-emit sentences of the
  operations guide and the README say the address comes from the catalog's
  servers row, now anchored to the verified entry.
- How the round was run. Each area was fixed by one agent that edited only
  its own paths and reported to the lead in its final message; no agent
  messaged another; the reviewers' reproduction tests were ported from their
  read-only worktrees under names without the review prefix, and the
  documents were written against the decisions above and checked against the
  tree at the end.
- Consequence. Operators: the catalog schema moves to v6, because two guards
  joined the guard set and a `Store` compares the guard set with the
  schema's, so a v5 file from the sixth round is refused with `ErrSchema`
  and must be re-initialised like every earlier pre-release file (there is no
  migration; stop the processors, back the file up, `init`, re-register,
  crawl, re-approve from the git export). After the eighth review the refusal distinguishes an unreleased schema (below `firstReleasedSchema`, 6: delete and init again) from a released one (6 and above: never delete, read it with a build of that schema or migrate as its release notes say), so the first bump after v0.1.0 cannot tell an operator to destroy an audit log (`TestSchemaMessage_AdvisesDeletionOnlyForUnreleasedSchemas`). `server list`, `emit`, `crawl`,
  `serve` and `show` now refuse a file whose servers row disagrees with the
  audit log, and `emit` prints a change line whenever the address it writes
  differs from the newest verified `server.processor_set` entry. A rollback
  to a digest the chain never shows approved is `ErrCorrupt`, and so is any
  `tool_versions` status column that the chain does not support. `audit
  verify` reports a row at seq 0 or below as a chain break, a row count that
  differs from the entries walked, and a history row with id below 1; `audit
  list` shows such rows. The canary's OK line no longer says `rejected by the
  gateway`; it reports a bare 400 as not accepted as a notification, by the
  gateway or by the upstream, exit 0, and a
  `LIVE-CONFIG-MISMATCH` for a renamed backend target and for a `--url` or
  `--admin` port that is not the emitted one. `emit` refuses to write over
  the catalog, its journal files, the gateway binary or a foreign file. The
  pin limit is stated as it is: record the head after every verify and
  compare it before every decision you make after the processors were
  stopped. Document corrections of the round are listed in the corrections
  subsection of [../seam/RESULTS.md](../seam/RESULTS.md).
- Where. In `docs/threat-model.md` this round changed rows 7, 10, 18, 20, 21, 25
  and 26 and limits L17, L18 and L19, extends the chain rule to every column a
  decision or a server view acts on, and states the limit of the chain pin in
  row 21 as the code has it: a rewrite from any entry to the head made while
  no `Store` holds a pin is caught by the recorded head alone. In the code:
  `internal/catalog/versionhistory.go` (which replaces
  `proposers.go`), `internal/catalog/load.go`, `internal/catalog/views.go`
  and `internal/catalog/integrity_versions.go` (a),
  `internal/catalog/ghostrows.go`, `internal/catalog/anchor.go`,
  `internal/catalog/guards.go` and `internal/catalog/integrity.go` (b, g),
  `internal/catalog/serveranchor.go`, `internal/catalog/servers.go`,
  `internal/catalog/processoraddr.go`, `internal/catalog/snapshot.go`,
  `internal/catalog/crawl.go`, `internal/catalog/stateanchor.go` and
  `cmd/toolwarrant/emit.go` (c),
  `internal/catalog/audit.go`, `internal/catalog/chain.go` and
  `internal/catalog/integrity_audit.go` (d), `internal/catalog/approved.go`
  (e), `internal/catalog/chain.go` and `internal/catalog/store.go` (f),
  `internal/catalog/schema.go` (v6), `cmd/toolwarrant/probe.go`,
  `cmd/toolwarrant/verdicts.go` and `cmd/toolwarrant/verify.go` (h),
  `cmd/toolwarrant/liveaddrs.go`, `cmd/toolwarrant/liveadmin.go`,
  `cmd/toolwarrant/livecompare.go` and `cmd/toolwarrant/liveconfig.go` (i),
  `cmd/toolwarrant/emitout.go` and `cmd/toolwarrant/emit.go` (j); README,
  SECURITY.md, CLAUDE.md, the three documents under `docs/` and the
  corrections subsection of `seam/RESULTS.md` (k).
- Tests. The sixth-round tests that still pin the surrounding rules stay in
  force: catalog `TestOpen_RewrittenHeadEntryIsCaughtOnlyByThePinAndTheRecordedHead`
  (the head rewritten before any `Store` opens, the narrow case the sixth
  round named), `TestSnapshot_ReChainedLogIsCaughtByThePinAndTheRecordedHead`
  and `TestSnapshot_LogChangedAfterThePinIsCorrupt` (the pin while a `Store`
  is open), `TestIntegrity_RejectedVersionFlippedToPendingIsReported` and
  `TestIntegrity_ProcessorAddrRewrittenIsReported` (the detection `Integrity`
  already had of the column flips (a) and (c) now refuse), `TestOpen_VerifiesTheWholeChainAndPagesThroughIt`
  (the walk whose lower bound (d) moves); cmd
  `TestProbeReportsARelayedUpstreamAnswerAsInconclusive`,
  `TestProbeReportsARelayed400WithAJSONRPCErrorAsInconclusive` and
  `TestProbeReportsA400WithABatchOfJSONRPCErrorsAsInconclusive` (the
  inconclusive shapes (h) keeps), `TestLiveComparisonChecksTheURLPath` (the
  path rule (i) extends to the ports), `TestEmitRefusesAnIrregularOut` (the
  `--out` rule (j) extends) and `TestReEmitIgnoresAForgedAddressInTheFileAtOut`
  (the file at `--out` lends nothing; (c) adds the servers row). The
  regression tests of this round, each failing on the sixth-round code and
  ported from the reviewers' reproductions under names without the review
  prefix: catalog `TestDecisions_VersionColumnsMustMatchTheVerifiedChain`,
  `TestRollback_TargetForgedWithAGhostApprovalsRowIsCorrupt` (the sole
  proposer's rollback to her own bytes) and
  `TestApprove_RejectedVersionFlippedToPendingIsCorrupt` (a);
  `TestGuards_RowsBelowIdOneAreRefusedByThePositiveIdGuards`,
  `TestDecisions_GhostApprovalsRowIsNamedNotMistakenForAReplace`,
  `TestRecordCrawl_GhostVersionRowIsNamedNotMistakenForAReplace` and
  `TestSnapshot_GhostApprovalsRowWithAPositiveIDBreaksTheCurrentApproval` (b,
  g); `TestServers_ColumnsAreAnchoredToTheVerifiedChain`,
  `TestServers_RunTheFileCheckLikeEveryOtherView` and
  `TestSetProcessorAddr_ForgedColumnEqualToTheNewAddressIsCorrupt`,
  `TestServers_PausedFlagIsAnchoredOnEveryPathThatReadsIt` and
  `TestServers_PausedFlagWithoutAnEntryIsCorrupt`,
  `TestSnapshot_DisabledToolReEnabledByAColumnFlipIsCorrupt`,
  `TestSnapshot_ToolDeprecatedByAColumnFlipIsCorrupt`,
  `TestApproved_ToolHiddenByAColumnFlipIsCorrupt`,
  `TestEmitRefusesACatalogWhoseToolStateColumnWasEdited`,
  `TestSnapshot_PlantedToolRowWithoutAnEntryIsCorrupt` and
  `TestServers_ASecondServerAddedEntryIsNotTheAnchor` (c);
  `TestAudit_RowBelowSeqOneIsAChainBreakOnEveryWalk` (d);
  `TestApproved_ApproverAndTimeComeFromTheVerifiedEntry` and
  `TestApproved_BlankedApprovalTimeIsCorrupt` (e);
  `TestSnapshot_ConcurrentReadersAndAWriterNeverSeeAFalseTruncation` (f, the
  concurrent-writer test that fails on the old code);
  `TestOpen_SuffixRewrittenWhileNoStoreHeldAPinIsCaughtByTheRecordedHeadAlone`
  (k, the limit as the code has it); and the reviewer's side probes, which
  held, `TestApprove_GhostProposerAppendedWithPlainSQLIsRefused` and
  `TestSnapshot_SwappingToolNamesIsCaughtByTheAnchor`; cmd
  `TestEmitRefusesACatalogWhoseProcessorAddressIsNotTheOneTheChainRecords`
  (c), `TestProbeDoesNotAttributeARelayedPlainTextRefusalToTheGateway` and
  `TestProbeReadsTheJSONShapesAnUpstreamCanRelayOnA400` and
  `TestProbeReadsAnEventStreamBehindALeadingByteOrderMark` (h),
  `TestLiveComparisonComparesTheBackendTargetName`,
  `TestLiveComparisonHoldsTheURLAndAdminPortsAgainstTheEmittedFile` and
  `TestCompareCanaryAddresses` (i), and
  `TestEmitRefusesToReplaceTheCatalogOrAFileItDidNotWrite` (j).

## D18. L17 is a deployment requirement; the probe's expectation flag

- Context. agentgateway v1.6.0 forwards a `tools/call` sent as a JSON-RPC
  notification (no `id`, or `id: null`) to the upstream without the ExtMCP
  hook and without the allow rule (limit L17, [threat-model.md](threat-model.md)
  row 25); e2e scenario O records the HTTP 202 and the probe in the hostile
  upstream's request log on every run. Since D12 the canary's probe reports
  that shape as UNHOOKED-CALLS, exit 1, and since D13 the documents told the
  operator to run the probe once, record the limit and pass `--no-probe` until
  the pin moves, because a canary that fails on every run trains its readers
  to ignore it. That advice silenced the one check that would notice the
  gateway changing: a canary running with `--no-probe` cannot tell a pin that
  moved to a release with another answer from the pinned one, and the healthy
  line it printed said only that the probe was skipped. The post-v0.1
  research (2026-10-14) asked whether toolwarrant should close L17 itself with
  a pre-filter in front of the gateway's serving port that refuses id-less
  `tools/call`. The owner decided on 2026-10-14 (decision O-1 of the plan,
  option (b)): no pre-filter, D11 stands, and L17 becomes a stated deployment
  requirement with a probe flag that keeps the probe on.
- Decision (a): no pre-filter. A pre-filter would terminate HTTP, parse
  batched JSON-RPC and server-sent events, carry client bearer tokens, need
  the canary to learn a second listener and reverse the README non-goal of no
  data plane (D11): two to four weeks of work and a permanent attack surface,
  for a behaviour the probe already makes visible. D11's own condition for
  revisiting it, a gateway behaviour that no control on our side can make
  visible, is not met.
- Decision (b): L17 is a deployment requirement. The gateway's serving port
  must be reachable only by clients that send a JSON-RPC id on every
  `tools/call` (the official SDKs do) or through an enforcement point that
  refuses id-less `tools/call`; toolwarrant provides none. SECURITY.md states
  it as the sixth line of the trust boundary and as a hardening-checklist
  item, README L17 and the threat model's L17 and row 25 carry it, and
  [operations.md](operations.md) gains a "Deployment requirements" section
  before "Running the canary".
- Decision (c): `verify-gateway --expect-unhooked`. The flag declares that the
  gateway forwards the probe. Under it a 202 prints `KNOWN-LIMIT <server>: the
  gateway forwarded the id-less tools/call (HTTP 202), as agentgateway v1.6.0
  does (L17)`, the one-line account ends `id-less tools/call forwarded
  unhooked as declared with --expect-unhooked (KNOWN-LIMIT L17)`, and the check
  exits 0; the line is a report like MISSING, not counted as a failing verdict
  line, so a scheduled run that printed it on every check exits 0 when it is
  stopped. Any other answer the probe classifies, a bare 400 and each of the
  PROBE-INCONCLUSIVE shapes alike, is the failing verdict `PROBE-CHANGED
  <server>: the gateway no longer answers the probe with 202 (the id-less
  tools/call came back HTTP N); the pin moved or the gateway changed under it;
  re-qualify (L7) and drop --expect-unhooked once the probe's answer is
  understood`, exit 1, and it stops an un-flagged scheduled run like every
  other failing verdict; the loop's closing sentence names it. An answer the
  probe cannot classify (a 2xx without a body, any other status) stays a
  `check failed` line on both paths. `classifyProbe` is untouched: the flag
  changes what an outcome means, not what the probe sees, so the shapes D13 to
  D17 pinned are the same shapes. `--expect-unhooked` and `--no-probe` are
  exclusive, a usage error (exit 2) decided before anything is fetched;
  `--no-probe` remains for a canary that must not send the probe at all.
- Consequence. Operators on the pinned gateway run the canary with
  `--expect-unhooked` instead of `--no-probe` and read KNOWN-LIMIT on every
  check; the first check after a move of the pin to a release that answers the
  probe otherwise fails as PROBE-CHANGED, which is the re-qualification
  reminder (L7). Exit 0 is OK, MISSING or KNOWN-LIMIT only. The documents that
  promised an OK line ending `(--no-probe)` now show the KNOWN-LIMIT line and
  the OK line as printed with the flag (README step 7, the SECURITY.md canary
  item, the operations guide's example and verdict list). The upstream report
  of the behaviour stays the owner's hand-written action (SECURITY.md). What
  D18 does not do: no proxy, no change to the probe's classification, no
  change to the processor or the emitter, no new e2e scenario (scenario O
  gains a third run).
- Where. `cmd/toolwarrant/verify.go` (the flag, the exclusivity check, the
  failure sentence), `cmd/toolwarrant/verdicts.go` (`probeReport.verdict`,
  the KNOWN-LIMIT and PROBE-CHANGED lines and summary parts),
  `cmd/toolwarrant/verifyloop.go` (the tally sentence),
  `cmd/toolwarrant/main.go` (the synopsis); SECURITY.md, README.md, CLAUDE.md,
  CONTRIBUTING.md, [threat-model.md](threat-model.md) (row 25, L17 and their
  notes), [operations.md](operations.md) ("Deployment requirements", "Running
  the canary", "Exit codes").
- Tests. cmd `TestExpectUnhookedTurnsThe202IntoAKnownLimitLine` (the 202 as
  KNOWN-LIMIT with exit 0, the probe still reaching the upstream, a scheduled
  run that printed the line twice and exited 0 when stopped),
  `TestExpectUnhookedFailsWhenTheGatewayStopsForwarding` (the go-sdk
  upstream's bare 400 and the four inconclusive shapes each PROBE-CHANGED with
  exit 1 naming the status, the scheduled run stopping after one listing and
  one probe session, and the same answers keeping their verdicts without the
  flag), `TestExpectUnhookedAndNoProbeAreExclusive` (exit 2 with no session
  opened against the gateway), `TestVerdictsFailAndSummarizeEachCheck` and
  `TestLoopTallyOutcome` (extended); e2e scenario O, third run with the flag
  on 2026-10-14: the pinned binary answered 202, `verify-gateway` printed
  `KNOWN-LIMIT hostile: the gateway forwarded the id-less tools/call (HTTP
  202), as agentgateway v1.6.0 does (L17)` and an OK line ending `id-less
  tools/call forwarded unhooked as declared with --expect-unhooked
  (KNOWN-LIMIT L17)`, exited 0, and the hostile upstream's request log gained
  one probe request. Each of the three new tests fails on the code before this
  decision with `flag provided but not defined: -expect-unhooked`, exit 2.

## D19. TLS and client certificates on the processor link

- Context. The link between the gateway and a processor was plain `host:port`
  gRPC (limit L11, [threat-model.md](threat-model.md) row 17 and L11): the
  processor's only guard against a caller who reaches its port was the shared
  secret (D8), confidential against other hosts only, and every hook crossed
  the network in clear whenever a processor ran off loopback. The post-v0.1
  research (2026-10-14) found that agentgateway v1.6.0 already dials a
  processor with TLS when its entry carries
  `routes[].policies.mcpGuardrails.processors[].policies.backendTLS` (`cert`,
  `key`, `root`, `hostname`; the schema also accepts `insecure`,
  `insecureHost`, `alpn`, `subjectAltNames`, `keyExchangeGroups` and
  `spiffe`, and `requestHeaderModifier`, `transformations` and `backendAuth`
  beside the block), and that the gateway's Rust source deserialises
  `policies: backendTLS: {}` under a `host:` processor; the handshake against
  a grpc-go listener was unobserved. The owner decided on 2026-10-14
  (decision O-2 of the plan): TLS on the link without moving the gateway pin,
  in four pull requests (the processor's listener, the canary's reader, the
  emitter's block, the end-to-end scenario Q), and a verified client
  certificate satisfies the non-loopback listen rule in place of the shared
  secret.
- Decision (a): the processor terminates TLS. `serve --tls-cert PATH --tls-key
  PATH` makes the listener TLS 1.3 only (`processor.Config.TLS`, forced to
  1.3 on a copy of the caller's configuration), and `--tls-client-ca PATH`
  makes every connection present a client certificate that authority signed
  (`RequireAndVerifyClientCert`); a connection without one, from another
  authority or in plaintext is refused in the handshake and never reaches a
  hook. Certificate and key go together, the authority needs both, and any
  TLS flag with `--listen unix:` is refused, each a usage error (exit 2); the
  three files pass `readRegularFile` and the key must be owner-only, as the
  database is (exit 1 otherwise). A configuration with no certificate, or
  with client verification against no authority, is refused by the processor
  itself, because crypto/tls would otherwise verify against the system roots.
  The listening line names the mode after the target. Landed first (pull
  request 2.4a), ahead of any producer of the gateway's block.
- Decision (b): the emitter writes the block from a flag that is not
  persisted. `emit --processor-tls NAME=cert=PATH,key=PATH,root=PATH,hostname=NAME`
  (repeatable, one per server; all four fields, each once; a path cannot
  carry a comma) puts `policies: backendTLS:` with the four quoted fields on
  that server's processor entry, after the request-header filter and before
  the metadata. Nothing of it goes into the catalog: the paths are files on
  the gateway host, which the catalog cannot anchor to anything it verifies,
  and recording them would be schema v7 with the first migration, for a value
  the operator holds anyway. The flag is therefore given on every emit, as
  `--secret-env` is, and omission fails closed: an entry without the block is
  dialled in plaintext, which a processor started with `--tls-cert` refuses
  in the handshake, so the route goes dark instead of unguarded. The first
  step of the emitter's pull request was a probe of the pinned binary:
  `--validate-only` opens the block's three files (`read resource file PATH`,
  exit 1, for a path it cannot open), parses the certificate and the key (`no
  certificate`, `no key`), does not parse the root bundle (a file of garbage
  validates), reads the hostname as a DNS name or an IP literal (`invalid dns
  name` for an empty one, a bracketed address, a `host:port` and the
  resolver's numeric shorthand), and accepts a block without `cert` and
  `key`, without `hostname`, with an IPv4 or IPv6 literal as `hostname`, and
  an empty block. So `emit --gateway-binary` needs the three files at those
  paths on the host that emits, readable by the user that emits, and the
  rules below are the emitter's own, not a repeat of the gateway's parser.
- Decision (c): every field is required and the hostname is a DNS name. A
  block is all four fields or nothing, each path absolute (the gateway reads
  a relative path from its own working directory, which the emitter cannot
  know), printable ASCII and at most 4096 bytes, written through `quote` like
  every other value; the hostname is printable ASCII within 253 bytes,
  matches the processor-host pattern and is neither an IP literal nor a
  numeric spelling the resolver would read as one. The hostname is the name
  the gateway verifies the processor's certificate under and sends as SNI, so
  requiring it, and refusing the IP literals the gateway would accept, leaves
  one certificate shape to document and to issue: a DNS subject alternative
  name equal to the hostname (`toolwarrant-processor` in the tests,
  `internal/testcert`). The gateway's own validation accepts the partial and
  numeric shapes, so a block the emitter refuses is never one the gateway
  would have loaded differently.
- Decision (d): a verified client certificate satisfies the listen policy
  (owner decision O-2). `serve --allow-non-loopback` is accepted with
  `--tls-client-ca` and without `--secret-env`, because the certificate
  authenticates every hook as the secret does; a secret given as well is
  checked on every hook as before; `--insecure-no-secret` is still the only
  way to listen off loopback with neither. The emitter's warning for a
  processor off loopback states the protection: with the block it says the
  hooks cross the network under TLS, names the hostname and says serve must
  require that certificate with `--tls-client-ca` or carry the shared secret;
  without the block the plaintext line is unchanged. The printed serve
  command for a server with the block ends `--tls-cert PROCESSOR_CERT
  --tls-key PROCESSOR_KEY --tls-client-ca GATEWAY_CA`: the processor's files
  live on its own host, so emit prints names to fill in, not paths.
- Decision (e): the canary's shape, pinned before the producer existed (pull
  request 2.4b). The emitted-file reader opens `policies:` at indent 8 after
  the request-header filter and before the metadata, `backendTLS:` at indent
  10, and reads `cert`, `key`, `root` and `hostname` as quoted scalars at
  indent 12; a second block, an unquoted scalar (the schema's `insecure:
  true`) or a list is refused rather than guessed at, and a policy beside the
  block is left unread. The live side reads the same four fields from
  `policies.backendTLS` of `GET /api/config`, keeps the map nil for an absent,
  null or empty policies object and for a null block, and the shape walk
  reports every other field of the block (`insecure`, `insecureHost`, `alpn`,
  `subjectAltNames`, `keyExchangeGroups`, `spiffe`) and every other processor
  policy (`requestHeaderModifier`, `transformations`, `backendAuth`) by name
  as `not in the emitted file`. The comparison prints `processor backendTLS:
  the live processor has none while the emitted file carries it; the gateway
  dials this processor without TLS` and `processor backendTLS: the live
  processor carries backendTLS the emitted file does not` for a block one side
  lacks (an empty block differs from no block), and one `processor backendTLS
  KEY: emitted X, live Y` line per field that differs, in file order, both
  values shown because they are paths and a name, not secrets. The emitter
  writes exactly that shape, so the reader needed no change when the producer
  landed.
- Consequence. A processor that must run off loopback runs with `--tls-cert`,
  `--tls-key` and `--tls-client-ca`, and the gateway's file carries its block
  from `emit --processor-tls` on every emit; a rotation is a second processor
  on a new port with the new files, a re-emit with the new block, and the old
  processor retired after the longest session lifetime tolerated, as the
  secret is rotated. `emit --gateway-binary` with the flag needs the three
  files on the emitting host, else it exits 1 with the gateway's message and
  writes nothing. Exit codes: a value that is not the grammar or names an
  unknown server is a usage error (2); a path that is not absolute, a missing
  field or a hostname that is not a DNS name is the emitter's refusal (1),
  and the file is untouched. Limit L11 narrows to what remains: the hook
  still carries the client's headers after the filter, and a processor on a
  unix socket stays plaintext; the handshake against the real gateway and
  what `GET /api/config` renders for the block are what end-to-end scenario
  Q observed (the last bullet). What D19 does not do: no catalog columns for
  the block, no `alpn` written (grpc-go requires h2, and scenario Q showed
  the gateway's rustls client offers it, so the field is not needed), no TLS
  on unix sockets, no change to the probe or to what the processor enforces.
- Where. `cmd/toolwarrant/servetls.go` (the three flags, their rules, the
  files, the listening-line notes), `cmd/toolwarrant/serve.go`
  (`listenPolicy.hasClientCA`), `internal/processor/processor.go`
  (`Config.TLS`), `internal/processor/serve.go` and
  `internal/processor/tls.go` (the hardened copy, the refusals, the
  warning), `internal/testcert` (the test-only material);
  `cmd/toolwarrant/emittls.go` (the flag's grammar, the plans), `cmd/toolwarrant/emit.go`
  (the placeholders), `internal/emit/tls.go` (`ProcessorTLS`, its rules,
  the writer), `internal/emit/route.go`, `internal/emit/validate.go`,
  `internal/emit/warning.go`, `internal/emit/testdata/with_tls.yaml`;
  `cmd/toolwarrant/livetls.go`, `liveconsts.go`, `liveconfig.go`,
  `liveadmin.go`, `liveshape.go`, `livecompare.go` (the canary);
  `e2e/scenario_tls_test.go` and `e2e/tlslab_test.go` (scenario Q, run right
  after H), `scripts/requalify-gateway.sh` (item 15 reads the TLS tests and
  scenario Q); SECURITY.md, README.md, CLAUDE.md,
  [threat-model.md](threat-model.md) (rows 17, 22 and 26, L11, L18 and their
  notes), [operations.md](operations.md) ("Running the processor", "Running
  the canary", "Rotating the shared secret", "Re-emitting the gateway
  configuration", "Moving the gateway pin", "Exit codes").
- Tests. Processor `TestServe_TLSListenerRefusesPlaintextAndUnknownClients`,
  `TestServe_TLSWithClientCARequiresAClientCertificate`,
  `TestServe_TLSWithoutClientCAAcceptsAnyClient`,
  `TestServe_ClientCertificateSilencesTheNoSecretWarning`,
  `TestServe_RefusesAnUnusableTLSConfig`; cmd
  `TestServeTLSFlagsNeedCertAndKeyTogether`,
  `TestServeTLSRefusesAUnixSocketListener`,
  `TestServeTLSRefusesAGroupReadableKey`,
  `TestServeTLSOverGRPCEnforcesApprovals`,
  `TestServeTLSRefusesAClientWithoutACertificate`,
  `TestServeTLSClientCASatisfiesTheNonLoopbackRule`,
  `TestCheckListenAddrPolicy` (decisions (a) and (d)); emit
  `TestGatewayValidateOnlyOpensBackendTLSFiles` (the probe: each missing file
  refused with `read resource file`, a relative path refused, a garbage root
  accepted), `TestGatewayParsesBackendTLS` (the unknown field, `no
  certificate`, `no key`, `invalid dns name`, and the lenient acceptances),
  `TestProcessorTLSIsWrittenUnderPolicies`,
  `TestProcessorTLSRequiresEveryField`,
  `TestProcessorTLSPathsMustBeAbsolute`,
  `TestProcessorTLSHostnameIsADNSName`, `TestNoTLSMeansNoPolicies`,
  `TestWarningNamesTheLinkProtection`, the `with_tls` golden in `TestGolden`
  and `TestGoldenFilesValidateWithRealGateway` (decisions (b) and (c)); cmd
  `TestEmitWritesBackendTLSForAProcessorOverride` (the block, the warning,
  the placeholders, nothing in `server list` or the audit log, the next emit
  without the flag writing no block), `TestEmitProcessorTLSFlagGrammar`,
  `TestEmitProcessorTLSNamesUnknownServer`,
  `TestEmitPrintsTheServeCommandWithTLSPlaceholders`,
  `TestEmitWithTheGatewayBinaryNeedsTheTLSFilesOnThisHost` (decisions (b)
  and (d)); canary `TestEmittedConfigReadsTheProcessorTLS`,
  `TestLiveComparisonComparesTheProcessorTLS`,
  `TestLiveComparisonReportsAnInsecureTLSFlag`,
  `TestCompareProcessorsSeesAMissingBackendTLS` and
  `TestEmittedConfigReadsWhatEmitWrites`, which since the emitter landed
  reads the real emitted block (decision (e)). The emit tests fail on the
  code before this decision with `unknown field TLS in struct literal`, and
  the cmd tests with `flag provided but not defined: -processor-tls`, exit 2.
  End-to-end scenario `Q_ProcessorTLS` of `TestEndToEnd` (run right after H,
  while mock is the only server) drives the whole link against the pinned
  binary; `TestRequalifyScript_citesExistingTestsAndScenarios` and
  `TestRequalifyScript_reportsEveryItemOnce` keep item 15 of the
  re-qualification script reading it.
- Observations from end-to-end scenario Q, 2026-10-14, agentgateway v1.6.0
  on darwin/arm64 under `make e2e`, with the processor started as `serve
  --tls-cert --tls-key --tls-client-ca` (its listening line: `TLS 1.3 with a
  client certificate required (hooks are authenticated by the client
  certificate; no --secret-env)`) and `GRPC_GO_LOG_SEVERITY_LEVEL=info` in its
  environment, since grpc-go reports a refused handshake at its info level
  and discards it by default; the gateway's log is its request line per MCP
  call, whose `error=` carries the upstream failure. (1) The first handshake:
  after `emit --processor-tls mock=cert=PATH,key=PATH,root=PATH,hostname=toolwarrant-processor`
  and the gateway's `loaded config from File`, a new session listed add and
  echo 46.3 ms after the reload and `tools/call echo` was allowed; the
  gateway logged the five request lines at info (server/discover,
  initialize, notifications/initialized, tools/list, tools/call), the
  processor's stderr gained only grpc-go's `CPU time info is unavailable on
  non-linux environments`, and the TLS processor's stats on SIGTERM read
  `lists served=2 ... calls allowed=1`. (2) ALPN: grpc-go v1.86 refuses a TLS
  client that selected no application protocol (`credentials: cannot check
  peer: missing selected ALPN property`, `GRPC_ENFORCE_ALPN_ENABLED` defaults
  to true); no such line appeared and the listing served, so the gateway's
  rustls client offers h2 and emit writes no `alpn` field. (3) `GET
  /api/config` renders `policies.backendTLS` under mock's processor with
  exactly the keys `cert`, `hostname`, `key` and `root`, each the emitted
  value (the three paths and the hostname), and the 1133-byte answer holds no
  PEM private key; `verify-gateway --admin` printed `OK: the gateway serves 2
  tool(s), 2 approved and current; live configuration matches the emitted
  file`, so the live shape is the one `liveProcessorDoc` and
  `cmd/toolwarrant/testdata/admin_config.json` pin (nothing to re-record) and
  limit L18 does not widen to the key. (4) mTLS: with the processor
  restarted with `--tls-client-ca` naming an authority that did not sign the
  gateway's certificate, the processor logged `ServerHandshake("127.0.0.1:PORT")
  failed: tls: failed to verify certificate: x509: certificate signed by
  unknown authority`, the gateway answered tools/list with `mcpGuardrails
  checkResponse failed: upstream call failed: SendRequest: connection error:
  received fatal alert: UnknownCA` and tools/call with `... stream closed
  because of a broken pipe`; nothing was served. (5) Downgrade, the plaintext
  entry scenario H left behind a TLS processor: processor `ServerHandshake(...)
  failed: tls: first record does not look like a TLS handshake`, gateway
  `upstream call failed: SendRequest: connection error: connection reset`,
  tools/list failed and tools/call was denied. (6) Downgrade, the TLS entry
  behind a plaintext processor: processor `transport: http2Server.HandleStreams
  received bogus greeting from client: "\x16\x03\x01..."` (a TLS
  ClientHello), gateway `upstream call failed: Connect: received corrupt
  message of type InvalidContentType`, fail closed. (7) A root bundle of
  garbage: `emit --gateway-binary` printed `validated with ...
  --validate-only` and the gateway reloaded the file, then the gateway
  answered `upstream call failed: Connect: invalid peer certificate:
  UnknownIssuer` and the processor logged `ServerHandshake(...) failed: remote
  error: tls: unknown certificate authority`, fail closed; a re-emit with the
  real root served again. (8) `insecure: true` posted into the block through
  the admin API: status 200; a new session still listed add and echo and
  `tools/call echo` was allowed, so the gateway kept dialling the processor
  with its certificate unverified and the route shows nothing; against a
  byte-identical copy of the emitted file `verify-gateway --admin` printed
  `LIVE-CONFIG-MISMATCH mock: processor 1: backendTLS field insecure: not in
  the emitted file`, exit 1, and the original document posted back was
  healthy again. (9) The restore to a plaintext processor and an entry
  without the block was healthy by the canary with and without `--admin`;
  the second TLS processor's stats read `lists served=6 ... calls
  allowed=2`. Every line is in the run's notes (`demo/last-run.log` after
  `demo/run.sh`).

## D20. The v0.2 release round: build provenance, immutable releases, the tag policy, the changelog as the notes, the response time, the reproducible build and the catalog's durability

- Context. v0.1.0 (2026-10-12) and v0.1.1 (2026-10-14) were cut with the D16
  pipeline: goreleaser, syft, a keyless cosign bundle over the checksums file,
  and notes grouped from the commits since the previous tag. The post-v0.1
  research of 2026-10-14 (three reports and a synthesis in the research
  folder) rated what the pipeline still lacked: the cosign bundle is a
  message signature, not a provenance statement, so a release carried no
  build provenance (SLSA Build Level 0 in effect); GitHub's immutable
  releases and release attestations were not in use; the tag policy was
  unwritten and `go.mod` unguarded against a `replace` that would build a
  release nobody else can fetch; the notes were the raw commit list, which the
  OpenSSF Best Practices `release_notes` criterion forbids; SECURITY.md
  promised seven days without saying what follows; the build was reproducible
  in fact (a verifier rebuilt v0.1.0 byte for byte on another host) but the
  procedure was unwritten; and the catalog relied on the SQLite driver's
  compile-time default for `synchronous`. The owner decided on 2026-10-14
  (O-3, O-4 and O-5 of the plan, the rest as recommended) and the round
  landed as pull requests #15 (policy and anchors), #16 (durability), #20
  (guards and CHANGELOG.md) and the release workflow change.
- Decision (a): build provenance. After goreleaser, the release workflow runs
  `actions/attest-build-provenance`, pinned to the commit its v4.2.2 tag
  pointed at, with `subject-checksums` naming the checksums file, so the
  subjects of the statement are the four archives and the four SBOMs by name
  and SHA-256; the predicate is SLSA provenance v1
  (`https://slsa.dev/provenance/v1`) naming this repository, the workflow
  path, the tag ref and the commit; the statement is signed keyless under the
  workflow's OIDC identity, recorded in Sigstore's public Rekor log (the
  repository is public) and stored by GitHub, which is SLSA Build Level 2:
  the attestation is made in the job that built the binaries, and Level 3,
  which needs the build inside a reusable workflow, is not taken. The bundle
  is uploaded to the draft as `toolwarrant_<version>_provenance.intoto.jsonl`,
  the asset name the OpenSSF Scorecard Signed-Releases check awards its full
  score for, and the job holds `attestations: write` for the store. The
  cosign bundle over the checksums file stays: it is verified without gh or a
  GitHub account.
- Decision (b): immutable releases and the published-tag refusal. The owner
  enables immutable releases before the first v0.2.0 candidate (O-5). From
  then on a published release's tag is locked to its commit and its assets
  are frozen while the release exists, and GitHub issues a release
  attestation that `gh release verify` and `gh release verify-asset` (gh 2.81
  or later) check. Candidates and their releases are kept, as immutable
  releases require; the rule of D16 (d) that deleted the candidate tags
  before a final tag is retired, which (d) below makes possible. The gate of
  the release workflow refuses a tag whose release is already published:
  "Get a release by tag name" answers only for a published release, and any
  answer other than a release or a 404 stops the gate rather than passing
  it, so a re-run can never try to swap assets under a known version, with
  or without the setting.
- Decision (c): the tag policy and the go.mod guard. A tag is never moved or
  deleted: the Go module system treats a tag as immutable, a re-pointed tag
  gives every `go install` user a SECURITY ERROR from the go command and a
  deleted tag's content stays on proxy.golang.org; a bad release is a new tag
  plus a `retract vX.Y.Z // reason` directive in `go.mod`. The tag ruleset
  (`v* tags: owner only`, id 24941252) blocks the creation, update and
  deletion of `v*` tags for everyone but the owner, who holds to the same
  rule. `make release-check` refuses a `go.mod` with a `replace` or `exclude`
  directive, or one it cannot read (a `retract` is allowed), since a release
  must build from published modules only.
- Decision (d): CHANGELOG.md is the release notes. The file follows keep a
  changelog: a pull request adds one prose line under `## [Unreleased]`
  naming the test that proves it, the release commit moves those lines under
  `## [x.y.z] - YYYY-MM-DD` and leaves an empty Unreleased heading above
  them, and `make release-check` refuses a tree without the Unreleased
  heading and, run as `make release-check VERSION=x.y.z`, one without the
  version's heading. The release workflow runs `scripts/release-notes.sh`
  before goreleaser: a final tag takes its own section; a candidate takes the
  version's section once the release commit has added it and the Unreleased
  section until then, so a candidate cut on the release commit and one cut
  before it both carry the notes the final tag will; a section ends at the
  next level-two heading or the first link reference definition; a missing
  heading, a heading that appears twice or an empty section stops the run
  before any draft exists. goreleaser gets the file as `--release-notes` and
  the release pipe puts the header and footer of `.goreleaser.yaml` around
  it. The `changelog` block with its `use: git` groups is gone and is not
  replaced by `changelog: disable: true`: in goreleaser v2.18.2 that setting
  skips the changelog pipe, which is where the `--release-notes` file is
  read, so the body would be the header and footer around nothing (read in
  `internal/pipe/changelog` and `internal/pipe/release` at the tag on
  2026-10-14; the plan had assumed the file survives the setting). The
  previous tag no longer decides anything about the notes, which is what lets
  (b) keep the candidates.
- Decision (e): the response time and the public anchors. SECURITY.md
  promises an acknowledgement within two days and aims at a fix in the next
  tag; a confirmed problem still open fourteen days after the report gets a
  dated note in the advisory saying why and when (O-4; seven days before,
  with no fallback). The policy names the two public logs that already anchor
  a release, the Rekor entry inside the cosign bundle and sum.golang.org's
  record of the module at each tag, and the Releasing procedure fetches each
  tag through proxy.golang.org right after publishing and checks the record,
  so it exists before any user's first download.
- Decision (f): the reproducible build, written down and run on every
  release. SECURITY.md and [operations.md](operations.md) give the command: a
  clean clone at the tag, `CGO_ENABLED=0 GOFLAGS=-mod=readonly
  GOTOOLCHAIN=go1.27.2 GOOS=... GOARCH=... go build -trimpath -ldflags "-s -w
  -X main.version=<v>"`, then `cmp` against the archive's binary; v0.1.0 was
  rebuilt that way on another host on 2026-10-14 for linux/amd64 and
  darwin/arm64. The release workflow's last step runs the same command for
  linux/amd64 on the tagged commit, with the toolchain read from `go.mod`,
  and compares the result with the archive goreleaser just built, so a build
  input the documented command does not carry fails the release run instead
  of a verifier.
- Decision (g): the catalog pins `synchronous(FULL)` in the connection string
  of every pooled connection of every open mode (O-3: FULL made explicit,
  the driver's default until then; NORMAL only after a measured, verified
  benchmark), so a returned decision is on the disk across a power loss and
  not only across a crash of the process, and the anchor queries are pinned
  to the audit log's subject index with EXPLAIN QUERY PLAN. The round's two
  test-infrastructure changes (the gotestsum timing table with the `-short`
  policy, and the L2 golden of the keys the gateway drops) are recorded in
  CLAUDE.md and in [threat-model.md](threat-model.md) rather than here.
- Consequence. Operators verify a release with gh alone (`gh attestation
  verify`, `gh release verify`, `gh release verify-asset`) or with cosign and
  shasum as before, and can rebuild it with one documented command; the notes
  they read are the prose the pull requests wrote; a candidate stays visible
  as a pre-release; a published release never changes. Maintainers write the
  changelog line with the change, make the release commit with
  `make release-check VERSION=x.y.z`, and may run
  `scripts/release-notes.sh vx.y.z` to read the notes a tag will publish; the
  release run has three more steps and one more permission, and a step that
  fails after goreleaser leaves a draft that is not published and is replaced
  by a re-run. What D20 does not do: no reusable workflow (Build Level 3), no
  container image, no package-manager formula, no automatic publication (a
  draft still needs a person), no provenance for the seam or mock binaries,
  which are never released.
- Where. `.github/workflows/release.yml` (the gate's second step; the version,
  notes, attestation, upload and rebuild steps; the third permission),
  `.goreleaser.yaml` (no changelog block, the footer), `scripts/release-notes.sh`
  (new), `Makefile` (`release-guards`), `CHANGELOG.md`, SECURITY.md
  (Supported versions, Reporting a vulnerability, Release integrity),
  README.md (the install paragraph and Status), CONTRIBUTING.md, CLAUDE.md,
  [operations.md](operations.md) (Releasing), `internal/catalog/openmodes.go`.
- Tests and proof. `internal/releaseguards`:
  `TestReleaseNotes_aFinalTagTakesItsOwnSectionAndStopsAtTheLinks`,
  `TestReleaseNotes_aCandidateTakesUnreleasedUntilTheReleaseCommit`,
  `TestReleaseNotes_refuseAnEmptySectionOrAMissingHeading`,
  `TestReleaseNotes_refuseATagThatIsNotAVersion`,
  `TestReleaseNotes_everyReleasedVersionInTheTreeHasNotes` (the tree's own
  changelog, every dated heading) and
  `TestReleaseNotes_theWorkflowHandsTheFileToGoreleaserAndKeepsThePipe` (the
  workflow runs the script and passes the file, attests the checksums file
  with `attestations: write` and uploads the `.intoto.jsonl`;
  `.goreleaser.yaml` has no `disable:` line and no `use: git`), beside the
  guards of (c) and (d)
  (`TestReleaseGuards_refuseAReplaceOrExcludeDirectiveInGoMod`,
  `TestReleaseGuards_refuseAChangelogWithoutAnUnreleasedSection`,
  `TestReleaseGuards_refuseAVersionWithoutADatedChangelogEntry`,
  `TestReleaseGuards_runFirstInReleaseCheck`) and the catalog tests of (g)
  (`TestOpen_EveryPooledConnectionIsSynchronousFullWithForeignKeysInWAL`,
  `TestAnchorQueries_StayOnTheAuditLogBySubjectIndex`). The workflow cannot
  run before a tag, so its proof is the first v0.2.0 candidate: its run must
  show the notes step printing the changelog section, the attestation step
  naming eight subjects, the `.intoto.jsonl` as the eleventh asset, the
  rebuild step's `cmp` silent, and `gh attestation verify`, `gh release
  verify`, `gh release verify-asset` and the cosign path succeeding against
  the published candidate (the plan's section 6). What was checked on
  2026-10-14 before the tag: the action's v4.2.2 tag peeled with `gh api` (a
  lightweight tag at commit 4d101475d8b20a2381f78447822ac1eab6504dd8), its
  `action.yml` read at that commit (`subject-checksums` in, `bundle-path`
  out, and the SLSA provenance predicate when no predicate input is given),
  the goreleaser v2.18.2 source read for the path of the notes file through
  the pipes, `gh release upload` read to resolve a draft by its tag, and
  actionlint v1.7.12 and `make release-check` passing on the tree.
