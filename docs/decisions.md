# Design decisions D1 to D22

These records are taken from the commit messages that state each decision: the
five wave-1 commits of 2026-10-07 (b9e4533 core, 29dd670 processor, f2a3e5a
emit, c728172 crawl and fetch, 20e32b4 textdiff and export), the catalog commit
8b7a574, the emitter commit 611e081, the end-to-end commit 21164fd, the commits
of the third round (2026-10-11, the fixes after the second review), which state
D11 and D12 and the catalog integrity changes recorded in
[threat-model.md](threat-model.md) rows 20 and 21, and the commits of the fourth
round (2026-10-11, the fixes after the third review), which state D13, and the
commits of the fifth round (2026-10-12, the fixes after the fourth review),
which state D14, the commits of the sixth round (2026-10-12, the fixes after the
fifth review), which state D15, the release design of 2026-10-12, which is D16,
and the commits of the seventh round (2026-10-12, the fixes after the seventh
review, scoped to the catalog chain and the canary), which state D17, and the
L17 decision of 2026-10-14 (owner decision O-1 of the post-v0.1 plan, taken
after the research of that day), which is D18, and the TLS decision of
2026-10-14 (owner decision O-2 of the same plan, landed as the processor's
listener TLS, the canary's reader and the emitter's block), which is D19, and
the v0.2 release round of 2026-10-14 (the plan's PR 1.4 with owner decisions O-4
and O-5, landed as pull requests #15, #16, #20 and the release workflow change),
which is D20, and the v0.3 round of 2026-10-14 and 2026-10-15 (the plan's Phases
4 and 5 with owner decisions O-6, O-7 and O-8, landed as pull requests #29, #30,
#31, #32, #33 and #34), which is D21, and the v0.4 round of 2026-10-15 and
2026-10-16 (the signed-approvals plan's PRs 7.1 to 7.7 with owner decisions O-9
to O-18, landed as pull requests #46 to #52 and the end-to-end and document
pull request that wrote this record), which is D22. The post-review sections of
[../seam/RESULTS.md](../seam/RESULTS.md) quote the same decisions and record the
corrections they forced to the spike's findings. Each record gives the context
(what a review found), the decision, its consequences for operators and for
other packages, and where it lives in code with the tests that pin it. Where a
decision is proven on the real gateway, the end-to-end scenario is named:
`TestEndToEnd` in `e2e/` runs scenarios A to S against the agentgateway v1.6.0
binary (`make e2e`; `demo/run.sh` keeps the last run in `demo/last-run.log`).

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
  evidence equals the approved digest: the digest observed in the latest gateway
  listing and the digest the latest crawl recorded in `LastSeen`. A `LastSeen`
  that is not a 64-character lowercase hex digest (the `UnusableDigest` marker)
  denies as unverified. No evidence at all denies. An empty `LastSeen` with a
  matching observed digest allows, so a tool the gateway listed correctly is
  callable even if the last crawl missed it. Observed evidence that agrees with
  the approval can expire (`Config.MaxEvidenceAge`); the crawl's word can too
  (`Config.MaxCrawlAge`; both in D21 (a)).
- Consequence. A client that never re-lists is caught by the crawl's `LastSeen`
  within the crawl cadence (limit L1); the end-to-end scenario C measured both
  paths (denied 1.5 ms after another session listed the drifted definition
  through the gateway, and otherwise as soon as the crawl recorded the drift). A
  tool that was never listed through the gateway and never crawled is denied.
  The rule is one-directional on purpose: after an upstream revert, or after a
  rollback, the tool is listed again on the very next `tools/list` because the
  live bytes hash to the approved digest, but `tools/call` is denied as `changed
  since approval` until the next crawl records the revert in `LastSeen`
  (scenario D). Crawl right after a rollback. A `LastSeen` that is the unusable
  marker hides the tool from listings as well as from calls (D3), so a tool
  hidden for a marker is also uncallable; the reverse does not hold. A
  `LastSeen` that is another real digest (a stale crawl, a rollback not yet
  followed by a crawl, an upstream that shows the crawler something else, limit
  L4) still lists the tool while the live bytes hash to the approved digest and
  denies its calls until the next crawl records the revert, which is the rule
  above. The third review found the earlier wording of this record, "what is
  listed is exactly what is callable", contradicted by this very paragraph; the
  marker direction is the one that holds. `MaxEvidenceAge` aged conflict markers
  too (limit L15) until D21 (a), which ages only agreeing evidence and closes
  the limit.
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
- Decision (a): the serving-path evidence reaches the chain. For every approved
  version, `Snapshot`, `Approved` and `Versions` read the newest
  `version.approved` or `version.rolled_back` audit entry about the tool,
  require its `after_hash` to equal the approved digest, and require the entry
  to re-seal from its predecessor (`audit.Seal`), next to the newest-decision
  rule of D13 (a). The verifier memory of `RecheckTTL` caches the result by
  entry hash, so the price is one indexed read and one seal per approved tool
  per ten minutes per `Store` (history: the memory and the byte re-hash on the
  serving path were removed by D21 (d); since the v0.3 round the serving path
  hands out digests anchored to verified entries and reads no bytes, and every
  path that reads the stored bytes behind a digest hashes them on every call
  with no memory). A forger who rewrites a definition and its `hash_seen` under
  re-created guards must now also rewrite and re-chain the log suffix, which
  `audit verify --expect-head` betrays. Corrected by D15 (a) and (b): the
  re-seal against the predecessor alone accepted an entry rewritten in place (a
  new `after_hash` or actor, the hash recomputed from the real `prev_hash`) with
  the head unchanged, and the verifier memory keyed by the stored hash column
  accepted a rewritten `after_hash` alone while the memory was warm; the fifth
  review served such an entry from a long-lived `Store` and from a fresh one,
  with `Integrity` clean. Since the sixth round the entry must be part of the
  chain the `Store` verified.
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
  crawl, re-approve from the git export). After the eighth review the refusal distinguishes an unreleased schema (below `firstReleasedSchema`, 6: delete and init again) from a released one (6 and above: never delete, read it with a build of that schema or migrate as its release notes say), so the first bump after v0.1.0 cannot tell an operator to destroy an audit log (`TestSchemaMessage_AdvisesDeletionOnlyForUnreleasedSchemas`). (Note, 2026-10-16: D22 (g) is that bump, schema v7, and carried the in-place migration of a v6 file, never the delete advice.) `server list`, `emit`, `crawl`,
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
- Correction (2026-10-15). The context above and the documents D18 rewrote
  said that agentgateway v1.6.0 answers the probe with HTTP 202 on every check
  and told the quickstart's reader to expect UNHOOKED-CALLS and then pass
  `--expect-unhooked`. That was observed against the end-to-end harness's
  hostile upstream (`e2e/hostile_test.go`), which accepts an id-less request as
  a notification, not against the quickstart's own `cmd/mockupstream`. On
  2026-10-15 three independent verifiers ran the published v0.3.0 darwin/arm64
  binary against agentgateway v1.6.0 with `cmd/mockupstream` (go-sdk) as the
  upstream, as README step 7 instructs: `verify-gateway --admin` without
  `--expect-unhooked` printed `OK: the gateway serves 2 tool(s), 2 approved
  and current; live configuration matches the emitted file; the id-less
  tools/call was not accepted as a notification (HTTP 400, by the gateway or
  by the upstream)` and exited 0; with `--expect-unhooked` it printed
  `PROBE-CHANGED mock: the gateway no longer answers the probe with 202 (the
  id-less tools/call came back HTTP 400); the pin moved or the gateway changed
  under it; re-qualify (L7) and drop --expect-unhooked once the probe's answer
  is understood` and exited 1; an id-less `tools/call` sent by hand to the
  gateway route and directly to the mock both returned HTTP 400 with the body
  `invalid request: missing id for "tools/call"`; the gateway's log carried
  `error="mcp: upstream error: 400 Bad Request"`; and the processor's stats at
  SIGTERM read `calls allowed=2 denied=2 (stale=0)`, the id-bearing calls and
  none of the seven id-less probes. So the gateway forwarded every probe to the
  upstream without the hook (L17 stands) and relayed the upstream's refusal:
  the HTTP status the canary reports is the upstream's answer, 202 from an
  upstream that accepts the call as a notification (UNHOOKED-CALLS, or
  KNOWN-LIMIT under the flag) and 400 from one that refuses a request without
  an id (the clause of the OK line that attributes the refusal to nobody,
  D17). The design already covered both answers: `classifyProbe` (D13 to D17)
  reports the 202 and the bare 400 as it did, and decision (c) above makes a
  non-202 answer PROBE-CHANGED under the flag by design, which is what the mock
  produced. The flag is therefore for deployments whose upstream answers 202;
  the quickstart must not pass it. README step 7 and L17, SECURITY.md (the
  hardening checklist and the pin paragraph), [operations.md](operations.md)
  ("Deployment requirements", "Running the canary", the verdict list, item 1 of
  "Moving the gateway pin") and [threat-model.md](threat-model.md) (row 25, L17
  and their notes) were corrected on 2026-10-15 to state this; no code, test or
  flag changed (e2e scenario O, `O_UnhookedCallProbe` of `TestEndToEnd`, and
  cmd `TestExpectUnhookedFailsWhenTheGatewayStopsForwarding`, which drives the
  go-sdk upstream's bare 400 to PROBE-CHANGED, already pin both answers).
  The same unqualified claim stands as history in D13 (h) ("On the pinned
  gateway, which answers 202"), in the D13 round summary ("the probe still
  fails every check"), in D17 ("answers 202 before forwarding") and in the
  D13 (h) entry of seam/RESULTS.md; this correction supersedes each of them,
  and none is rewritten. The canary's own help text for --no-probe and
  --expect-unhooked in cmd/toolwarrant/verify.go still attributes the 202 to
  the gateway and recommends the flag; a follow-up change brings those two
  strings in line with this correction.
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
  real root served again. (8) `insecure: true`, posted into the block through
  the admin API while the block named the garbage root again, so that the
  flag's effect is observable: with that root the route had just failed
  closed (gateway `Connect: invalid peer certificate: UnknownIssuer`,
  processor `remote error: tls: unknown certificate authority`); the post
  answered status 200; the sessions opened while the gateway was still
  applying the document were refused the same way (the note quotes six
  processor lines, every one `ServerHandshake(...) failed: remote error: tls:
  unknown certificate authority`), then a new session listed add and echo and
  `tools/call echo` was allowed, so under the flag the gateway dialled the
  processor without verifying its certificate, and the route shows nothing;
  against a byte-identical copy of the garbage-root file, which makes the
  flag the only difference, `verify-gateway --admin` printed
  `LIVE-CONFIG-MISMATCH mock: processor 1: backendTLS field insecure: not in
  the emitted file`, exit 1; the original document (the real root, no flag)
  posted back and the real-root file put back on disk were healthy again.
  (9) The restore to a plaintext processor and an entry without the block
  was healthy by the canary with and without `--admin`;
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

## D21. v0.3: approval UX and the catalog design items

- Context. The post-v0.1 research of 2026-10-14 and the catalog design pass of
  the same day produced the plan of the next releases; the owner decided its
  open questions on 2026-10-14. O-6: a description change is graded WARNING; the
  UTS #39 confusables table is vendored under `third_party/unicode` with its
  licence recorded by hand; `internal/toolname` is unchanged; the narrower
  digest profile and component hashes are deferred. O-7: `--max-crawl-age`
  default off; `--max-evidence-age` changed so that a contradiction never ages;
  scenario R may restart a processor mid-run as H does. O-8: digests on the
  serving path and bytes hashed where bytes are handed out, with the guarantee
  rewording, after a measurement. The round landed on 2026-10-14 and 2026-10-15
  as pull requests #29 (4.1, the two ages), #31 (4.2, the drift classifier), #33
  (4.3, look-alikes and mixed-script words), #32 (5.1, the reload measurement),
  #34 (5.2, verify-on-read) and #30 (5.3, the signed export), under a
  document-ownership rule: each feature pull request owned its code, its tests,
  its [operations.md](operations.md) section and its CHANGELOG.md line, and this
  record, the known limits and the guarantee sentences of README.md, SECURITY.md
  and [threat-model.md](threat-model.md) were written once, afterwards, from the
  decision texts the six pull requests handed over. Each sub-decision below
  carries its own context, decision, consequence, where and proof. In
  [threat-model.md](threat-model.md) this round changed the catalog bullet of
  the actors list, rows 3, 4, 13 and 21, the notes of rows 21, L1 and L19, and
  the limits L1, L6, L9, L13, L14, L15 (closed) and L16 (closed).

### D21 (a). Only agreeing evidence ages; `--max-crawl-age` bounds L1 when crawls stop

- Context. The call rule (D9) judges a `tools/call` from two pieces of evidence:
  the digest the gateway last listed for the tool (observed) and the digest the
  latest crawl recorded (`LastSeen`). Two limits followed from how each was
  aged. L15: `observedDigest` applied `Config.MaxEvidenceAge` to every entry of
  the observed table, and conflict markers are entries (`digest ==
  observedConflict`, written by `markConflicts`), so a contradiction older than
  the age stopped denying and the call passed on the crawl's word although the
  most recent page the processor had seen showed another definition; the catalog
  design pass of 2026-10-14 confirmed it in `observed.go` and `judgeCall`. L1: a
  `LastSeen` equal to the approval carried a call for ever, so a crawler that
  stopped left the gap unbounded. The research proposed a bound on the crawl's
  age and the owner decided O-7.
- Decision (1): ageing only ever removes evidence that would allow.
  `observedDigest` returns `(digest, seenAt, ok)` and no longer ages;
  `judgeCall` reads the clock once and `listingEvidence` drops an observation
  only when it equals the approved digest and is older than `MaxEvidenceAge`,
  because a digest the gateway listed long ago says nothing about what the
  upstream serves now. A contradiction, another digest or the conflict marker,
  is returned whatever its age and denies as `changed since approval` until a
  clean page shows the approved bytes, because its age does not undo the change
  it recorded. This closes L15; its README one-liner and its threat-model row
  keep the number, marked closed, so the numbering of the later limits holds.
- Decision (2): `Config.MaxCrawlAge`, `serve --max-crawl-age DURATION`, default
  zero. In the `LastSeen == Approved` branch the call is allowed when a fresh
  agreeing listing stands or `crawlFresh` holds: `MaxCrawlAge == 0`, or
  `Snapshot.CrawledAt` (the start of the latest complete crawl of the server) is
  within the age; a snapshot with no complete crawl is never fresh. Otherwise
  the call is denied `crawl evidence too old` (`causeStale`), counted in
  `Stats.CallsStale` beside `CallsDenied`, and the stats line reads `calls
  allowed=N denied=N (stale=N)`. A negative value is a usage error, exit 2. One
  `s.now()` and a subtraction per call. The bound holds when crawls stop; it
  does not shorten L1 below the crawl cadence, and a listing contradiction
  denies as changed whatever the crawl's age.
- Consequence. An operator who sets nothing sees no new denial and `stale` stays
  0. With `--max-crawl-age` at a few crawl periods, a stopped crawler shows as
  `stale` growing with `denied`, while a changed definition does not move
  `stale`. A client that never re-lists is denied once both the crawl and its
  listing are older than their ages, which is the L1 gap bounded; a listing by
  any session refreshes the tool for every session, because evidence is per
  tool, not per session. A server with no complete crawl needs a listing before
  any call under the flag. What (a) does not do: `LastSeen` carries no per-tool
  timestamp (the age is the server's latest complete crawl); list filtering is
  unchanged; the crawler host's clock writes `CrawledAt` and the processor
  host's clock reads it, so a crawler clock ahead of the processor's makes a
  crawl look fresher than it is, and the flag assumes the two hosts keep time
  together (NTP, or the same host). The example `serve` command in
  [operations.md](operations.md) is unchanged; the flag bullets there describe
  both ages.
- Where. `internal/processor/processor.go` (`Config.MaxEvidenceAge` reworded,
  `Config.MaxCrawlAge`, `Stats.CallsStale`), `internal/processor/call.go`
  (`judgeCall`, `listingEvidence`, `crawlFresh`, `denyCall` counting the stale
  cause), `internal/processor/observed.go` (`observedDigest`),
  `internal/processor/results.go` (`causeStale`); `cmd/toolwarrant/serve.go`
  (the flag, the negative check, `writeStats`), `cmd/toolwarrant/main.go` (the
  synopsis); `e2e/scenario_freshness_test.go` (scenario R, registered right
  after I in `e2e/e2e_test.go`); [operations.md](operations.md) ("Running the
  processor": the two age bullets and the stats line); CHANGELOG.md (Added and
  Changed); README.md L1 and L15, [threat-model.md](threat-model.md) row 4, L1
  and L15, CLAUDE.md and the pointers in D9 through this record.
- Tests and proof. processor `TestEvidence_ContradictionsNeverExpire` (another
  digest and the conflict marker, with `LastSeen` the approval and empty; denied
  as changed before, at, one second past and 1000 hours past the age; a clean
  page releases; on the code before this round it failed with `call was not
  denied: pass:{}` and `not yet verified` where `changed since approval` is
  required), `TestEvidence_ObservedDigestsExpire` (kept by name; its third case,
  which asserted the L15 behaviour, now asserts that an aged agreeing listing
  leaves the call to the crawl and the entry stays in the table),
  `TestJudgeCall_StaleCrawlDeniesUnlessFreshlyListed` (exactly the age is fresh,
  a second past is stale; a fresh listing carries the call and ages too; a new
  complete crawl carries it with no listing; no complete crawl is never fresh; a
  contradiction wins over the crawl's age; a stale crawl that never saw the tool
  stays not yet verified), `TestCheckRequest_MaxCrawlAgeZeroKeepsTheOldRule`,
  `TestCheckRequest_StaleCrawlCountsInStats` (two stale of four denied; the log
  carries `cause="crawl evidence too old"` twice; an allowed call moves
  nothing), `TestJudgeCall_RuleTable` (eight stale rows: only the row whose sole
  allowing evidence is the crawl's word changes); cmd
  `TestServeRejectsANegativeMaxCrawlAge` (exit 2 naming the flag; 0 and 1h start
  and print `(stale=0)`; on the old code `flag provided but not defined:
  -max-crawl-age`), `TestWriteStatsPinsTheLine`,
  `TestServeEnforcesApprovalsOverGRPC`; e2e scenario R
  (`R_StaleCrawlDeniesCalls`) on 2026-10-14 against agentgateway v1.6.0 with
  `--max-crawl-age 2s --max-evidence-age 2s` and the catalog's latest crawl
  minutes old: `2.1 ms after the session listed, ... tools/call echo -> allowed:
  hello`; `3006.5 ms after the listing, tools/call echo on the same session ->
  denied (result isError): tool "echo": crawl evidence too old`; `a new session
  listed, tools/call echo -> allowed: hello`; `100.3 ms after a crawl and with
  no listing since the denial, tools/call echo -> allowed: hello`; the processor
  printed `calls allowed=3 denied=2 (stale=2)` on SIGTERM; `TestEndToEnd` passed
  A to R and N in 47.8 s (the first run showed the same shape at 1.3, 3005.0 and
  248.4 ms). The plan placed R after M; scenario N reads the wrong-backend count
  scenario J leaves on mock's processor and a restart after J resets it (N
  failed with `mock's processor counted no wrong-backend hooks before its
  restart`), so R runs right after I, while mock is the only server, as Q runs
  right after H.

### D21 (b). Drift classification: a grade and the kinds of change before the diff, advisory only

- Context. An approver who read the escaped diff of a tool with many versions
  could not tell a description tweak from a removed parameter without reading
  every line, and the digest that decides what is served (D1) says nothing about
  how a version differs; `show` listed the versions with no way to pick out the
  one that also removes a parameter (the picker limit L6 names), and L9 made
  every `_meta` change drift without saying which member. The research proposed
  a classifier over the two canonical documents; the owner decided (O-6) that a
  description change is graded WARNING, not the INFO other classifiers give it,
  because the description-first rug pull is threat-model row 3. The review of
  the first implementation found two shapes of change that graded `none` while
  the documents differed; the never-none promise below records what closed them.
- Decision. `internal/drift` (`Compare(fromCanonical, toCanonical []byte)
  (Report, error)`) classifies the change between two canonical documents as
  `catalog.VersionView.Canonical` hands them out: every top-level member that
  differs gets a kind and a grade, and the grade of the report is the largest
  one. CRITICAL widens what the tool may do or breaks the contract the approver
  reviewed: `parameter-removed`, `parameter-type-changed`,
  `required-parameter-added`, `parameter-made-required`, `annotations-loosened`
  (readOnlyHint true to false, destructiveHint false to true, openWorldHint
  false to true, idempotentHint true to false; an absent hint reads at its MCP
  default, so dropping `readOnlyHint: true` is CRITICAL, and a hint that stood
  at its safe value and now cannot be read as a boolean counts as loosened,
  while a move from an unreadable value is `annotations-changed`),
  `name-changed`. WARNING changes what the model reads or what the host does
  without widening the tool: `description-changed` (O-6),
  `optional-parameter-added`, `input-schema-changed` (an enum, a constraint, a
  nested schema, a parameter made optional, a `required` list that changed in a
  way no parameter explains, a parameter `type` that changed between two values
  outside the JSON Schema vocabulary or whose type array was reordered, an empty
  `properties` object that appeared or vanished), `output-schema-changed`,
  `annotations-changed` (a hint tightened included), `meta-changed` (hosts act
  on `_meta`, D1; agentgateway acts on `_meta.ui`), `other` (a top-level key the
  package does not know). INFO is display only: `title-changed`,
  `icons-changed`. A kind the package does not know grades CRITICAL, failing
  closed. The grades are ordered none < Info < Warning < Critical: `Max()` over
  an empty report is `none` and `Summary()` prints `none`. A tool that appears
  or disappears is a crawl-level change (`ChangeNew`, `ChangeMissing`,
  `ChangeDeprecated`), not a kind. Two documents that differ never grade `none`:
  every member that differs yields at least one finding, and two documents the
  classifier reads as equal yield none, so `drift: none` never stands above a
  diff that shows a change. Both documents are hostile text: every path goes
  through `textdiff.Escape` (a line break inside a key is spelled `\n`, as
  textdiff spells it in the paths it prints under the drift line; drift imports
  textdiff, never the reverse), every detail comes from a closed vocabulary
  (`added`, `removed`, `changed`, `made required`, `string -> integer`, `true ->
  absent`), and a document that is not exactly one JSON object in valid UTF-8
  (decoded with `UseNumber`, trailing data refused as `textdiff/walk.go` does)
  is refused through sentinel errors that name the side and never a byte.
  `Report` sorts its findings by severity, the most severe first, then by path;
  `Max`, `Kinds` (unique, the worst first and then by name) and `Summary`
  (`CRITICAL (parameter-removed, description-changed)`, or `none`) are what the
  commands print. Shown: `diff` prints `drift: GRADE (kinds)` after the `to:`
  header, and `drift: not classified (nothing approved to compare with)` against
  the empty document, since grading a first proposal against nothing would call
  every member added; `show` adds a CHANGE column with each version's grade
  against the approved one (the grade alone; `-` for the approved version and
  while nothing is approved) and one line under the table grouping the other
  versions by identical kind set, the worst group first, with the kinds (`change
  versus the approved version 1: 1 version (4) CRITICAL (parameter-removed,
  description-changed); 2 versions (2-3) WARNING (description-changed)`), which
  is the L6 picker without auto-approval; `show --json` gives every version
  `"change": {"severity", "kinds"}`, `null` where the column shows `-`;
  `approve` prints the same `change versus the approved version N: GRADE
  (kinds)` line on stderr before the suspicious-text review and never gates on
  it; `list` is unchanged, since `Tools` carries no bytes.
- Consequence. The classification is advice: the gate stays the digest (D1),
  nothing here approves, hides or serves anything, and a CRITICAL grade is the
  reason to read the diff, not a refusal; the digest the operator names is what
  is approved. A stored canonical form the classifier refuses stops `show` and
  `approve` with an error naming the version numbers, never the bytes: the
  catalog hashes every form it hands out, so that is a fault to stop on, not a
  grade, and both commands fail closed. What (b) does not do: no change to the
  suspicious-text review (D21 (c) extends it), no auto-approval of INFO or
  WARNING versions, no classification across servers, no look-alike detection,
  no export of textdiff's inline escaper.
- Where. `internal/drift/drift.go` (the grades, the kinds, `Compare`, the
  top-level rules), `internal/drift/schema.go` (the inputSchema rules;
  `typeMemberDiffers` and the empty-properties rule are the two never-none
  fixes), `internal/drift/annotations.go` (the four hints with their MCP
  defaults, `hintRule.loosened`), `internal/drift/path.go` (escaped path
  segments); `cmd/toolwarrant/drift.go`, `cmd/toolwarrant/view.go` (diff and
  show), `cmd/toolwarrant/decide.go` (approve); [operations.md](operations.md)
  ("Reading a drift classification"), CLAUDE.md (the layout bullet),
  CHANGELOG.md (three Unreleased lines); README.md ("Drift shows as hidden, and
  classified") and [threat-model.md](threat-model.md) (row 3 proof, L6 and L9)
  through this record.
- Tests and proof. `internal/drift`: `TestCompare_ParameterRemovedIsCritical`,
  `TestCompare_ParameterTypeChangedIsCritical`,
  `TestCompare_RequiredParameterAddedIsCriticalOptionalIsWarning`,
  `TestCompare_ExistingParameterMadeRequiredIsCritical`,
  `TestCompare_DescriptionChangeIsWarningNotInfo` (O-6; with the description
  graded INFO it fails with `description change graded INFO, want WARNING`),
  `TestCompare_AnnotationHintLoosenedIsCriticalTightenedIsWarning` (the four
  loosenings, the MCP default for an absent hint, `true -> other` loosened, a
  tightening and a move from an unsafe value WARNING),
  `TestCompare_MetaChangeIsWarningBecauseHostsActOnIt`,
  `TestCompare_TitleAndIconsAreInfo`,
  `TestCompare_IdenticalDocumentsHaveNoFindings`,
  `TestCompare_FindingsAreSortedBySeverityThenPath`,
  `TestCompare_RefusesInvalidDocumentsWithoutEchoingThem` (both sides, every
  sentinel, the error names the side and never the marker),
  `TestCompare_HostileKeysAreEscapedInPaths` (zero-width space, ESC, bidi
  override and a line break in keys),
  `TestCompare_OutputSchemaAndUnknownKeysAreWarning`,
  `TestCompare_RequiredListChangesTheParametersDoNotExplain`,
  `TestCompare_TypeChangesOutsideTheVocabularyAreWarning` (`"foo"` to `"bar"`,
  `5` to `6`, `{"a":1}` to `{"a":2}`, `["string","null"]` to
  `["null","string"]`, each one `input-schema-changed` at
  `$.inputSchema.properties.mode.type`, WARNING),
  `TestCompare_EmptyPropertiesObjectAddedOrRemovedIsWarning`,
  `TestSeverity_StringsAndUnknownKindFailsClosed`; rapid:
  `TestProperty_compareSwapsAddedAndRemovedKinds`,
  `TestProperty_maxSeverityIsTheLargestFinding`,
  `TestProperty_compareNeverPanicsOnRandomJSON` and, beyond the plan's three,
  `TestProperty_everyMemberChangedOnItsOwnYieldsAFinding`, which is the pin of
  the never-none promise: it mutates every member of a drawn definition one at a
  time (delete, or replace by a value of the same shape) and holds the invariant
  that the decoded documents are equal exactly when the report is empty; on the
  code before the fix it failed after 2 checks with `documents equal: false,
  findings: []`, while the same invariant in the two independent-draw tests
  passed 3000 checks on that code, because two independently drawn documents
  almost never differ in a reordered type array alone; the two holes the review
  found and it pins are the parameter `type` member compared only through the
  parameter rules and `properties` absent on one side and `{}` on the other;
  `FuzzCompare` (the same invariant runs inside it; 30 s on 2026-10-14: 408,911
  execs, 104 new interesting inputs, PASS). `cmd/toolwarrant`:
  `TestDiffPrintsTheDriftClassification`, `TestShowGroupsVersionsByChangeKinds`,
  `TestApprovePrintsTheClassificationAndNeverGatesOnIt` (a CRITICAL approval
  exits 0 and the catalog's refusals still decide); against `view.go` and
  `decide.go` before the change the three fail with `first diff lacks ... drift:
  not classified`, `show before approval lacks CHANGE` and `stderr lacks change
  versus the approved version 1: CRITICAL (parameter-removed)`; the two
  never-none unit tests fail on the first implementation with `findings = []`,
  and `TestCompare_HostileKeysAreEscapedInPaths` fails on the first path
  spelling with `Path:$._meta["a\"b\\c\u{000A}d"] ..., want ...
  Path:$._meta["a\"b\\c\nd"]`.

### D21 (c). Look-alikes and mixed-script words: UTS #39 skeletons over a vendored table, three classes under one flag

- Context. Since the first release the review of a changed definition has been
  the escaped diff of `internal/textdiff`, which makes a character a person
  cannot see or a terminal would obey visible as `\u{...}` (row 13) and said of
  look-alikes only that they pass (L14): a Cyrillic letter at U+0430 where a
  Latin a stood is a printable character that draws the same glyph, so an escape
  has nothing to make visible, and a parameter renamed from `path` to that
  spelling showed in the diff as two identical words while the digest and the
  drift classifier (D21 (b)) reported a removed and a newly required parameter
  with no hint that the two names read the same. The research proposed UTS #39:
  the skeleton transform over the confusables table and the Highly Restrictive
  script profile. The owner decided (O-6) that the table is vendored under
  `third_party/unicode` with its licence recorded by hand, since
  THIRD_PARTY_NOTICES.md is generated from the module cache only, and that
  `internal/toolname` is unchanged in v0.3. One fact changed the plan while
  vendoring: unicode.org publishes the security data only as 16.0.0 and latest
  (18.0.0 of 2026-08-06, 6712 mappings), with no 17.0.0 directory, while
  go1.27.2 ships `unicode.Version` 17.0.0.
- Decision (1): the skeleton and its table. `textdiff.Skeleton(s)` is UTS #39
  section 4: NFD, each code point replaced by its table prototype, NFD again; a
  byte that is not UTF-8 is kept as it is. The table is
  `internal/textdiff/confusables_table.go`, a sorted `[]confusable{src rune; dst
  string}` of 6712 entries looked up by binary search, generated by
  `gen_confusables.go` (behind `//go:build ignore`, never part of the package),
  which reads `third_party/unicode/confusables.txt` as data under the rules for
  upstream text (bounded lines, every code point checked, a duplicate source or
  a malformed field stops the run, nothing from the file echoed into an error)
  and writes only ASCII escapes. The generator pins the header to
  `confusablesVersion = "18.0.0"` and refuses any other version;
  `scripts/gen-confusables.sh --check`, modelled on `gen-proto.sh`, regenerates
  into a temporary directory and compares, and the `ci` lint job runs it after
  `make lint` (the Makefile is unchanged), so a hand edit of the table or a data
  file swapped under it fails every pull request. Version policy: the vendored
  header is 18.0.0 while go1.27 ships Unicode 17.0.0 tables;
  `TestConfusables_versionIsTheVendoredHeaderAndNotOlderThanTheToolchains` pins
  the header equal to the constant and not older than the toolchain's version,
  since a table older than the toolchain would miss code points the toolchain
  knows (the test the plan named, which would have pinned the header to the
  toolchain's own Unicode version, could not be written because no 17.0.0 data
  exists); when unicode.org publishes a newer table the owner decides whether to
  re-vendor, and a re-vendoring moves the constant, the README's version and
  date and a CHANGELOG line together, never as a toolchain side effect. Why the
  one-version lead is safe: the table maps code points to prototypes and is data
  compared for equality, nothing in it is executed, and it consults no toolchain
  table, so a code point assigned in 18.0.0 is still folded by the skeleton; the
  toolchain not knowing it only means the mixed-script rule reads its script as
  `Unknown` and the suspicious-character scan reports it as unassigned, both of
  them refusals and never a silent pass. The split between the two rules: a word
  made only of code points the toolchain does not know has one script,
  `Unknown`, so it is not a mixed-script word and the suspicious-character scan
  is what reports it, while an `Unknown` code point beside letters of any script
  makes the word mixed-script.
- Decision (2): what is found and how it is said. `LookAlike(from, to)` is true
  when the skeletons are equal and the strings differ.
  `LookAlikeChanges(fromCanonical, toCanonical)` runs over two canonical
  documents: every string value that changed at the same path, and object keys
  paired by skeleton within one object, in every object (`outputSchema` and
  `_meta` as well as `inputSchema.properties`, a superset of the plan's "keys
  under inputSchema.properties", because a swapped key anywhere is equally
  invisible in the diff; a key that vanished and a key that appeared in the same
  object with equal skeletons is one swap), each reported as `catLookAlike` with
  per-rune pairs `U+0430 (Cyrillic) for U+0061 (Latin) at byte N`. A visible
  change is never a look-alike and a value present on one side only is not
  either. `MixedScriptWords(s)` splits on whitespace and, for each word,
  collects the scripts of its letters ignoring Common and Inherited (digits,
  punctuation, combining marks); one script passes, and so do the three UTS #39
  Highly Restrictive combinations (Latin with Han, Hiragana and Katakana; Latin
  with Han and Hangul; Latin with Han and Bopomofo); anything else is
  `catMixedScript`, the line naming each script with its code points, the script
  with the fewest first since that is usually the intruder, at most eight
  (`maxScriptRunes`) per script before a count. Script names come from the
  stdlib `unicode.Scripts` map and a code point in none of its tables is
  `Unknown`. Code points are printed, never rune names and never the character
  in the detail; the path in front of a detail spells an object key as the
  upstream did, through the same escaper as every other path (invisible and
  terminal-controlling characters only), so a look-alike key reads as ordinary
  there, the documents say so, and that is why the code points are what to read
  (re-rendering a flagged key's path by code point would make one section's
  paths differ from the drift line's and the Changed text section's for the same
  key, so the path is left as spelt). `Tool` prints both classes for the new
  document in a `Look-alike changes` section after `Changed text`: the counts
  first (`4 (look-alike: 2, mixed-script: 2)`), then at most `maxLookAlikeLines`
  (100) detail lines and a `... N more not listed` line, `none` when there is
  nothing. Invalid documents are refused through sentinel errors without echoing
  a byte.
- Decision (3): the review in `approve`. `reviewSuspicious` gathers three
  classes and gates them behind the one flag `--accept-suspicious`, because each
  is accepted the same way, by reading the list: the suspicious characters of
  the version being approved (as before), its mixed-script words over every
  string value and object key (a parameter name is text the model reads too),
  and, while a version is approved, the look-alike changes of the new version
  against the approved one (`gatherSuspicion` compares nothing when there is no
  approved version, so a first approval has an empty look-alike class). Without
  the flag the command prints the lists on stderr after the drift line of (b),
  then `refusing to approve: the definition holds 2 mixed-script word(s) and 2
  look-alike change(s), listed above; review them and pass --accept-suspicious
  to approve anyway`, exits 1 and records nothing; with the flag the same lists
  are printed, then `warning: approving despite 2 mixed-script word(s) and 2
  look-alike change(s)`, and the approval is recorded as any other. `diff` shows
  the same two classes in its section so the review can be read before `approve`
  is run.
- Consequence. The rename of `path` to its Cyrillic spelling, invisible in the
  escaped diff, is now listed twice (as a look-alike swap against the approved
  version and as a mixed-script word on its own) and refused; a Latin acronym
  inside Japanese, Korean or Chinese text is approved without a word of warning;
  a reader of the refusal gets code points and scripts, never a glyph to
  misread. What (c) does not do: the gate stays the digest (D1), nothing here
  approves or serves anything; `internal/toolname` is unchanged (a script rule
  there would quarantine across crawler, processor and emitter; an owner
  decision later, tracked in (f)); a look-alike the table does not list and a
  mixed-script word the profile allows stay invisible, so L14 is narrowed, not
  closed, row 13's control grows and the L14 row shrinks; no go.mod change
  (`golang.org/x/text/unicode/norm` was already a dependency); the escapes-only
  rule for look-alikes in test files was applied to every new test file and the
  older `internal/textdiff` test files that hold visible accented letters are
  out of scope. The vendored table moves only with its pin, the version test and
  the vendored licence together.
- Where. `internal/textdiff/skeleton.go` (`Skeleton`, `confusableOf`,
  `LookAlike`), `internal/textdiff/scripts.go` (`MixedScriptWords`,
  `highlyRestrictive`, the script index built once on first use),
  `internal/textdiff/lookalike.go` (`LookAlikeChanges`, the key pairing, the
  section writer and its cap), `internal/textdiff/confusables_table.go`
  (generated), `internal/textdiff/gen_confusables.go` (`//go:build ignore`),
  `internal/textdiff/classify.go` (`catLookAlike`, `catMixedScript`, the package
  comment), `internal/textdiff/escape.go` (the comment on what `Escape` does not
  do), `internal/textdiff/tool.go` and `compare.go` (the section after `Changed
  text`); `cmd/toolwarrant/lookalike.go` (`gatherSuspicion`, `scanMixedScripts`,
  the printing) and `cmd/toolwarrant/decide.go` (`reviewSuspicious`);
  `scripts/gen-confusables.sh`; `.github/workflows/ci.yml` (the lint job's
  `scripts/gen-confusables.sh --check` step);
  `third_party/unicode/confusables.txt` and `third_party/unicode/LICENSE`
  (sha256 `6ed3ee967c9dfdf6677d563c9985182fbc50a2efb7d6059cd57b2e2ce18f5b92` and
  `e7a93b009565cfce55919a381437ac4db883e9da2126fa28b91d12732bc53d96`, recorded
  in the README Licence paragraph); [operations.md](operations.md) ("Reviewing
  suspicious text before approving"); CLAUDE.md (the command block, the lint
  sentence, the `internal/textdiff` and `scripts/` bullets, the pinned
  versions); CHANGELOG.md (two Added lines, one Changed line); README.md (L14,
  the Licence paragraph), SECURITY.md (the out-of-scope bullet) and
  [threat-model.md](threat-model.md) (row 13, L14) through this record.
- Tests and proof. `internal/textdiff`: `TestSkeleton_matchesUTS39Examples` (the
  UTS #39 examples: paypal with U+0430, U+0440 U+043E U+0440 to pop, rn for m,
  the fi ligature, 1I| to lll), `TestSkeleton_isIdempotent`,
  `TestSkeleton_keepsBytesThatAreNotUTF8`,
  `TestLookAlike_onlyWhenSkeletonsAgreeAndBytesDiffer`,
  `TestSwapsBetween_listCodePointsAndScripts`,
  `TestSwap_capsTheCodePointsItLists`, `TestCodePoints`,
  `TestMixedScriptWords_highlyRestrictiveProfile` (a Cyrillic letter inside
  Latin, Cyrillic with Han, Greek inside Latin, Hangul with Hiragana, an
  unassigned code point with Latin, byte offsets, two words),
  `TestMixedWord_listsTheRarestScriptFirstAndCapsEachList`,
  `TestScriptOf_agreesWithTheStdlibTables`,
  `TestHighlyRestrictive_combinations`,
  `TestConfusables_tableIsGeneratedFromTheVendoredFile` (the same sources and
  targets as the vendored file, sorted, no duplicate, the header naming version
  and count, no raw non-ASCII byte),
  `TestConfusables_versionIsTheVendoredHeaderAndNotOlderThanTheToolchains`,
  `TestConfusablesCI_lintJobRunsTheCheck` (ci.yml's `lint` job runs the check
  after `make lint`), `TestTool_lookAlikeSwapIsListedWithCodePoints`,
  `TestTool_visibleChangesAreNotLookAlikes`,
  `TestTool_mixedScriptWordsAreListed`,
  `TestTool_lookAlikeSectionIsCappedButCountsAreComplete`,
  `TestLookAlikeChange_detailCapsTheSwaps`,
  `TestLookAlikeChanges_refusesInvalidDocumentsWithoutEchoingThem`; rapid:
  `TestProperty_skeletonIsInvariantUnderConfusableSubstitution`,
  `TestProperty_lookAlikeSectionNeverHoldsRawSuspiciousRunes`; `FuzzSkeleton`
  (30 s on 2026-10-14: `fuzz: elapsed: 30s, execs: 190988 (0/sec), new
  interesting: 27 (total: 197)`, PASS; an earlier 30 s run the same day: 246428
  execs, 81 new interesting, PASS). `cmd/toolwarrant`:
  `TestApproveRefusesALookAlikeSwapUnlessAccepted`,
  `TestApproveRefusesMixedScriptWordsUnlessAccepted`,
  `TestApproveAcceptsCJKWithLatinAcronyms`; every new test file spells its
  look-alikes as `\u` escapes (`grep -cP '[^\x00-\x7F]'` is 0 on each).
  Mutations run on 2026-10-14 in scratch copies, never in the tree: with
  `Skeleton` returning its input, `TestSkeleton_matchesUTS39Examples` fails on
  all five examples (the first line reading `cyrillic a:
  Skeleton("p<U+0430>ypal") = "p<U+0430>ypal", want "paypal"`, the glyph spelt
  here by its code point),
  `TestProperty_skeletonIsInvariantUnderConfusableSubstitution` fails after 0
  tests and `TestTool_lookAlikeSwapIsListedWithCodePoints` fails on the section;
  with `highlyRestrictive` always true,
  `TestMixedScriptWords_highlyRestrictiveProfile` fails on all seven cases
  (`MixedScriptWords(...) = [], want [...]`),
  `TestTool_mixedScriptWordsAreListed` fails and
  `TestApproveRefusesMixedScriptWordsUnlessAccepted` fails with `exit 0, want
  1`; with `reviewSuspicious` never refusing,
  `TestApproveRefusesSuspiciousCharactersUnlessAccepted`,
  `TestApproveRefusesALookAlikeSwapUnlessAccepted` and
  `TestApproveRefusesMixedScriptWordsUnlessAccepted` each fail with `exit 0,
  want 1`; with the `scripts/gen-confusables.sh --check` step removed from a
  copy of ci.yml, moved before `make lint`, or the job renamed,
  `TestConfusablesCI_lintJobRunsTheCheck` fails with `the lint job lacks the
  step ...`, `the lint job runs ... before "- run: make lint"` and `has no job
  "lint"`; the reviewer's independent mutations (`pairKeys` a no-op,
  `approvedVersion` nil, the value-side `LookAlike` dropped) each failed their
  targeted test. The race suites without `-short` passed on 2026-10-14
  (`internal/textdiff` ok in 33.964 s alone and 92.158 s sharing the machine
  with the cmd suite and the fuzzer; `cmd/toolwarrant` ok in 82.774 s alone and
  144.206 s shared), and `scripts/gen-confusables.sh --check` prints
  `confusables_table.go is up to date`.

### D21 (d). The 10000-tool reload: measured first, then digests on the serving path and bytes hashed where bytes are handed out (verify-on-read, closes L16)

- Context. Every `Snapshot` re-hashed the canonical bytes of the approved
  version of every non-deprecated tool of the server (`recheckApproved`, in
  chunks of 256) unless the Store's verifier remembered the row from a check
  less than `RecheckTTL` (ten minutes) ago; that memory was the ten-minute
  window of L16 in which a rewrite of a verified row's bytes went unreported
  (D14 (a)). The two anchors, the newest `version.approved` or
  `version.rolled_back` entry about the tool and the newest state-bearing entry,
  were read back and re-hashed with `audit.HashOf` on every reload with no
  memory, so the floor of a reload was two small hashes per tool plus the policy
  query, which carried three correlated subqueries per row. The processor
  reloads on every generation bump, which every crawl and every decision makes,
  inside one hook under `loadMu` with `sourceTimeout` 10 s on the catalog reads
  and `maxConcurrentHooks` 32; hooks that arrive during a reload hold a slot
  while they wait on `loadMu` and the 33rd is denied as throttled, so a slow
  reload stalls every hook and a burst during it is partly refused. The upper
  bound that `RecheckTTL`'s comment, README L16 and the threat model's L16 row
  named, `MaxToolBytes` 256 KiB times `MaxToolsPerCrawl` 10000, about 2.5 GiB of
  canonical bytes, is not reachable: `MaxServerBytes` caps one server's
  canonical bytes across every version at 1 GiB, so the reachable worst case is
  1 GiB. The owner decided (O-8) option A, digests on the serving path and bytes
  hashed where bytes are handed out, with the guarantee rewording, after a
  measurement; the plan's contingency said that if the measurement showed the
  floor dominating, the floor batching would be folded in.
- Measurement (part 1, pull request #32, before any change).
  `BenchmarkSnapshot1000Approved`, `BenchmarkSnapshot10000Approved8KiB` and
  `BenchmarkSnapshot10000ApprovedAtCap` in
  `internal/catalog/recheck_bench_test.go`, each then with an "uncached"
  sub-benchmark (a verifier with no memory, so every reload re-hashed every
  approved version) and a "cached" one (one warm reload, then reloads within
  `RecheckTTL`); hashes/op counted the verifier's SHA-256 of canonical bytes
  only, not the two anchor hashes. A store was filled by successive complete
  crawls of disjoint slices, because `MaxCrawlBytes` forbids one crawl of 80 MiB
  or 2.5 GiB, under a policy with `DeprecateAfter` 0 so no slice was deprecated
  out of the snapshot; `benchFill` logs the split it chose. Host: darwin/arm64,
  Apple M4, go1.27.2, modernc.org/sqlite (pure Go) with SQLite's default page
  cache, WAL mode, the store on the internal SSD under the test's TempDir; every
  figure is read off the run logs. 1000 tools of 8 KiB (a raw definition of 8278
  bytes, 86 bytes of skeleton plus an 8192-byte description; one crawl; 35 MiB
  on disk): uncached 61.5, 63.0 and 64.9 ms/op over three runs of 19 iterations
  and 67.0 ms/op at `-benchtime 3x`, 1000 hashes/op, 37.57 MB/op, 319.2k
  allocs/op; cached 48.0, 49.9 and 51.1 ms/op and 55.8 ms/op at 3x, 0 hashes/op,
  17.87 MB/op, 310.6k allocs/op. 10000 tools of 8 KiB, the plan's fixed point
  (three complete crawls of 4053, 4053 and 1894 tools; 256 MiB on disk):
  uncached 652, 722 and 791 ms/op over three runs of 10 iterations, 663, 748 and
  752 ms/op over three runs of 20, 840 ms/op at 3x with `-v`, 10000 hashes/op in
  every run, 367.26 MB/op, 3.162M allocs/op; cached 548, 624 and 664 ms/op (10
  iterations), 575, 600 and 701 ms/op (20), 553 ms/op at 3x, 0 hashes/op, 171.10
  MB/op, 3.071M allocs/op. So a reload took 0.65 to 0.84 s with every byte
  re-hashed and 0.55 to 0.70 s within `RecheckTTL`; the byte re-hash was 50 to
  130 ms of it in the paired runs (98, 104, 127, 63 and 51 ms; the single 3x run
  is noisier at 287 ms); time and allocations scaled about linearly with tools
  (ten times the tools, 10.5 to 11 times the time; about 307 allocations and 17
  KB per tool at the floor); and the uncached reload allocated 196 MB more than
  the cached one for 82.8 MB of canonical bytes read, so each blob was copied
  about 2.4 times on its way to the hash. The CPU profile of the uncached 8 KiB
  reload (20 iterations, 11.83 s inside `Store.Snapshot`, 592 ms of CPU per
  reload against 748 ms of wall, the rest waiting on reads), cumulative inside
  `Snapshot`: `readPolicyRows` 5050 ms, 42.7 percent (252 ms per reload, of
  which 3940 ms is `pread` of SQLite pages under the three correlated
  subqueries); the two anchors (`verifyAnchors` 2060 ms plus `anchorStates` 2460
  ms) 4520 ms, 38.2 percent (226 ms per reload; `chainMemory.verify` 3550 ms,
  inside it `audit.HashOf` 3420 ms and `jcs.Transform` 2730 ms; `readEntries`
  1020 ms); `recheckApproved`, the byte re-hash, 2250 ms, 19.0 percent (112 ms
  per reload, of which 2140 ms is `pread` of the canonical blobs, and
  crypto/sha256 160 ms flat for the whole run, 8 ms per reload). Flat by
  package, of the 10410 ms attributed inside `Snapshot`: crypto/sha256 160 ms,
  1.5 percent; modernc.org/sqlite reads through `pread` 6970 ms, 67.0 percent
  (the blob reads under `recheckApproved` 2140 ms, 20.6 percent; the page reads
  of the policy query and of the entry reads 4830 ms, 46.4 percent);
  gowebpki/jcs plus encoding/json plus internal/audit and gate (the anchors'
  canonicalisation and hashing) 1400 ms, 13.4 percent; modernc.org/sqlite and
  libc VM, btree and pager code 780 ms, 7.5 percent; runtime 540 ms, 5.2
  percent; database/sql scanning 10 ms, 0.1 percent (`database/sql.Rows.Next` is
  7920 ms cumulative, but that is the SQLite step beneath it). The cached 8 KiB
  profile (20 iterations, 9.67 s inside `Snapshot`, 484 ms of CPU per reload
  against 575 ms of wall) had the same shape without `recheckApproved`:
  `readPolicyRows` 4980 ms, 51.5 percent; `chainMemory.verify` 3350 ms
  (`audit.HashOf` 3280, jcs 2750); flat `pread` 5920 ms, 67.4 percent; jcs 1030
  ms, 11.7 percent; runtime 810 ms, 9.2 percent; crypto/sha256 70 ms, 0.8
  percent. At the cap (`BenchmarkSnapshot10000ApprovedAtCap`,
  `TOOLWARRANT_BENCH_LARGE=1`, run twice with 45 GiB free): each raw definition
  exactly 262144 bytes, 79 complete crawls of at most 128 tools; the benchmark
  lifts only its own Store's per-server byte cap, as the cap tests lower theirs,
  because `MaxServerBytes` refuses the 33rd crawl of a real server, so the
  figure is the plan's paper bound with the per-server cap lifted and not a
  store a real catalog can hold; 5248 MiB on disk, not 2.5 GiB, because the raw
  definition is stored next to the canonical one. First run, five iterations
  each: uncached 15.78 s/op, 10000 hashes/op, 5.419 GB/op, 3.154M allocs/op;
  cached 0.825 s/op, 0 hashes/op, 169.0 MB/op, 3.064M allocs/op; 766 s for the
  whole benchmark including the fill. Second run, one iteration each with `-v`:
  uncached 13.44 s/op, cached 0.568 s/op, 534 s in all. Profile of the first run
  inside `Snapshot`: 23.05 s of CPU over the five uncached reloads, 4.6 s per
  reload against 15.8 s of wall, so two thirds of an at-cap reload waited on
  reads; flat, of 29530 ms: `pread` 23830 ms, 80.7 percent (`recheckApproved`
  24.05 s cumulative, of which `_vdbeColumnFromOverflow` 18.86 s, the overflow
  pages of the 256 KiB blobs); crypto/sha256 3060 ms, 10.4 percent, about 612 ms
  per uncached reload for 2.5 GiB; runtime 900 ms; sqlite and libc 760 ms;
  memmove and memclr of blob copies 410 ms; jcs 350 ms. The cached at-cap reload
  (0.57 to 0.83 s) was the same floor as at 8 KiB: within `RecheckTTL` the
  per-reload cost did not depend on definition size. Reading: at the plan's
  fixed point the byte re-hash did not dominate (at most a fifth of an uncached
  reload; crypto/sha256 itself 1.5 percent); four fifths was the floor every
  reload paid within `RecheckTTL`, the policy query with its three correlated
  subqueries (about 250 ms, 43 to 52 percent, almost all SQLite page reads) and
  the canonicalisation and hashing of the 20000 anchor entries (about 170 to 230
  ms, 29 to 38 percent, almost all jcs). So removing the byte re-hash from the
  reload saves about 0.1 s of a 0.7 s reload at 10000 tools of 8 KiB and leaves
  the stall under `loadMu` in place, which is what made the plan's contingency
  apply; the change earns its place at the tail: at the cap the re-hash was the
  whole cost (13 to 16 s uncached against 0.6 to 0.8 s cached), which exceeds
  `sourceTimeout` 10 s and would fail the reloading hook, and at the reachable 1
  GiB a linear extrapolation from the cap, not measured, gives 5.4 to 6.3 s per
  uncached reload on this SSD, under `sourceTimeout` with no margin for a slower
  disk. Corrections to the plan's estimates, recorded so they are not copied:
  the at-cap file is about 5 GiB on disk, not 2.5 GiB; the 2.5 GiB bound is
  unreachable and 1 GiB is the reachable one; 10000 is the plan's fixed
  measurement point and not the worst case for the floor, which scales with the
  non-deprecated approved tools that `MaxToolsPerCrawl` does not bound
  (`MaxToolsPerServer` is 50000, and rotation under `DeprecateAfter` 3 can hold
  about three crawls' worth in a snapshot).
- Decision (part 2, pull request #34): digests on the serving path, bytes hashed
  where bytes are handed out, and the floor batched. The processor never uses
  catalog bytes: it compares the digest of the live definition with
  `ToolPolicy.Approved`, a column the anchor of D14 (a) and D15 already binds to
  a verified audit entry. So `Snapshot`, `Tools` and `Tool` hand out digests and
  read no canonical bytes: their statements name no canonical or raw column, the
  approved digest is checked against the newest-decision rule (D13) and anchored
  to the verified chain (D15), and the state column to its newest entry (D17
  (c)), in one anchor pass per read (`anchorTools`: one `readEntries` pass over
  the entries both rules name, each distinct entry hashed once within that read
  and never across reads; both anchors of a tool are one entry while its
  approval is the newest lifecycle entry about it). Every path that reads the
  stored bytes behind a digest hashes them against that digest on every call,
  with no memory between calls: `Approved` and `ApprovedWithHead` (`export`,
  `emit`) and `Versions` (`show`, `diff`) through `gate.DigestOfCanonical`,
  `loadTool` (every decision) as before, `Integrity` as before; `export`, `show`
  and `diff` are the paths that hand those bytes out. `verifier.go`,
  `RecheckTTL`, `Store.verified` and the forensic bound wiring are deleted. The
  snapshot's policy query takes the seq of the newest decision entry and of the
  newest state-bearing entry about every tool of the server from one range read
  of the `audit_log_by_subject` index grouped by subject
  (`newestEntriesOfServer`, a covering SEARCH joined to the tool rows through an
  automatic index, both pinned by the plan test) in place of two correlated
  subqueries per row; the approvals' newest-decision rule stays a correlated
  subquery (folding it into a derived table measured slower). What is not done,
  as the plan required: no memory keyed by the stored hash column or any
  metadata column, no longer TTL, no hashing only when the generation moved. No
  schema change.
- Consequence. The guarantee reads: every path that reads the stored bytes
  behind a digest (`export`, `emit`, `show`, `diff`, every decision) hashes them
  against that digest on every call, with no memory between calls; `export`,
  `show` and `diff` are the paths that hand those bytes out; the serving path
  (the snapshot the processor serves from, and `list`) hands out digests alone,
  each anchored to a verified audit entry, and reads no bytes. The residual,
  stated plainly: a rewrite of an approved version's stored bytes with the
  digest column intact is invisible to `Snapshot` and `list`, cannot change what
  the gateway serves (the processor compares the live definition's digest with
  the anchored digest, never with the stored bytes), and is refused at once by
  `export`, `emit`, `show`, `diff` and every decision and named by `Integrity`
  (`checkApprovedBytes`), which `audit verify` runs. A rewritten digest column
  is caught by the snapshot at once, by the newest-decision rule alone or by the
  chain anchor when `hash_seen` was rewritten with it. The ten-minute window of
  D14 (a) is gone on both sides: a rewritten definition is refused on the next
  call of the Store that read it clean a moment ago, of a fresh Store and of a
  read-only Store. A reload is O(entries) with one or two small hashes per tool
  and zero definition bytes read, whatever the definitions' size, so L16 closes;
  its README one-liner and threat-model row cite this record and carry no
  figures. Measured on the same host under the load of other sessions, the
  before and after binaries run interleaved three times on the same 10000-tool 8
  KiB store (3 x 10 iterations): before 747, 638 and 851 ms per reload cold and
  528, 566 and 574 ms warm; after 272, 271 and 283 ms with 10000 hashes/op (one
  audit entry per tool), 95.2 MB/op against 367.3 cold and 171.1 warm, 1.668M
  allocs/op against 3.162M and 3.071M; the same benchmark on the tree rebased
  onto main measured 255, 292 and 283 ms (load average 2 to 5). Of the gain, the
  serving path without bytes and with the single anchor pass measured 377, 371
  and 415 ms, and the one-pass audit read brought it to 267, 348 and 282 ms
  (same store, successive windows); a derived table for the approvals'
  newest-decision rule on top measured 489, 462 and 313 ms and is not kept. The
  1000-tool reload measured 56.4, 28.5 and 29.9 ms (25.2, 26.9 and 25.4 ms on
  the rebased tree; 1000 hashes/op, 9.9 MB/op) against 61.5 to 67.0 ms cold and
  48.0 to 55.8 ms warm in part 1. The at-cap benchmark keeps its name and
  definition and was not re-run after the change: a reload no longer reads the
  bytes, so their size cannot enter the reload cost, and the before figures
  above stand as the record of what the change removed. The hashes/op the
  benchmarks report count the anchor pass alone: the pin check and the suffix
  walk hash through `audit.HashOf` and `audit.VerifyFrom` and do not grow with
  the tool count. Two items the profile points at are tracked under Phase 6 of
  the plan, not done: a `cache_size` or `mmap_size` measurement on the catalog's
  read pool, and a one-join rewrite of the remaining floor. D14 (a)'s
  verifier-memory text stays as history with a cross-reference here; the
  post-review line of seam/RESULTS.md that says every read path re-hashes the
  approved bytes it hands out is historical, seam/ is not edited by this round,
  and a dated correction there is the owner's.
- Where. `internal/catalog/snapshot.go` (`Snapshot`, `snapshotQuery`,
  `newestEntriesOfServer`, `snapshotTools`), `views.go` (`Tools`, `Tool`,
  `Versions`, `scanVersionView`), `approved.go` (`Approved`, `ApprovedWithHead`,
  `readApprovedAnchored`, `scanApproved`), `anchor.go` (`anchorTools`,
  `anchorSeqs`, `readAllEntries`, `entryChecker`, `anchorApproved` as a wrapper,
  `anchorKnownTools`), `stateanchor.go` (`knownStateRefs`, `anchorStates` as a
  wrapper), `chain.go` (`hashCount`, `chainMemory.hashed`), `recheck.go`
  (`wireStore`, `approvedRef`, `checkApprovedProfile`), `recheck_bench_test.go`
  (the three benchmarks and `benchFill`), `store.go`, `catalog.go` and
  `schema.go` comments; `verifier.go` deleted; [operations.md](operations.md)
  ("What the catalog checks before it trusts the file"); CHANGELOG.md;
  SECURITY.md (the finding scope), [threat-model.md](threat-model.md) (the
  catalog bullet, row 21 and its note, L16), README.md L16, CLAUDE.md (the
  catalog line) and the cross-reference in D14 (a) through this record.
- Tests and proof.
  `TestSnapshot_ReadsNoCanonicalBytesAndStillServesTheAnchoredDigest` (the three
  statements name no byte column; after a bytes-only rewrite `Snapshot`, `Tools`
  and `Tool` serve the unchanged anchored digest on the same and on a fresh
  Store, the reload hashed two entries for two tools, `Approved` and `Versions`
  are `ErrCorrupt` mentioning `does not hash to its`, `Disable` is `ErrCorrupt`,
  `Integrity` names the row), `TestApproved_TamperedBytesAreCaughtAtOnce`
  (`Approved` and `Versions` clean, bytes rewritten, `ErrCorrupt` at once on the
  same Store, a fresh Store and a read-only Store, `Disable` `ErrCorrupt`,
  `Versions` of the untouched tool still answering, the repaired row clean at
  once), `TestVersions_TamperedBytesAreCaughtAtOnce` (a superseded and an
  approved version each rewritten and repaired; `Versions` `ErrCorrupt` naming
  the version number on the writer and on a read-only reader, `Tool` still
  answering with the anchored digest),
  `TestSnapshot_AChangedDigestColumnIsCaughtByTheAnchor` (the digest alone:
  `newest approval decision`; the digest and `hash_seen` under re-created
  guards: `is not the one its newest approval entry`, on `Snapshot`, `Tools` and
  `Tool`, and `ErrCorrupt` on `Approved` and `Versions`),
  `TestSnapshot_AnchorsTheDigestAndApprovedCatchesTamperedBytes` (in place of
  the test the documents cited before, which re-checked the digest on the
  snapshot: the consistent digest and `hash_seen` forgery `ErrCorrupt` naming
  the anchor, the bytes-only rewrite served by `Snapshot` and refused by
  `Approved`, the dropped guard named on every load),
  `TestBenchmarkSnapshotHashesOnlyAuditEntries` (8 tools: 8 hashes per reload
  after approval, 16 after an empty complete crawl writes a `tool.missing` entry
  per tool, and `testing.Benchmark` over `benchSnapshot` reports hashes/op 16
  with one tool's bytes rewritten),
  `TestAnchorQueries_StayOnTheAuditLogBySubjectIndex` (`snapshotQuery`'s log
  access is `SEARCH l USING COVERING INDEX audit_log_by_subject (subject>? AND
  subject<?)` and its join is `SEARCH n USING AUTOMATIC COVERING INDEX
  (subject=?)` with no `SCAN n`),
  `TestApprovedWithHead_HeadAndToolsComeFromOneSnapshot` and
  `TestAuditHead_IsTheVerifiedHeadAndMovesWithTheLog` ((e) unchanged by the
  one-pass anchor); the full `internal/catalog` suite under `-race` without
  `-short`, ok in 288.7 s on the rebased tree; `make e2e` against agentgateway
  v1.6.0, `TestEndToEnd` PASS in 35.4 s with scenarios A to R;
  `BenchmarkSnapshot10000Approved8KiB` and `BenchmarkSnapshot1000Approved` as
  quoted above. The tests that pinned the ten-minute memory, the verifier tests
  and the recheck tests of `internal/catalog`, are deleted or renamed with it.

### D21 (e). The export is signed and names the log it mirrors: manifest version 3, `export --sign-key`, `export verify`, and the approvals and the head read from one snapshot

- Context. Since D14 the documents named three anchors against the one boundary
  the chain cannot close, an entry appended or a suffix rewritten by whoever can
  write the 0600 file while no `Store` holds a pin: the head the operator
  records after `audit verify`, the git export of approved definitions and
  backups. The export was a write-only mirror with a crash-safe manifest
  (version 2: the files, their digests, approvers and times), and nothing tied
  it to a head: the plan called the recorded head and the export two unlinked
  anchors, so an export could be re-made from a rewritten log and nothing in it
  said which log it mirrored, and nothing authenticated the export directory
  against whoever could write it or its repository. The owner decided (section
  10 of the plan, as recommended): sign the manifest with an Ed25519 key read
  from a file, bind it to the audit head, keep per-person signing of approval
  records for L13, and keep the narrower digest profile and component hashes out
  of this round (O-6, (f) below). The first review of the pull request found
  that the export read the head in a second read transaction after `Approved`,
  so a commit between the two (the scheduled crawl appends every minute and can
  deprecate a tool out of `Approved`'s state filter after
  `Policy.DeprecateAfter` absences; another operator can approve or revoke) made
  `MANIFEST.json` name a head whose approval set was not the one the files
  mirrored, and that the head was read after `checkFile` had released the walk
  lock, so a walk by another handle of the same `Store` could advance it past
  the snapshot that read had verified; both are fixed here.
- Decision (1): the manifest is version 3 and the export reads its two inputs
  from one snapshot. `MANIFEST.json` records, between `status` and `tools`,
  `audit_head` (64 lower-case hex digits: the hash of the newest audit entry as
  the catalog's own walk computed it from the entry's fields, `audit.Genesis`
  for an empty log) and `digest_profile` (`gate.DigestProfile`, `full-v1`). The
  decision is `Store.ApprovedWithHead`, one read transaction for the approvals
  and the head: its first statement, the chain walk to the head and the read of
  the pin all happen under one hold of the walk lock (`checkFilePinned`, which
  `checkFile` now wraps), followed by the approvals and every anchor from the
  same snapshot; `Approved` is `ApprovedWithHead` without the head, and
  `Store.AuditHead`, which returns the head alone under the same lock, is not
  offered to the export as a path of its own. A commit made while the export
  runs therefore lands in both the head and the files or in neither.
  `parseManifest` reads version 2 and version 3 each only in its own shape, so
  an export directory from v0.2 is still cleaned up rather than left behind, and
  `Write` refuses options the manifest cannot carry.
- Decision (2): the signature. `export --sign-key PATH` reads an Ed25519 private
  key from that path only: a regular file whose mode gives group and others
  nothing (0600 or stricter), checked by `Lstat` before the open and again on
  the opened file, opened with `O_NOFOLLOW|O_NONBLOCK` so no link is followed
  and no pipe waited on, at most `export.MaxKeyFileBytes` (8 KiB), holding
  exactly one PEM `PRIVATE KEY` block whose PKCS#8 content is an Ed25519 key
  (`crypto/x509.ParsePKCS8PrivateKey`); a symbolic link, a directory, a missing
  file, a shared mode, a second PEM block, a `PUBLIC KEY` block, an ECDSA key or
  a garbage block is refused with exit 1 before the catalog is opened and before
  the export directory exists. The key is never taken from the environment or a
  flag value, never printed or logged (the CLI tests assert no PEM header and no
  seed in any output), and every buffer it passed through is cleared, the parsed
  key when the command ends. The export writes `MANIFEST.json.pub` (the public
  key as PKIX PEM) and then `MANIFEST.json.sig` (base64 of the Ed25519 signature
  over the exact bytes of the complete manifest, one line), each only when its
  bytes differ, the signature last so a crash never leaves a verifying signature
  without its key; the manifest's digests cover every tool file, so one
  signature binds the whole export to the head. An export without `--sign-key`
  after a signed one leaves the stale `.sig` and `.pub` in place, and `export
  verify` and `Commit` refuse the pair (`MANIFEST.json.sig does not sign the
  current MANIFEST.json`) until the next signed export or until both files are
  removed; `Commit` stages the pair only when the signature verifies over the
  current manifest under the recorded key, refusing one file without the other
  or a stale pair; git's own commit signing stays off (D13's
  `commit.gpgsign=false`), the manifest signature is the export's signature.
- Decision (3): the verifier. `export verify --dir DIR --pub-key FILE
  [--expect-head HEX]` opens no database. It fails closed, exit 1 naming what
  was found, unless: `MANIFEST.json` is a complete manifest this version reads;
  `MANIFEST.json.pub` records exactly the key in FILE (a directory signed by
  another key is refused before its signature is tried); `MANIFEST.json.sig` is
  that key's signature over the manifest's bytes; every listed file's bytes,
  less the trailing newline, hash to its digest; the entries on disk are exactly
  the listed files, their server directories, the manifest and its two signature
  files (an extra, missing, renamed or nested entry, a symlink, a pending
  manifest and a foreign manifest each fail; a top-level `.git` is the
  repository `--commit` keeps and is skipped); and, with `--expect-head`, the
  manifest records that head. The `--pub-key` file is read under the CLI's
  regular-file rules and the export package's own bound for a PEM key file
  (`export.MaxKeyFileBytes`), the bound it applies to `MANIFEST.json.pub`, and
  the size refusal names a PEM public key file, not an emitted file. Names from
  the directory and the manifest are quoted with `strconv.Quote`, paths escaped
  with `textdiff.Escape`, and the head and profile are validated against
  `[0-9a-f]{64}` and `[a-z0-9-]+` before they are printed.
- Consequence. The recorded head and the export now name each other: an export
  that verifies under the operator's key and records the head the operator
  recorded mirrors the log as it stood at that head, so a rewrite made while no
  store held a pin has to pass two anchors that agree instead of two that did
  not. Every crawl and every decision moves the head, so an export after the log
  grew rewrites the manifest and its signature with no tool file touched, and
  `--commit` records that as a commit; `export` prints the head and the profile,
  and `export verify` prints them back or says that a version 2 manifest records
  none. A head recorded beside an export is the head of exactly the approvals
  the export carries, under a concurrent crawl or decision as well. The
  hardening checklist of SECURITY.md gains `export verify --dir DIR --pub-key
  FILE --expect-head HEAD` as a routine step beside `audit verify
  --expect-head`. What (e) does not do: the signature authenticates the export
  against whoever can write the export directory or its repository and binds it
  to a head; it does not authenticate the person who approved (L13: per-person
  keys and signed approval records wait for that round; the L13 row says so, and
  the threat model gains no row for the export directory's writer), the entries
  inside the catalog are not signed, and the digest profile stays `full-v1`
  (O-6). A head in a manifest proves nothing by itself: the operator must still
  record the head outside the database and keep the public key outside the
  export, because the copy inside the directory only says which key signed;
  [operations.md](operations.md) carries that rule and the quickstart gains no
  reminder.
- Where. `internal/catalog/chain.go` (`checkFilePinned`),
  `internal/catalog/approved.go` (`ApprovedWithHead`, `readApprovedAnchored`),
  `internal/catalog/audithead.go` (`AuditHead`, `headOf`);
  `internal/export/manifest.go` (version 3, `parseManifest` for versions 2 and
  3), `internal/export/sign.go` (`ReadSigningKey`, `ParsePublicKey`,
  `MaxKeyFileBytes`, `signManifest`, `signatureFiles`),
  `internal/export/verify.go` (`Verify`, `VerifyReport`),
  `internal/export/export.go` (`Options`, `Report`), `internal/export/guard.go`;
  `cmd/toolwarrant/export.go` (`--sign-key`, `exportInputs`),
  `cmd/toolwarrant/exportverify.go` (`export verify`),
  `cmd/toolwarrant/paths.go` (`readRegularFile` with the kind of file it reads),
  `cmd/toolwarrant/main.go`; CHANGELOG.md (two Added lines, one Changed line);
  [operations.md](operations.md) ("Exporting the approved definitions and
  verifying an export", "The recorded head, the export and backups");
  SECURITY.md (the Scope boundary, the finding scope, the checklist), README.md
  (the trust model and the one rule), [threat-model.md](threat-model.md) (the
  boundary in the catalog bullet, row 21 and its note, L13, the L19 note) and
  CLAUDE.md (the catalog and export bullets) through this record.
- Tests and proof. catalog: `TestAuditHead_IsTheVerifiedHeadAndMovesWithTheLog`
  (the genesis on an empty log, equal to `VerifyAudit`'s head and to the pin
  after every decision, agreeing between a long-lived and a fresh read-only
  Store, moving with a crawl, `ErrReplaced` on a replaced file),
  `TestApprovedWithHead_HeadAndToolsComeFromOneSnapshot` (two readers, one on
  the writer's Store and one on a read-only Store of the same file, against a
  writer toggling the only approved tool for two seconds and recording the head
  of every commit: every result pairs the approvals with that commit's head; on
  the tree before this decision the two-call read paired 76 of 208 results with
  another commit's head, and one transaction with the pin read after the lock
  paired 5 of 239; five runs under `-race` showed none, at 66 writes and 315
  reads, then 63/295, 63/306, 65/311, 41/193 and 60/290 writes and reads).
  export: `TestWrite_ManifestRecordsTheAuditHeadAndProfile`,
  `TestWrite_RefusesOptionsTheManifestCannotCarry`,
  `TestParseManifest_ReadsVersionTwoAndThreeInTheirOwnShapes`,
  `TestWrite_CleansUpAfterAVersionTwoManifest`,
  `TestReadSigningKey_RefusesEveryUnsafeShape` (mode 0644, symlink, directory,
  not PKCS#8, not Ed25519, two blocks, oversized),
  `TestWrite_SignsTheManifestAndASecondWriteTouchesNothing`,
  `TestWrite_WithoutAKeyLeavesTheSignatureFilesAloneAndVerifyRefusesThem`,
  `TestCommit_StagesTheSignatureFilesAndRefusesAStalePair`,
  `TestVerify_RoundTripsASignedExport`, `TestVerify_FailsClosedOnEveryTamper` (a
  flipped byte, a missing file, an extra file, a renamed file, a nested
  directory, a symlink, a wrong key, a stale signature, a pending manifest, a
  wrong expected head), `TestVerify_ReadsAVersionTwoManifestWithoutAHead`,
  `TestVerify_RefusesAKeyOfTheWrongSize`. cmd:
  `TestExportSignsTheManifestAndVerifyRoundTrips` (export, the same head from
  `audit verify`, verify with and without `--expect-head`, exit 1 for a changed
  byte, a removed file, an extra file, another key and the head from before a
  crawl, the re-export printing `0 written, 0 removed, 1 unchanged` with a new
  head, `--commit` tracking the pair and refusing a stale one),
  `TestExportRefusesAnUnsafeSigningKeyBeforeTouchingAnything` (every refusal
  with exit 1, the flag and the path named, no PEM header or seed in the output,
  the export directory not created), `TestExportVerifyUsageHelpAndRefusals`
  (usage exit 2, the help text, garbage, a private key, a directory, an
  oversized file past `export.MaxKeyFileBytes` refused as a PEM public key file,
  a directory that is not an export). Each test fails on the code before this
  decision: the new test files do not compile against it (`Options`,
  `AuditHead`, `ApprovedWithHead`, `manifestFile` undefined), `export
  --sign-key` and `export verify --pub-key` exit 2 with `flag provided but not
  defined`, a plain export wrote `"version": 2`, and the oversized key was read
  under a 1 MiB bound and reported the directory instead. An `openssl genpkey
  -algorithm ed25519` key run through the built binary exported, verified with
  exit 0, and was refused at mode 0644 with exit 1. Suites on 2026-10-14: the
  full catalog suite under `-race` 288.304 s (357 s in the earlier run),
  `cmd/toolwarrant` 79.409 s, `internal/export` 9.419 s.

### D21 (f). What v0.3 leaves out: the narrower digest profile and component hashes, and what is tracked instead

- Context. The catalog design kept two items from the research that would change
  what a digest covers or what the catalog stores about it: a narrower digest
  profile (`core-v1`, chosen per server with `server add --digest-profile
  core-v1` and a `servers.digest_profile` column) that would leave members such
  as `_meta` out of the digest, and stored component hashes
  (`tool_versions.components`, bound into the chain by a `components=` detail
  token) that would let the processor say which component of a definition
  mismatched. Either one needs the first released schema bump: v7, a guard DDL
  change and the chain binding, with an in-place migration in `migrate`
  rebuilding the table and a release note saying that a v6 file is migrated in
  place. The owner decided on 2026-10-14 (O-6): neither in v0.3.
- Decision. The digest profile stays `full-v1` and the schema stays v6.
  `core-v1` is not offered because it reopens the hole D1 closed, unapproved
  `_meta` riding on an approved tool while agentgateway acts on `_meta.ui`; it
  weakens the gate per server through a knob; and MCP #2743 is open, so a
  profile fixed now risks two realignments. Component hashes are not stored
  because what they buy, a processor-side "which component mismatched" line, is
  not worth the first released schema bump and the chain binding it needs. The
  cheap substitute the plan names in their place, logging the live digest (64
  hex digits, safe to print) on the processor's `digest mismatch` line so that
  the operator can `show` and `diff` it against the version the crawl records as
  pending, is not implemented in v0.3 either. It is tracked under Phase 6 of the
  plan together with the mixed-script rule for `internal/toolname` (c), the
  `cache_size` or `mmap_size` measurement on the catalog's read pool and the
  one-join rewrite of the remaining reload floor (d), the at-cap after-figure of
  (d), the dated correction of the historical serving-path line in
  seam/RESULTS.md (d), and immutable releases (O-5, D20 (b); not enabled when
  v0.2.0 was published and still not enabled).
- Consequence. L2 and L9 stand as written: a tool with a key the gateway drops
  or with a volatile `_meta` member cannot stay approved, and the remedy stays
  with the upstream (D10). The `digest mismatch` log line still carries the
  server, the count and the quoted names, not the live digest, so an operator
  who sees it runs a crawl and reads `show` for the pending version. A later
  decision that takes `core-v1` or component hashes takes the schema bump with
  it; the design text for both is kept in the research folder, not in this
  repository.
- Where. Nothing in code changed for (f); the plan (section 8, "Not in v0.3",
  and section 9, Phase 6) and this record.
- Tests and proof. The tests that pin what stands: gate
  `TestDigestProfile_IsFullV1WithNoExclusions` and
  `TestDigest_MetaIsPartOfTheDigest` (D1); catalog
  `TestOpen_RefusesOtherSchemaVersions` (schema v6 is the only version a `Store`
  opens; note of 2026-10-15: since D22 (g) a `Store` also opens a v6 file by
  migrating it in place, and the test now pins that 6 migrates and every other
  version is refused).
- Note (2026-10-15). The cheap substitute landed, with no schema change: the
  processor writes one `digest mismatch` line per mismatched tool (the first
  ten of a page, in page order, the cap every list of names in its log has)
  with the quoted `tool` name, the `approved` digest and the `live` digest the
  served definition hashes to, 64 hex digits each and never a byte of the
  definition, and the `tools/list filtered` line gained a `mismatched` count
  next to the other hidden categories, so the count survives the cap. The
  field names are the `approved:` and `live:` rows of `show`; the live digest
  is what `diff SERVER TOOL --to LIVE` takes once a crawl has recorded that
  definition as pending, and a live digest no crawl records is the gateway's
  re-serialisation (L2) or an upstream serving the crawler another definition
  than the gateway (L4), since the crawler reads the upstream itself. The log
  of `TestFilter_DigestMismatchLogsTheLiveDigest` shows `level=INFO
  msg="digest mismatch" server=mock tool="\"echo\""
  approved=e1d84112f0966155af725d179db9a8490e5692e1b80313684019e76608fae3c2
  live=d32af4fc4f1eedfc912ce8406690b85a115fce218e1d593cd922593ef5375afb` for
  the approved and the changed `echo`, the changed description absent from the
  log, and for thirteen mismatched tools ten lines and `mismatched=13`; on the
  code before this note the test fails on the missing `live=` field and on
  the one line for the thirteen tools. `internal/processor/filter.go`,
  `internal/processor/list.go`. The rest of the Phase 6 list stands as tracked.

## D22. v0.4: signed per-person decisions and the operator trust list (closes L13 with a stated residual)

- Context. D14, D15 and D17 fixed the trust boundary of the catalog file:
  whoever can write the 0600 file can append a correctly sealed audit entry, so
  an approval was attributed by the chain to whatever `--as NAME` said, and
  L13 asked for a decision provable as one person's. The research report of
  2026-10-15 (twelve findings, each verified three to zero) ranked the
  primitives and fixed the rules for whatever is signed; two design proposals
  were merged into the plan of 2026-10-15, and the owner decided its open
  questions O-9 to O-18 the same day, every one as recommended: sshsig through
  ssh-agent (O-9), no new head anchor in v0.4 and the head log first in v0.5
  (O-10), a signed versioned trust list in the chain (O-11), an in-place v7
  migration with the bootstrap attesting the legacy history (O-12), `--as` as
  a label that must match the key (O-13), threshold 1 only (O-14), suffix-only
  verification at reload (O-15), all eight human decisions signed (O-16), the
  signature before the transaction with the compare-and-set inside it (O-17),
  ssh-agent first and a key file second (O-18). The round landed on
  2026-10-15 and 2026-10-16 as pull requests #46 (7.2, schema v7), #47 (7.1,
  `internal/signing`), #48 (7.3, `internal/trust`), #49 (7.4, the trust list
  in the chain), #50 (7.5, signed decisions through `Decide`, three
  adversarial review rounds), #51 (the quoting follow-up of the walk's
  sentences) and #52 (7.6, the CLI, two review rounds), under the document
  ownership rule of D21: each feature pull request owned its code, its tests,
  its [operations.md](operations.md) region and its CHANGELOG.md line, and
  this record, the known limits and the guarantee sentences of README.md,
  SECURITY.md and [threat-model.md](threat-model.md) were written once,
  afterwards, from the decision texts the pull requests handed over and the
  decisions the orchestrator took between them. Each sub-decision below
  carries its own context, decision, consequence, where and proof. In
  [threat-model.md](threat-model.md) this round rewrote the operators bullet
  of the actors list and added the key, the agent socket and the trust root
  to it, extended the catalog bullet, row 21 and its note, added row 27 and
  its note, closed L13 with its residual and added L20; SECURITY.md gained
  the fifth line of its Scope, a checklist item and the supported-versions
  rows for 0.4.x; README.md the trust-model paragraph, the `trust init` and
  `--ssh-key` steps of the quickstart, the L13 and L20 one-liners and the
  schema sentence.
- What a verified signature proves, in one paragraph. It proves that whoever
  controlled the private half of a key named for operator X in the trust list
  in force at that seq produced exactly this decision for exactly this catalog
  on top of exactly this head. It does not prove X was present: an unlocked
  agent or a stolen unencrypted key file signs too, and a FIDO2 key with touch
  narrows it to physical presence. Authorisation is a second check, separate
  from validity (research finding 6): the embedded key must resolve to a name
  in the list in force, and that name must be the entry's actor and the
  payload's actor; a valid signature from a key the list does not name is
  `ErrCorrupt`, never a warning. What the whole round proves, in one sentence:
  every approval the gate serves after the cut-over was made by a person who
  held a key the trust list named for them at the time, over a history they
  had seen up to that head, and nothing appended without such a key can
  approve, enable, resume or re-enable anything, whatever the writer can
  write.
- The residual, stated plainly and carried into every document. (1) Rollback
  by truncation: whoever can write the file while no `Store` holds a pin can
  cut the chain back to an earlier signed state and rewrite the mutable tables
  to match, dropping a later disable, reject, rollback or approval; they
  cannot add a decision. The controls are the head printed after every signed
  decision (every signed record is itself a signed head, finding 11), `audit
  verify --expect-head`, `--expect-head` on every decision as the operator's
  compare-and-set (finding 12), `--trust-root`, the signed export (D21 (e))
  and backups; the head log that lets the processor detect a rollback at
  reload is O-10 and the first v0.5 item. (2) Threshold 1: one compromised
  key approves and can evict the other signer of a two-person list (TUF's
  rule with threshold 1 allows it); threshold 2 is the fix and waits. (3) An
  unlocked agent or a readable key file on a compromised workstation signs.
  (4) Removal is not retroactive: decisions a key signed before its removal
  stand and must be undone by hand. (5) Crawls, `server add` and `emit`'s
  `server.processor_set` are unsigned (L20): a crawl run as `--as alice` by
  someone else makes alice a proposer and blocks her approval of that digest;
  neither can put an unapproved digest on the wire. (6) A catalog never
  bootstrapped serves as v0.3 did, with a warning on every `serve` start and
  every decision; `serve --trust-root` turns that into a refusal, and v0.5 is
  where the default flips (O-12). (7) A lost key: enrol a second key at init
  and keep it offline; without one there is no in-file recovery, the path is
  the existing re-initialisation (fresh `init`, re-register, re-approve from
  the export).
- Deferred beyond v0.4, with the reason (the plan's section 5, extended by
  the decisions taken between the pull requests). The head log (`--head-log`,
  `audit record-head`, `audit verify --head-log`, `serve --head-log`, scenario
  T): O-10; its value needs an off-host copy the operator already has to keep
  for the recorded head, and its processor check adds a file read on the hook
  path; the `toolwarrant/head/v1` payload type and the
  `head@toolwarrant.invalid` namespace are reserved in `internal/signing` so
  the records of v0.4 need no change. Thresholds above 1, the `trust
  canon|sign|set` multi-step flow, a `signed_signatures` table and
  propose-and-countersign decisions: O-14; a second UX, a lifecycle state the
  gate does not know, a second schema object. Per-operator permitted decision
  kinds and per-server or per-tool scopes: at threshold 1 every listed key
  signs everything, and the payload type is versioned (`trust-list/v1`) so a
  v2 can add them. Sigstore keyless: finding 5, needs live network and a
  public log. Secure Enclave and third-party agents: whatever an agent exposes
  over the ssh-agent protocol works today. A witness service: once the head
  log exists. Signing crawls, `server add` and `emit`'s `server.processor_set`
  (L20): a scheduled crawl or re-emit would need a key; v0.5 with the head
  log. `audit show-signature SEQ --out DIR`: `audit list --json` and the
  `ssh-keygen -Y verify` recipe of [operations.md](operations.md) do it.
  Signer fingerprints in the export manifest (manifest v4): reachable through
  `audit list --json` on the catalog. Moving the export manifest's Ed25519
  signature (D21 (e)) onto sshsig: a second signing story for the export's
  operators, revisited after the list has run for a release. Approval expiry
  and break-glass re-bootstrap after a lost key: not evidenced by the
  research; the two-key rule and re-initialisation are the recovery. Refusing
  a never-bootstrapped catalog by default (O-12 (c)): v0.5, after the owner has
  run the cut-over. Rule 6 and the continuity rule applied to history before
  the bootstrap: they would refuse any legacy file whose history an older
  lifecycle wrote differently (the legacy residual of (f)). Added between the
  pull requests: verifying the signed pages of the open-time walk in parallel
  goroutines, so that a 10000-decision catalog opens in less than the 1.5 s
  measured in (e) (orchestrator decision 10: the sigref specification of (c)
  was not changed to cheapen it); comparing `before_hash` across a decision
  transaction's entries, a tightening of the shape rule of (d) that nothing
  needs today (decision 17); and the repository-wide "escape once" pass over
  the CLI's older refusal sites that pre-escape a value `describe()` escapes
  again (`paths.go`, `export.go`, `exportverify.go`, `servetls.go`,
  `emitout.go`, `emitvalidate.go`, `emitports.go`, `global.go`,
  `liveconfig.go`, `audit.go`, and `livetls.go`, which the review of the pass
  found behind `cell()`; decision 34; done on 2026-10-16, right after
  the release: those sites now embed the value as given and `describe()`
  escapes the sentence once, which `TestRefusalsEscapeHostileValuesOnce` pins
  as one `\u{001B}` per hostile value).

### D22 (a). Decisions are signed with OpenSSH `sshsig` records under toolwarrant's own namespaces, over the exact bytes of a typed payload, with a key that passes toolwarrant's policy and lives in ssh-agent or in an unencrypted OpenSSH key file

- Context. The research report fixed four rules for whatever is signed: a
  dedicated namespace so a git or export signature can never be replayed as a
  decision (finding 2); the exact bytes signed, stored and verified before any
  parse, never a re-canonicalisation (finding 7); an authenticated type inside
  the signed bytes so two payload kinds cannot be confused (finding 8); and
  the library's gaps named, since github.com/hiddeco/sshsig does not refuse
  ssh-dss or small RSA and its `Verify` accepts an empty expected namespace
  (findings 2 and 3). The owner decided O-9 and O-18 on 2026-10-15. The
  pull request is #47 (PR 7.1).
- Decision (1): the primitive and where it lives. `internal/signing` is the
  one package that touches the envelope. `Sign(ctx, payload, key, namespace)`
  returns a `Record{Payload, Signature, Signer}`: the bytes as given, the
  sshsig wire blob, and the `SHA256:` fingerprint of the key.
  `Verify(payload, sig, namespace, signer)` checks, in a fixed order, the
  bounds (`MaxPayloadBytes` 64 KiB, `MaxSignatureBytes` 4 KiB), the blob's
  shape, which includes being the canonical encoding of the signature it
  parses to (the library's `Signature` type drops the wire `reserved` string
  unchecked, so a blob with it set verifies under the library and has a
  `RecordDigest` of its own; here it is `ErrSignatureFormat`, so one signature
  has one byte form), the key policy on the embedded key, the embedded key's
  fingerprint against the one the record names (`ErrNotTheExpectedKey`, before
  any cryptography), the message hash (sha512, OpenSSH's default; a sha256
  signature is refused by name), for an ssh-rsa key the inner signature
  algorithm (rsa-sha2-512; the library's `Verify` accepts an rsa-sha2-256 blob
  and it is refused here by name, `ErrSignatureAlgorithm`), the namespace,
  and then the signature. `Sign` verifies its own output under the signer's
  public key before returning it, so a faulty or hostile agent cannot make the
  CLI store a signature that does not verify (`ErrSignerOutput`, nothing
  returned). `RecordDigest(Record)` is the `sigref` token an audit entry
  carries: the lower-case hex SHA-256 of the RFC 8785 form of
  `{"payload":<base64>,"signature":<base64>,"signer":"SHA256:..."}`. `Armor`
  and `Unarmor` move a blob to and from the `-----BEGIN SSH SIGNATURE-----`
  block `ssh-keygen` reads and writes; `Unarmor` requires that line at the
  first byte, as `ssh-keygen`'s dearmor does, and refuses headers, a second
  block and trailing text. The pre-1.0, single-maintainer risk of the library
  is carried by the pin, by the two-way interop tests against the system
  `ssh-keygen` in CI, and by this package being the only importer, so an
  in-house envelope over x/crypto/ssh could replace it without touching a
  caller.
- Decision (2): the namespaces and the types. `Namespace` is a string type
  whose only accepted values are the constants `NamespaceDecision`
  (`decision@toolwarrant.invalid`), `NamespaceTrust`
  (`trust@toolwarrant.invalid`) and the reserved `NamespaceHead`
  (`head@toolwarrant.invalid`, written by nothing in v0.4 and reserved with
  `TypeHead` so the head log of v0.5 needs no format change); `Sign` and
  `Verify` refuse any other value, so no caller string, and in particular no
  empty expected namespace, reaches the library. Every payload carries its
  `type` inside the signed bytes, `TypeDecision` (`toolwarrant/decision/v1`)
  or `TypeTrustList` (`toolwarrant/trust-list/v1`), and each parser reads
  `type` first and refuses another (`ErrType`), so a trust list signed under
  the decision namespace verifies as bytes and is refused as a decision, and
  the reverse.
- Decision (3): the payloads are bytes, made once. `MarshalDecision` and
  `MarshalTrustList` produce the RFC 8785 form through `gate.Canonical` and
  validate every field first; the catalog stores those bytes verbatim and
  never rebuilds them from columns. `ParseDecision` and `ParseTrustList` run
  only on bytes whose signature verified and accept exactly what the marshal
  wrote: the bytes equal their own canonicalisation, valid UTF-8, no duplicate
  key, exactly the key set (ten for a decision, eight for a list, two for each
  signer), string values within their caps (actor as D7, server as
  `validateServerName`, tool as `toolname.Validate`, catalog 32 hex, heads and
  digests 64 hex, `signed_at` RFC 3339 UTC to the second with a `Z`, `signer`
  a `SHA256:` fingerprint), integers canonical and bounded, one to
  `MaxSigners` (64) signers each with a canonical key line. A decision's
  `kind` is one of the eight (approve, reject, rollback, disable, enable,
  pause, resume, budget_reset); `digest` is present exactly for approve,
  reject and rollback, `tool` is empty exactly for pause and resume, so there
  is one shape per kind and every field is always present. `signed_at` is
  informational, the signer's clock; `prev_head` is the freshness token.
- Decision (4): the key policy. `CheckKeyPolicy` accepts `ssh-ed25519`,
  `sk-ssh-ed25519@openssh.com`, `ecdsa-sha2-nistp256`, `-384`, `-521`,
  `sk-ecdsa-sha2-nistp256@openssh.com` and `ssh-rsa` with a modulus of at
  least `MinRSABits` (3072), and refuses `ssh-dss`, smaller RSA, certificates
  and any other type. It runs before signing, before verifying (on the
  embedded key), on a key asked of the agent and on a key read from a file;
  `internal/trust` applies it to every key a list names. A key is stored and
  shown as one `authorized_keys` line, `type base64`, no comment, no options
  (`MarshalKey`), and `ParseAuthorizedKey` accepts only that spelling, strict
  base64 included. Identity is the `SHA256:` fingerprint `ssh-keygen -l`
  prints (`Fingerprint`); FIDO2 keys are recognised by their `sk-` prefix
  (`NeedsTouch`) so the CLI can say a touch is coming.
- Decision (5): the key handling rules. ssh-agent: `OpenAgent(ctx, sock)`
  takes the value of `SSH_AUTH_SOCK` (the package reads no environment) and
  refuses it unless it is shorter than `MaxSocketPathBytes` (104, darwin's
  `sun_path`), a unix socket by `Lstat` (no link followed), owned by this
  uid, and either with no group or other bits (OpenSSH's `ssh-agent` makes it
  0600) or inside a directory of this uid with no group or other bits
  (launchd's agent on macOS makes a 0666 socket in a 0700 directory, the
  release platform's default agent, which the plan's literal rule would have
  refused; the implementer's deviation, pinned both ways). The dial and the
  key list are bounded by `AgentTimeout` (5 s) and by the context; a `Sign`
  through the agent is bounded by the caller's context alone (the CLI's
  `--sign-timeout`); the agent is asked to sign with the one key the operator
  named, and a missing key is `ssh-agent at SSH_AUTH_SOCK does not hold the
  key SHA256:...`. Key file: `ReadPrivateKeyFile(path)` applies the export
  key's rules generalised (a regular file by `Lstat` and again on the open
  file, `O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`, mode with no group or other bits
  checked on both, at most `MaxKeyFileBytes` 16 KiB, exactly one PEM block),
  parses it with `ssh.ParseRawPrivateKey`, refuses a passphrase-protected key
  with `load the key into ssh-agent; toolwarrant does not read passphrases`
  and a file that is neither a key nor a `.pub` line with `not a PEM private
  key` (no PEM marker in any output), applies the policy, clears every buffer
  the key passed through, and returns a `SigningKey` whose `Close` marks it
  closed and clears the Ed25519 seed (an ECDSA or RSA secret cannot be
  cleared through the standard library and is left to the collector).
  `KeySource{Path, AuthSock}.Open(ctx)` is the one entry the CLI uses: a file
  whose first line is a public key means that key through the agent at
  `AuthSock`; any other file is a private key under the file rules; a public
  key with options, or with no socket given (`SSH_AUTH_SOCK is not set`), is
  refused by name. No function returns or prints private material; the
  fingerprint is the only key text an error carries.
- Consequence. A record is three fields the catalog can store and the chain
  can commit to through `sigref`; its signature is re-verifiable by an auditor
  with stock `ssh-keygen -Y verify` and an `allowed_signers` line, and a
  signature `ssh-keygen -Y sign` made, from a key file or through an agent,
  verifies here. A git commit signature (`-n git`) or an export signature can
  never be presented as a decision; a decision can never be read as a trust
  list. Dependencies: `github.com/hiddeco/sshsig` v0.2.0 (Apache-2.0) and
  `golang.org/x/crypto` v0.58.0 (BSD-3-Clause with the Go patent grant) are
  new to the module; x/crypto's own graph moves `golang.org/x/text` to
  v0.43.0, `golang.org/x/sys` to v0.49.0 and `golang.org/x/sync` to v0.24.0;
  `THIRD_PARTY_NOTICES.md` is regenerated with the licence files read from the
  module cache, and `scripts/gen-third-party-notices.sh --check` runs on every
  pull request of the round since #49, when the catalog's import of
  `internal/trust` pulled both modules into the binary (its section 1 names the
  binaries that link each module). `govulncheck` reports nothing the code
  calls. The CI gitleaks job flagged a test fixture of this pull request that
  only looked like a key; the fixture assembles the header at run time and the
  one fingerprint is listed in `.gitleaksignore` with its reason, as SECURITY.md
  says.
- Where. `internal/signing` (`doc.go`, `record.go`, `payload.go`,
  `decision.go`, `trustlist.go`, `keys.go`, `agent.go`, `keyfile.go`,
  `source.go`), `internal/signing/sigtest` (test keys and in-process agents, a
  keyring, one that never answers a Sign and one that never answers at all;
  no key material in the tree), `go.mod`, `go.sum`,
  `scripts/gen-third-party-notices.sh`, `THIRD_PARTY_NOTICES.md`,
  `.gitleaksignore`, CLAUDE.md (the Stack line and the `internal/signing`
  bullet), CHANGELOG.md.
- Tests and proof. `TestConstants_PinTheNamespacesTypesAndBounds` (every
  constant above); `TestVerify_RefusesAnotherNamespace` (decision under trust,
  head, empty, `git`, a trailing space; `Sign` under the same);
  `TestVerify_RefusesAnotherKeyBeforeLookingAtTheSignature`;
  `TestVerify_RefusesASHA256Signature`;
  `TestVerify_RefusesAnRsaSha2256Signature` (an ssh-rsa blob with an
  rsa-sha2-256 inner signature: `ErrSignatureAlgorithm`, while the library's
  own `Verify` accepts the blob);
  `TestVerify_RefusesANonCanonicalSignatureEncoding` (the same blob with
  `reserved` set is `ErrSignatureFormat` from `Verify` and from `Armor`, the
  library accepts it, and the two byte forms had different digests);
  `TestVerify_RefusesAFlippedPayloadByteAndAFlippedSignatureByte` (every byte
  of both); `TestSign_VerifiesTheAgentsSignatureBeforeReturningIt` (an agent
  that answers zeros: `ErrSignerOutput`, no record);
  `TestRecordDigest_ChangesWithPayloadSignatureOrSigner`;
  `TestUnarmor_RefusesWhatSshKeygenWouldNotWrite`;
  `TestSignAndVerify_RefuseOutOfBoundsInputs`;
  `TestDecision_MarshalIsCanonicalAndParseRequiresTheExactBytes` (the exact
  plan document and 26 refusals: whitespace, key order, a trailing byte,
  unknown, missing and duplicate keys, a non-string value, the wrong type, an
  unknown kind, upper-case hex, a short head, actor and tool over their caps,
  a server with a slash, a malformed fingerprint, `signed_at` with an offset
  or a fraction, pause with a tool, disable with a digest, approve without
  one, invalid UTF-8, empty, an array, oversized);
  `TestDecision_EveryKindMarshalsItsOwnShape`;
  `TestDecision_RefusesATrustListUnderTheDecisionNamespace`;
  `TestTrustList_MarshalAndParseRoundTrip`;
  `TestTrustList_RefusesKeyCommentsOptionsAndNonCanonicalKeyLines` (16
  spellings); `TestTrustList_RefusesBoundsAndShape` (65 signers refused, 64
  parse); `TestCheckKeyPolicy_RefusesDSAAndRSABelow3072AndAcceptsTheSKTypes`
  (RSA 3071 refused, 3072 accepted, a certificate refused);
  `TestFingerprint_MatchesSshKeygen`;
  `TestAgent_SignsWithAnEd25519KeyAndNamesAMissingKey`;
  `TestAgent_RSAKeySignsRsaSha2512`; `TestAgent_RefusesASharedOrForeignSocket`
  (0600 in 0700 and 0666 in 0700 accepted, 0666 and 0660 in 0755 refused, a
  regular file, a link, a directory, an empty value, a missing path and a
  104-byte path refused); `TestAgent_SignHonoursTheContextDeadline` (an agent
  that never answers a Sign: the error wraps `context.DeadlineExceeded` and
  names the fingerprint, 20 of 20 runs green);
  `TestKeyFile_RefusesEveryUnsafeShape` (modes 0644, 0640, 0604, a link, a
  directory, a pipe, a missing path, an empty path, an oversized file, two PEM
  blocks, a public key, garbage, a garbage block, an encrypted key with the
  agent advice, DSA, RSA-2048; no error carries a body line, the seed or the
  PEM marker); `TestKeyFile_ClosedKeySignsNothing`;
  `TestKeySource_PublicKeyPathSignsThroughTheAgentAndPrivateKeyPathSignsFromTheFile`;
  `TestKeySource_NeverPrintsPrivateMaterialInAnError`; the interop, which ran
  on this host (OpenSSH 10.3p1) and on the ubuntu runners and skips with the
  reason where `ssh-keygen` is not on PATH:
  `TestSign_ProducesASignatureSshKeygenVerifiesUnderTheNamespace` (`Good
  "decision@toolwarrant.invalid" signature for alice` for Ed25519, ECDSA
  P-256 and RSA-3072; refused under `-n git`, for another principal and over a
  changed payload),
  `TestVerify_AcceptsASignatureSshKeygenMadeAndRefusesItUnderAnotherNamespace`
  (a `-n git` signature is `ErrNamespaceMismatch` naming `"git"`),
  `TestOpenSSH_SignatureVerifiesWithSshKeygenAndTheReverse` (`ssh-keygen -Y
  sign -f id.pub` against the in-process agent verifies here and `Sign`
  through the same agent is `Good ... signature for alice` to `ssh-keygen -Y
  verify`); the properties
  `TestProperty_signThenVerifyHoldsForEveryKeyTypeAndRandomPayloadAndFailsForEveryMutation`,
  `TestProperty_recordDigestIsInjectiveOnTheEncodedTriple`,
  `TestProperty_decisionMarshalParseRoundTripForEveryValidShape`; the fuzzers
  `FuzzParseDecision` (289454 execs in 20 s, 144 interesting inputs, no
  failure), `FuzzParseTrustList` (335095 execs, 158) and `FuzzUnarmor` (866570
  execs, 60; a junk-prefixed armor is a seed), each holding the law that
  whatever parses re-marshals to exactly the input. Break-check by mutation on
  2026-10-15: dropping the hash check, the self-verify, the directory rule,
  the canonical-bytes check, the ssh-dss refusal, the namespace comparison or
  the private-key mode check each failed its named test.

### D22 (b). Every human decision goes through one entry point, carries a signed record once a trust list is in force, and is bound to the head it was signed over by a compare-and-set inside the write transaction

- Context. (a) gives signatures over exact bytes, (c) the operator list in the
  chain; what remained was the decision itself. The owner decided O-13 (`--as`
  is a label that must match the key's operator), O-16 (all eight human
  decisions are signed, because `enable` and `resume` are the two that undo a
  revocation: a forged `tool.enabled` or `server.resumed` appended by whoever
  can write the file would re-serve what a person disabled or paused) and
  O-17 (the signature is made before the transaction, the compare-and-set
  inside it, so the write lock is never held on a person or an agent). The
  pull request is #50 (PR 7.5).
- Decision. `Store.Decide(ctx, Decision)` is the one write path of a human
  decision; `Approve`, `Reject`, `Rollback`, `Disable`, `Enable`,
  `ResetProposalBudget`, `PauseServer` and `ResumeServer` are `Decide` without
  a record and keep their tests. A `Decision` names the kind (`signing.Kind`,
  the eight constants), the server, the tool (empty for pause and resume), the
  digest (approve, reject and rollback only), the person and, when a list is
  in force, the `signing.Record` over the `toolwarrant/decision/v1` payload.
  Before any lock is taken the record is verified under the decision
  namespace and parsed, and the payload must name this catalog, the deciding
  actor and exactly the decision being made (`ErrInvalid` otherwise). Inside
  the transaction, after the chain was verified to its head: an unsigned
  decision while a list is in force is `ErrSignatureRequired` for every one of
  the eight kinds; a payload whose `prev_head` is not the pin is
  `ErrHeadMoved` (`audit head mismatch`) and nothing is written, which also
  refuses the same record a second time and the loser of two signatures over
  one head; the `decision.signed` entry is sealed from the pin, so its
  `prev_hash` is the `prev_head` the payload names by construction, checked
  with the walk's own `checkDecisionRecord` (one function for the writer and
  the reader) and stored first with its row; then the lifecycle, budget or
  server entries follow in the same transaction, each ending with
  ` signed=N`, the seq of that entry. The record's signer must be the key the
  list in force names for the entry's actor: an unlisted key is
  `ErrNotASigner`, a key listed for another person is `ErrNotASigner` saying
  `the key belongs to <name>` (O-13), a key the newest list no longer names is
  refused from the rotation on while its earlier decisions stand, and a
  signed decision on a catalog without a list is `ErrNoTrustList`. Before
  the bootstrap nothing changes: the unsigned methods write exactly what v0.3
  wrote, no token, no row (O-12). `Decide` returns a `Receipt`: `Seq` is the
  `decision.signed` entry (0 for an unsigned decision) and `Head` the hash of
  the last entry the transaction wrote, the head the CLI prints (O-10 (d)).
- The `decision.signed` entry. Subject the server (pause, resume) or
  `server/tool`; actor the person; no before or after hash; detail
  `kind=<kind> digest=<64 hex or -> signer=SHA256:... sigref=<hex>`. The
  record in `signed_records` at its seq, the exact bytes that were signed. The
  snapshot's one pass over a server's entries filters by event, so a
  `decision.signed` entry about `server/tool` is never taken as a decision or
  state entry.
- Where. `internal/catalog/decide.go` (`Decision`, `Decide`,
  `prepareDecision`, `prepareDecisionRecord`, `recordSigned`,
  `decisionWriteError`, `applyDecision`, `changeFor`), `ops.go` (the six
  wrappers, `transitionTx`, `resetBudgetTx`), `servers.go` (`PauseServer`,
  `ResumeServer`, `setPausedTx`), `signed.go` (`fieldSigned`,
  `decisionDetail`, `signedNote`), `catalog.go` (`ErrSignatureRequired`).
- Tests and proof. `TestDecide_RefusesAPayloadSignedForAnotherCatalog`,
  `TestDecide_RefusesADecisionWhoseShapeOrPayloadDoesNotFit`,
  `TestDecide_UnsignedDecisionAfterTheBootstrapIsRefused` (the eight kinds),
  `TestDecide_RefusesAPayloadWhosePrevHeadIsNotThePin`,
  `TestDecide_RefusesAReplayedSignature`,
  `TestConcurrency_TwoSignedApprovalsOverOneHeadLetExactlyOneWin` (six rounds
  of two handles, exactly one winner each),
  `TestDecide_SignedApprovalWritesTheSignedEntryFirstAndTheLifecycleEntriesNameIt`,
  `TestDecide_EveryKindSignsAndItsEntriesCarryTheToken` (the eight kinds, the
  `version.superseded` and `version.proposed` an approve, rollback, disable or
  enable writes beside its own event carrying the token too),
  `TestDecide_ValidSignatureFromAnUnlistedKeyIsNotAuthorization`,
  `TestDecide_LabelMustEqualTheSignersOperatorName`,
  `TestDecide_RefusesAKeyRevokedByTheNewestTrustList`,
  `TestDecide_UnsignedDecisionBeforeTheBootstrapStillWorks`; end to end,
  scenario S approves, disables, enables and approves signed through the
  built binary and the gateway serves the result.

### D22 (c). The operators are named by a signed, versioned list inside the audit chain; the list rotates under TUF's root rule at a threshold of one; a key's signature is authorisation only when the list in force names that key for that person; every record is bound to its entry by a digest token and to the head it was signed over by a compare-and-set; the root is pinned by fingerprint or trusted on first use

- Context. (a) gives a signature that proves which key signed which bytes,
  and nothing about who the key belongs to: the sshsig blob embeds a public
  key and no identity (finding 1), and the library does no principal lookup
  (finding 3), so the identity-to-key binding is toolwarrant's own. gitsign's
  history is the warning (finding 6): a verifier that checks that someone
  signed, but not who, is called dangerous by Sigstore's own maintainers.
  TUF's root metadata is the prior art for a list that changes hands safely
  (finding 10): version N+1 signed by a threshold of keys of both version N
  and N+1, the version exactly N+1 or it is a rollback, revocation by
  publishing a list without the key. Seven TUF implementations miscounted
  duplicate key ids toward a threshold (finding 9, CVE-2020-6174 and
  siblings). The owner decided O-11, O-12, O-14, O-15 and O-17. The pull
  requests are #48 (PR 7.3, `internal/trust`, the pure rules) and #49 (PR
  7.4, the records in the chain).
- Decision (1): the shape and the rules of a list (`internal/trust`). A trust
  list is the `toolwarrant/trust-list/v1` payload of (a): the catalog
  identity, the head it extends, the signer's fingerprint, `signers` as an
  ordered array of `{"key": "<type base64>", "name": "<D7 name>"}`,
  `threshold`, `version`. `internal/trust` is the one place that says which
  such lists are acceptable and how one list may follow another; it imports
  `internal/signing` (payload shape, key line, key policy, the two namespaces)
  and `golang.org/x/text/unicode/norm` (the NFKC fold the catalog's
  `normalizeActor` applies), and nothing else, so the catalog's walk, the
  CLI's `trust` commands and the rendering an auditor uses apply one
  implementation. `trust.Validate(signing.TrustList) (trust.Record, error)`
  applies the rules a list must satisfy on its own: a version from 1; a
  threshold of exactly 1 (`ErrUnsupportedThreshold`, so no record of this
  release can claim a rule its verifier does not apply); one to
  `signing.MaxSigners` (64) operators; every name normalised as D7 does
  (`trust.NormalizeName`, the rule of the catalog's `normalizeActor`
  re-implemented and pinned from both sides) and unique; every key its one
  canonical `authorized_keys` line, within `signing.CheckKeyPolicy`, and
  unique by fingerprint across the list. The returned `Record` is bound to
  its content: `Validate` stores a SHA-256 over the version, the threshold and
  every operator's name, key and fingerprint, and every other function of the
  package recomputes it, so a zero, hand-built or altered-after-`Validate`
  record names nobody, authorises nothing, cannot bootstrap, rotate, fold or
  render. Names are unique per list on purpose: one person is one entry, so a
  future threshold above one counts people and not keys, and a second key for
  one person is enrolled under a second name (`alice@backup`, which D7
  allows); the two-key rule of the residual is done that way.
- Decision (2): the TUF rule at a threshold of one. The first list of a
  catalog is the bootstrap, `trust.bootstrap`: `trust.CheckBootstrap(next,
  signer, pinnedRoot)` requires version 1 (`ErrBootstrapVersion`), a signer
  that is one of the list's own keys (`ErrNotSelfSigned`; trust on first use,
  the list vouches for itself) and, when the operator pinned a root, that the
  signer equals the pinned fingerprint (`ErrNotThePinnedRoot`, naming both).
  Every later list is a rotation, `trust.rotated`: `trust.CheckRotation(prev,
  next, signer)` requires `next.Version == prev.Version+1` (`ErrRollback`; a
  lower and a skipped version alike) and a signer that is a key of both
  `prev` and `next` (`ErrSignerNotInBothLists`). With one signature per
  record the rule says: one listed key may add any key, remove any other key,
  or rename, in one step; a key that is leaving cannot sign its own
  replacement, a key that is arriving cannot vouch for itself, and the last
  remaining key can neither remove itself nor hand the list to a new key, so
  a list is never emptied and signing can never be switched off by a
  rotation. `trust.State{Current *Record; BootstrapSeq, ListSeq int64}` is
  the list in force after folding the trust records of a chain up to a point;
  `State.Apply(seq, kind, next, signer, pinnedRoot)` folds one record in
  increasing seq order from 1 (`ErrSeqOrder` otherwise), refuses a second
  bootstrap while a list is in force (`ErrSecondBootstrap`), a rotation
  before any bootstrap (`ErrNoList`) and any other event (`ErrKind`), applies
  the pinned root to the bootstrap only (O-15: the bootstrap is below the pin
  and cannot change under it), and returns a new `State`, leaving the receiver
  as it was, so a walk keeps the state it had before a refused record.
  Revocation is a rotation that omits the key; it is not retroactive.
- Decision (3): authorisation is a second check, separate from validity
  (finding 6). `signing.Verify` proves that the key whose fingerprint the
  record names signed exactly these bytes under this namespace. Whether that
  key may decide is `Record.Authorize(fingerprint, actor)` on the list in
  force at that seq: the key must be listed (`ErrUnauthorizedSigner`; a valid
  signature from a key the list does not name authorises nothing) and listed
  for exactly the person the entry names (`ErrAnotherOperatorsKey`, naming
  both people, so `--as` can never put a name in the audit log that the key
  does not back, O-13). `Record.Lookup(fingerprint) (name, ok)` is the
  resolution the CLI uses to default `--as`. The catalog turns every refusal
  into `ErrCorrupt`, never a warning, and requires besides that the entry's
  actor equal the listed canonical name letter for letter (the `Store` writes
  no other spelling, so `ALICE` under alice's key is a forgery).
- Decision (4): the auditor's file. `trust.AllowedSigners(Record)` renders the
  list as the `allowed_signers` file stock `ssh-keygen -Y verify -f FILE -I
  NAME -n NAMESPACE` reads: one line per key, in list order, `NAME
  namespaces="decision@toolwarrant.invalid,trust@toolwarrant.invalid" TYPE
  BASE64`, the key being the stored line itself, so the file holds exactly
  the public keys the chain holds and nothing else; the `namespaces=` option
  restricts each key to toolwarrant's two namespaces in the file alone, so an
  auditor's `ssh-keygen` refuses a git or export signature by the same key.
- Decision (5): the two events and the token (the chain, #49). A trust list
  is one audit entry about the subject `@trust` (no server name starts with
  `@`, no tool subject lacks a `/`): `trust.bootstrap` for version 1,
  `trust.rotated` for every later version, actor the person whose key signed,
  no before or after hash, detail `version=N signers=K signer=SHA256:...
  sigref=<hex>`. The record itself, the exact RFC 8785 bytes
  `signing.MarshalTrustList` produced, the sshsig blob and the signer's
  fingerprint, sits in `signed_records` at the entry's seq (schema v7, (g)).
  `sigref` is `signing.RecordDigest`, so the entry's hash, and through it the
  chain, commits to the exact record: a row swapped under an entry no longer
  matches the token the chain verified and is `the signed record of audit
  entry N was replaced` (the fourth and fifth reviews' lesson about every
  table the chain does not cover, applied to the new table). The three signed
  events are chain-recorded events, so the checked read behind `audit list
  --json` (`Store.SignedRecords`) verifies each entry through the memory and
  its row against the token. The table holds nothing the chain does not name:
  a row at the seq of an entry that carries no record is refused where the
  walk meets the entry, by one primary-key range seek of seqs per walked page
  (`signed_records row N belongs to audit entry N, a "tool.discovered", which
  carries no signed record; the row was inserted by hand`). Every value a
  refusal sentence prints that it read from the file before matching it
  against a known constant is quoted with `strconv.Quote`, an unverified
  record's signer fingerprint included (#51).
- Decision (6): the compare-and-set. The payload names the audit head the
  signer saw as `prev_head`. `Store.SetTrust(ctx, rec signing.Record, by
  Actor)` verifies the signature and parses the list before any lock is taken
  (the catalog never calls a signer), then, inside the write transaction and
  after the chain was verified to its head, refuses the record with
  `ErrHeadMoved` (`audit head mismatch`) unless that head is the pin, seals
  the entry from the pin, runs the walk's own `checkTrustRecord` on the
  sealed entry and the record, and only then stores both (`txn.sealSigned`
  and `txn.storeSigned`, one rule function for the reader and the writer).
  The entry's `prev_hash` is the pin by construction, so a stored `prev_head`
  always equals its entry's `prev_hash`, which is what the walk requires of
  every record: every trust record is a signed head, and a signature made over
  a head the log has left behind is never stored. The write lock is never
  held on a person or an agent. Observed while writing the test: a crawler
  whose whole cycle is shorter than the operator's read-sign-write window (a
  few milliseconds, where a synced commit takes about twenty) starves every
  compare-and-set; the scheduled crawl of a deployment runs once a minute, and
  the CLI's one automatic retry (O-17, (h)) covers a crawl landing in the
  signing window.
- Decision (7): the pinned root and trust on first use. `OpenOptions.TrustRoot`
  is the fingerprint the operator recorded at the bootstrap; the catalog
  accepts any `SHA256:`-prefixed value and refuses other prefixes as
  `ErrInvalid` (the full shape check is the CLI's, (h)). The walk passes it to
  `trust.State.Apply`, so a bootstrap another key signed is `the trust
  bootstrap at entry N was signed by SHA256:X, not the pinned trust root
  SHA256:Y; the catalog was re-bootstrapped or replaced`, and a catalog with
  no trust list at all is `the catalog has no trust list and a trust root
  ... was given` (`ErrCorrupt` wrapping `ErrNoTrustList`): the pin says the
  operator bootstrapped this catalog, so a file without a bootstrap is another
  file or a history cut back below it. Both rules end every walk
  (`requireTrustRoot` after `verifyChainLocked`'s walk), so the open-time
  walk, every write transaction and every checked read apply them and a
  forensic open, which does not walk at open, refuses on its first view;
  `Integrity` prints the no-trust-list sentence, counted under
  `TrustListsInvalid`, only for a log that holds no trust entry at all, and
  under a wrong pinned root with a bootstrap present names the bootstrap
  refusal alone (one line, not two). Without a pin the bootstrap's own signer
  is trusted on first use (O-11).
- Decision (8): the suffix walk (O-15). `chainMemory` carries, beside the pin
  and the hashes, a `trustMemory` (the `trust.State` after folding every
  verified trust record, the bootstrap's signer, the count of lists) and the
  outcome of every verified `decision.signed` entry. `recordPage` verifies the
  signed entries of a page first, against the list in force after the pages
  before, reading the rows by primary key once per page (`SEARCH
  signed_records USING INTEGER PRIMARY KEY`), and records nothing of a page
  one of them fails: the walk stops there, the pin stays below the refused
  record, and the refusal is the `ErrCorrupt` the open or the read returns. So
  every signed record is verified once at open, the appended ones on each
  reload, and none on a crawl-only reload. `Integrity` applies the same
  functions to every signed entry in order, prints each refusal with the
  walk's sentence, keeps the list in force past a refused record so later
  records are judged against it, and names a row of no signed entry.
- Decision (9): the bootstrap attests the legacy history (O-12). Nothing
  before the bootstrap is read or rewritten; approvals made before it are
  served by chain anchoring alone, as in v0.3, and are listed by `Integrity`
  as `LegacyApprovalsInService` until re-approved with a signed decision
  ((d), (h)).
- The residual, stated plainly. At a threshold of one, one compromised key
  rotates the list and can evict the other signer: the rotation rule allows
  it because the compromised key is in both the old and the new list, and the
  evicted operator's keys sign nothing afterwards. The controls are the walk's
  (every rotation is a signed record in the chain naming its signer, so the
  eviction is attributed to the key that made it; `audit verify --expect-head`
  and the head printed after every signed write make the rotation visible;
  `--trust-root` keeps a replaced catalog from passing as the original) and
  the operator's own: a second key per person under a second name kept
  offline. Threshold two, where no single key can rotate, is the fix and
  waits for the propose-and-countersign flow (O-14). Removal is not
  retroactive. A rollback of the file to an earlier signed state while no
  `Store` holds a pin is the pin limit of D17; the recorded head, the trust
  root, the signed export and backups are the controls. A swapped row below a
  running `Store`'s pin is not re-read by its suffix walk (O-15): the serving
  path reads no row, so the swap changes nothing served, and the restart,
  `audit verify` and the checked read of the records catch it; a
  `signed_records` row above the head, which only a write with the foreign key
  off can place, belongs to no walked page and is inert until an entry arrives
  at its seq, where the walk or the `Store`'s own insert refuses it, and
  `audit verify` names it at once (a stated residual, not closed with a count
  on every idle reload). A lost key has no in-file recovery beyond a second
  enrolled key; the path is otherwise re-initialisation.
- Where. `internal/trust` (`doc.go`, `record.go`, `rotation.go`,
  `authorize.go`, `allowedsigners.go`, `state.go`);
  `internal/catalog/signed.go` (the three events, `fieldSigned`,
  `TrustEntries`), `trust.go` (`SetTrust`, `TrustList`, `SigningState`,
  `TrustView`, `Receipt`), `trustwalk.go` (`checkRecordBinding`,
  `checkPayloadBinding`, `checkTrustRecord`, `checkTrustActor`,
  `verifySignedEntries`, `checkOrphanRows`), `integrity_signed.go`
  (`SignedRecordsInvalid`, `SignedRecordsOrphaned`, `TrustListsInvalid`),
  `chain.go` (`recordPage`, `trustMemory`), `chaincheck.go`, `audit.go`
  (`sealEntry`, `storeEntry`, `sealSigned`, `storeSigned`), `store.go`
  (`OpenOptions.TrustRoot`, `requireTrustRoot`), `catalog.go`
  (`ErrSignatureRequired`, `ErrNotASigner`, `ErrHeadMoved`, `ErrNoTrustList`);
  `internal/catalog/validate_test.go` (the catalog's `TestNormalizeActor` runs
  `trust.NormalizeName` on every human row); CLAUDE.md (the catalog and
  `internal/trust` bullets); [operations.md](operations.md) ("The operator
  trust list"); CHANGELOG.md (two lines).
- Tests and proof. trust: `TestRecord_RulesRefuseARecordValidateDidNotProduce`
  (a zero record, a hand-built one, one renamed and one version-bumped after
  `Validate`), `TestRecord_ValidateNormalisesNamesAndRefusesDuplicateNamesAndKeys`,
  `TestRecord_RefusesAnEmptyListAndOneOverMaxSigners`,
  `TestRecord_RefusesAThresholdOtherThanOne`,
  `TestRecord_RefusesAKeyOutsideThePolicyAndANonCanonicalKeyLine`,
  `TestNormalizeName_AgreesWithCatalogsNormalizeActorTable`,
  `TestCheckBootstrap_IsSelfSignedByAListedKeyAndMatchesAPinnedRoot`,
  `TestCheckRotation_MustBeExactlyNextVersionAndSignedByAKeyOfBothLists`,
  `TestState_FoldsBootstrapAndRotationsAndRefusesASecondBootstrapOrARotationBeforeOne`,
  `TestState_RefusesAnUnknownKindAndASeqOutOfOrderAndLeavesTheReceiverUnchanged`,
  `TestAuthorize_ValidKeyNotInTheListIsNotAuthorization` (with a signature
  `signing.Verify` accepts), `TestAuthorize_AnotherOperatorsKeyIsNamed`,
  `TestAllowedSigners_RendersOneLinePerKeyWithBothNamespacesAndSshKeygenAcceptsIt`
  (the exact lines; this host's OpenSSH 10.3p1 verified a decision and a list
  for Ed25519, ECDSA P-256 and RSA-3072, `-Y find-principals` named the
  principal, and refused the same signature under `-n git`, for another
  listed principal and over a changed payload),
  `TestProperty_rotationNeverLowersTheVersion`,
  `TestProperty_stateAfterFoldingEqualsTheLastAcceptedRecord`,
  `FuzzRecordValidate` (768533 execs in 20 s, 84 interesting inputs, no
  failure). catalog:
  `TestSetTrust_BootstrapWritesAVersionOneListSignedByItsOwnKeyAndBindsItToTheChain`
  (the approved tool stays served),
  `TestSetTrust_RotationAddsAKeySignedByAKeyOfBothLists`,
  `TestSetTrust_RemovalNeedsAKeyThatStaysAndTheLastSignerCannotBeRemoved`,
  `TestSetTrust_RefusesASecondBootstrapAnUnlistedKeyAndAWeakKey`,
  `TestSetTrust_RefusesAPayloadSignedForAnotherCatalog`,
  `TestSetTrust_ExpectHeadRefusesWhenTheLogMoved` (a record over a stale head
  refused with nothing written; fifty rotations under a crawler that commits
  every forty milliseconds, each retried on `ErrHeadMoved`, leave `prev_head`
  equal to `prev_hash` in every row; 29 of 50 rotations retried on the idle
  host, and under a load average of 45 to 73 with the race detector four runs
  passed with 89 to 113 refusals; the test parks the crawler after five
  refusals in a row so it fails only when the compare-and-set never succeeds),
  `TestWalk_RefusesATrustListWithTheWrongVersionOrSigner` (a non-canonical
  actor included),
  `TestWalk_RefusesATrustRecordWhoseTokensOrPayloadDisagreeWithTheEntry`,
  `TestWalk_RefusesASwappedSignedRecordBecauseTheTokenDisagrees`,
  `TestWalk_RefusesASignedRecordRowUnderAnEntryThatCarriesNone`,
  `TestWalk_RefusesAReplayedTrustRecordFromAnotherCatalog`,
  `TestWalk_DecisionRecordsAreBoundAndAuthorisedAgainstTheListInForce`,
  `TestWalk_RefusalSentencesQuoteHostileStateHalves`,
  `TestWalk_RefusalSentencesQuoteAHostileSigner`,
  `TestReload_ANewTrustListEntersTheStateOnTheSuffixWalk` (a long-lived
  read-only `Store` sees version 2 after the writer rotates, one verification
  per record, none on a crawl-only reload),
  `TestOpen_PinnedTrustRootRefusesAnotherBootstrapAndAcceptsTheRightOne`,
  `TestOpen_PinnedTrustRootRefusesACatalogWithoutABootstrap`,
  `TestForensicOpen_VerifiesTrustLazilyAndNamesTheBrokenRecord`,
  `TestIntegrity_ReportsEveryTrustProblemTheWalkRefuses`,
  `TestSignedRecords_ReturnsTheRecordsOfSignedEntriesAndSkipsTheOthers`,
  `TestTrustEntries_ListsTheBootstrapAndEveryRotationInOrder`,
  `TestAnchorQueries_StayOnTheAuditLogBySubjectIndex` (the primary-key seek
  of the records and the subject-index read of the trust entries),
  `TestProperty_trustStateAfterAWalkEqualsTheStateAfterReplayingTheRecords`.
  sqlite3 break-checks of 2026-10-15 on copies of a fixture (bootstrap at seq
  6, rotation at 7, a crawl at 8 to 10): the two rows swapped made `list` exit
  1 at open with `the signed record of audit entry 6 was replaced: its digest
  is not the sigref token the entry carries` and `audit verify` print it for
  entries 6 and 7; the row of seq 7 copied under seq 8 made `list` exit 1
  with `signed_records row 8 belongs to audit entry 8, a "tool.discovered",
  which carries no signed record; the row was inserted by hand`; the
  `trust.rotated` detail edited from `version=2` to `version=3` made `list`
  exit 1 with `the audit log is broken at entry 7` and `audit verify` print
  `audit entry 7 does not re-seal` and `audit entry 7 says version="3" but its
  signed trust list is version 2`. End to end, scenario S bootstraps the list
  through the built binary, rotates it three times (bob added, the reviewer
  removed and added back), refuses the last signer's removal and a removed
  key's decision, and refuses the processor under a stranger's root.

### D22 (d). After the bootstrap every entry a human decision alone writes must name the verified signed record of its own transaction and say what that decision did, every entry about a tool must start where the chain left the tool, the walk checks all of it once per entry and the anchor pass checks the binding once per anchored entry with two parses and one lookup, and signature verification never happens on the serving path

- Context. The processor's serving path (`Snapshot`) anchors every approved
  digest and every tool's state to the newest entry about the tool, verified
  through the chain memory (D15, D17 (c)). A correctly sealed
  `version.approved` appended after the bootstrap by whoever can write the
  file would pass both anchors; the signed record alone changes nothing unless
  the entries it does not sign are refused. O-15 fixes the cost: signature
  verification in the walk only (every signed entry once at open, the new
  suffix on each reload, none on a crawl-only reload) and an O(1) rule per
  anchored entry. The plan's rules 5 and 6 alone admit the replay, the
  borrowed token, the lying from half and the false transition the three
  adversarial reviews of #50 found; the contiguity rule, the content rule, the
  continuity rule and the shape rule below are the design additions those
  reviews forced.
- Decision (1): rule 5, the binding, as the walk applies it
  (`checkLifecycleEntry`, `checkSignedBinding`, `bindOutcome`). After the
  bootstrap, an entry whose event only a human command writes
  (`version.approved`, `version.rejected`, `version.rolled_back`,
  `tool.disabled`, `tool.enabled`, `tool.budget_reset`, `server.paused`,
  `server.resumed`) must carry ` signed=N` where N is a verified
  `decision.signed` entry below it, about the same subject, by the same
  person, at the same time, whose kind writes that event (approve: approved
  and superseded; rollback: rolled_back and superseded; disable: disabled and
  superseded; enable: enabled, superseded and proposed; reject, budget_reset,
  pause, resume: their own event) and, for an approval, rollback or
  rejection, whose digest is the one the entry records. The entry must
  belong to N's transaction as the chain shows it, that is N itself or the
  entries right after it that carry the same token, because the write lock
  makes a transaction's entries contiguous: the walk carries "the decision
  transaction that is open" from entry to entry (`chainMemory.open`, an
  `openTxn`, across pages); an entry without a token closes it, a trust entry
  closes it, a verified `decision.signed` opens its own. Without this rule a
  `version.approved` appended after a later disable, naming a
  `decision.signed` alice did make, with her time, actor and digest copied,
  binds and re-serves the digest she disabled. Every refusal is `ErrCorrupt`
  with a fixed sentence naming the entry: `audit entry N is a
  version.approved after the trust bootstrap (entry B) and names no signed
  record; the entry was appended outside toolwarrant`, and for a token that
  does not bind: `names signed=K, which is not the seq of a decision.signed
  entry below it`, `names signed=K, which is not a verified decision.signed
  entry`, `names signed=K, whose transaction ended before it; a signed record
  attests the entries of its own transaction only`, `names signed=K, a
  decision.signed about S by A at T, but the entry is about S2 by A2 at T2;
  the entries of one decision share its subject, actor and time`, `is a
  "tool.enabled" but names signed=K, a decision of kind approve, which writes
  no such entry`, `is a version.approved of digest D but names signed=K,
  which decided digest D2`. The binding then reads the entry's content
  (`bindContent`, added after the first review): an entry of a tool kind
  carries a `state=A->B` the kind can make (`lifecycle.DecisionMayMove` for
  approve, reject, rollback, disable and enable; a budget reset stays put)
  and an entry of a pause or resume carries the paused flag the kind leaves,
  each with its sentence: `audit entry N moves tool "S/T" from "disabled" to
  "enabled" under event "tool.disabled" but names signed=K, a decision of
  kind disable, which makes no such move; the entry was appended outside
  toolwarrant`, `audit entry N is a server.paused saying paused=false but
  names signed=K, a decision of kind pause, which leaves the server
  paused=true; the entry was appended outside toolwarrant`, `names signed=K,
  a decision of kind approve about a tool, but carries no state field; the
  entries of a tool decision record its transition`, `names signed=K, a
  decision of kind pause about a server, but carries no paused flag`. Entries
  that carry a token but are not human-only (the `version.superseded` of an
  approve) are held to the same binding, content included, so a token cannot
  be borrowed by an entry that says the opposite of its decision.
- Decision (2): the continuity rule (`checkContinuity`, `toolLast`,
  `chainMemory.states`), added after the second review, which makes the from
  half of every `state=A->B` trustworthy for rule 5 and rule 6 alike. The
  walk remembers, for every tool subject, what the newest entry about the
  tool left it: the entry's seq, its time and its transition, one value per
  tool and never one per entry, kept beside `hashes` and `signed`, advanced in
  `recordPage` from a page-local map, dropped in `drop`, and tracked from the
  genesis (before the bootstrap the memory is kept and nothing is refused,
  O-12), so the first entry after the bootstrap is checked against the state
  before it. After the bootstrap every entry about a tool, with a token or
  without, must move the tool from that state, unless it is a sibling of that
  entry, the same transition at the same time (`auditTool` writes one entry
  per lifecycle event of one operation, each with the operation's before and
  after, so the entries of one operation repeat its transition). A tool entry
  that records no transition is refused as such by rule 6 (`audit entry N
  about "S/T" is a tool entry (its detail starts with digest=) but carries no
  state field; every entry the catalog writes about a tool records its
  transition, so the entry was appended outside toolwarrant`): every entry the
  catalog writes about a tool carries one (every released build since v0.1.0
  does), and accepted it would have become the newest entry about the tool
  with nothing for the rule to compare the next entry with (the third
  review's finding). A tool whose newest entry recorded no transition, which
  only a stateless entry planted before the bootstrap leaves, is refused
  rather than skipped (`audit entry N says tool "S/T" moves from "A" but the
  newest entry about it (seq M) records no transition; the entry was appended
  outside toolwarrant`), and a tool the chain holds no entry about must start
  from `discovered`, where `insertTool` creates every tool (`audit entry N
  says tool "S/T" moves from "A" but no earlier entry is about the tool, and
  the first entry about a tool starts from discovered; the entry was appended
  outside toolwarrant`). The refusal otherwise: `audit entry N says tool
  "S/T" moves from "A" but the newest entry about it (seq M) left it "C"; the
  entry was appended outside toolwarrant`, filed under
  `CrawlTransitionsForged` for a token-less entry and under
  `UnsignedDecisionsAfterBootstrap` for a token-bearing one. What it closes: a
  sealed `tool.enabled` saying `disabled->enabled` under the token of a
  review-policy enable whose own entries left the tool in `pending_review`
  (the writer checked the lifecycle under the `Store`'s policy, the walk a
  policy-agnostic table), and the lying crawl-shaped entry of (f). The
  sibling exception admits nothing wider: an entry that repeats the newest
  transition at its time leaves the tool where that transition already left
  it.
- Decision (3): the transaction shape (`checkTransactionShape`, `openTxn`,
  `txnEvent`), one small value per open transaction. Every entry naming
  `signed=K` carries the state field and the `after_hash` of the first entry
  that named the token (the whole operation's before and after are on every
  event), no (event, digest) pair appears twice (the pair rather than the
  event alone, because an enable under review may legitimately write two
  `version.superseded` of two digests in one decision, the approval it retires
  and the pending version `supersedePending` retires when it re-proposes the
  last seen digest, and no decision repeats a pair), and nothing follows the
  decision's own event, the human-only event of its kind, which every command
  writes last (`openTxn.ownEvent`), so the transaction open at the head
  cannot be extended under its token once that event is written. Sentences,
  as the code prints them: `audit entry N names signed=K and says
  state="A->B" but the first entry of that transaction (seq F) says
  state="C->D"; the entries of one decision record one transition`, `audit
  entry N names signed=K and records after_hash D but the first entry of that
  transaction (seq F) records E; the entries of one decision record one
  approved digest`, `audit entry N is a second tool.disabled of digest none
  under signed=K (entry F wrote the first); a decision writes each of its
  events once`, `audit entry N names signed=K but that transaction ended with
  its version.approved (seq F), the last entry a decision writes; the entry
  was appended outside toolwarrant`. `before_hash` is not part of the shape
  rule and this record does not promise it.
- Decision (4): rule 6, the crawl-transition guard (`checkCrawlTransition`,
  `lifecycle.CrawlMayMove`), with the continuity rule after it. After the
  bootstrap, an entry about a tool that no decision signed moves the tool's
  state only along a transition a crawl observation can make: discovered to
  pending_review or itself, pending_review to deprecated or itself, enabled
  to changed_pending_reapproval, deprecated or itself,
  changed_pending_reapproval to enabled, deprecated or itself, disabled to
  itself only, deprecated to pending_review or itself, and nothing to or from
  a state the lifecycle does not define; and only from the state the newest
  entry about the tool left it in. The table is exported from
  `internal/lifecycle`, whose property tests check every step the state
  machine takes against it (so it cannot be narrower than the machine) and
  whose `TestCrawlMayMove_EqualsTheInvariantsTable` spells it out pair by pair
  (so it cannot be wider). The refusals: `audit entry N moves tool "S/T" from
  "disabled" to "enabled" under event "tool.reverted", which no crawl can do;
  the entry was appended outside toolwarrant` for the entry that confesses
  where the tool was, and the continuity sentence for the one that lies. Order
  on the token path: `bindOutcome`, continuity, shape; on the crawl path: the
  crawl table, continuity.
- Decision (5): the anchor pass (`entryChecker.verify`,
  `chainMemory.requireSigned`). Every anchor of a checked read goes through
  `entryChecker.verify`: the decision anchor, the state anchor, the three
  server anchors (`anchorServer`, `anchorPaused`) and the version history
  (`versionsFromLog`). After `chainMemory.verify` it applies the binding of
  rule 5 to the entry when a bootstrap is in force below it and its event is
  one of the eight: one `detailField` parse of the token, one of the state
  field or the paused flag, one map lookup of the outcome the walk recorded,
  the same `bindOutcome` comparison; contiguity, continuity and the shape are
  the walk's, which recorded the entry the anchor reads, and are not redone.
  It reads no bytes and hashes nothing, so `hashes/op` of the reload
  benchmarks is unchanged. The state anchor counts `tool.budget_reset` among
  the state-bearing entries, as `Integrity`'s tools pass does, so the two name
  the same entry when a column is edited after a reset. Signature
  verification stays in the walk: the read-only `Store` verifies a signed
  approval's record once, on the reload that meets it, and nothing on the
  reloads after crawls; a swapped decision record is refused by the walk that
  meets it and by every fresh open, while a `Store` whose pin lies above the
  rows keeps serving, the restart and `audit verify` catching the swap.
- Decision (6): rules 2 and 4 for the record itself (`checkDecisionRecord`),
  shared by the writer and the walk: the kind token, the digest token and the
  subject must be the payload's (`audit entry N says digest="D2" but its
  signed decision names digest D`, `audit entry N is about "alpha/echo" but
  its signed decision is about "alpha/sum"`), and the signer must be the key
  the list in force at that entry names for the actor (`signer X is not in
  trust list vK in force at that entry`, `signer X belongs to "alice" but the
  entry and payload name "bob"`).
- `Integrity` applies the same functions to every entry in order
  (`integrity_decisions.go`, one more streaming pass over the log after the
  signed records were folded, with its own map of every tool's last state
  from the genesis), prints each refusal with the walk's sentence under
  `UnsignedDecisionsAfterBootstrap` (rule 5, a missing or non-binding token,
  the continuity or the shape of a token-bearing entry) and
  `CrawlTransitionsForged` (rule 6 and the continuity of a token-less entry),
  goes on past each, and lists the approvals in force that predate the
  bootstrap in `LegacyApprovalsInService`, sorted, as information and not a
  problem. The report has one line per forgery: a refused entry's state is
  recorded, so the entries built on it are not each reported again, and the
  stateless attack prints two lines, the stateless entry under rule 6 and the
  lie built on it under the continuity rule, since both are forgeries.
- Where. `internal/catalog/decisionwalk.go` (`checkDecisionRecord`,
  `checkDecisionTokens`, `decisionWalk`, `lifecycleStep`,
  `checkLifecycleEntry`, `checkSignedBinding`, `checkCrawlTransition`),
  `decisionbind.go` (`bindOutcome`, `bindContent`, `bindPausedFlag`,
  `kindMayMove`, `eventDigest`, `lookupSigned`, `requireSigned`),
  `decisioncontinuity.go` (`toolLast`, `stateField`, `leftState`,
  `checkContinuity`, `openTxn`, `txnEvent`, `checkTransactionShape`,
  `lookupState`), `trustwalk.go` (`pageInput.lastState`, `pageOutcome.open`
  and `.states`, `verifySignedEntries`), `chain.go` (`chainMemory.open`,
  `chainMemory.states`, `recordPage`, `drop`), `chaincheck.go` (the checked
  read, `verifyChain`), `anchor.go` (`entryChecker.verify`), `stateanchor.go`
  (`toolStateEvents` with `tool.budget_reset`), `serveranchor.go` and
  `versionhistory.go` (routed through `entryChecker`), `integrity.go`,
  `integrity_signed.go`, `integrity_decisions.go`;
  `internal/lifecycle/crawlmoves.go` (`CrawlMayMove`), `decisionmoves.go`
  (`DecisionMayMove`); the page-boundary test of this record,
  `internal/catalog/continuitypage_test.go`.
- Tests and proof. `TestWalk_RefusesAnUnsignedApprovalAppendedAfterTheBootstrap`,
  `TestWalk_RefusesAnUnsignedEnableOrResumeAppendedAfterTheBootstrap`,
  `TestWalk_RefusesASignedTokenThatDoesNotBindTheEntry` (the seven token
  probes, the six content probes, the four history probes: the enable token
  on a `tool.enabled` saying `disabled->enabled` after a review-policy enable
  with the state and the pointer edited, the budget-reset token on a
  `tool.budget_reset` saying `enabled->enabled` on a disabled tool, a sibling
  `version.superseded` recording another `after_hash`, a second
  `tool.disabled` repeating the first, and the three extensions after the
  approve's own entry: a second `version.approved` naming another digest, a
  `version.superseded` of the approved digest and one of a third digest),
  `TestWalk_TheShapeRuleSentencesAreFixed` (the four sentences byte for
  byte), `TestWalk_RefusesAPayloadWhoseKindOrDigestDisagreesWithTheEntry`,
  `TestWalk_RefusesAValidSignatureFromAKeyOutsideTheTrustList`,
  `TestWalk_RefusesASignatureWhoseKeyBelongsToAnotherName`,
  `TestWalk_RefusesAPayloadCopiedFromAnotherCatalog`,
  `TestWalk_ARemovedKeysEarlierDecisionsStandAndItsLaterOnesAreRefused`,
  `TestWalk_RefusesACrawlShapedEntryThatLeavesDisabled` ((f) lists its
  cases), `TestWalk_ContinuityMemoryCrossesThePageBoundary` (this pull
  request: the log padded to exactly the walk's page size of 5000 entries so
  the signed disable's `tool.disabled` is entry 5000 and the lying
  `tool.reverted` saying `changed_pending_reapproval->enabled`, with the
  column edited, is entry 5001; the long-lived `Store`, every fresh open and
  `Integrity` refuse it naming entry 5000 as the one that left the tool
  disabled; 16.6 s under `-race` on the Apple M4 of 2026-10-16, a `-short`
  skip named in CLAUDE.md, run by the `test-full` job; before it the page
  boundary was covered by the reviewers' scratch tests only),
  `TestWalk_AcceptsEveryCrawlTransitionTheLifecycleMakes` (drawn
  Store-written histories never trip either rule, and a fresh walk remembers
  for each tool exactly the state the row holds; 1000 checks at 109 s),
  `TestProperty_anchorRuleAcceptsOnlyTheSignedEntryOfTheSameTransaction`
  (oracles written out field by field to the rule and not to the code; the
  corrected oracle fails the code before the third fix at 20000 checks, which
  is the gate, not rapid's default 100),
  `TestSnapshot_ServesOnlySignedApprovalsAfterTheBootstrapAndReadsNoBytes`,
  `TestSnapshot_ABudgetResetIsTheNewestStateEntryOnBothPaths`,
  `TestSnapshot_ReloadAfterACrawlVerifiesNoSignature`,
  `TestSnapshot_SwappedSignedRecordRowIsCorrupt`,
  `TestReview_ForgedSignedApprovalWithoutAKeyIsRefusedEverywhere` (the
  approvals row, the version status, the pointer, the state column and a
  sealed `version.approved` at the head, as an approval writes them, refused
  by `Open`, `Snapshot`, `Approved`, `Versions`, `Tools`, every decision and
  the crawl, named by `Integrity`, while `VerifyAudit` alone is green as D14
  admits), `TestIntegrity_ReportsEveryDecisionRecordProblemTheWalkRefuses`
  (seven forgeries in one file: 3 invalid records, 3 unsigned decisions, 1
  forged crawl transition, the well-formed signed approval between them not
  reported), `TestIntegrity_CountsLegacyApprovalsInService`,
  `TestWalk_LegacyApprovalsBeforeTheBootstrapNeedNoRecord`,
  `TestBenchmarkSnapshotHashesOnlyAuditEntries` (holds at n and 2n); lifecycle:
  `TestCrawlMayMove_EqualsTheInvariantsTable`,
  `TestDecisionMayMove_EqualsTheInvariantsTable`; cmd:
  `TestServeDeniesEveryHookAfterAnUnsignedApprovalIsAppended` (the in-process
  processor over gRPC denies every hook `catalog unavailable` from its next
  reload after a sealed `version.approved` is appended). sqlite3 break-checks
  of 2026-10-16 through the built binary on fixture catalogs (the sentences as
  printed then, before #51 quoted the state halves): a sealed
  `version.approved` of a pending tool after the bootstrap made `list` exit 1
  at open and `audit verify` print the rule 5 sentence among six integrity
  lines; a sealed `tool.reverted disabled->enabled` by the crawler with the
  column edited made both name the crawl-table sentence; the two decision
  records swapped named `the signed record of audit entry 12 was replaced` and
  `audit entry 13 names signed=12, which is not a verified decision.signed
  entry`; a sealed `tool.disabled` at the disable's own time saying
  `disabled->enabled` under its token named the content-binding sentence; a
  sealed `tool.reverted changed_pending_reapproval->enabled` and a sealed
  `tool.enabled disabled->enabled` under a review-policy enable's token with
  the state and the pointer edited each named the continuity sentence against
  the entry that left the tool `disabled` or `pending_review`. End to end,
  scenario S repeats the unsigned approval and the crawl-shaped revert through
  the built binary: the processor exited 1 at open and `audit verify` exited
  1, each naming the entry (the proof note of row 27 in
  [threat-model.md](threat-model.md) quotes the lines).

### D22 (e). The costs measured: the migration, the reload, the open, the continuity memory and the end-to-end restart

- The migration ((g); 2026-10-15, by hand, Apple M4). One immediate
  transaction adds one table and four triggers and reads or rewrites no row
  of any other table. Against a catalog the published v0.3.0 binary wrote
  (9 audit entries, 32 schema objects, `audit log ok: 9 entries, head
  e6dd20ce...2fb3a`): the branch binary's `serve`, `audit verify` and `audit
  list` each exited 1 with the migration message and left the file's SHA-256
  and `user_version` 6 unchanged; its `init` exited 0, after which the file
  had `user_version` 7, 37 objects (`table signed_records` and its four
  triggers), 0 rows in `signed_records`, every other table's row count
  unchanged and `audit verify` printed the same head; the v0.3.0 binary then
  refused the file (`database is version 7, this build supports 6`). The
  migration's wall time was not timed; it is one DDL transaction on a file of
  a few hundred rows.
- The reload (D21 (d)'s regression check). `BenchmarkSnapshot10000Approved8KiB`
  measured 255 to 259 ms/op at 10000 hashes/op on the Apple M4 after #49
  (2026-10-15; 258.7 ms after its review round, with the range seek per walked
  page costing the serving path nothing on an idle reload) and 252 ms/op at
  10000 hashes/op at the merged head of #50 (2026-10-16, f21461b; 249 ms at
  144c52a with three iterations); the D21 (d) band of 370 to 415 ms was
  recorded on 2026-10-14 on the same machine against the v0.3 tree. The
  regression check is hashes/op, not the wall time: the anchor rule hashes
  nothing and its cost is two `strings.Fields` parses per anchored human
  decision (the `signed=` token, then the state field or the paused flag), of
  which that store has 10000; the continuity and shape rules run in the walk
  only and add nothing to the reload (`TestBenchmarkSnapshotHashesOnlyAuditEntries`
  holds at n and 2n).
- The open. `BenchmarkOpen10000SignedApprovals` (`recheck_bench_test.go`)
  opens a read-only `Store` on a catalog of `MaxToolsPerCrawl` (10000) tools
  each approved with a signed Ed25519 decision after the bootstrap, 10001
  signed records and about 30000 audit entries: 1.563 s/op at 10001
  verifications/op, 631.39 MB and 9087578 allocations per open at the merged
  head of #50 (f21461b, one iteration, Apple M4, 2026-10-16; 1.532 s, 631.42
  MB and 9087763 allocations at 144c52a with three iterations; 1.587 s before
  the first review's fix). That is about 155 us per signed record, above the
  plan's estimate of "under one second". A CPU profile of five opens of a
  3000-record catalog (0.49 s per open, the same per-record cost) puts about
  half in Ed25519 field arithmetic, about a fifth in the RFC 8785
  canonicalisation that `signing.RecordDigest` (the sigref token over the
  base64 record) and `signing.ParseDecision` (the exact-bytes check, finding
  7) perform, and the rest in the row reads, the entry hashes and the
  allocator. The orchestrator decided (decision 10) to accept and record the
  number rather than change the sigref specification of (c) to cheapen it,
  and to list parallel verification of the signed pages among the v0.5 items:
  a real catalog holds tens to hundreds of signed decisions, not ten
  thousand. The cost is paid once per signed record, at open and on the
  suffix walk that meets it, never on the serving path: a crawl-only reload
  verifies nothing (O-15; `TestSnapshot_ReloadAfterACrawlVerifiesNoSignature`).
  A processor that restarts on a 10000-decision catalog therefore takes about
  1.5 s longer to open than a v0.3 processor on the same file; the serving
  path is unchanged.
- The continuity memory. One `toolLast` per tool subject (seq, time, from,
  to) and the shape of each decision transaction cost about 13 MB and 70000
  allocations per open for 10000 tools (631.4 MB against 618.7 MB before the
  rule) and no measurable wall time (1.532 s against 1.529 s); the third
  review's rules (the stateless refusal, the ended clause) cost nothing
  measurable either (verifications/op, memory and allocations within noise at
  f21461b).
- End to end (scenario S, 2026-10-16, Apple M4, `make e2e` against
  agentgateway v1.6.0). A signed approve through the in-process ssh-agent took
  32.6 ms for the whole CLI run, the key resolution, the `SigningState` read,
  the review, the Ed25519 signature and `Decide`'s transaction included.
  mock's processor restarted under `--trust-root` on a log of 72 entries (the
  bootstrap, three rotations, eight decision records and the entries they
  produced among them) was listening 45.4 ms after its start, the open-time
  walk having verified every signed record, and served add and echo 50.9 ms
  after its start; its line read `signed decisions: enforced from entry 48
  (trust list v4, 2 signers, root SHA256:... at entry 47)`. The whole scenario
  ran in 1.64 s inside a 38.98 s `TestEndToEnd`.

### D22 (f). The crawl-transition guard, the continuity rule and the legacy residual

- Context and decision. Rule 6 closes a gap the signatures alone leave open:
  the state anchor (D17 (c)) compares the tools column with the after half of
  the newest entry about the tool and never replays the lifecycle, so a
  correctly sealed `tool.reverted` with `state=disabled->enabled`, appended by
  whoever can write the file and matched by one `UPDATE` of the column,
  re-enables a disabled tool under a clean chain, signatures or not. After the
  bootstrap the walk refuses it. The first adversarial review of #50 showed the
  same shape with a key's token borrowed: a sealed `tool.disabled` with
  `state=disabled->enabled` naming the disable's own `signed=K` while that
  transaction is the chain tail passed the binding, because rule 6 ran only
  on token-less entries; the binding reads the content too ((d),
  `bindContent`). The second review showed that both checks read the from
  half from the forged entry itself: a sealed `tool.reverted` saying
  `changed_pending_reapproval->enabled` (or `enabled->enabled`, or
  `tool.returned enabled->enabled`, or `tool.drifted
  enabled->changed_pending_reapproval`, each a move a crawl may make) about a
  disabled tool passed the crawl table, and a sealed `tool.enabled` saying
  `disabled->enabled` under a review-policy enable's token passed the
  decision table, and each with the column edited was served on every path
  with `Integrity` clean. The continuity rule ((d), decision 2) is what closes
  both: the walk knows where the chain left every tool and refuses an entry
  that starts anywhere else, `audit entry N says tool "S/T" moves from
  "changed_pending_reapproval" but the newest entry about it (seq M) left it
  "disabled"; the entry was appended outside toolwarrant`. The third review
  showed the last gap in the same place: a sealed tool entry with no state
  field at all was accepted, became the newest entry about the tool, and the
  continuity rule's skip of a tool whose newest entry recorded no transition
  freed the next entry to claim any start, on every path and across the page
  boundary; rule 6 now refuses the stateless entry and the continuity rule
  refuses the entry after it, and the skip, which no released build's history
  ever needed, is gone. So nothing appended without a key, and nothing that
  borrows the token of a decision it contradicts, outruns or extends past its
  own event, can approve, enable, resume or re-enable anything.
- The legacy residual, stated as the code has it. Rule 6 and the continuity
  rule apply after the bootstrap only (the plan's section 5, the last item):
  applied to the history before it, they would refuse any legacy file whose
  history an older lifecycle wrote differently. The memory of every tool's
  state is kept from the genesis all the same, so a tool disabled before the
  bootstrap is protected by its pre-bootstrap entry against a lying entry
  appended after it, and a stateless tool entry planted before the bootstrap
  refuses every entry about the tool after it instead of freeing them (the
  state anchor refuses the tool itself while that entry is its newest, so
  nothing is served either way). Before any bootstrap the same sealed
  `tool.reverted` is accepted, and with the column edited the disabled tool is
  served again; the last case of `TestWalk_RefusesACrawlShapedEntryThatLeavesDisabled`
  records exactly that (`Open` succeeds, `Snapshot.Serves` is true) and
  `Integrity`, which compares the column with the newest entry, is clean on
  such a file, and the entry then counts as the state the tool was left in
  for every entry after the bootstrap. The controls for a never-bootstrapped
  catalog are v0.3's: the recorded head, the signed export and backups; the
  bootstrap is the cut-over, and O-12's default flip in v0.5 is where the
  residual ends. Approvals made before the bootstrap stand by chain anchoring
  alone and are listed by `Integrity` as `LegacyApprovalsInService` until
  re-approved with a signed decision.
- Where. `internal/lifecycle/crawlmoves.go` (`CrawlMayMove`) and its
  invariants test, `internal/catalog/decisionwalk.go`
  (`checkCrawlTransition`), `decisioncontinuity.go` (`checkContinuity`);
  [operations.md](operations.md) ("What every reader requires of the entries
  after the bootstrap").
- Tests and proof. `TestWalk_RefusesACrawlShapedEntryThatLeavesDisabled`: the
  confessing `tool.reverted disabled->enabled` and the four lying probes
  `tool.reverted changed_pending_reapproval->enabled`, `tool.reverted
  enabled->enabled`, `tool.returned enabled->enabled` and `tool.drifted
  enabled->changed_pending_reapproval`, each by the crawler and by a person,
  each with the column edited; the four stateless vehicles (the full tool
  detail minus its state field, `digest=-` alone, and the digest field alone
  under `tool.returned` and `tool.drifted`), each followed by the lie, with
  the walk refusing at the stateless entry and `Integrity` counting both under
  `CrawlTransitionsForged`; the stateless entry planted before the bootstrap,
  whose lie after it is refused with the "records no transition" sentence; a
  tool the chain holds no entry about starting from `enabled`; a tool disabled
  before the bootstrap lied about after it, refused against its pre-bootstrap
  entry; and the legacy residual before any bootstrap, recorded as the code
  has it. `TestWalk_ContinuityMemoryCrossesThePageBoundary` ((d)).
  `TestCrawlMayMove_EqualsTheInvariantsTable` and the lifecycle's property
  tests, which read the table on every step. End to end, scenario S: with
  mock's processor stopped, a sealed `tool.reverted` from `disabled` to
  `enabled` by the crawler about a tool a signed decision had disabled, with
  the state column edited, made the processor exit 1 at open and `audit
  verify` exit 1, both naming `audit entry 67 moves tool "mock/echo" from
  "disabled" to "enabled" under event "tool.reverted", which no crawl can do`
  (run of 2026-10-16).

### D22 (g). Schema v7: the `signed_records` table and the in-place migration of a v6 file

- Context. Signed decisions and the signed trust list need a place for the
  record itself: the exact RFC 8785 bytes that were signed, the signer's
  fingerprint and the sshsig wire blob, one per signed audit entry, bound to
  the chain through the `sigref` token of the owning entry's detail. The audit
  log's columns cannot hold a blob of that size and shape without changing
  the chain's own fields, so a table is needed, and a table is a schema
  change. Schema v6 is the first released schema (v0.1.0 to v0.3.x) and D17's
  eighth review promised that the first bump after it would carry a migration
  or name the build that reads a v6 file, never the delete advice; D21 (f)
  described the in-place path. The owner decided O-12 on 2026-10-15. The pull
  request is #46 (PR 7.2).
- Decision. `schemaVersion` is 7 and `migratableFrom` is 6. The migration
  `migrateV6ToV7` runs inside the one immediate transaction `migrate` already
  holds for a read-write open: it refuses a v6 file that already holds an
  object under one of the five names it creates (`ErrCorrupt`, "already holds
  table signed_records ... nothing was written"), creates `signed_records`
  (`seq INTEGER PRIMARY KEY REFERENCES audit_log (seq)`, `payload BLOB` of 1
  to 65536 bytes, `signer_fingerprint TEXT GLOB 'SHA256:*'`, `signature BLOB`
  of 1 to 4096 bytes; no UNIQUE constraint beyond the rowid alias, so the
  automatic index list is unchanged), creates its four guards
  `signed_records_no_update`, `signed_records_no_delete`,
  `signed_records_no_replace` (BEFORE INSERT on an existing seq) and
  `signed_records_positive_id` (AFTER INSERT on a seq below 1), sets `PRAGMA
  user_version = 7`, and then the usual guard comparison runs against the
  migrated schema, so a v6 file that had lost a guard is still corruption and
  nothing commits. No row of any other table is read or rewritten. A read-only
  open (the processor) and a forensic open (`audit verify`, `audit list`) of a
  v6 file return `ErrSchema` with a message naming the migration (`run
  "toolwarrant init" with this build ... a read-only open does not migrate`),
  never the delete advice, and write nothing; `schemaMessage` prints the
  migration sentence only for the migratable version and tells an older
  released schema to be read with a build of that schema or migrated with
  each release in turn. The ghost-row check every read and write runs covers
  the new table, `Integrity` counts such a row in `GhostRows`, and the column
  CHECKs bound what raw SQL can plant. The release notes header of
  `.goreleaser.yaml` names v7 and the migration sentence, and `make
  release-check` (its `release-schema-line` target) refuses a header naming
  another version than the code writes. The CLI's schema advice names the
  migration and never deletion.
- Consequence. Upgrading from v0.1.0 to v0.3.x is: stop the processors, back
  the file up and record its head with the build that wrote it, run `init`
  (or any writing command) with the new binary, compare the head, start the
  processors. Every command but `serve` (read-only), `audit verify` and `audit
  list` (forensic) opens the file read-write and migrates a v6 file on its
  first run, `list`, `show`, `diff` and `server list` included, so the backup
  comes first. The audit head of a migrated file is the head it had, so the
  recorded head stays valid across the upgrade and `export verify
  --expect-head` keeps working; every approval is served as before. A
  processor started on a v6 file exits 1 with the message instead of
  migrating, by design (`serve` must never write); a v0.3.x processor left
  running keeps answering from its cached snapshot until the first crawl or
  decision with the new build moves the generation, then denies every hook
  from its next reload with `unexpected table signed_records ... the file was
  edited outside toolwarrant`, and the fix is to restart it on the new build,
  never to restore a backup over the migrated file; a v0.3.x binary then
  refuses the migrated file as written by a newer build ("database is version
  7, this build supports 6"), which moves every host to the new build
  together. A crash in the middle of the migration leaves a v6 file that
  migrates on the next read-write open (SQLite DDL is transactional); two
  processes opening a v6 file at once migrate it once. A v6 file this build
  refuses as corrupt before migrating it has no forensic path in this build
  and is inspected with a v0.3.x binary, so one is kept through the upgrade.
  What (g) does not do: it does not sign or verify anything, it does not
  change the chain, it does not bootstrap a trust list (O-12: a catalog never
  bootstrapped serves as v0.3 did), and it does not migrate from v2 to v5,
  which stay refused with the re-initialise advice. The residual is the one
  (c) states: whoever can write the file can plant a well-formed row in the
  table; the walk refuses a row without a matching `sigref` token in a
  verified entry.
- Where. `internal/catalog/schema.go` (`schemaVersion = 7`, `migratableFrom =
  6`, `migrate`, `schemaMessage`, `historyTables`), `schemav7.go` (the
  bounds, the DDL, the four guards, `migrateV6ToV7`,
  `refuseForeignV7Objects`), `guards.go`, `ghostrows.go`, `integrity.go`,
  `integrity_signed.go`, `openmodes.go` (`prepareFile`, `checkReadOnlyFile`),
  `cmd/toolwarrant/advice.go` (`adviceSchema`), `.goreleaser.yaml` (the
  header), `Makefile` (`release-schema-line`), `internal/releaseguards`
  (`schemaline_test.go`), [operations.md](operations.md) ("Recovering from
  ErrCorrupt and ErrSchema", "Releasing"), CLAUDE.md (the catalog and
  releaseguards bullets), CHANGELOG.md (one Changed line).
- Tests and proof. catalog
  `TestMigrate_V6FileIsMigratedInPlaceAndKeepsEveryRowAndTheHead` (a v6 file
  built from the frozen v0.3.0 DDL, copied verbatim from a fresh catalog the
  published v0.3.0 binary initialised: after `Open`, `user_version` is 7, the
  table and its four guards exist, every other table keeps its row count,
  `AuditHead` is the head the v6 file had, `Snapshot` serves the legacy
  approval alone, `Integrity` is clean and a second open migrates nothing),
  `TestMigrate_ReadOnlyAndForensicOpensOfAV6FileNameTheMigrationAndWriteNothing`
  (both opens pin `run "toolwarrant init" with this build` and `a read-only
  open does not migrate`, never "delete", and the file's SHA-256 is
  unchanged), `TestMigrate_RefusesAV6FileThatAlreadyHoldsAForeignSignedRecordsTable`,
  `TestMigrate_RefusesAV6FileThatLostAGuardAndCommitsNothing` (`ErrCorrupt`
  naming the guard, `user_version` still 6, no `signed_records` object, the
  file digest unchanged), `TestMigrate_TwoProcessesOpeningAV6FileAtOnceMigrateItOnce`
  (the second opener a real process, exactly five objects named
  `signed_records*`, same head and rows),
  `TestSchema_SignedRecordsGuardsRefuseUpdateDeleteReplaceAndGhostRows`,
  `TestSchema_SignedRecordsGhostRowIsCorruptAndCountedByIntegrity`,
  `TestSchema_SignedRecordsRefusesOversizedRows` (a row at both bounds stored;
  since #49 the planted row is reported as an orphan), the updated
  `TestOpen_RefusesOtherSchemaVersions` (6 migrates on a read-write open after
  a read-only open named the migration; 8, 99, -3 and 1 to 5 refused),
  `TestOpen_RefusesAPreReleaseSchemaFileUntouched` (pins `this build uses 7`),
  `TestSchemaMessage_AdvisesDeletionOnlyForUnreleasedSchemas`,
  `TestSchema_ConstraintsHoldAgainstDirectSQL`,
  `TestSchema_AutomaticIndexesArePinned`; releaseguards
  `TestReleaseGuards_schemaLineNamesTheMigration` (a header naming v6 is
  refused with "release notes name schema v6 but internal/catalog/schema.go
  writes v7"; `make -n release-check` reads the line before `goreleaser
  check`). The hand-run of 2026-10-15 against the published v0.3.0 binary's
  catalog is recorded in (e).

### D22 (h). The CLI names the key by path and never by value, derives the deciding person from the key, signs after the review and outside the write lock over the head it read, retries once when a crawl landed in the signing window and never under --expect-head, pins every open to the recorded root, and prints fingerprints and nothing else of a key

- Context. (a) to (f) gave the records, the list and the catalog's
  compare-and-set; what remained was the operator's side: where the key comes
  from, who the decision is attributed to, when the signature is made, what
  happens when the head moves, and what the operator must record. The owner
  decided O-13, O-17 and O-18. The research findings that bind the CLI: 2 (one
  namespace per payload type), 3 (the library signs with keys the policy
  refuses, so the CLI relies on `internal/signing`'s policy), 4 (a FIDO2 key
  asks for a touch and a lost one has no backup: the two-key rule), 5 (nothing
  online), 8 (the typed payload), 11 (the head and the root kept off the file:
  the record-the-root rule and the head printed after every signed write).
  The pull request is #52 (PR 7.6, two review rounds).
- Decision (1): the key, by path only (`sshkey.go`). `--ssh-key PATH` (env
  `TOOLWARRANT_SSH_KEY`) is a global flag read as `ssh-keygen -Y sign -f`
  reads it (`signing.KeySource`): a file whose first line is a public key
  means "ask the agent at `SSH_AUTH_SOCK` for exactly this key", and the agent
  is never asked to sign with another; any other file is an unencrypted
  OpenSSH private key under the export key's file rules, a passphrase-protected
  one is refused with `load the key into ssh-agent; toolwarrant does not read
  passphrases`, and a file that is neither is `not a PEM private key; name
  the private key file ssh-keygen wrote (the PEM block), or its .pub to sign
  through ssh-agent` (no PEM marker in any output). An agent that accepts the
  connection and never lists its keys is `ssh-agent at SSH_AUTH_SOCK did not
  answer the key list within 5s; nothing was written; run ssh-add -l to see
  whether it answers`, exit 1, after the signing package's 5 s bound on the
  dial and the list, which `--sign-timeout` does not shorten, and never
  `interrupted`, which only the process's own ^C prints (the CLI tells the two
  apart by its own context); an agent that does not hold the key is
  `ssh-agent at SSH_AUTH_SOCK does not hold the key SHA256:FP`, and a `.pub`
  with no `SSH_AUTH_SOCK` set is refused by name. A key the list does not name
  is refused with its fingerprint and the `trust show` advice once. A path or
  value the operator gave is escaped once, when the refusal is printed, so a
  control character shows as `\u{001B}` and never doubled. The key is
  resolved before the catalog is opened in every command, so a refused key
  changes nothing; it is closed when the command ends. Every signature is
  bounded by `--sign-timeout` (60 s by default): a timeout is `signing timed
  out after 60s waiting for the agent; nothing was written`, and nothing was,
  since every write follows its signature; for a FIDO2 key the command prints
  `touch your security key for SHA256:FP` on stderr before the agent waits.
  The agent's signature is verified locally before it is handed to the catalog
  (`signing.Sign` verifies its own output). Fingerprints are the only key
  material any output carries; the public key line appears only where it is
  the output (`trust show --json`, `trust show --allowed-signers`) and inside
  the payloads `audit list --json` carries.
- Decision (2): the actor from the key (O-13; `signedActor`). With a trust
  list in force the person deciding is the operator the list names for the
  key's fingerprint; `--as`, `TOOLWARRANT_ACTOR` and `budget reset --by` are
  labels that must agree with it (`--as bob names another operator than the
  key SHA256:FP, which the trust list lists for alice`, exit 2, the refusal
  naming the label as it was given: `--as bob`, `--by bob` or
  `TOOLWARRANT_ACTOR=bob`) and may be left out; a key the list does not name
  is refused with its fingerprint, exit 1, and nothing is written; the
  proposer rule holds against the derived name. Without a list the commands
  run as v0.3 ran them, with `warning: this decision is not signed: the
  catalog has no trust list (L13); run "toolwarrant trust init"` on stderr,
  and a key given then is a usage error naming `trust init`, since a signed
  decision needs a list to be verified against and a record with none would
  be `ErrCorrupt` on the walk. With a list and no key every one of the eight
  decisions is exit 2 with the fix (`signing is required since the trust
  bootstrap at entry N; pass --ssh-key PATH (or set TOOLWARRANT_SSH_KEY)
  naming a key the trust list holds`), before anything about the tool is
  read.
- Decision (3): when the signature is made, and the retry (O-17;
  `signflow.go`). A decision reads the catalog identity, the audit head and
  the list in one `SigningState`, reviews the decision as before (the drift
  line, the suspicious-text review), then signs the `toolwarrant/decision/v1`
  payload over that head outside the catalog's write lock and hands the
  record to `Decide`, which compares the head inside its transaction. When
  `Decide` returns `ErrHeadMoved` and the operator named no head, the log grew
  while they signed (a scheduled crawl landed in the window): the command says
  `the log grew while you signed; signing again` on stderr and signs once more
  over the new head; a second move is `the log moved twice while you signed;
  stop the scheduled crawl and try again`, exit 1, and the first signature was
  never written. With `--expect-head HEX` (a flag of every decision and of the
  trust writes) the head read for signing must be the one the operator
  recorded (`audit head mismatch: expected ..., found ...; the log grew since
  you recorded the head or it was rewritten, and nothing was signed`) and a
  head that moves under the signature is refused without a second signature;
  on a catalog without a trust list `--expect-head` is a usage error, since it
  compares the head inside a signed write and an unsigned `Decide` has no
  compare-and-set to compare in. The line after the command's own, `signed as
  alice with SHA256:FP over head PREV; audit head now HEAD`, is the head to
  record. The trust writes go through the same `signedWrite`. The crawler
  starvation of (c) stands: one retry covers the once-a-minute crawl of a
  deployment.
- Decision (4): the trust commands (`trust.go`, `trustshow.go`). `trust init`
  signs a version 1 list naming the acting person (`--as` or the OS user,
  never the system actor) with the key that signs it, records it as the
  bootstrap and prints the root with the record-the-root rule: `trust list v1
  recorded at entry N: alice SHA256:FP` and `decisions from entry N+1 on must
  be signed by a listed key; record the trust root SHA256:FP with the audit
  head HEAD outside the database and pass it as --trust-root (env
  TOOLWARRANT_TRUST_ROOT) to every command and to serve`; a second init is
  refused. `trust add NAME --key PUBKEY_FILE` (the `.pub` as ssh-keygen wrote
  it, comment allowed, options refused) and `trust remove NAME` write the next
  version signed by a listed key, print the list in force and `signed as
  alice`, and refuse, before anything is signed, the last signer's removal
  (`the trust list must keep at least one signer`) and a key signing its own
  removal (`a key cannot sign its own removal; sign with a key that stays`),
  which the catalog's rotation rule refuses again; `remove`'s line ends
  `decisions signed before this entry stand`. `trust show` prints the list,
  its root and its counts, one row per operator with the entry that first
  listed the key (read through `Store.TrustEntries`, the subject index, never
  the whole log), `--json` the view with the key lines and `--allowed-signers`
  the file stock `ssh-keygen -Y verify -f` reads, through
  `trust.AllowedSigners`; without a list it says `no trust list; decisions are
  attributed by name only (L13); run "toolwarrant trust init"` and exits 0.
- Decision (5): the record-the-root rule and the pin. `--trust-root
  SHA256:FP` (env `TOOLWARRANT_TRUST_ROOT`) is a global flag every command
  applies through its open as `OpenOptions.TrustRoot`, `serve`, `audit
  verify` and `audit list --json` included; its shape (`SHA256:` and 43
  base64 characters decoding to 32 bytes) is checked by the CLI and a
  malformed value is exit 2. A catalog whose bootstrap another key signed, or
  that has no trust list, is refused, exit 1; `audit list` in text form lists
  the entries (the forensic view) and its `--json` withholds the records with
  the refusal on stderr; the catalog with no trust list gets the advice `this
  catalog has no trust list: run "toolwarrant trust init" without
  --trust-root (or TOOLWARRANT_TRUST_ROOT), or name the root of the catalog
  you meant`, never the corrupt advice, since a never-bootstrapped catalog (a
  brand-new `init` under `TOOLWARRANT_TRUST_ROOT` included) has no backup to
  restore. The processor prints `signed decisions: enforced from entry B+1
  (trust list vK, R signers, root SHA256:FP at entry B)` or `signed decisions:
  not enabled; the catalog has no trust list (L13 open); run "toolwarrant
  trust init"` after its listening line, and a correctly sealed approval
  appended after the bootstrap without a key makes its next reload fail and
  every hook deny `catalog unavailable`.
- Decision (6): what the readers say (`auditsigned.go`, `showsigner.go`).
  `audit verify` ends, after a clean chain and a clean integrity report, with
  `signed records ok: N decisions and M trust lists verified; trust list vK in
  force (alice SHA256:..., bob SHA256:...); root SHA256:... at entry B; U
  entries before the bootstrap are unsigned history vouched for by alice` and,
  when an approval in force predates the bootstrap, `unsigned approvals in
  service: N (approved before the cut-over at entry B; re-approve them to sign
  them): server/tool` from `IntegrityReport.LegacyApprovalsInService`
  (re-approving is disable, enable, approve, each signed) (Note, 2026-10-16:
  the post-publish follow-up reworded the line to `to sign one, disable,
  enable and approve it, each signed): server/tool, ...`, joined with a comma
  and a space, since a signed `approve` of an approval in force is refused
  with `cannot approve in state enabled`.), or `signed records: none; the
  catalog has no trust list (L13 open)`; a refused record
  is an `integrity problem:` line as every other finding. `audit list --json`
  gives every entry `"signed": {"payload": <base64>, "signature": "-----BEGIN
  SSH SIGNATURE-----...", "signer": "SHA256:..."}` or `null`, through
  `Store.SignedRecords`, and on a broken file keeps listing with `null`
  everywhere and `signed records not shown: ...; run "toolwarrant audit
  verify"` on stderr (the listing is the forensic view, `audit verify` the
  judge). `show` prints `approved by alice, signed with SHA256:FP (audit entry
  N)`, `approved by alice, unsigned (before the cut-over at entry B)` or
  `approved by alice, unsigned (no trust list)` under the versions table and
  `show --json` carries `"signer": {"operator", "key", "entry"}` or `null`,
  from the verified approval entry (`ToolView.ApprovedBy`, `ApprovedSeq`,
  `SignedSeq`).
- Break-glass, as the operations guide states it. A list whose keys are all
  lost has no in-file recovery: no key can sign the next list or a decision,
  and the file cannot be un-bootstrapped. With a second listed key (a
  colleague's, or a backup enrolled under `alice@backup` on day one) the path
  is `trust remove` of the lost key signed by the one that stays, then `trust
  add` of its replacement; what the lost key signed stands. Without one,
  restore from a backup taken before the loss and replay from the signed
  export, or re-initialise (fresh `init`, `server add`, `crawl`, `trust init`
  with the new key, re-approve from the export) and record the new root with
  the new head. A compromised key is removed the same way; its decisions
  before the removal stand and are undone by hand (threshold 1, O-14).
- Exit codes. 2: a decision without a key once a list is in force; a key, or
  `--expect-head`, on a catalog without a list; `--as` (or `--by`) naming
  another operator than the key's; a trust write without a key; the system
  actor; a malformed `--trust-root`; a `--sign-timeout` that is not positive.
  1: a key file that fails the file rules, is encrypted or is neither a key
  nor a `.pub` line; an agent that does not hold the key, cannot be reached or
  does not answer the key list within 5 s; a signing timeout; `audit head
  mismatch` under `--expect-head` or after the log moved twice; a key outside
  the trust list; every trust-list rule refusal; a catalog without a bootstrap
  or with another root under `--trust-root`; every `ErrCorrupt`.
- Where. `cmd/toolwarrant/sshkey.go` (`keySource`, `optionalSigner`,
  `requireSigner`, `cliSigner.sign`, `trustRoot`, `isFingerprint`,
  `operatorOf`, `signedActor`, `labelGiven`, `signerList`), `signflow.go`
  (`decisionFlow`, `beginSigned`, `settle`, `decide`, `report`, `signedWrite`,
  `checkExpectedHead`, `afterSigning`), `trust.go` (`trustCommands`,
  `runTrustInit`, `runTrustAdd`, `runTrustRemove`, `rotateTrustAs`,
  `setTrust`, `readPublicKeyFile`), `trustshow.go` (`runTrustShow`,
  `printAllowedSigners`, `signerSince`), `auditsigned.go` (`reportTrust`,
  `bootstrapActor`, `auditJSON`), `showsigner.go` (`approvalLine`),
  `global.go` (the three flags, `openStore`'s `TrustRoot`), `decide.go`,
  `server.go`, `budget.go` (the eight decisions through the flow), `serve.go`
  (`signedDecisionsLine`), `advice.go`, `main.go` (the `trust` command,
  `app.afterSign`); `internal/catalog/catalog.go` (`ToolView.ApprovedBy`,
  `ApprovedSeq`, `SignedSeq`), `views.go` (`adoptApproval`), `signed.go`
  (`TrustEntries`); [operations.md](operations.md) ("Signing decisions and
  managing the operator trust list", the first paragraph of "Running the
  processor", "Reading the audit log and recording its head", "Exit codes");
  CLAUDE.md (the `cmd/toolwarrant` bullet); CHANGELOG.md (three Added lines).
- Tests and proof. `TestTrustInitRecordsTheBootstrapAndPrintsTheRoot`,
  `TestTrustInitRefusesASecondBootstrapAndTheSystemActor`,
  `TestTrustAddAndRemoveRotateTheListAndRefuseTheLastSigner`,
  `TestTrustShowPrintsTheListTheAllowedSignersFileAndJSON` (its sub-step
  feeds `trust show --allowed-signers` and a record from `audit list --json`
  to the host's `ssh-keygen -Y verify` and `-Y check-novalidate`, and refuses
  it under `-n git`), `TestTrustUsageHelpAndRefusals`, `TestTrustRootShape`,
  `TestDecisionsRequireAKeyOnceATrustListIsInForce` (exit 2 with the fix for
  each of the eight commands), `TestApproveSignsThroughTheAgentAndPrintsTheHead`,
  `TestApproveSignsWithAKeyFileAndRefusesAnUnsafeOne` (every refusal exit 1,
  the agent that lacks the named key pinned with its fingerprint, no `PRIVATE
  KEY` in any output), `TestApproveDerivesTheActorFromTheKeyAndRefusesAMismatch`
  (the three label forms and `--by` over `--as`),
  `TestApproveRetriesOnceWhenTheHeadMovedWhileSigning` (a crawl injected
  between the signature and the write through `app.afterSign`),
  `TestApproveExpectHeadRefusesAMovedLogWithoutARetry`,
  `TestApproveWithoutATrustListWarnsOnStderrAndRefusesAKey`,
  `TestRollbackRejectDisableEnablePauseResumeAndBudgetResetSignLikeApprove`,
  `TestApproveTouchHintIsPrintedForASecurityKey` (an in-process agent that
  serves an Ed25519 key as `sk-ssh-ed25519@openssh.com` and signs as a
  security key does, so the signature verifies under x/crypto's sk verifier
  end to end), `TestSigningTimeoutWritesNothing`,
  `TestSigningTimeoutRefusalRendersWholeSeconds` (`60s`, never `1m0s`),
  `TestAnAgentThatNeverAnswersIsNamedAndWritesNothing` (5.1 s each for
  `approve` and `trust add`, the sentence, the unchanged head and list, no
  `interrupted`), `TestDecisionsAfterTheBootstrapRefuseAnUnlistedKey` (the
  `trust show` advice exactly once),
  `TestAuditVerifyReportsTheSignedRecordsAndLegacyApprovals`,
  `TestAuditVerifyNamesAForgedSignedRecord`,
  `TestAuditListJSONCarriesTheSignedRecord` (the broken-file case included),
  `TestShowNamesTheSignerOrTheLegacyApproval`,
  `TestServePrintsTheSignedDecisionsLineAndRefusesWithoutABootstrapUnderTrustRoot`,
  `TestServeTrustRootRefusesAnotherBootstrap`,
  `TestServeDeniesEveryHookAfterAnUnsignedApprovalIsAppended`,
  `TestEveryCommandRefusesACatalogWhoseRootIsNotTheTrustRoot` (a
  never-bootstrapped catalog and `init` of a brand-new path under the pin
  get the no-trust-list advice, never `restore it from a backup`),
  `TestNoOutputCarriesKeyMaterial` (thirty-seven runs of the signed flow on
  success and on every refusal, the retry, the wrong root, a private key
  handed to `trust add --key` and a `serve` start and stop),
  `TestSelfApprovalAndSystemActorRefusals` (the proposer rule against the
  signer's operator name), `TestHelpAndVersion` and `TestUsageErrors`
  extended; catalog `TestTrustEntries_ListsTheBootstrapAndEveryRotationInOrder`.
  The implementer's live probe of 2026-10-16 (the built binary, a real
  `ssh-agent -a` on a socket under `mktemp -d`, Ed25519 keys, cmd/mockupstream)
  printed `trust list v1 recorded at entry 9: alice SHA256:cRY7...`, `signed
  as alice with SHA256:cRY7... over head 440a80cf...; audit head now
  cb244f99...`, `ssh-keygen -Y verify`'s `Good "decision@toolwarrant.invalid"
  signature for alice with ED25519 key SHA256:cRY7...` and `-n git`'s
  `Couldn't verify signature: namespace does not match`, the key-file approve
  with `SSH_AUTH_SOCK` unset, the hung agent's sentence after 6 s, the
  escaped-once path, the unlisted key's advice once and the plain-text file
  refused with no PEM marker. End to end, scenario S drives the whole surface
  through the built binary and the real gateway with an in-process agent
  (the proof note of row 27 in [threat-model.md](threat-model.md)), and
  scenario N's re-initialised catalog takes an unsigned approval with the
  warning and a processor printing `signed decisions: not enabled`. A FIDO2
  key through a real agent was not available on the implementer's host; the
  touch hint and the sk signature are proven by the in-process agent of
  `TestApproveTouchHintIsPrintedForASecurityKey`, and the owner's proof with a
  real security key is (i)'s.

### D22 (i). The observed first signed approval

- Placeholder (2026-10-16). The owner's first signed approval on their real
  catalog after the v0.4.0 release is to be recorded here, as the plan's
  release round states: the `init` that migrated the v6 file with `audit
  verify`'s head unchanged, the `trust init` line with the root and the head
  recorded, the processors restarted with `--trust-root` and their `signed
  decisions: enforced from entry` lines, the `signed as ... with SHA256:...
  over head ...; audit head now ...` line of the first approval through
  ssh-agent (with a FIDO2 key, the `touch your security key` hint and the
  accepted signature), `audit verify`'s `signed records ok` line and its
  `unsigned approvals in service` count, and the time the first approval took.
  Until the owner fills it, the observed signed approval is the one of
  end-to-end scenario S on 2026-10-16 (Apple M4, agentgateway v1.6.0, an
  in-process ssh-agent, Ed25519): `trust init` recorded the bootstrap at
  entry 47 and printed the root and the head; the signed approve of echo took
  32.6 ms for the whole CLI run and printed `signed as reviewer with
  SHA256:A0ZB... over head 9b27bbb9...; audit head now 31cab125...`; `audit
  verify` printed `signed records ok: 5 decisions and 2 trust lists verified;
  trust list v2 in force (reviewer SHA256:A0ZB..., bob SHA256:UiPs...); root
  SHA256:A0ZB... at entry 47; 46 entries before the bootstrap are unsigned
  history vouched for by reviewer`; and the processor restarted under the
  root was listening 45.4 ms after its start ((e)).
