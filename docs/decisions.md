# Design decisions D1 to D12

These records are taken from the commit messages that state each decision: the
five wave-1 commits of 2026-10-07 (b9e4533 core, 29dd670 processor, f2a3e5a
emit, c728172 crawl and fetch, 20e32b4 textdiff and export), the catalog
commit 8b7a574, the emitter commit 611e081, the end-to-end commit 21164fd, and
the commits of the third review round (2026-10-11), which state D11 and D12 and
the catalog integrity changes recorded in [threat-model.md](threat-model.md)
rows 20 and 21. The post-review sections of
[../seam/RESULTS.md](../seam/RESULTS.md) quote the same decisions and record the
corrections they forced to the spike's findings. Each record gives the context
(what a review found), the decision, its consequences for operators and for
other packages, and where it lives in code with the tests that pin it. Where a
decision is proven on the real gateway, the end-to-end scenario is named:
`TestEndToEnd` in `e2e/` runs scenarios A to P against the agentgateway v1.6.0
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
  `ServiceNames`.
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
  callable until a clean crawl records the approved digest. A page the
  processor denies as a whole, whatever denied it (a repeated name, a tool it
  cannot read or hash, more than 10000 tools), leaves the conflict marker on
  every catalog tool it listed, so a decoy placed next to a changed tool
  cannot keep that tool's older evidence alive: its calls are denied as changed
  until a clean page shows the approved digest (third round; the second
  review's decoy pages had kept `tools/call` passing until the next crawl). The
  crawl package's `ErrDuplicateTool` is never returned any more. The processor
  parses every page twice.
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
  duplicate page through the gateway is denied as a whole).

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
  carries one must be 0600 and readable by the gateway alone; the CLI writes
  such a file 0600 and warns. The CLI exposes `--secret-env` on `emit` and
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
  A `LastSeen` that is the unusable marker hides the tool from listings too
  (D3), so what is listed is exactly what is callable. `MaxEvidenceAge` also
  ages conflict markers (limit L15).
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
- What the gateway strips. The end-to-end scenario L lists a tool carrying an
  unknown top-level key, an unknown `annotations` member and a `_meta` member
  through the gateway and diffs what a client received against what the
  upstream served (`demo/last-run.log`): dropped `x-vendor` (with its member
  `x-vendor.tier`) and `annotations.x-risk`; kept `annotations.title`,
  `annotations.readOnlyHint` and the `_meta` member `vendor/ui`; nothing added.
  The second review's lab, which is not pinned by a test in this tree,
  additionally observed a `_meta` member named `ui` and a top-level `execution`
  key dropped while `openai/outputTemplate` under `_meta`, `title`,
  `outputSchema`, `icons` and vendor keys inside `inputSchema` survived, and
  numbers re-serialised (`1e2` as `100.0`, harmless under RFC 8785). The two
  observations agree on unknown top-level and `annotations` keys; on `_meta`
  they show that some members survive and some do not, and neither log records
  the rule, so a `_meta` member must be assumed droppable until the pinned
  gateway version shows otherwise (limits L2 and L9). Scenario L re-derives the
  list on every run, so a move of the gateway pin re-derives it.
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
  scenario L.

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
with its live-configuration comparison and its unhooked-call probe (D12), the
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
  MISMATCH sub-label and exit 1, with or without `--config`.
- Where. `cmd/toolwarrant/verdicts.go` (`compare`, the LEAK rule),
  `cmd/toolwarrant/verify.go` (`--admin`, the probe, `--no-probe`),
  `internal/emit/listeners.go` (the listener inputs). Tests: cmd
  `TestCompareSortsLiveToolsIntoVerdicts`,
  `TestVerifyGatewayReportsLeaksAgainstAPassThroughUpstream`,
  `TestVerifyGatewayChecksTheEmittedConfig`; e2e scenarios F (CONFIG-EDITED and
  LEAK across a hand edit, and the `--every 1s --keep-going` canary that
  exited 1 on SIGTERM after reporting both), O (UNHOOKED-CALLS, exit 1, from
  the pinned binary's HTTP 202, with the probe in the hostile upstream's
  request log; `--no-probe` reports the probe as skipped) and P
  (LIVE-CONFIG-MISMATCH, exit 1, after the processors were removed through
  `POST /api/config`, against a byte-identical copy of the emitted file; the
  gateway rewrote the watched file with the header lines kept, so that file
  reported CONFIG-EDITED).
