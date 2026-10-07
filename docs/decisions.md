# Design decisions D1 to D10

These records are taken from the commit messages that state each decision: the
five wave-1 commits of 2026-10-07 (b9e4533 core, 29dd670 processor, f2a3e5a
emit, c728172 crawl and fetch, 20e32b4 textdiff and export) and the catalog
commit 8b7a574. The post-review section of [../seam/RESULTS.md](../seam/RESULTS.md)
quotes the same decisions and records the corrections they forced to the spike's
findings. Each record gives the context (what the review found), the decision,
its consequences for operators and for other packages, and where it lives in
code with the tests that pin it.

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
  lone or ill-paired surrogate escapes (`ErrNotUTF8`) and refuses numbers that
  are not exact doubles (`ErrNumberPrecision`). `VolatileKeys` stays exported
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
- Where. `internal/gate/digest.go`, `internal/gate/numbers.go`;
  `internal/catalog/schema.go` (the `digest_profile` column). Tests:
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
  is logged once at Debug (`hook names another backend`) and counted in
  `Stats.WrongBackend`, so an operator can pin the real value with
  `serve --target`. The exact `service_names` value is assumed to be the backend
  target name; the live gateway showed `services=["other"]` for a backend named
  `other`, consistent with that, and the end-to-end test will confirm it. Tests
  that send hooks must carry `ServiceNames`.
- Where. `internal/processor/guard.go` (the admit check),
  `internal/processor/processor.go` (`Config.Target`);
  `internal/emit/validate.go`. Tests: `TestAdmit_HooksAboutAnotherBackendAreDenied`,
  `TestAdmit_AnotherRoutesCallNeverRidesOnThisServersApproval`,
  `TestAdmit_TargetMayDifferFromTheServerName`, `TestAdmit_FirstWrongBackendIsLoggedOnce`;
  emit `TestDuplicateProcessorAddrNamesBothServers`.

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
  entries with their reason, and `crawl --strict` exits 1 when any tool was
  rejected or unusable (CLI wiring in the current wave). The crawl package's
  `ErrDuplicateTool` is never returned any more. The processor parses every
  page twice.
- Where. `internal/processor/filter.go`, `internal/processor/list.go`,
  `internal/processor/observed.go`; `internal/crawl/vet.go`,
  `internal/crawl/list.go`; `internal/lifecycle/observe.go`
  (`UnusableDigest` in `internal/lifecycle/lifecycle.go`); `internal/catalog/crawlprep.go`,
  `internal/catalog/crawl.go`. Tests:
  `TestCheckResponse_RepeatedNameDeniesThePageAndTheCallsUntilACleanPage`,
  `TestUnusableToolsDoNotFailTheCrawl`, `TestRepeatedNamesMakeEveryCopyUnusable`,
  `TestObserveUnusable_MarksLastSeenAndChangesNothingElse`,
  `TestRecordCrawl_PoisonNameIsQuarantined`, `TestRecordCrawl_DuplicateNamesAreUnusable`.

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
  every proposer at once, for a lab.
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
- Consequence. Excess becomes a denial or a hidden tool, never a pass. A tool
  over 256 KiB can never be approved. A tool that changes faster than people
  decide is hidden until someone decides (limit L6). A listing over a cap is
  recorded as a failed crawl with a class. Fifteen oversized tools (7.5 MiB)
  cost 371 ms for the page where one 16 MiB tool cost 1.75 s before.
- Where. `internal/processor/limits.go`, `internal/processor/serve.go`;
  `internal/catalog/catalog.go` (exported caps), `internal/catalog/crawlprep.go`,
  `internal/catalog/tooldef.go`; `internal/crawl/config.go`. Tests:
  `TestCheckResponse_OversizedPayloadIsDenied`, `TestServe_RecvLimitIsThePayloadCap`,
  `TestConcurrency_HooksBeyondTheSlotLimitAreDeniedNotQueued`,
  `TestCheckResponse_OversizedToolIsHiddenUnhashedAndDeniesCalls`;
  catalog `TestRecordCrawl_ProposalBudgetCapsVersions`,
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
  such a file 0600 and warns (current wave). The CLI exposes `--secret-env` on
  `emit` and `serve`. Whether the live gateway delivers `metadata_context` on
  the response hook could not be confirmed with `--validate-only`; if it did
  not, every `tools/list` would be denied while a secret is set (fail closed,
  visible as `Stats.Unauthenticated`). The end-to-end test settles it. The two
  packages' key constants are pinned equal by a test.
- Where. `internal/processor/guard.go`, `internal/processor/serve.go`,
  `internal/processor/processor.go` (`Config.Secret`, `SecretMetadataKey`);
  `internal/emit/emit.go`, `internal/emit/quote.go`. Tests:
  `TestAdmit_SharedSecretIsRequiredOnEveryHook`, `TestServe_SharedSecretIsCheckedOverGRPC`,
  `TestWire_SecretIsReadFromMetadataContextOnBothHooks`,
  `TestWire_SecretMetadataKeyIsTheOneEmitWrites`,
  `TestServe_RefusesAListenerReachableFromOtherHosts`; emit
  `TestSecretWrittenAsCELStringLiteral`, `TestHostileSecretsAreValidCEL`.

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
  `LastSeen` within the crawl cadence (limit L1). A tool that was never listed
  through the gateway and never crawled is denied. `MaxEvidenceAge` also ages
  conflict markers (limit L15).
- Label note. The catalog commit 8b7a574 also labels `PauseServer` and
  `ResumeServer` "(D9)". To keep the numbering of RESULTS.md, that decision is
  recorded here as D9a: a paused server refuses crawls (`ErrPaused`), its
  snapshot is empty so nothing of it is served, and decisions keep working
  until `ResumeServer`. Pause and resume write `server.paused` and
  `server.resumed` audit entries and require a human actor.
- Where. `internal/processor/call.go` (`judgeCall`); D9a in
  `internal/catalog/servers.go`. Tests: `TestJudgeCall_RuleTable`,
  `TestJudgeCall_NonDigestLastSeenMarkersDenyAsUnverified`,
  `TestCheckRequest_AbsentOrUncrawledToolsNeedOnePieceOfEvidence`,
  `TestCheckRequest_DeniesWhenTheLatestCrawlDiffersEvenIfNeverListed`,
  `TestEvidence_ObservedDigestsExpire`; catalog `TestPauseAndResumeServer`.

## D10. Digest mismatches are counted and reported, not hashed around

- Context. agentgateway v1.6.0 re-serialises tool definitions before the ExtMCP
  hook and drops top-level keys and `annotations` keys it does not know
  (MEDIUM). A tool carrying such a key is permanently "changed since approval":
  the crawler's digest can never equal the gateway's. Before D10 such a tool
  was indistinguishable from an unapproved one.
- Decision (29dd670 processor). Mismatches are counted apart from unapproved
  tools (`Stats.ToolsMismatched` against `Stats.ToolsUnapproved` and
  `Stats.ToolsOversized`) and logged at Info as `digest mismatch` with quoted
  names. v0.1 does not hash a projection of what the gateway re-serialises; it
  detects the case and reports it, so the tool stays hidden.
- Consequence. Limit L2: such a tool cannot be served in v0.1 at all, because
  the catalog can only approve what the crawl saw and the gateway never serves
  those bytes. The `serve` stats line prints the breakdown and `verify-gateway`
  reports the case as MISMATCH (CLI wiring in the current wave, to be verified
  by the end-to-end test). A mismatch on a tool that was just approved is this
  case, not drift.
- Where. `internal/processor/results.go`, `internal/processor/list.go`,
  `internal/processor/processor.go` (`Stats`); the known limit is also stated in
  the package comments of `internal/gate` and `internal/processor`. Tests:
  `TestCheckResponse_MismatchedAndUnapprovedAreCountedApart`,
  `TestCheckResponse_LogNamesTheBrokenToolButTheClientReasonDoesNot`.
