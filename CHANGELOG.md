# Changelog

Every change an operator can see is recorded here, one line of prose per
change, naming the test that proves it (a change to a document alone names
the document). The file follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
A pull request adds its line under Unreleased; the release commit moves those
lines under a `## [x.y.z] - YYYY-MM-DD` heading and leaves an empty
`## [Unreleased]` above them (CONTRIBUTING.md, Before you open a pull request;
docs/operations.md, Releasing). `make release-check` refuses a tree without
the Unreleased heading and, run as `make release-check VERSION=x.y.z`, one
whose changelog has no heading for that version.

## [Unreleased]

### Added

- The canary (`toolwarrant verify-gateway --admin HOST:PORT`) reads a processor's `policies.backendTLS` block (cert, key, root, hostname) from the emitted file and from the running gateway's `GET /api/config` and compares the two by presence and then field by field, so a processor link that carries TLS on one side only, or another root or hostname, is a `LIVE-CONFIG-MISMATCH` that names the field instead of one "field policies: not in the emitted file" line; a file without the block compares exactly as before (`TestEmittedConfigReadsTheProcessorTLS`, `TestLiveComparisonComparesTheProcessorTLS`, `TestLiveComparisonReportsAnInsecureTLSFlag`, `TestCompareProcessorsSeesAMissingBackendTLS`).
- End-to-end scenario L compares the key paths agentgateway v1.6.0 drops, keeps and adds before the ExtMCP hook with the lists recorded in `e2e/testdata/gateway_tool_keys.json`, and every run writes the lists it saw to `logs/gateway_tool_keys.observed.json` in its work directory so that a moved pin is re-recorded by copying that file; the threat model (L2, L9), docs/decisions.md D10 and docs/operations.md state the recorded lists (`TestToolKeysGoldenRefusesWhatItCannotCompare`).
- `toolwarrant serve --tls-cert PATH --tls-key PATH [--tls-client-ca PATH]` terminates TLS 1.3 on the processor listener and, with a client CA, requires and verifies the gateway's client certificate; a verified client certificate satisfies the non-loopback listen rule in place of the shared secret (owner decision O-2; `TestServe_TLSWithClientCARequiresAClientCertificate`, `TestServeTLSRefusesAGroupReadableKey`). The emitter does not yet write the gateway's `backendTLS` block.
- Both `ci` test jobs run `go test` through gotestsum v1.13.0 and write every test slower than one second to the step summary; `make test-timings` prints the same table locally. A test may consult `testing.Short()` only when its full run exceeds thirty seconds on the runner per that table, and `TestShortPolicy_everyShortSkipIsNamedInCLAUDEAndRunsInFull` fails when such a test is not named in CLAUDE.md or its package is not run in full by the `test-full` job.

### Changed

- `make release-check`, and with it the `ci` release-check job on every pull request, refuses a `go.mod` that carries a `replace` or `exclude` directive or that cannot be read (a `retract` is allowed), a `CHANGELOG.md` without its `## [Unreleased]` heading and, run as `make release-check VERSION=x.y.z`, a changelog without the `## [x.y.z] - YYYY-MM-DD` heading for the version being released (`TestReleaseGuards_refuseAReplaceOrExcludeDirectiveInGoMod`, `TestReleaseGuards_refuseAChangelogWithoutAnUnreleasedSection`, `TestReleaseGuards_refuseAVersionWithoutADatedChangelogEntry`).
- The `ci` docs job checks that every test name `CHANGELOG.md` and CONTRIBUTING.md cite is a test function and that their relative links resolve, as it already did for README.md, SECURITY.md, CLAUDE.md, `docs/` and `seam/RESULTS.md`; CONTRIBUTING.md states the changelog rule and names the two tests that prove the changelog guards.
- SECURITY.md promises an acknowledgement of a vulnerability report within two days, and a confirmed problem still open fourteen days after the report gets a dated note in the advisory saying why and when (owner decision O-4; the policy said seven days before).
- A tag is never moved or deleted; a bad release is a new tag plus a `retract vX.Y.Z // reason` directive in `go.mod` (SECURITY.md Release integrity, CONTRIBUTING.md Branches and commits, docs/operations.md Releasing). Release candidates and their releases are kept rather than deleted before the final tag.
- SECURITY.md names the two public logs that anchor a release, the Rekor entry inside the signature bundle and sum.golang.org's record of the module at each tag, and gives the procedure that rebuilds a release byte for byte from a clean clone at the tag; docs/operations.md Releasing fetches each new tag through the module proxy right after publishing, checks that the record exists, and records the repository settings as they stand (rulesets, secret scanning, immutable releases still to be enabled).

### Fixed

- The catalog pins `synchronous(FULL)` in the connection string of every pooled connection of every open mode, so an approval, a rollback or a crawl is on the disk before its command returns, across a power loss and not only across a crash of the process; the driver's compile-time default was relied on before (`TestOpen_EveryPooledConnectionIsSynchronousFullWithForeignKeysInWAL`).

## [0.1.1] - 2026-10-14

### Fixed

- `Approved`, which `emit` and `export` read, anchors the state of every tool row of the server before leaving one out, so a tool whose state column was edited by hand is `ErrCorrupt` on the emit path as it already was for `list`, `audit verify` and the crawl; before, `emit` wrote a gateway file with one allow rule fewer, exit 0 and no change line (`TestApproved_ToolHiddenByAColumnFlipIsCorrupt`, `TestEmitRefusesACatalogWhoseToolStateColumnWasEdited`).
- `Snapshot`, which the processor serves from, anchors every row of the server before leaving deprecated ones out, so a row flipped to deprecated by hand is `ErrCorrupt` on the serving path instead of a tool that vanishes from the policy without an error (`TestSnapshot_ToolDeprecatedByAColumnFlipIsCorrupt`).

### Changed

- `make release-check`, which the `ci` release-check job runs on every pull request, fails when the platform list of `scripts/gen-third-party-notices.sh` differs from the goos x goarch of `.goreleaser.yaml`, since the notices would then miss a platform's modules, and when the signing block loses `--bundle`, the flag without which cosign v3 writes no signature.
- The `ci` lint job runs actionlint v1.7.12 on both workflow files, so an expression or schema error in `release.yml` fails a pull request instead of the tag that runs it, which is how three release candidates were spent on 2026-10-12.

## [0.1.0] - 2026-10-12

First release. toolwarrant for MCP is a control plane in front of agentgateway v1.6.0: it crawls upstream MCP servers, stores every tool definition as an immutable version identified by the SHA-256 of its RFC 8785 canonical JSON, lets a named person approve one exact digest, emits the gateway configuration and enforces the approval at the gateway as an ExtMCP processor in strict mode, so that a tool is served only while its live definition hashes to the approved digest. Nothing is served until approved and a crawl never approves anything. The catalog is an SQLite file at schema v6 with a hash-chained audit log. The release carries the `toolwarrant` binary for darwin/arm64, darwin/amd64, linux/amd64 and linux/arm64, built from the tagged commit with CGO disabled and `-trimpath`, one SPDX SBOM beside each archive, and a checksums file signed keyless with cosign by the release workflow (docs/decisions.md D16; verification in SECURITY.md, Release integrity).

[Unreleased]: https://github.com/sairam0424/toolwarrant/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/sairam0424/toolwarrant/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/sairam0424/toolwarrant/releases/tag/v0.1.0
