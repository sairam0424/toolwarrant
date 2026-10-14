# CLAUDE.md

toolwarrant is a control plane in front of the agentgateway v1.6.0 MCP gateway: it crawls upstream MCP servers, stores every tool definition as an immutable version identified by the SHA-256 of its RFC 8785 canonical JSON, lets a named person approve one exact digest, and enforces that approval at the gateway as an ExtMCP processor (strict mode: a tool is served only while the live definition hashes to the approved digest). Nothing is served until approved, a crawl never approves anything, and everything an upstream sends is hostile.

## Stack

Go 1.27 (`go.mod`: `go 1.27`, `toolchain go1.27.2`), one module `github.com/sairam0424/toolwarrant`, pure Go (modernc.org/sqlite, no cgo). Dependencies: gowebpki/jcs (RFC 8785), modernc.org/sqlite, google.golang.org/grpc v1.86.0-dev, google.golang.org/protobuf v1.36.12, golang.org/x/text, modelcontextprotocol/go-sdk v1.8.0 (seam tools and tests only), pgregory.net/rapid (tests only, MPL-2.0). Lint: golangci-lint v2.14.0 with the repository `.golangci.yml`. Licence Apache-2.0; `THIRD_PARTY_NOTICES.md` is generated.

## Commands

Always `export GOFLAGS=-mod=readonly`. Never `go get` or `go mod tidy` without regenerating `THIRD_PARTY_NOTICES.md` in the same commit. The Makefile wraps the common runs.

```sh
make build                                            # go build ./... && go vet ./...
make test                                             # go test -race -count=1 -timeout 1500s -cover ./... (prints per-package coverage)
make test-timings                                     # the same run under gotestsum --format pkgname, then every test slower than 1s (needs gotestsum on PATH: go install gotest.tools/gotestsum@v1.13.0)
make lint                                             # gofmt, go vet (also -tags e2e), golangci-lint (also --build-tags e2e)
make vuln                                             # govulncheck ./... (install: go install golang.org/x/vuln/cmd/govulncheck@v1.9.0, the version CI pins)
make e2e                                              # go test -tags e2e -count=1 -timeout 900s -v ./e2e against the real gateway
make demo                                             # demo/run.sh: builds, runs the e2e test, keeps demo/last-run.log
make release-guards                                   # go.mod has no replace or exclude; CHANGELOG.md has an Unreleased section and, with VERSION=x.y.z, the entry for that version
make release-check                                    # release-guards, then goreleaser check; the release notes name the schema version the code writes; the notices script's platform list equals goreleaser's goos x goarch; the checksums are signed as a bundle
make release-snapshot                                 # goreleaser snapshot into dist/ (gitignored): four archives, SBOMs, checksums; unsigned
go build -o bin/ ./cmd/...                            # binaries; bin/ is gitignored
go test -short -race -count=1 -timeout 900s ./...     # skips six tests, named below
go test -race -count=1 -run 'TestCheckRequest_DeniesWhatIsNotApproved' ./internal/processor/
go test -run '^$' -fuzz FuzzCheckResponse -fuzztime 20s ./internal/processor/
go generate ./internal/extmcpv1                       # regenerate the ExtMCP stubs; refuses other protoc/plugin versions
scripts/gen-proto.sh --check
scripts/gen-third-party-notices.sh --check            # must pass whenever go.mod changed; 40-55 s; needs a compiling tree
scripts/requalify-gateway.sh vX.Y.Z SHA256 [--e2e]   # the L7 checklist against a candidate gateway release (docs/operations.md, Moving the gateway pin); runs the binary only through the tests and make e2e
seam/run.sh guarded; seam/day5.sh; seam/day34-paging-latency.sh; seam/day34-sessions.sh; seam/day34-reload.sh
```

`-short` skips six tests: the three Unicode walks of `internal/textdiff`
(`TestEscape_everyRune`, `TestEscape_coversEveryRuneTheToolNameRuleForbids`,
`TestNames_noSuspiciousRuneHasAnEmptyName`), two slow catalog tests
(`TestVerifyAudit_PagesThroughLargeLogs`,
`TestRecordCrawl_LargeCrawlDoesNotBlockADecision`) and the processor's gRPC size
test (`TestServe_AcceptsAPageOverGRPCsDefaultLimit`); the CI `test-full` job
runs those three packages without `-short`.

The `-short` policy: a test may consult `testing.Short()` only when its full run
exceeds thirty seconds on the runner per the timing table; every such test is
named in CLAUDE.md and runs in full in `test-full`. The timing table is the
"tests slower than 1s" step of the `test` and `test-full` jobs (gotestsum
v1.13.0 runs `go test` with `--jsonfile`, then `gotestsum tool slowest
--threshold 1s` writes every test over one second, slowest first, to the step
summary, also after a failure); `make test-timings` prints the same table
locally. `TestShortPolicy_everyShortSkipIsNamedInCLAUDEAndRunsInFull` in
`internal/shortpolicy` parses every Go file of the module, not only the test
files, and fails when a test or fuzz target consults `testing.Short()` without
being named in this file or without its package on the `test-full` command line,
and when anything else consults it: a helper, a method, `TestMain`, a benchmark,
or any function in a file without the `_test.go` suffix (a shared helper there
would otherwise hide the skip).

The seam scripts and the end-to-end test need the v1.6.0 release binary at `.cache/agentgateway-darwin-arm64` (gitignored; `TOOLWARRANT_GATEWAY_BIN` overrides the path) and the seam scripts need the four seam binaries in `bin/`. Outside the seam scripts and `make e2e` (which starts the gateway on loopback ports it picks itself and stops it) the gateway binary may only be run with `--validate-only`. The e2e scenarios share one stack and depend on each other's end state, so run the whole `TestEndToEnd`, not one subtest. Anything over two minutes runs in the background with output to a file.

The CI workflow is `.github/workflows/ci.yml`, triggered by every pull request and every push to main: lint (gofmt, go vet, golangci-lint, and actionlint on both workflow files), vet and build, the short test suite under `-race`, the three packages whose tests `-short` skips (`internal/textdiff`, `internal/catalog`, `internal/processor`) in full (both test jobs run `go test` through gotestsum v1.13.0, one line per package and the failed tests' output at the end, and write the tests slower than one second to the step summary), govulncheck, gitleaks, the notices check, the release configuration check (`make release-check`), and the documentation checks (every test name cited in README.md, SECURITY.md, CONTRIBUTING.md, CLAUDE.md, CHANGELOG.md, docs/ and seam/RESULTS.md must exist as a test function, every relative link must resolve). The e2e job runs on `workflow_dispatch` only, against the linux release binary checked against the recorded checksum; it passed on 2026-10-12. The `requalify` job runs on a dispatch whose inputs `gateway_version` and `gateway_sha256` name a candidate release and runs `scripts/requalify-gateway.sh --e2e` against it (`TestRequalifyCI_dispatchJobRunsTheScript`). Run the documentation checks by hand with:

```sh
for n in $(grep -ohE '\b(Test|Fuzz)[A-Z_][A-Za-z0-9_]*' README.md SECURITY.md CONTRIBUTING.md CLAUDE.md CHANGELOG.md docs/*.md seam/RESULTS.md | sort -u); do grep -rqE "^func $n\(" --include='*_test.go' --exclude-dir=.cache --exclude-dir=.git . || echo "missing test: $n"; done
```

## Repository layout

- `cmd/toolwarrant`: operator CLI, a thin client of the internal packages; `run()` is driven in-process by tests, `main` only exits.
- `cmd/mockupstream`, `cmd/seamclient`, `cmd/seamgate`, `cmd/seamprocessor`: spike scaffolding for the seam tests and the e2e test; never deployed.
- `internal/catalog`: SQLite registry (schema v6, the first released schema; a v2, v3, v4 or v5 file from an unreleased build is refused with `ErrSchema` and must be re-initialised; a later schema will name the build that reads a v6 file or carry a migration, never the delete advice); the only writer of lifecycle state and the audit log, in one transaction; per-crawl and per-server caps and the per-crawl cap on rejected entries, quarantine, proposal budget and its reset, each server's processor address, integrity checks (guard and table DDL, the no-delete, no-replace and positive-id guards, every checked read and write refusing a history row or audit row below id 1 (a forensic open reads past such a row, as it reads past a missing guard), and the absence of foreign triggers, views, unique indexes and unaccounted automatic indexes; the newest-decision rule and the newest audit entry for every approved version; the whole chain verified once at open and the suffix after the pin on every reload, every walk starting at the smallest possible seq, bound included, so a row at seq 0 or below is a chain break, with the locally computed hash of every decision entry kept in memory, so that the serving path and the decision path trust an audit entry only when its hash computed from its fields equals the one that walk recorded, never the stored hash column; every version's status and ever-approved flag reconstructed from the verified entries on every decision and in `Versions`, a rollback target accepted only when a verified approval or rollback entry names its digest; `Server` and `Servers` checked like every other view and anchored to the verified `server.processor_set`, `server.added` and newest `server.paused` or `server.resumed` entries, and the paused flag anchored on every path that acts on it (`Snapshot`, `RecordCrawl`, pause and resume); every tool's state column anchored to the newest verified lifecycle entry about the tool on every path that acts on it (`Snapshot`, `Tools`, `Tool`, `Approved`, the decisions, the crawl; `Approved` and `Snapshot` anchor every tool row of their scope before leaving one out, so an edited state cannot hide a tool from emit, export or the processor); the server row anchored to the first `server.added` entry, a second one reported by `Integrity`; `Approved` taking the approver from the verified entry; every checked read taking the walk lock before its first statement, so that a read snapshot never predates the pin it is compared with; the catalog identity and the file's device and inode compared on every read against a replaced file; `Integrity` verifying every entry's seal and link as it streams the log, comparing the row count with the entries walked, and cross-checking every mutable column and every subject the log describes). The trust boundary is D14, D15 and D17: whoever can write the file can append a correctly sealed entry; a forger who rewrites an entry must rewrite every entry from it to the head, which a running `Store` catches through its pin, and which, made while no `Store` holds a pin (the CLI between commands, the processors while stopped), is caught by the recorded head, the git export and backups alone.
- `internal/lifecycle`: pure state machine (states, commands, events, `Serves`) and the exported digest-shape rule (`IsDigest`, `LastSeenVerifiable`) that the processor and the canary share; property-tested invariants.
- `internal/gate`: RFC 8785 canonicalisation and SHA-256 digest, profile `full-v1`; refuses inexact numbers and non-UTF-8.
- `internal/audit`: hash chain over audit entries (`Seal`, `Verify`, `VerifyFrom`, `Head`).
- `internal/crawl`: raw MCP Streamable HTTP `tools/list` client; vets every tool, quarantines, never approves.
- `internal/fetch`: the only egress path; SSRF-hardened dialer (connect-time address checks, DNS pinning, caps).
- `internal/processor`: ExtMCP gRPC processor; list filtering, call rule, caps, shared secret, digest cache, observed-evidence table sized from the snapshot, holding evidence for every catalog tool a page names (servable or not) and kept across a pause; an unreadable page marks every servable tool, a page the gRPC transport refuses for size is observed on the `CheckResponse` call and marks them too, and a page seen while the snapshot is empty (paused server) is judged against the names already tracked; a replaced catalog file is a source error. Listener TLS (`Config.TLS`): TLS 1.3 forced on a copy of the caller's configuration, server-only or with a client CA that then authenticates the hooks in place of the shared secret (O-2, D19); a configuration with no certificate or with client verification against no authority is refused.
- `internal/emit`: agentgateway v1.6.0 config emitter; gateways form with a loopback bind, listener inputs, explicit allow rules, failClosed, sha256 header, `Verify`, validation with the gateway binary, the request-header filter on every processor entry, refusal of a processor address on one of the gateway's own sockets (compared with the input's own bind and listener addresses; a host that is a name rather than an IP literal is refused on any port the gateway binds, since a name may resolve to this host) and of a numeric-looking host that is not an IP literal; the loopback aliases common resolvers map without DNS count as loopback. The gateway's `backendTLS` block on a processor entry (`Server.TLS`, D19): all four fields or none, absolute printable-ASCII paths on the gateway host that the emitter never opens, a DNS hostname (an IP literal is refused), written after the request-header filter and before the metadata where the canary reads it; the gateway's `--validate-only` opens the three files, so validating with the binary needs them on the emitting host.
- `internal/export`: write-only mirror of approved definitions into a directory and git; crash-safe manifest.
- `internal/textdiff`: escaped diff renderer and invisible-character findings for approvers.
- `internal/drift`: advisory classifier of the change between two tool definitions (`Compare` over two canonical documents): a kind and a grade (INFO, WARNING, CRITICAL) per changed member, the report's `Max`, `Kinds` and `Summary`, findings sorted by grade then path; a description change is WARNING (O-6), a loosened annotation hint, a removed, retyped or newly required parameter and a changed name are CRITICAL; paths escaped through `textdiff.Escape`, no detail carries upstream bytes, invalid documents refused without echoing them; the gate stays the digest. Shown by `diff` (the `drift:` line), `show` (the CHANGE column, the grouping line, `change` in `--json`) and `approve` (printed, never gating).
- `internal/toolname`: the one tool-name rule shared by crawler, catalog, processor and emitter.
- `internal/strictjson`: rejects JSON objects that two parsers could read differently.
- `internal/mcpwire`: pure helpers over raw MCP JSON-RPC payloads; the entry count of a `tools/list` page is taken by a streaming decoder that stops at the cap before the array is materialised.
- `internal/shortpolicy`: no code, only the test that enforces the `-short` policy above against every Go file of the module, CLAUDE.md and the `test-full` command of ci.yml.
- `internal/requalifypolicy`: no code, only the tests that keep `scripts/requalify-gateway.sh` honest: every test it names exists, every e2e scenario it reads is one of `TestEndToEnd`, the seventeen items are each reported once, and the `requalify` job of ci.yml runs it (`TestRequalifyScript_citesExistingTestsAndScenarios`, `TestRequalifyScript_reportsEveryItemOnce`, `TestRequalifyCI_dispatchJobRunsTheScript`).
- `internal/testcert`: test-only certificate material (an ECDSA CA, a server certificate with the DNS SAN `toolwarrant-processor` and the loopback IP SANs, client certificates), generated when a test asks and written owner-only; no key material is in the tree. Used by the processor's and the serve command's TLS tests, and by end-to-end scenario Q.
- `internal/releaseguards`: no code, only the tests of the three guards `make release-check` runs first (`make release-guards`), run against scratch copies of the Makefile, go.mod and CHANGELOG.md, and of `scripts/release-notes.sh`, the release workflow's notes step (a final tag's own changelog section, a candidate's fallback to Unreleased, the refusals), run against scratch changelogs, plus the check that release.yml hands the file to goreleaser and `.goreleaser.yaml` keeps the changelog pipe enabled.
- `internal/extmcpv1`: generated ExtMCP stubs (package `api`) from `third_party/agentgateway/ext_mcp.proto`.
- `e2e/`: the end-to-end test behind the `e2e` build tag (`TestEndToEnd`, scenarios A to Q on one shared stack; Q runs right after H and puts TLS on mock's processor link; `e2e/testdata/gateway_tool_keys.json` is the L2 golden of the key paths the gateway drops, keeps and adds, which scenario L compares exactly); `demo/run.sh` runs it unattended into `demo/last-run.log` (gitignored).
- `seam/`: spike scripts and gateway configs; `seam/RESULTS.md` holds findings F1 to F5, decisions D1 to D10 as the commits state them, and the post-review corrections after each review round.
- `scripts/`: `scripts/gen-proto.sh`, `scripts/gen-third-party-notices.sh`, `scripts/requalify-gateway.sh` with its helpers `scripts/requalify-lib.sh` (the L7 checklist; docs/operations.md, Moving the gateway pin), `scripts/release-notes.sh` (the CHANGELOG.md section a tag publishes; run by the release workflow, usable by hand before a tag).
- `docs/`: `docs/threat-model.md`, `docs/decisions.md` (D1 to D20), `docs/operations.md`.
- `CHANGELOG.md`: one prose line per change an operator can see, under `## [Unreleased]` until the release commit moves the lines under `## [x.y.z] - YYYY-MM-DD` (keep a changelog; `make release-check` refuses a tree without the Unreleased heading and, with `VERSION=x.y.z`, without that version's heading).
- `.github/workflows/ci.yml`: the CI workflow; `.github/workflows/release.yml`: the release workflow on `v*` tags, gated on a successful `ci` run of the tagged commit and on no published release for the tag; it takes the notes from CHANGELOG.md through `scripts/release-notes.sh`, attests the archives and SBOMs (SLSA provenance, the `.intoto.jsonl` asset) and rebuilds linux/amd64 against the archive (D16, D20); `.goreleaser.yaml`: what a tag builds, signs and publishes as a draft (D16), with no changelog block, since goreleaser v2.18.2 reads `--release-notes` inside the changelog pipe and `disable: true` would skip the file with the pipe.

## Rules

- Conventional commits (`type(scope): subject`) with a WHY paragraph in the body; no `Co-Authored-By` trailer.
- Tests before commit: every behaviour change gets a test; gofmt, go vet and golangci-lint clean; `go test -race` on the touched packages; keep existing tests passing or say which design decision changed them.
- Nothing is pushed, tagged, published or registered without the owner.
- Keep "MCP" out of the product name; "toolwarrant for MCP" is the permitted form.
- Treat upstream text as hostile: `textdiff.Escape` in text mode, `strconv.Quote` in logs, never print tokens or credential-bearing URLs, fail closed.
- Read `seam/RESULTS.md` (including its post-review sections) and `docs/decisions.md` D10 to D20 before changing anything the gateway sees: `internal/emit`, `internal/processor`, `internal/extmcpv1`, `cmd/toolwarrant/verify.go`, `cmd/toolwarrant/probe.go`, `cmd/toolwarrant/liveadmin.go`, `cmd/toolwarrant/livecompare.go`, `cmd/toolwarrant/livetls.go`, `cmd/toolwarrant/servetls.go`.
- Documents cite tests by their exact names and state what the logs show, not what was expected; when a test is renamed, update every document that cites it (the CI `docs` job fails otherwise). Plain prose, no marketing language, no em dashes.
- A change an operator can see adds one prose line under `## [Unreleased]` in `CHANGELOG.md`, naming the test that proves it; the release commit moves those lines under the version's heading and leaves an empty `## [Unreleased]` above them.
- Style: a doc comment on every exported identifier saying why; lower-case error messages wrapped with `%w`; named constants; functions under about 50 lines, files under about 400; no package-level mutable state.
- Test files must not contain literal invisible or format characters: build them at run time or use `\u` escapes, then check with `grep -P`.
- Never edit `go.mod`, `go.sum`, `.gitignore`, `.cache/`, `seam/` or `third_party/` as part of an unrelated change; `seam/RESULTS.md` is only appended to or corrected, measured results are never removed.

## Pinned external versions

agentgateway v1.6.0 (ExtMCP proto and config schema); modelcontextprotocol/go-sdk v1.8.0; MCP revision 2026-07-28; google.golang.org/grpc v1.86.0-dev (GO-2026-6443 fix; move to v1.85.0 when tagged); protoc v7.36.2 (libprotoc 36.2), protoc-gen-go v1.36.12, protoc-gen-go-grpc v1.6.2; golangci-lint v2.14.0.
