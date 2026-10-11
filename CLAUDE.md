# CLAUDE.md

toolwarrant is a control plane in front of the agentgateway v1.6.0 MCP gateway: it crawls upstream MCP servers, stores every tool definition as an immutable version identified by the SHA-256 of its RFC 8785 canonical JSON, lets a named person approve one exact digest, and enforces that approval at the gateway as an ExtMCP processor (strict mode: a tool is served only while the live definition hashes to the approved digest). Nothing is served until approved, a crawl never approves anything, and everything an upstream sends is hostile.

## Stack

Go 1.27 (`go.mod`: `go 1.27`, `toolchain go1.27.2`), one module `github.com/sairam0424/toolwarrant`, pure Go (modernc.org/sqlite, no cgo). Dependencies: gowebpki/jcs (RFC 8785), modernc.org/sqlite, google.golang.org/grpc v1.86.0-dev, google.golang.org/protobuf v1.36.12, golang.org/x/text, modelcontextprotocol/go-sdk v1.8.0 (seam tools and tests only), pgregory.net/rapid (tests only, MPL-2.0). Lint: golangci-lint v2.13.2 with the repository `.golangci.yml`. Licence Apache-2.0; `THIRD_PARTY_NOTICES.md` is generated.

## Commands

Always `export GOFLAGS=-mod=readonly`. Never `go get` or `go mod tidy` without regenerating `THIRD_PARTY_NOTICES.md` in the same commit. The Makefile wraps the common runs.

```sh
make build                                            # go build ./... && go vet ./...
make test                                             # go test -race -count=1 -timeout 1500s -cover ./... (prints per-package coverage)
make lint                                             # gofmt, go vet (also -tags e2e), golangci-lint (also --build-tags e2e)
make vuln                                             # govulncheck ./... (install: go install golang.org/x/vuln/cmd/govulncheck@latest)
make e2e                                              # go test -tags e2e -count=1 -timeout 900s -v ./e2e against the real gateway
make demo                                             # demo/run.sh: builds, runs the e2e test, keeps demo/last-run.log
go build -o bin/ ./cmd/...                            # binaries; bin/ is gitignored
go test -short -race -count=1 -timeout 900s ./...     # skips the three Unicode walks and two slow catalog tests
go test -race -count=1 -run 'TestCheckRequest_DeniesWhatIsNotApproved' ./internal/processor/
go test -run '^$' -fuzz FuzzCheckResponse -fuzztime 20s ./internal/processor/
go generate ./internal/extmcpv1                       # regenerate the ExtMCP stubs; refuses other protoc/plugin versions
scripts/gen-proto.sh --check
scripts/gen-third-party-notices.sh --check            # must pass whenever go.mod changed; 40-55 s; needs a compiling tree
seam/run.sh guarded; seam/day5.sh; seam/day34-paging-latency.sh; seam/day34-sessions.sh; seam/day34-reload.sh
```

The seam scripts and the end-to-end test need the v1.6.0 release binary at `.cache/agentgateway-darwin-arm64` (gitignored; `TOOLWARRANT_GATEWAY_BIN` overrides the path) and the seam scripts need the four seam binaries in `bin/`. Outside the seam scripts and `make e2e` (which starts the gateway on loopback ports it picks itself and stops it) the gateway binary may only be run with `--validate-only`. The e2e scenarios share one stack and depend on each other's end state, so run the whole `TestEndToEnd`, not one subtest. Anything over two minutes runs in the background with output to a file.

The CI workflow is `.github/workflows/ci.yml`: lint, vet and build, the short test suite under `-race`, the full textdiff walk and the slow catalog tests, govulncheck, gitleaks, the notices check, and the documentation checks (every test name cited in README.md, SECURITY.md, CLAUDE.md, docs/ and seam/RESULTS.md must exist as a test function, every relative link must resolve). The e2e job runs on `workflow_dispatch` only and needs the owner to record the checksum of the linux gateway binary. Run the documentation checks by hand with:

```sh
for n in $(grep -ohE '\b(Test|Fuzz)[A-Z_][A-Za-z0-9_]*' README.md SECURITY.md CLAUDE.md docs/*.md seam/RESULTS.md | sort -u); do grep -rqE "^func $n\(" --include='*_test.go' --exclude-dir=.cache --exclude-dir=.git . || echo "missing test: $n"; done
```

## Repository layout

- `cmd/toolwarrant`: operator CLI, a thin client of the internal packages; `run()` is driven in-process by tests, `main` only exits.
- `cmd/mockupstream`, `cmd/seamclient`, `cmd/seamgate`, `cmd/seamprocessor`: spike scaffolding for the seam tests and the e2e test; never deployed.
- `internal/catalog`: SQLite registry (schema v2); the only writer of lifecycle state and the audit log, in one transaction; caps, quarantine, proposal budget and its reset, integrity checks (guard DDL, approval records, audit cross-check).
- `internal/lifecycle`: pure state machine (states, commands, events, `Serves`); property-tested invariants.
- `internal/gate`: RFC 8785 canonicalisation and SHA-256 digest, profile `full-v1`; refuses inexact numbers and non-UTF-8.
- `internal/audit`: hash chain over audit entries (`Seal`, `Verify`, `Head`).
- `internal/crawl`: raw MCP Streamable HTTP `tools/list` client; vets every tool, quarantines, never approves.
- `internal/fetch`: the only egress path; SSRF-hardened dialer (connect-time address checks, DNS pinning, caps).
- `internal/processor`: ExtMCP gRPC processor; list filtering, call rule, caps, shared secret, digest cache.
- `internal/emit`: agentgateway v1.6.0 config emitter; gateways form with a loopback bind, listener inputs, explicit allow rules, failClosed, sha256 header, `Verify`, validation with the gateway binary.
- `internal/export`: write-only mirror of approved definitions into a directory and git; crash-safe manifest.
- `internal/textdiff`: escaped diff renderer and invisible-character findings for approvers.
- `internal/toolname`: the one tool-name rule shared by crawler, catalog, processor and emitter.
- `internal/strictjson`: rejects JSON objects that two parsers could read differently.
- `internal/mcpwire`: pure helpers over raw MCP JSON-RPC payloads.
- `internal/extmcpv1`: generated ExtMCP stubs (package `api`) from `third_party/agentgateway/ext_mcp.proto`.
- `e2e/`: the end-to-end test behind the `e2e` build tag (`TestEndToEnd`, scenarios A to P on one shared stack); `demo/run.sh` runs it unattended into `demo/last-run.log` (gitignored).
- `seam/`: spike scripts and gateway configs; `seam/RESULTS.md` holds findings F1 to F5, decisions D1 to D10 as the commits state them, and the post-review corrections.
- `scripts/`: `scripts/gen-proto.sh`, `scripts/gen-third-party-notices.sh`.
- `docs/`: `docs/threat-model.md`, `docs/decisions.md` (D1 to D12), `docs/operations.md`.
- `.github/workflows/ci.yml`: the CI workflow.

## Rules

- Conventional commits (`type(scope): subject`) with a WHY paragraph in the body; no `Co-Authored-By` trailer.
- Tests before commit: every behaviour change gets a test; gofmt, go vet and golangci-lint clean; `go test -race` on the touched packages; keep existing tests passing or say which design decision changed them.
- Nothing is pushed, tagged, published or registered without the owner.
- Keep "MCP" out of the product name; "toolwarrant for MCP" is the permitted form.
- Treat upstream text as hostile: `textdiff.Escape` in text mode, `strconv.Quote` in logs, never print tokens or credential-bearing URLs, fail closed.
- Read `seam/RESULTS.md` (including its post-review sections) and `docs/decisions.md` D10 to D12 before changing anything the gateway sees: `internal/emit`, `internal/processor`, `internal/extmcpv1`, `cmd/toolwarrant/verify.go`.
- Documents cite tests by their exact names and state what the logs show, not what was expected; when a test is renamed, update every document that cites it (the CI `docs` job fails otherwise). Plain prose, no marketing language, no em dashes.
- Style: a doc comment on every exported identifier saying why; lower-case error messages wrapped with `%w`; named constants; functions under about 50 lines, files under about 400; no package-level mutable state.
- Test files must not contain literal invisible or format characters: build them at run time or use `\u` escapes, then check with `grep -P`.
- Never edit `go.mod`, `go.sum`, `.gitignore`, `.cache/`, `seam/` or `third_party/` as part of an unrelated change; `seam/RESULTS.md` is only appended to or corrected, measured results are never removed.

## Pinned external versions

agentgateway v1.6.0 (ExtMCP proto and config schema); modelcontextprotocol/go-sdk v1.8.0; MCP revision 2026-07-28; google.golang.org/grpc v1.86.0-dev (GO-2026-6443 fix; move to v1.85.0 when tagged); protoc v7.36.2 (libprotoc 36.2), protoc-gen-go v1.36.12, protoc-gen-go-grpc v1.6.2; golangci-lint v2.13.2.
