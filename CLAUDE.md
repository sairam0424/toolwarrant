# CLAUDE.md

toolwarrant is a control plane in front of the agentgateway v1.6.0 MCP gateway: it crawls upstream MCP servers, stores every tool definition as an immutable version identified by the SHA-256 of its RFC 8785 canonical JSON, lets a named person approve one exact digest, and enforces that approval at the gateway as an ExtMCP processor (strict mode: a tool is served only while the live definition hashes to the approved digest). Nothing is served until approved, a crawl never approves anything, and everything an upstream sends is hostile.

## Stack

Go 1.27 (`go.mod`: `go 1.27`, `toolchain go1.27.1`), one module `github.com/sairam0424/toolwarrant`, pure Go (modernc.org/sqlite, no cgo). Dependencies: gowebpki/jcs (RFC 8785), modernc.org/sqlite, google.golang.org/grpc v1.86.0-dev, google.golang.org/protobuf v1.36.12, golang.org/x/text, modelcontextprotocol/go-sdk v1.8.0 (seam tools and tests only), pgregory.net/rapid (tests only, MPL-2.0). Lint: golangci-lint 2.13 with the repository `.golangci.yml`. Licence Apache-2.0; `THIRD_PARTY_NOTICES.md` is generated.

## Commands

Always `export GOFLAGS=-mod=readonly`. Never `go get` or `go mod tidy` without regenerating `THIRD_PARTY_NOTICES.md` in the same commit.

```sh
go build ./... && go vet ./...                        # whole module
go build -o bin/ ./cmd/...                            # binaries; bin/ is gitignored
go test -race -count=1 -timeout 1500s -cover ./...    # full suite; textdiff walks all of Unicode (minutes under -race)
go test -short -race -count=1 -timeout 900s ./...     # skips the three Unicode walks and two slow catalog tests
go test -race -count=1 -run 'TestCheckRequest_DeniesWhatIsNotApproved' ./internal/processor/
go test -run '^$' -fuzz FuzzCheckResponse -fuzztime 20s ./internal/processor/
gofmt -l . && golangci-lint run ./...                 # .golangci.yml reports every finding, no exclusions
govulncheck ./...                                     # install: go install golang.org/x/vuln/cmd/govulncheck@latest
go generate ./internal/extmcpv1                       # regenerate the ExtMCP stubs; refuses other protoc/plugin versions
scripts/gen-proto.sh --check
scripts/gen-third-party-notices.sh --check            # must pass whenever go.mod changed; 40-55 s; needs a compiling tree
seam/run.sh guarded; seam/day5.sh; seam/day34-paging-latency.sh; seam/day34-sessions.sh; seam/day34-reload.sh
```

The seam scripts need the v1.6.0 release binary at `.cache/agentgateway-darwin-arm64` (gitignored) and the four seam binaries in `bin/`. Outside the seam scripts the gateway binary may only be run with `--validate-only`. Anything over two minutes runs in the background with output to a file.

## Repository layout

- `cmd/toolwarrant`: operator CLI, a thin client of the internal packages; `run()` is driven in-process by tests, `main` only exits.
- `cmd/mockupstream`, `cmd/seamclient`, `cmd/seamgate`, `cmd/seamprocessor`: spike scaffolding for the seam tests; never deployed.
- `internal/catalog`: SQLite registry (schema v2); the only writer of lifecycle state and the audit log, in one transaction; caps, quarantine, proposal budget.
- `internal/lifecycle`: pure state machine (states, commands, events, `Serves`); property-tested invariants.
- `internal/gate`: RFC 8785 canonicalisation and SHA-256 digest, profile `full-v1`; refuses inexact numbers and non-UTF-8.
- `internal/audit`: hash chain over audit entries (`Seal`, `Verify`, `Head`).
- `internal/crawl`: raw MCP Streamable HTTP `tools/list` client; vets every tool, quarantines, never approves.
- `internal/fetch`: the only egress path; SSRF-hardened dialer (connect-time address checks, DNS pinning, caps).
- `internal/processor`: ExtMCP gRPC processor; list filtering, call rule, caps, shared secret, digest cache.
- `internal/emit`: agentgateway v1.6.0 config emitter; explicit allow rules, failClosed, sha256 header, `Verify`.
- `internal/export`: write-only mirror of approved definitions into a directory and git; crash-safe manifest.
- `internal/textdiff`: escaped diff renderer and invisible-character findings for approvers.
- `internal/toolname`: the one tool-name rule shared by crawler, catalog, processor and emitter.
- `internal/strictjson`: rejects JSON objects that two parsers could read differently.
- `internal/mcpwire`: pure helpers over raw MCP JSON-RPC payloads.
- `internal/extmcpv1`: generated ExtMCP stubs (package `api`) from `third_party/agentgateway/ext_mcp.proto`.
- `seam/`: spike scripts and gateway configs; `seam/RESULTS.md` holds findings F1 to F5, decisions D1 to D10 and the post-review corrections.
- `scripts/`: `scripts/gen-proto.sh`, `scripts/gen-third-party-notices.sh`.
- `docs/`: `docs/threat-model.md`, `docs/decisions.md`, `docs/operations.md`.

## Rules

- Conventional commits (`type(scope): subject`) with a WHY paragraph in the body; no `Co-Authored-By` trailer.
- Tests before commit: every behaviour change gets a test; gofmt, go vet and golangci-lint clean; `go test -race` on the touched packages; keep existing tests passing or say which design decision changed them.
- Nothing is pushed, tagged, published or registered without the owner.
- Keep "MCP" out of the product name; "toolwarrant for MCP" is the permitted form.
- Treat upstream text as hostile: `textdiff.Escape` in text mode, `strconv.Quote` in logs, never print tokens or credential-bearing URLs, fail closed.
- Read `seam/RESULTS.md` (including its post-review section) before changing anything the gateway sees: `internal/emit`, `internal/processor`, `internal/extmcpv1`.
- Style: a doc comment on every exported identifier saying why; lower-case error messages wrapped with `%w`; named constants; functions under about 50 lines, files under about 400; no package-level mutable state.
- Test files must not contain literal invisible or format characters: build them at run time or use `\u` escapes, then check with `grep -P`.
- Never edit `go.mod`, `go.sum`, `.gitignore`, `.cache/`, `seam/` or `third_party/` as part of an unrelated change.

## Pinned external versions

agentgateway v1.6.0 (ExtMCP proto and config schema); modelcontextprotocol/go-sdk v1.8.0; MCP revision 2026-07-28; google.golang.org/grpc v1.86.0-dev (GO-2026-6443 fix; move to v1.85.0 when tagged); protoc v7.36.2 (libprotoc 36.2), protoc-gen-go v1.36.12, protoc-gen-go-grpc v1.6.2; golangci-lint 2.13.
