# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| none | No version has been released. The code is pre-release and exists only in a local repository. |

When the first version is tagged this table will name it and say how long it
receives fixes. Until then there is nothing to upgrade to and nothing to patch
in place; a problem found now is fixed on the main branch before the first
release.

## Reporting a vulnerability

PLACEHOLDER. The repository owner must complete this section before the
repository is made public, and must remove this paragraph when doing so.

- Once the repository is public: use GitHub private vulnerability reporting on
  it (the Security tab, "Report a vulnerability"). The owner must enable private
  reporting before the first announcement. GitHub is a CVE numbering authority,
  so a CVE can be requested through the advisory that the report creates.
- Until then: OWNER, write a contact address or another private reporting
  mechanism here. There is no public channel yet.

Do not open a public issue for a security problem. A useful report names the
commit hash, gives a minimal reproduction (a test under `internal/` or a command
sequence against `cmd/mockupstream`), and states what an attacker gains: a
definition served without approval, a call allowed against changed evidence, an
address reached that the egress policy forbids, a secret printed, an audit edit
that `audit verify` does not detect. Response and fix targets will be set by the
owner together with the first release.

## Scope

In scope:

- The `toolwarrant` binary (`cmd/toolwarrant`) and the packages under
  `internal/` it is built from.
- The agentgateway configuration that `toolwarrant emit` writes, and the
  processor behaviour of `toolwarrant serve` against agentgateway v1.6.0.
- The scripts under `scripts/` and this documentation where it describes a
  control that does not hold.

Findings in scope include, in order of severity: an unapproved or changed
definition served through a correctly configured gateway and processor; a
`tools/call` allowed for a tool whose evidence differs from the approved digest;
a hook about another backend judged with this server's approvals; a decision
made by the system actor or by a proposer of the version; the crawler reaching
an address or scheme the egress policy forbids; an edit to the database that
`audit verify` or the digest re-check does not report; upstream text reaching a
terminal, a log line or a file name unescaped; a bearer token, shared secret or
credential-bearing URL printed, stored or logged; anything under
`internal/export` writing outside its directory or running a program during
`Commit`.

Out of scope:

- agentgateway itself. Report gateway bugs to the agentgateway project. The
  known behaviours this project works around (re-serialised definitions,
  per-session processor binding, wildcard route binds) are documented as limits
  in [README.md](README.md) and [docs/threat-model.md](docs/threat-model.md).
- The upstream MCP servers. Everything they send is treated as hostile; a
  malicious upstream that is correctly hidden is the system working.
- The spike scaffolding `cmd/mockupstream`, `cmd/seamclient`, `cmd/seamgate`
  and `cmd/seamprocessor`. They exist for the seam tests and must never be
  deployed.
- Deployments that ignore the hardening checklist below: a processor on a
  reachable interface without a shared secret, an unguarded route or bind on
  the serving gateway, a shared or world-readable database, a hand-edited
  configuration file.
- Homoglyph detection in the diff renderer (a documented limit of
  `internal/textdiff`) and behaviour change behind an unchanged definition (the
  digest detects definition drift only).
- Denial of service of an operator's own catalog by that operator.

## Threat model

The threat model, with the control that exists in code for each threat and the
test or seam result that proves it, is in [docs/threat-model.md](docs/threat-model.md).
Its second table lists the residual risks and what an operator can do about
each. The spike findings F1 to F5 and the design decisions D1 to D10 are
recorded in [seam/RESULTS.md](seam/RESULTS.md) and [docs/decisions.md](docs/decisions.md).

## Operator hardening checklist

Each item names the control it relies on. Items marked "current wave" are CLI
wiring that is being completed now and is to be verified by the end-to-end
test; the underlying package behaviour is tested.

- Run every processor on a loopback address or a unix socket:
  `serve --listen 127.0.0.1:PORT` or `serve --listen unix:/path` (the socket is
  created owner-only, 0600). `serve` refuses a non-loopback TCP address unless
  `--allow-non-loopback` is given; pass that flag only together with
  `--secret-env`, and only on a network nobody but the gateway can reach (the
  CLI advises the pairing in its help text but does not enforce it). The ExtMCP
  protocol has no authentication of its own.
- Set a shared secret: `emit --secret-env VAR` and `serve --secret-env VAR`
  with the same value, 16 to 256 printable ASCII characters. The processor then
  refuses, in constant time, every hook that does not carry it. Without a
  secret, whoever can reach the processor port decides what the gateway serves.
  Current wave.
- Keep the database owner-only. `init` creates it 0600 and the catalog refuses
  an existing file that is readable by its group or by others. The WAL and SHM
  files inherit the mode. Never share one database file between operators.
- Keep the emitted configuration readable by the gateway only when it carries a
  secret: the secret is written into the file in clear, `emit` writes such a
  file 0600 and prints a warning (current wave). Without a secret the file holds
  only upstream URLs and tool names and is written 0644.
- No crawl route on the serving gateway. The control plane crawls upstreams
  directly, so the emitted configuration contains only guarded routes. Never add
  an unguarded route or a second bind by hand: any unguarded path is a complete
  bypass (seam test 12, finding F2).
- Run `verify-gateway` as a canary, not once at deploy time. It opens a new MCP
  session on every run, which is the only way to see a processor that a reload
  dropped (sessions that already exist keep the old chain; seam test 14 as
  corrected). Use `--every DURATION` and treat LEAK and CONFIG-EDITED (exit
  code 1) as incidents. Current wave for `--every`, `--config` and the
  CONFIG-EDITED and MISMATCH verdicts; LEAK, MISSING and OK exist and are
  tested.
- Record the audit head outside the database after every `audit verify`, and
  verify with `audit verify --expect-head HASH`. The chain proves that nothing
  inside it was altered; only a head recorded elsewhere proves that the whole
  log was not replaced.
- Keep upstreams unreachable except from the gateway and the control plane
  host. The gateway's route bind listens on every interface (the v1.6.0 schema
  has no bind address), so firewall the gateway's listen port too.
- One owner for the configuration file: regenerate it with `emit`, never edit
  it by hand. The header records the SHA-256 of the body and `emit.Verify`
  fails on any edit.
- Give the processor its own OS user with read access to the database. The
  processor opens the catalog read-only (current wave); SQLite still needs the
  `-shm` file to exist and be writable by that user, or the directory must
  allow creating it.
- Run crawls under the system actor (no `--as`, no `TOOLWARRANT_ACTOR`) in
  automation, and decide as yourself. A person whose crawl proposed a digest
  cannot approve it.

## Dependency policy

- Every dependency is pinned in `go.mod` and `go.sum`; every build runs with
  `GOFLAGS=-mod=readonly`. The Go toolchain is pinned (`go 1.27`,
  `toolchain go1.27.1`).
- `govulncheck ./...` runs in CI and before every release. The last recorded
  run (2026-10-07) found no vulnerabilities.
- grpc is pinned to v1.86.0-dev because of GO-2026-6443, a server panic in grpc
  v1.84.0 on requests without authority or Host headers. The processor runs a
  gRPC server with `failureMode: failClosed`, so a crash there denies every
  tool; v1.86.0-dev is the first tag that contains the fix (tagged 2026-09-24;
  no v1.85.0 release existed at the time). The plan is to move to v1.85.0 as
  soon as it is tagged and to record the move in the commit message.
- `THIRD_PARTY_NOTICES.md` is generated from the module cache by
  `scripts/gen-third-party-notices.sh` and must be regenerated in the same
  commit as any `go.mod` change; `scripts/gen-third-party-notices.sh --check`
  is the CI gate. `pgregory.net/rapid` (MPL-2.0) is linked into tests only.
- The ExtMCP stubs in `internal/extmcpv1` are regenerated only by
  `scripts/gen-proto.sh`, which refuses any protoc, protoc-gen-go or
  protoc-gen-go-grpc version other than the ones recorded in the generated
  headers, so a protocol change cannot hide in a generator-version diff.
- agentgateway is pinned to v1.6.0. A move of the pin requires re-running the
  emitter's binary validation tests and the end-to-end test against the new
  release before the pin changes.

## Release integrity plan

Not yet done; nothing has been released. Before the first announcement:

- Every release is a signed git tag.
- Every release ships an SBOM and build provenance for its binaries, with
  published checksums.
- `toolwarrant version` prints the build version (set at link time) and the
  pinned gateway version, so a deployment can be matched to a release.
- The repository has private vulnerability reporting enabled and this file has
  a real reporting section.
