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
commit hash, gives a minimal reproduction (a test under `internal/` or
`cmd/toolwarrant`, a command sequence against `cmd/mockupstream`, or an
end-to-end scenario under `e2e/`), and states what an attacker gains: a
definition served without approval, a call allowed against changed evidence, an
address reached that the egress policy forbids, a secret printed, an audit edit
that the catalog does not detect, a served tool the canary does not report.
Response and fix targets will be set by the owner together with the first
release.

## Pending actions for the owner

- Complete the reporting section above.
- Report two behaviours of agentgateway v1.6.0 to the agentgateway project, by
  hand: a `tools/call` sent as a JSON-RPC notification (no `id`, or `id: null`)
  is forwarded to the upstream without the ExtMCP hook and without the
  `mcpAuthorization` rule (known limit L17), and the admin API on the admin
  listener accepts `POST /api/config` and answers `GET /config_dump` without
  authentication (known limit L18). toolwarrant's controls for both are
  documented below and in [docs/threat-model.md](docs/threat-model.md) rows 25
  and 26; the reports are not written yet.
- Record the SHA-256 of the linux release asset of agentgateway v1.6.0 in the
  `e2e` job of [.github/workflows/ci.yml](.github/workflows/ci.yml), which
  refuses to run until the placeholder is replaced.

## Scope

In scope:

- The `toolwarrant` binary (`cmd/toolwarrant`) and the packages under
  `internal/` it is built from.
- The agentgateway configuration that `toolwarrant emit` writes, and the
  processor behaviour of `toolwarrant serve` against agentgateway v1.6.0.
- The canary (`toolwarrant verify-gateway`): a served tool it does not report as
  LEAK, a live configuration that differs from the emitted file in any gateway
  or route (an added route, a route moved to another path, a processor removed)
  that it does not report with `--admin`, a body hash that differs from the
  recorded one that it does not report with `--expect-body-hash`, an id-less
  `tools/call` the probe does not detect or calls healthy without the gateway's
  own refusal.
- The scripts under `scripts/`, the CI workflow, and this documentation where it
  describes a control that does not hold.

Findings in scope include, in order of severity: an unapproved or changed
definition served through a correctly configured gateway and processor; a
`tools/call` allowed for a tool whose evidence differs from the approved digest;
a hook about another backend judged with this server's approvals; an approval by
the system actor or by a proposer of the version (a rollback by a proposer is
permitted by design: the target was approved by someone before, see decision D4
and `internal/lifecycle/decide.go`); the crawler reaching an address or scheme
the egress policy forbids; an edit to the database that the catalog's integrity
checks do not report (the digest re-check, the newest-decision rule for every
approved version, the guard definitions and the absence of foreign triggers and
views, all applied at open and on every snapshot load, the audit chain, and
`Store.Integrity`'s cross-check of every mutable column the log describes
against the approvals table and the log, which `audit verify` runs after the
chain check); upstream text reaching a terminal, a log line or a file name
unescaped; a bearer token, shared secret or credential-bearing URL printed,
stored, logged or written into a file that is not owner-only; anything under
`internal/export` writing outside its directory or running a program during
`Commit`.

Out of scope:

- agentgateway itself. Report gateway bugs to the agentgateway project. The
  known behaviours this project works around are documented as limits in
  [README.md](README.md) and [docs/threat-model.md](docs/threat-model.md):
  re-serialised definitions (L2), per-session processor binding (L3), the
  forwarding of id-less `tools/call` messages without the hook (L17) and the
  unauthenticated admin API (L18). The last two are the owner's pending reports.
- The upstream MCP servers. Everything they send is treated as hostile; a
  malicious upstream that is correctly hidden is the system working.
- Other local users of the gateway host. The admin listener is bound to
  loopback by the emitted file, but its API is unauthenticated, so every local
  user of that host is inside the trusted computing base; the checklist below
  says what to do about it.
- The spike scaffolding `cmd/mockupstream`, `cmd/seamclient`, `cmd/seamgate`
  and `cmd/seamprocessor`. They exist for the seam tests and the end-to-end
  test and must never be deployed.
- Deployments that ignore the hardening checklist below: a processor on a
  reachable interface without a shared secret, an unguarded route or a
  non-loopback bind on the serving gateway that is not firewalled, a shared or
  world-readable database, a hand-edited configuration file, a gateway host
  with other local users.
- Homoglyph detection in the diff renderer (a documented limit of
  `internal/textdiff`) and behaviour change behind an unchanged definition (the
  digest detects definition drift only).
- Denial of service of an operator's own catalog by that operator.

## Threat model

The threat model, with the control that exists in code for each threat and the
test or seam result that proves it, is in [docs/threat-model.md](docs/threat-model.md).
Its second table lists the residual risks and what an operator can do about
each. The spike findings F1 to F5 and the design decisions D1 to D13 are
recorded in [seam/RESULTS.md](seam/RESULTS.md) and [docs/decisions.md](docs/decisions.md).

## Operator hardening checklist

Each item names the control it relies on. Every item is covered by an in-process
test and, where the gateway is involved, by a scenario of the end-to-end test
(`make e2e`); the test names are in the threat model.

- Run every processor on a loopback address or a unix socket:
  `serve --listen 127.0.0.1:PORT` or `serve --listen unix:/path` (the socket is
  created owner-only, 0600). `serve` refuses a non-loopback TCP address unless
  `--allow-non-loopback` is given, and with that flag refuses to listen without
  `--secret-env` unless `--insecure-no-secret` is passed as well; the pairing
  is enforced, not advised. Use it only on a network nobody but the gateway can
  reach. The ExtMCP protocol has no authentication of its own, and the link is
  plaintext gRPC; every processor entry `emit` writes carries the gateway's
  `requestHeaders` filter (only the `:method` pseudo-header allowed;
  `authorization`, `cookie` and `proxy-authorization` denied by name as well),
  so a client's credentials do not ride each hook to the processor, which reads
  no header (decision D13, known limit L11).
- Set a shared secret: `emit --secret-env VAR` and `serve --secret-env VAR`
  with the same value, 16 to 256 printable ASCII characters. The processor then
  refuses, in constant time, every hook that does not carry it; the gateway
  delivers it on both hooks (e2e scenario H). Without a secret, whoever can
  reach the processor port decides what the gateway serves. The secret is
  confidential against other hosts only: see the admin listener item.
- Treat the gateway's admin listener as part of the trusted computing base. The
  emitted file binds the admin, stats and readiness listeners to 127.0.0.1
  (`emit --admin-addr`, `--stats-addr` and `--readiness-addr`, defaults
  127.0.0.1:15000, 15020 and 15021; keep them on loopback), but the admin API
  is unauthenticated: any local user of
  the gateway host can read the loaded configuration with the shared secret in
  clear (`GET /config_dump`) and replace the running configuration
  (`POST /api/config`), which the gateway applies and writes back to the
  watched file. Run the gateway on a dedicated host, in a container or in its
  own network namespace when other local users exist, and run the canary with
  `--admin` so a replaced configuration is reported as LIVE-CONFIG-MISMATCH:
  the comparison covers the whole document, so an added route or gateway, a
  route moved to another path, a removed processor or a changed allow rule is
  reported, not only a change inside the named route (decision D13); or turn
  the admin API off (`emit --disable-admin`, the gateway's own
  `adminAddr: off`) and accept that the live comparison then has nothing to
  query. Rotate the secret whenever another user could have reached
  loopback while the admin API was on (known limit L18).
- Keep the database owner-only and run the processor as its owner. `init`
  creates the file 0600 and the catalog refuses an existing file that is
  readable by its group or by others; the CLI has no flag to allow a shared
  file, so a processor under another OS user cannot open it. The processor
  opens the catalog read-only and can never change it. SQLite needs the `-wal`
  and `-shm` files next to the database and a read-only open cannot create
  them: run one ordinary command as the owner after `init` (any `list` does) in
  a directory the owner can write, so the files exist before the processor
  starts. Never share one database file between operators.
- Keep the emitted configuration readable by the gateway's user only. `emit`
  writes the file 0600 whatever it carries (decision D13; before the fourth
  round a file without a secret and without a query string was written 0644,
  and a credential in a URL path went into a world-readable file in silence,
  because the only credential heuristic looks at query strings). Make the file
  readable by the user the gateway runs as and by nobody else: `chown` it to
  that user, or grant that user a read ACL. The shared secret is written into
  the file in clear, and so is every upstream URL, path and query string
  included; `emit` still prints a warning when the file carries a secret or
  when a server URL has a query string, which is where credentials usually
  live, and the mode no longer depends on that heuristic being right.
- No crawl route on the serving gateway. The control plane crawls upstreams
  directly, so the emitted configuration contains only guarded routes. Never add
  an unguarded route or a second bind by hand: any unguarded path is a complete
  bypass (seam test 12, finding F2).
- Run `verify-gateway` as a canary, not once at deploy time. It opens a new MCP
  session on every run, which is the only way to see a processor that a reload
  dropped (sessions that already exist keep the old chain; seam test 14 as
  corrected). Pass `--config FILE` with `--expect-body-hash HEX` (the
  `body sha256` line `emit` printed, recorded off the gateway host, the way the
  audit head is), pass `--admin ADDR`, use `--every DURATION`, and treat exit
  code 1 (LEAK, CONFIG-EDITED, LIVE-CONFIG-MISMATCH, UNHOOKED-CALLS,
  PROBE-INCONCLUSIVE) and every `check failed` line as an incident. On
  agentgateway v1.6.0 the unhooked-call probe reports UNHOOKED-CALLS on every
  check (known limit L17): run it once, record the limit, and pass `--no-probe`
  until the pin moves to a gateway that refuses the shape, because a canary that
  fails on every run trains its readers to ignore it; re-run the probe on every
  move of the pin. Exit 0 is OK or MISSING only; MISMATCH and UNVERIFIED are
  sub-labels of a LEAK line, never a verdict that passes (decisions D12 and
  D13).
- Record the audit head outside the database after every `audit verify`, and
  verify with `audit verify --expect-head HASH`. The chain proves that nothing
  inside it was altered; only a head recorded elsewhere proves that the whole
  log was not replaced. `audit log ok` in forensic mode means the chain is
  consistent, not that the file is intact; every other command refuses a file
  whose guard objects are missing or redefined, or that holds a trigger or view
  the schema did not create.
- Keep upstreams unreachable except from the gateway and the control plane
  host. The emitted file binds the gateway's serving port to 127.0.0.1 by
  default (e2e scenario I); a non-loopback `emit --bind-address` is an explicit
  choice that `emit` warns about, and that port must be firewalled.
- One owner for the configuration file: regenerate it with `emit`, never edit
  it by hand. The header records the SHA-256 of the body and `emit.Verify`
  fails on any edit that leaves the header alone. The hash is unkeyed, so it is
  tamper-evidence, not proof (known limit L19): record the `body sha256` line
  `emit` prints outside the gateway host and pass it to the canary as
  `--expect-body-hash HEX`, which reports CONFIG-EDITED when the body hashes to
  anything else, header recomputed or not (decision D13); the canary's listing
  and its live-configuration comparison are the controls against an edit the
  recorded hash cannot see. Pass `emit --gateway-binary PATH` so a file the
  gateway would refuse fails `emit` instead of freezing every server's
  configuration on the next reload. Re-emitting keeps every server's processor
  address, so a re-emit after adding a server does not darken the others
  (decision D13).
- Run crawls under the system actor (no `--as`, no `TOOLWARRANT_ACTOR`) in
  automation, and decide as yourself. A person whose crawl proposed a digest
  cannot approve it.

## Dependency policy

- Every dependency is pinned in `go.mod` and `go.sum`; every build runs with
  `GOFLAGS=-mod=readonly`. The Go toolchain is pinned (`go 1.27`,
  `toolchain go1.27.2`).
- `govulncheck ./...` runs as the `govulncheck` job of
  [.github/workflows/ci.yml](.github/workflows/ci.yml) on every pull request
  and every push to main once the repository is on GitHub, and before every
  release. The last recorded run by hand (2026-10-11) found no vulnerabilities
  after the move to go1.27.2 and golang.org/x/net v0.60.0.
- grpc is pinned to v1.86.0-dev because of GO-2026-6443, a server panic in grpc
  v1.84.0 on requests without authority or Host headers. The processor runs a
  gRPC server with `failureMode: failClosed`, so a crash there denies every
  tool; v1.86.0-dev is the first tag that contains the fix (tagged 2026-09-24;
  no v1.85.0 release existed at the time). The plan is to move to v1.85.0 as
  soon as it is tagged and to record the move in the commit message.
- `THIRD_PARTY_NOTICES.md` is generated from the module cache by
  `scripts/gen-third-party-notices.sh` and must be regenerated in the same
  commit as any `go.mod` change; `scripts/gen-third-party-notices.sh --check`
  is the `notices` job of the CI workflow. `pgregory.net/rapid` (MPL-2.0) is
  linked into tests only.
- gitleaks runs as the `gitleaks` job of the CI workflow over the whole
  history; a secret that was ever committed is treated as compromised.
- The ExtMCP stubs in `internal/extmcpv1` are regenerated only by
  `scripts/gen-proto.sh`, which refuses any protoc, protoc-gen-go or
  protoc-gen-go-grpc version other than the ones recorded in the generated
  headers, so a protocol change cannot hide in a generator-version diff.
- agentgateway is pinned to v1.6.0. A move of the pin requires re-running the
  emitter's binary validation tests and the end-to-end test against the new
  release before the pin changes; scenario L re-derives which keys the gateway
  strips, and the canary probe re-checks whether id-less calls are still
  forwarded and whether the shapes the probe calls healthy are still the
  gateway's own refusals (a 2xx answer with a body that is not a plain 202 is
  PROBE-INCONCLUSIVE, decision D13).

## Release integrity plan

Not yet done; nothing has been released. Before the first announcement:

- Every release is a signed git tag.
- Every release ships an SBOM and build provenance for its binaries, with
  published checksums.
- `toolwarrant version` prints the build version (set at link time) and the
  pinned gateway version, so a deployment can be matched to a release.
- The repository has private vulnerability reporting enabled and this file has
  a real reporting section.
- The CI workflow has run green on the repository, including the dispatched
  end-to-end job against the release binary of agentgateway v1.6.0.
