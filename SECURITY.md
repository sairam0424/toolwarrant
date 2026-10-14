# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.2.x | Yes: fixes land on `main` and ship in the next tag. |
| 0.1.x | No: fixes are not backported; the newest 0.2.x tag opens a 0.1.x catalog file as it is, since both write schema v6. |

There is no long-term branch; a fix is a new tag from `main`. A problem found
in the pinned agentgateway v1.6.0 itself is reported upstream (see below) and
worked around here where the design allows.

## Reporting a vulnerability

Use GitHub private vulnerability reporting on this repository: the Security tab,
"Report a vulnerability". It is switched on (docs/operations.md, Releasing,
lists the repository settings as they stand), so it exists wherever this file
is read as part of a release. The report is visible to the maintainer only.
GitHub is a CVE numbering authority, so a CVE can be requested through the
advisory the report creates. Please do not open a public issue for a
vulnerability; the new-issue chooser points here for that reason.

The maintainer acknowledges a report within two days and aims to ship a fix in
the next tag; a confirmed problem not fixed within fourteen days of the report
gets a dated note in the advisory saying why and when. The two behaviours of
agentgateway v1.6.0 itself (known limits L17 and L18 below) are the
maintainer's to report to the agentgateway project, by hand; that report is
pending, and toolwarrant documents its own controls for both in
[docs/threat-model.md](docs/threat-model.md) rows 25 and 26.

## Scope

The trust boundary, in six lines:

- Whoever can write the 0600 catalog file can append a correctly sealed audit
  entry that approves a definition; the recorded audit head, the git export
  (since D21 (e) signed with `export --sign-key` and recording the head it
  mirrors, so `export verify --dir DIR --pub-key FILE --expect-head HEAD` checks
  the export against the key you hold and the head you recorded) and backups
  detect it, nothing inside the file does (row 21 of the threat model and the
  note of known limit L19, which carries the catalog file's boundary; decisions
  D14 and D21 (e)).
- Whoever reaches the processor without the shared secret, or without a
  client certificate its `--tls-client-ca` accepts, decides what is served
  (known limit L11, decision D19).
- Every local user of the gateway host reaches the admin API, which hands out
  the loaded configuration and accepts a replacement (known limit L18).
- The upstream is hostile: everything it sends is attacker-controlled input.
- Operator names are asserted, not authenticated: `--as` and `TOOLWARRANT_ACTOR`
  are taken as given beyond the OS account that runs the command, so the
  per-person rule and the proposer rule hold against the name given (residual
  risk L13 in the threat model).
- The gateway's serving port must be reachable only by clients that send a
  JSON-RPC id on every `tools/call` (the official SDKs do) or through an
  enforcement point that refuses id-less `tools/call`; toolwarrant provides
  none (decision D11, known limit L17; written out in
  [docs/operations.md](docs/operations.md), Deployment requirements, decision
  D18).

In scope:

- The `toolwarrant` binary (`cmd/toolwarrant`) and the packages under
  `internal/` it is built from.
- The agentgateway configuration that `toolwarrant emit` writes, and the
  processor behaviour of `toolwarrant serve` against agentgateway v1.6.0.
- The canary (`toolwarrant verify-gateway`): a served tool it does not report as
  LEAK, a live configuration that differs from the emitted file in any
  non-empty top-level section, `config` field, listener address, gateway or
  route (an added route or `binds` listener, a route moved to another path, a
  processor removed, its `requestHeaders` filter or metadata changed, a route
  key, policy, match or backend the emitted file cannot carry, a renamed
  backend target, a `--url` or `--admin` port that is not the emitted one)
  that it does not report with `--admin`, a body hash that differs from the
  recorded one that it does not report with `--expect-body-hash`, an id-less
  `tools/call` answered 202 that the probe does not report as UNHOOKED-CALLS
  (as KNOWN-LIMIT with `--expect-unhooked`), an answer other than 202 under
  `--expect-unhooked` that it does not report as PROBE-CHANGED (decision D18),
  a probe answer the probe attributes to the gateway (since the seventh round
  it attributes none: it proves the fail-open shape of v1.6.0 and cannot
  prove the hook, decision D17), and a `--config` path that makes the canary
  block or exit 0 without a verdict.
- `emit`: an `--out` that names the catalog database, its `-wal` or `-shm`
  sibling, the gateway binary or a regular file whose header lines are not
  emit's that it does not refuse, and a processor address written into the
  gateway configuration that the newest verified `server.processor_set`
  audit entry does not carry without a change line (decision D17).
- The scripts under `scripts/`, the CI workflow, and this documentation where it
  describes a control that does not hold.

Findings in scope include, in order of severity: an unapproved or changed
definition served through a correctly configured gateway and processor; a
`tools/call` allowed for a tool whose evidence differs from the approved digest;
a hook about another backend judged with this server's approvals; an approval by
the system actor or by a proposer of the version (a rollback by a proposer is
permitted by design: the target was approved by someone before, see decision D4
and `internal/lifecycle/decide.go`, and since the seventh round a verified
`version.approved` or `version.rolled_back` audit entry about the digest must
show that, decision D17); the crawler reaching an address or scheme the egress
policy forbids; an edit to the database that the catalog's integrity checks do
not report (the hash of a definition's stored bytes against its digest on every
path that reads them, `export`, `emit`, `show`, `diff` and every decision, with
no memory between calls, the digest the serving path and `list` hand out
anchored to a verified audit entry, the newest-decision rule and the newest
audit entry for every approved version, the rule that the serving and decision
paths trust an audit entry only when it is part of the chain the `Store`
verified at open and extended on every reload, the reconstruction of every
version's status and ever-approved flag from the verified entries on every
decision, the anchoring of every server's processor address, URL hash and
allow-private flag and of every exported approver's name to the verified
entries, the refusal of audit rows at seq 0 or below and of approvals and
history rows with id below 1, the chain pin, the catalog identity and file
identity compared on every read, the guard, table and index definitions and the
absence of foreign triggers, views, unique indexes and unaccounted automatic
indexes, all applied at open and on every snapshot load, the audit chain, and
`Store.Integrity`'s verification of every entry's seal and link and its
cross-check of every mutable column the log describes and every subject the log
describes against the rows, which `audit verify` runs after the chain check and
when the chain is broken), with one stated boundary: an entry appended to the
audit log by whoever can write the 0600 file, correctly sealed, is not
detectable inside the file, and neither is a rewrite from any entry to the head
made while no `Store` holds a pin (the CLI between commands, the processors
while stopped); both are detected by the recorded head, the git export (signed
and bound to the head it mirrors since D21 (e)) and backups (decisions D14, D15,
D17 and D21 (e), known limit L19); a processor that keeps serving after the
catalog file at its path was replaced; upstream text reaching a terminal, a log
line or a file name unescaped; a bearer token, shared secret or
credential-bearing URL printed, stored, logged or written into a file that is
not owner-only; anything under `internal/export` writing outside its directory
or running a program during `Commit`.

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
- Look-alikes outside the UTS #39 confusables table and mixed-script words the
  Highly Restrictive profile allows (a documented limit of `internal/textdiff`;
  a listed look-alike against the approved version and a word that mixes scripts
  are reported by code point and refused by `approve` unless
  `--accept-suspicious`, D21 (c)), and behaviour change behind an unchanged
  definition (the digest detects definition drift only).
- Denial of service of an operator's own catalog by that operator.

## Threat model

The threat model, with the control that exists in code for each threat and the
test or seam result that proves it, is in [docs/threat-model.md](docs/threat-model.md).
Its second table lists the residual risks and what an operator can do about
each. The spike findings F1 to F5 and the design decisions are
recorded in [seam/RESULTS.md](seam/RESULTS.md) and [docs/decisions.md](docs/decisions.md);
the design decisions run to D20.

## Operator hardening checklist

Each item names the control it relies on. Every item is covered by an in-process
test and, where the gateway is involved, by a scenario of the end-to-end test
(`make e2e`); the test names are in the threat model.

- Run every processor on a loopback address or a unix socket:
  `serve --listen 127.0.0.1:PORT` or `serve --listen unix:/path` (the socket is
  created owner-only, 0600). `serve` refuses a non-loopback TCP address (a
  loopback literal, `localhost` and the loopback aliases common resolvers map
  without DNS, such as `localhost.localdomain` and `ip6-loopback`, count as
  loopback since the sixth round, decision D15) unless
  `--allow-non-loopback` is given, and with that flag refuses to listen without
  `--secret-env` or `--tls-client-ca` unless `--insecure-no-secret` is passed
  as well; the pairing is enforced, not advised. Use it only on a network
  nobody but the gateway can reach. The ExtMCP protocol has no authentication
  of its own, and the link is plaintext gRPC unless `serve` is given
  `--tls-cert` and `--tls-key` (TLS 1.3 only; with `--tls-client-ca` every
  connection must present a client certificate that authority signed, which
  authenticates the hooks as the secret does, owner decision O-2, decision
  D19; the key file must be owner-only, as the database is) and the gateway's
  file carries the matching `backendTLS` block, which `emit --processor-tls
  NAME=cert=PATH,key=PATH,root=PATH,hostname=NAME` writes on every emit (it is
  not recorded in the catalog; an emit without it writes a plaintext entry,
  which a processor started with `--tls-cert` refuses in the handshake, so
  the route fails closed; the gateway's `--validate-only` opens the three
  files, so `emit --gateway-binary` needs them on the emitting host).
  End-to-end scenario Q drives the handshake against the real gateway (the
  route serves under TLS with the gateway's client certificate; a plaintext
  side, a client certificate from another authority and a root bundle of
  garbage fail closed; D19 quotes the log lines), and the processor's TLS is
  proven against grpc-go clients by: cmd `TestServeTLSOverGRPCEnforcesApprovals`,
  `TestServeTLSRefusesAClientWithoutACertificate`,
  `TestServeTLSRefusesAGroupReadableKey`,
  `TestEmitWritesBackendTLSForAProcessorOverride`,
  `TestEmitWithTheGatewayBinaryNeedsTheTLSFilesOnThisHost`; processor
  `TestServe_TLSListenerRefusesPlaintextAndUnknownClients`,
  `TestServe_TLSWithClientCARequiresAClientCertificate`; emit
  `TestProcessorTLSIsWrittenUnderPolicies`,
  `TestGatewayValidateOnlyOpensBackendTLSFiles`); every processor
  entry `emit` writes carries the gateway's
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
  the comparison decodes the live document as a map of top-level sections and
  reports every non-empty section other than `config`, `gateways` and
  `routes` (a `binds` listener or a top-level `mcp` shortcut carries routes
  with no processor), a `config` field other than the three listener
  addresses, a changed listener address, an added route or gateway, a route
  moved to another path, a removed processor, a changed allow rule, a changed
  or removed `requestHeaders` filter, a `backendTLS` block under the
  processor's `policies` (the one `emit --processor-tls` writes) that only one
  side carries or whose `cert`, `key`,
  `root` or `hostname` differs (limit L11, D19; a `backendTLS` field or processor
  policy the file does not carry, `insecure` among them, is reported by
  name), changed processor metadata (compared as
  a hash, never printed), and in every live route any key other than `name`,
  `gateways`, `matches`, `policies` and `backends`, any policy other than
  `mcpAuthorization` and `mcpGuardrails`, a match that is not a single exact
  path and a backend that is not the one `mcp` backend with the emitted
  target host and target name, not only a change inside the named route, and
  a `--url` or `--admin` port that is not the emitted gateway or admin port
  (decisions D13, D14, D15 and D17); or turn
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
  starts. Never share one database file between operators. Stop every
  processor of a catalog file before you delete or replace it and start them
  after `init`: a processor detects a replaced or removed file and denies every
  hook until it is restarted (decision D14). `init` refuses a database path
  that is a symbolic link, and a component of its directory that is a
  symbolic link not owned by root (links the operating system installs, such
  as `/var` on macOS, are tolerated; decision D14).
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
- Let only id-sending clients reach the gateway's serving port. agentgateway
  v1.6.0 forwards a `tools/call` sent as a JSON-RPC notification (no `id`, or
  `id: null`) to the upstream without the ExtMCP hook and without the allow
  rule (known limit L17, threat model row 25), and toolwarrant has no data
  plane that could refuse the message (decision D11), so the deployment must:
  reach the serving port only from clients you control that send an id on
  every `tools/call` (the official SDKs do), or put an enforcement point in
  front of it that refuses an id-less `tools/call`, and keep the port off
  every other network (the emitted file binds it to 127.0.0.1;
  `emit --bind-address` widens it and warns). The canary's probe is how you see
  that the gateway still has the shape: run `verify-gateway` with
  `--expect-unhooked`, which prints the 202 as `KNOWN-LIMIT` with exit 0 and
  fails as PROBE-CHANGED, exit 1, when the answer changes (decision D18; the
  requirement is written out in [docs/operations.md](docs/operations.md),
  Deployment requirements; cmd `TestExpectUnhookedTurnsThe202IntoAKnownLimitLine`,
  `TestExpectUnhookedFailsWhenTheGatewayStopsForwarding`; e2e scenario O).
- Run `verify-gateway` as a canary, not once at deploy time. It opens a new MCP
  session on every run, which is the only way to see a processor that a reload
  dropped (sessions that already exist keep the old chain; seam test 14 as
  corrected). Pass `--config FILE` with `--expect-body-hash HEX` (the
  `body sha256` line `emit` printed, recorded off the gateway host, the way the
  audit head is), pass `--admin ADDR`, use `--every DURATION`, and treat exit
  code 1 (LEAK, CONFIG-EDITED, LIVE-CONFIG-MISMATCH, UNHOOKED-CALLS,
  PROBE-INCONCLUSIVE, PROBE-CHANGED) and every `check failed` line as an
  incident. On agentgateway v1.6.0 the unhooked-call probe is answered with
  HTTP 202 on every check (known limit L17): run it once without a probe flag
  and see UNHOOKED-CALLS, exit 1, record the limit, then run the canary with
  `--expect-unhooked`, which keeps the probe on, prints that 202 as
  `KNOWN-LIMIT` with exit 0, and fails as PROBE-CHANGED, exit 1, the moment the
  gateway answers anything else, which is how a moved pin or a gateway changed
  under it is noticed (decision D18; before it the advice was `--no-probe`,
  which silenced the one check that would notice; `--no-probe` still exists and
  is exclusive with `--expect-unhooked`). A canary that fails on every run
  trains its readers to ignore it, and one that sends no probe proves nothing
  about the shape. The probe proves that fail-open shape and nothing else: a
  bare 400 is reported as not accepted as a notification, by the gateway or by
  the upstream, never as the gateway's refusal, because a forwarding gateway
  relays whatever the upstream wrote (decision D17). Exit 0 is OK, MISSING or
  KNOWN-LIMIT only; MISMATCH and UNVERIFIED are sub-labels of a LEAK line,
  never a verdict that passes (decisions D12, D13 and D18).
- Record the audit head outside the database after every `audit verify`, and
  verify with `audit verify --expect-head HASH`. The chain proves that nothing
  inside it was altered; only a head recorded elsewhere proves that the whole
  log was not replaced or extended by someone who can write the file, since a
  correctly sealed entry that approves a definition can be appended by anyone
  with write access and nothing inside the file can refute it (decision D14).
  Inside the file an audit entry, and since the seventh round every column a
  decision or a server view acts on, is trusted only through the chain the
  `Store` verified when it opened, so a forger must rewrite every entry from the
  forged one to the head. A running `Store` catches that through the head it
  pinned; a rewrite made while no `Store` holds a pin, which is the CLI's state
  between commands and the processors' state while they are stopped, verifies
  clean on the next open and is caught by the recorded head alone (decision D15
  as corrected by D17). The processor's pin protects only while a processor runs
  and the CLI is never protected by a pin, so record the head after every verify
  and compare it with `--expect-head` before every decision you make after the
  processors were stopped. Keep the git export of approved definitions (`export
  --dir`, signed with `--sign-key` so that it records the head it mirrors) and
  backups as the other two anchors, and run `export verify --dir DIR --pub-key
  FILE --expect-head HEAD` beside `audit verify --expect-head` with the head you
  recorded: the export then verifies against the key you hold and the head you
  recorded, opening no database (decision D21 (e);
  `TestExportSignsTheManifestAndVerifyRoundTrips`). `audit log ok` in forensic
  mode means the chain is consistent, not that the file is intact; every other
  command, `list` and `show` included, refuses a file whose guard objects are
  missing or redefined, or that holds a trigger, view or unique index the schema
  did not create.
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
  (decision D13); the addresses live in the catalog's servers row (`server
  list` shows them), which since the seventh round must agree with the newest
  verified `server.processor_set` audit entry about the server, else `emit`
  refuses to emit, and `emit` never reads them from the file at `--out`, so a
  re-emit after a CONFIG-EDITED cannot adopt an address the editor chose, and
  prints a change line whenever the address it writes differs from that entry
  (decisions D14 and D17; before the seventh round the row was read with no
  check, so one `UPDATE` of the column made the remedy write a forger's
  address in silence). `--out` and the canary's `--config` must be regular
  files (decision D14), and `emit` refuses an `--out` that is the catalog
  database, its `-wal` or `-shm` sibling or the `--gateway-binary` path, and
  refuses to replace an existing regular file whose header lines are not its
  own, as usage errors naming the fix (decision D17; a file the gateway
  rewrote keeps the header lines and stays replaceable).
- Run crawls under the system actor (no `--as`, no `TOOLWARRANT_ACTOR`) in
  automation, and decide as yourself. A person whose crawl proposed a digest
  cannot approve it.

## Dependency policy

- Every dependency is pinned in `go.mod` and `go.sum`; every build runs with
  `GOFLAGS=-mod=readonly`. The Go toolchain is pinned (`go 1.27`,
  `toolchain go1.27.2`).
- `govulncheck ./...` runs as the `govulncheck` job of
  [.github/workflows/ci.yml](.github/workflows/ci.yml) on every pull request
  and every push to main, and before every
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
  forwarded (HTTP 202, the fail-open shape of v1.6.0); a canary running with
  `--expect-unhooked` reports PROBE-CHANGED, exit 1, the moment that answer
  changes (decision D18). The seventeen items of
  that re-qualification, the script that runs them
  (`scripts/requalify-gateway.sh vX.Y.Z SHA256 --e2e`, where SHA256 is the
  published digest of the candidate's linux asset, which the script checks
  before it runs anything) and the `requalify` job of the `ci` workflow are
  in [docs/operations.md](docs/operations.md), Moving the gateway pin (L7). The probe attributes
  no other answer to the gateway, so a move of the pin cannot make it claim a
  refusal it did not see: a 400 with an empty or non-JSON body is reported as
  not accepted as a notification, by the gateway or by the upstream; a 2xx
  answer with a body that is not a plain 202, a 400 whose body is JSON, an
  SSE event whose joined `data:` lines are JSON, a body with a byte-order
  mark before JSON and a body cut at the probe's 1 MiB read cap are
  PROBE-INCONCLUSIVE; and a 2xx without a body or any other status is a
  `check failed` line (decisions D13, D14, D15 and D17).

## Release integrity

The release workflow runs when a `v*` tag is pushed (decision D16).

- A release is one annotated git tag on a commit whose newest `ci` run from a
  push to `main` succeeded; the `release` workflow's gate refuses a tag whose
  commit has no such run, and the release job checks that the commit it
  built is the one the gate verified. Who may create a `v*` tag is a matter
  of write access and of the tag ruleset `v* tags: owner only` (id 24941252;
  docs/operations.md, Releasing); the workflow cannot enforce it, since
  GitHub runs the workflow file of the tagged commit. A published release is
  never re-run (a fix is a new tag).
- A tag is never moved or deleted. The Go module system treats a tag as
  immutable: a tag re-pointed to another commit gives every `go install` user
  a `SECURITY ERROR` from the go command, because the download no longer
  matches what sum.golang.org recorded for that version, and a deleted tag's
  content stays on proxy.golang.org. A bad release is a new tag plus a
  `retract vX.Y.Z // reason` directive in `go.mod` (a `retract` changes
  nothing in `THIRD_PARTY_NOTICES.md`: the notices script reads only the
  `require` blocks). The tag ruleset blocks the creation, update and deletion
  of `v*` tags for everyone but the repository owner, who holds to the same
  rule.
- The workflow builds the `toolwarrant` binary for darwin/arm64, darwin/amd64,
  linux/amd64 and linux/arm64 with CGO disabled and `-trimpath`, writes one
  SPDX SBOM per archive with syft, and signs the checksums file keyless with
  cosign under the workflow's own OIDC identity, as a sigstore bundle
  (`.sigstore.json`: signature, certificate and transparency-log entry).
- From v0.2.0 on the workflow also attests the build (decision D20 (a)).
  After goreleaser, `actions/attest-build-provenance`, pinned by commit, reads
  the checksums file, so the subjects of the statement are the four archives
  and the four SBOMs by name and SHA-256; the predicate is SLSA provenance v1
  (`https://slsa.dev/provenance/v1`) naming this repository, the workflow
  path `.github/workflows/release.yml`, the tag ref and the commit; the
  statement is signed keyless under the workflow's identity, recorded in
  Sigstore's public Rekor log and stored by GitHub, which is SLSA Build
  Level 2 (the attestation is produced in the job that built the binaries).
  The bundle is also a release asset,
  `toolwarrant_<version>_provenance.intoto.jsonl`, for offline verification.
  Releases before v0.2.0 carry the cosign bundle alone.
- The release notes are the version's section of `CHANGELOG.md`, extracted by
  `scripts/release-notes.sh` before goreleaser runs; a tag whose section is
  empty publishes nothing (D20 (d)). The workflow's gate refuses a tag whose
  release is already published, and once the owner has enabled immutable
  releases (before the first v0.2.0 candidate; D20 (b)) a published release's
  tag is locked to its commit and its assets are frozen for as long as the
  release exists, with a release attestation from GitHub that
  `gh release verify vX.Y.Z --repo sairam0424/toolwarrant` and
  `gh release verify-asset vX.Y.Z <file> --repo sairam0424/toolwarrant`
  (gh 2.81 or later) check; a fix is a new tag. Release candidates
  (`vX.Y.Z-rc.N`) are published as pre-releases and kept.
- Two public transparency logs anchor a release already. The sigstore bundle
  carries the entry that Sigstore's public Rekor log recorded for the
  signature, and `cosign verify-blob --bundle` checks that entry (the v0.1.0
  bundle carries one). sum.golang.org, the Go checksum database, records the
  module's `go.sum` lines at a tag the first time that version is fetched
  through proxy.golang.org, and the go command checks every later download of
  the version against the record. The Releasing section of
  docs/operations.md fetches each tag right after publishing and checks the
  record, so the record exists before any user's first download; the record
  for v0.1.0 exists.
- `toolwarrant version` prints the build version (the tag without its `v`,
  set at link time) and the pinned gateway version, so a deployment can be
  matched to a release. A binary built with
  `go install github.com/sairam0424/toolwarrant/cmd/toolwarrant@vX.Y.Z` has
  no link-time version and falls back to the module version the go command
  embedded, the tag with its `v` (`toolwarrant vX.Y.Z`;
  `TestVersionFallsBackToTheModuleVersion`); the binaries installed from
  v0.1.0 and v0.1.1 predate the fallback and print `dev`. `go version -m
  toolwarrant` names the module version and its `go.sum` hash for any such
  binary.
- The seam and mock binaries are never released.

Verifying a release before running it, with gh (2.81 or later; releases from
v0.2.0 on):

```sh
gh attestation verify toolwarrant_0.2.0_linux_amd64.tar.gz --repo sairam0424/toolwarrant \
  --signer-workflow sairam0424/toolwarrant/.github/workflows/release.yml \
  --source-ref refs/tags/v0.2.0
gh release verify v0.2.0 --repo sairam0424/toolwarrant
gh release verify-asset v0.2.0 toolwarrant_0.2.0_linux_amd64.tar.gz --repo sairam0424/toolwarrant
```

The first command fetches the provenance GitHub stores for the archive's
SHA-256 and proves the archive was built by this repository's release workflow
from that tag, checking the SLSA predicate type by default; without network,
pass the downloaded bundle and a trusted root fetched earlier
(`gh attestation trusted-root > trusted_root.jsonl` while online, then the
same command with `--bundle toolwarrant_0.2.0_provenance.intoto.jsonl
--custom-trusted-root trusted_root.jsonl`). The second and third commands
check GitHub's release attestation of an immutable release: that the release
under the tag and that asset are the ones published. With cosign and shasum,
which need no GitHub account and work for every release since v0.1.0:

```sh
cosign verify-blob --bundle toolwarrant_0.1.0_checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/sairam0424/toolwarrant/.github/workflows/release.yml@refs/tags/v0.1.0" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  toolwarrant_0.1.0_checksums.txt
shasum -a 256 -c --ignore-missing toolwarrant_0.1.0_checksums.txt
```

The first command proves the checksums file was produced by this repository's
release workflow at that tag; the second proves the downloaded archive is the
one it lists.

Rebuilding a release to check it, with the verified archive in the directory
you clone into: the build is reproducible (CGO disabled, `-trimpath`, no date
in the link flags, archive timestamps taken from the commit), so a clean clone
at the tag, built with the toolchain `go.mod` names, gives the archive's
binary byte for byte. The checkout must be clean: the version control state
is a build input, so a tree with local changes, or an archive without `.git`,
gives another binary.

```sh
git clone --branch v0.1.0 https://github.com/sairam0424/toolwarrant.git && cd toolwarrant
git status --short   # prints nothing
CGO_ENABLED=0 GOFLAGS=-mod=readonly GOTOOLCHAIN=go1.27.2 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags "-s -w -X main.version=0.1.0" -o rebuilt ./cmd/toolwarrant
tar -xzf ../toolwarrant_0.1.0_linux_amd64.tar.gz toolwarrant
cmp rebuilt toolwarrant
```

`GOTOOLCHAIN` names the toolchain `go.mod` pins (`toolchain go1.27.2`), which
the go command downloads when the host has another; `GOOS` and `GOARCH` select
the archive being checked. `cmp` prints nothing when the two files are equal.
v0.1.0 was rebuilt this way on 2026-10-14, on a host other than the release
runner, for linux/amd64 (SHA-256 of the binary
`34e1fd446d9f89606e282aeb38e34484f79ab269b59bcac3d96fd42023d2934e`) and for
darwin/arm64 (`aa60e92b74c8c360d186ea340284c08f70bd913b54c8e7663e9b7cfbabefc0f4`),
and `cmp` printed nothing for either.
