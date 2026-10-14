# Operations

This guide covers the day-to-day running of toolwarrant v0.1 against
agentgateway v1.6.0. Command names and flags are those of the CLI's command
table in `cmd/toolwarrant/main.go` (`toolwarrant help COMMAND` prints them).
Every behaviour described here is covered by an in-process test of
`cmd/toolwarrant` or of the package behind the command, and the chain through
the real gateway by a scenario of the end-to-end test (`e2e/`, `make e2e`,
scenarios A to P); see [threat-model.md](threat-model.md) for the test names.
The fourth round (the fixes after the third review, 2026-10-11, decision D13 in
[decisions.md](decisions.md)) changed the canary, `crawl --every`, `emit`,
`audit verify` and the recovery procedures. The fifth round (the fixes after
the fourth review, 2026-10-12, decision D14) changed what the canary compares,
where processor addresses live, what `list` and `show` refuse, what a running
processor does when the catalog file is replaced, and the recovery procedures
again. The sixth round (the fixes after the fifth review, 2026-10-12,
decision D15) changed what a store verifies when it opens and what it trusts
afterwards, what the canary compares inside every route and in `config`, when
`emit` records processor addresses and which processor hosts it refuses, how
the processor marks a page the transport refuses and judges a listing it sees
during a pause, and the probe's healthy shape. The seventh round (the fixes
after the seventh review, 2026-10-12, scoped to the catalog chain and the
canary, decision D17) changed what a decision and the server views trust (the
chain, never a column on its own), what `audit verify` and `audit list` show
about rows below the first, what the probe claims (nothing it cannot
attribute), what the live comparison compares (the backend target name and the
canary's own ports too), what `emit` refuses to write over, and the words in
which the limit of the chain pin is stated. Decision D18 (2026-10-14, after the
post-v0.1 research) added the "Deployment requirements" section and the
canary's `--expect-unhooked` flag; the sections below describe the behaviour
since then.

Global flags come before the command: `--db PATH` (or `TOOLWARRANT_DB`, default
`./toolwarrant.db`), `--as NAME` (or `TOOLWARRANT_ACTOR`; the name `crawler` is
reserved for the system actor) and `--allow-self-approval`. Every command except
`init` refuses to run when the database file does not exist, so a mistyped path
cannot quietly become an empty catalog.

## Running the processor

One processor guards one upstream. `emit` prints the exact command for each
server; the shape is:

```sh
toolwarrant --db /var/lib/toolwarrant/toolwarrant.db serve \
  --server github --listen 127.0.0.1:9001 \
  --secret-env TOOLWARRANT_SECRET_GITHUB \
  --max-evidence-age 10m
```

- `--listen` takes `host:port` or `unix:/path`. A TCP address must be loopback
  (a loopback literal, `localhost` or one of the loopback aliases common
  resolvers map without DNS, such as `localhost.localdomain` and
  `ip6-loopback`; D15) unless `--allow-non-loopback` is given, and with that
  flag `serve` still refuses to listen without `--secret-env` or
  `--tls-client-ca` unless `--insecure-no-secret` is passed as well, because
  anyone who reaches an unauthenticated processor decides what the gateway
  serves; a `--secret-env` or `--tls-client-ca` always wins over
  `--insecure-no-secret` (owner decision O-2, D19 planned: a verified client
  certificate authenticates the hooks as the secret does; cmd
  `TestServeTLSClientCASatisfiesTheNonLoopbackRule`,
  `TestCheckListenAddrPolicy`). Use the pairing only on a network nobody but
  the gateway can reach. A unix socket is created 0600, with a warning when its
  directory is not 0700. Both refusals are usage errors (exit code 2) because
  the fix is a flag.
- `--target NAME` is the backend name the gateway reports in `service_names`;
  it defaults to the server name, which is what the emitted configuration uses
  (end-to-end scenario J confirmed the value on the real gateway). Set it only
  if you emitted the file with another backend name. The processor logs the
  first mismatch once at Warn (`hook names another backend`, with the quoted
  `service_names` value), denies every such hook with `wrong backend` and
  counts them in the stats line.
- `--secret-env VAR` names the environment variable holding the shared secret
  that `emit --secret-env` wrote into the gateway file. It is read from the
  environment so that it never appears in a process listing, and it is checked
  up front against the emitter's rule (16 to 256 printable ASCII characters).
  The gateway delivers it in `metadata_context` on both hooks (scenario H).
- `--tls-cert PATH` and `--tls-key PATH` (both or neither) make the processor
  terminate TLS on its TCP listener, TLS 1.3 only (a client that offers at most
  1.2 is refused in the handshake), with the PEM certificate chain and private
  key in the two files. `--tls-client-ca PATH` names a PEM certificate
  authority and makes every connection present a client certificate that
  authority signed; a connection without one, with one from another authority,
  or in plaintext is refused in the handshake and never reaches a hook, so the
  stats line counts nothing for it. With `--tls-client-ca` the hooks are
  authenticated by the certificate, so `--allow-non-loopback` no longer needs
  `--secret-env` (owner decision O-2); a `--secret-env` given as well is
  checked on every hook as before. Without `--tls-client-ca` TLS protects the
  bytes on the wire and any TLS 1.3 client is served, so the non-loopback rule
  is unchanged. The three files must be regular files (a symbolic link,
  directory, named pipe, device or socket is refused before it is opened, as
  every file the CLI opens by path) and the key must be readable by its owner
  only, as the database is (`chmod 600`). One of `--tls-cert` and `--tls-key`
  without the other, a `--tls-client-ca` without both, and any TLS flag with
  `--listen unix:` (the socket is guarded by its file permissions and the
  gateway dials it in plaintext) are usage errors (exit code 2); a file that is
  missing or not PEM, or a key that group or others can read, is exit code 1.
  The listening line names the mode after the target: `TLS 1.3 with a client
  certificate required` or `TLS 1.3 with a server certificate only`. The
  gateway's side of the link is the `backendTLS` block on its processor entry,
  which the live comparison already compares and which a later `emit` writes
  (D19, planned, together with the end-to-end scenario Q that observes the
  handshake against the real gateway; until then the processor's TLS is proven
  against grpc-go clients only). Rotate a certificate as the secret is rotated
  (see "Rotating the shared secret"): a second processor on a new port with the
  new files, re-emit, retire the first. (cmd
  `TestServeTLSOverGRPCEnforcesApprovals`,
  `TestServeTLSRefusesAClientWithoutACertificate`,
  `TestServeTLSFlagsNeedCertAndKeyTogether`,
  `TestServeTLSRefusesAUnixSocketListener`,
  `TestServeTLSRefusesAGroupReadableKey`; processor
  `TestServe_TLSListenerRefusesPlaintextAndUnknownClients`,
  `TestServe_TLSWithClientCARequiresAClientCertificate`,
  `TestServe_TLSWithoutClientCAAcceptsAnyClient`,
  `TestServe_ClientCertificateSilencesTheNoSecretWarning`,
  `TestServe_RefusesAnUnusableTLSConfig`.)
- `--max-evidence-age DURATION` expires the digests the processor remembers
  from gateway listings; 0 (the default) keeps them until the next listing or a
  catalog change. It ages conflict markers too (limit L15).
- The processor opens the catalog read-only and can never change it (cmd
  `TestServeOpensTheCatalogReadOnly`, catalog `TestOpenWith_ReadOnly`). Run it
  as the catalog's owner: the catalog refuses a database file that its group
  or others can read, and the CLI has no flag to allow a shared file, so a
  processor under another OS user cannot open it. SQLite needs the `-wal` and
  `-shm` files next to the database; a read-only open cannot create them, so
  run one ordinary command as the owner after `init` (any `list` does) in a
  directory the owner can write.
- The processor reloads its snapshot only when the catalog's generation counter
  moves, so approvals, rejects, rollbacks, disables and pauses take effect on
  the very next hook without a restart while the file is the same (scenarios
  D and E). When its store opens it verifies the whole audit chain once, from
  the first entry to the head, and pins the head (D15; the read `audit verify`
  already pays). Every reload re-checks the guard objects and every table's
  DDL, refuses a trigger, view, unique index or unaccounted automatic index
  the schema did not create, requires the newest approve or rollback decision
  about every approved tool to name the approved version and digest (D13) and
  the newest `version.approved` or `version.rolled_back` audit entry about it
  to carry that digest (D14), verifies the entries after the pin and advances
  it, and trusts an audit entry only when the hash computed from its fields
  equals the hash its own verified walk recorded for that sequence number,
  never the hash column stored in the file (D15; before the sixth round the
  entry was re-sealed against its predecessor only and the pin covered the
  head and the suffix after it only, so an approval entry rewritten in place
  below the head was served); a catalog it cannot read or trust denies every
  hook (`source errors`). A store is safe for concurrent use: a reader whose
  read snapshot predates a commit that another handle of the same store
  already verified cannot occur: every checked read takes the store's walk
  lock before its first statement, so its snapshot never predates the pin it
  is compared with and it is never refused as a truncated log (D17; the
  seventh review showed a reader in exactly that position getting `audit
  entry N, which this store verified, is gone; the log was truncated or the
  file replaced under a running reader` for an untouched file; no shipped
  runtime reads and writes one store at once today, so no processor was
  affected). The pin protects a store only while it is open: the processor's
  pin protects while the processor runs, and a CLI command's store opens and
  closes with the command, so a rewrite of the audit log made while every
  processor is stopped is caught by the head you recorded alone.
- The file must stay the same file. `init` writes a random catalog identity
  into the database and the processor's store records it together with the
  file's device and inode when it opens; every read re-checks both (D15;
  before the sixth round the generation read compared the identity and every
  other read the device and inode alone), so a catalog file that was deleted,
  replaced or re-initialised under a
  running processor is refused (`ErrReplaced`, which is also `ErrCorrupt`):
  every hook is denied with the reason `catalog unavailable`, counted under
  `source errors`, and `catalog unavailable, denying` is logged at Error until
  the processor is restarted (D14; before the fifth round the processor kept
  reading the deleted file through its open handle, its generation never
  moved, and it served the old approvals with `source errors` at zero; e2e
  scenario N deletes and re-initialises the catalog under two running
  processors, both denied everything 23 and 26 ms later, and a processor
  started on the new file served the re-approved tool and denied a tool
  approved only in the deleted one; catalog
  `TestGeneration_DetectsADeletedAndReinitialisedFile`, processor
  `TestCheckResponse_ReplacedCatalogFileDeniesEveryHook`). Stop every
  processor of a file before you delete or replace it, and start them after
  `init`; the recovery procedures below say so at each step where a file is
  deleted.
- The evidence the processor remembers from the gateway's own listings lives
  in a table sized from the snapshot. It records evidence for every catalog
  tool a page names, servable or not (D15; before the sixth round evidence
  seen while a tool could not be served was discarded, so a listing while a
  tool was disabled or its server paused left the older agreeing digest in
  place), never for a name the catalog does not know, and when it is full it
  evicts an entry that agrees with its approval,
  never a conflict marker or a changed digest (D13), so a full table cannot
  make a changed tool callable; when nothing agreeing is left the new evidence
  is dropped and counted (`Stats.EvidenceDropped`), and while that count is
  above zero a servable tool with no listing evidence is denied as not yet
  verified until a listing records it. A page the processor cannot read through
  to the end (one of more than 10000 tools included) marks every
  catalog tool of the server, servable or not, as conflicting until a clean page shows the
  approved digest (D13), and so does a `CheckResponse` call the gRPC transport refuses
  for size (D15), when a gateway forwards such a page at all: agentgateway
  v1.6.0 answers the client HTTP 500 on `tools/list` before the hook runs for
  a page over its own limit (e2e scenario J, 6 MiB and 9 MiB pages, the
  processor logging nothing), so such a page marks nothing and a client that
  listed earlier keeps its evidence until the next clean listing or crawl;
  expect `tools/call` denials with the reason `changed since approval` after a
  page the processor did read and deny, until the upstream serves a clean
  listing (limit L1). The table is pruned only
  against a non-empty snapshot and never loses a contradiction, so a
  `server pause` followed by a `server resume` keeps every marker and changed
  digest the gateway's listings recorded (D14; before the fifth round the
  empty snapshot of a paused server emptied the table, and a resumed server
  was judged on the last crawl's digest alone), and a listing the gateway
  makes during the pause is judged against the names already in the table: a
  readable page records its digests for them and an unreadable page marks
  every one (D15; before the sixth round the empty snapshot made every name a
  catalog miss and such a page recorded nothing; processor
  `TestCheckResponse_OversizedPageMarksEveryServableToolBeforeDenial`,
  `TestServe_OversizedPageOverTheWireMarksEveryCatalogTool`,
  `TestCheckResponse_EvidenceIsKeptForEveryCatalogTool`,
  `TestCache_ListingWhileDisabledDeniesTheEnabledCallUntilACleanListing`,
  `TestCache_PauseAndResumeKeepTheListingEvidence`; e2e scenario J pads a page
  past the cap next to a changed tool and checks that the session which listed
  the clean page is denied on its next call).
- Logs are JSON lines on stderr. Tool names in log lines are quoted, so a name
  cannot forge a log line. Denials and hides are logged; the shared secret and
  catalog contents never are.
- On SIGINT or SIGTERM the processor stops gracefully, prints its counters and
  exits 0; an error that stops it exits 1. The stats line is:
  `stats: lists served=N denied=N, tools hidden=N (mismatched=N unapproved=N
  oversized=N unverified=N), calls allowed=N denied=N, wrong backend=N,
  unauthenticated=N, throttled=N, source errors=N, evidence dropped=N`
  (scenario N; pinned by `TestWriteStatsPinsTheLine`). `evidence dropped` is
  `Stats.EvidenceDropped`; a non-zero value is a standing condition, described
  under the evidence table above. Tools the catalog has never heard
  of are `hidden` minus the named categories. Since the third round the
  processor also counts tools hidden because the latest crawl left the
  unusable marker in the catalog while the gateway showed the approved bytes
  (`Stats.ToolsUnverified`, the `unverified` field of the `tools/list filtered`
  log line).
- Interpretation. `mismatched` on a tool you just approved is the gateway
  re-serialisation case (limit L2), not drift; the canary reports such a tool
  as MISSING. `unauthenticated` above zero with a secret configured means the
  gateway is not sending it, or is sending another one: every such hook was
  denied. `throttled` means more than 32 hooks were in flight; the surplus was
  denied, never queued. `wrong backend` means the route sends hooks about
  another backend to this processor: check the emitted file and the Warn line.

Start the processors before the gateway, or accept that the gateway denies
every hooked request until they are up (`failureMode: failClosed`; scenario G
saw the route serve again within about 60 ms of a processor restart).

## Deployment requirements

toolwarrant keeps no data plane of its own (decision D11): the gateway is the
data plane, and a behaviour of agentgateway v1.6.0 that toolwarrant can only
make visible, not refuse, is met by the deployment.

Only clients that send a JSON-RPC `id` on every `tools/call` may reach the
gateway's serving port, or an enforcement point that refuses an id-less
`tools/call` must stand in front of it. agentgateway v1.6.0 forwards a
`tools/call` sent as a notification (no `id`, or `id: null`) to the upstream
without the ExtMCP hook and without the allow rule (limit L17, threat model row
25), so a client that drops the id executes any tool the upstream has, approved
or not. The official SDKs always send an id; a hand-written client, or a proxy
that rewrites messages, may not. toolwarrant provides no such enforcement point
and will not (D11, D18): it would have to terminate HTTP, parse batched JSON-RPC
and server-sent events, carry client credentials, teach the canary a second
listener, and reverse the README's non-goal of no data plane. Keep the serving
port on 127.0.0.1 (the emitted default) or on a network only those clients
reach; `emit --bind-address` widens it and prints a warning. The canary's probe
shows that the gateway still has the shape: run `verify-gateway` with
`--expect-unhooked` (next section), which prints the 202 as `KNOWN-LIMIT` on
every check and fails as PROBE-CHANGED the moment the gateway answers anything
else (D18; cmd `TestExpectUnhookedTurnsThe202IntoAKnownLimitLine`,
`TestExpectUnhookedFailsWhenTheGatewayStopsForwarding`; e2e scenario O). The
report of the behaviour to the agentgateway project is the owner's action
([../SECURITY.md](../SECURITY.md)). The other host-level requirements, the
processors on loopback or a unix socket with the shared secret, the admin
listener treated as part of the trusted computing base, the owner-only database
and configuration file, are the items of the hardening checklist in
[../SECURITY.md](../SECURITY.md).

## Running the canary

`verify-gateway` is the deploy-time self-test and the canary. It opens a new
MCP session through the gateway route like a client would, lists the tools and
compares each served definition with the catalog's serving policy. With
`--config` it checks that the file on disk is the one `emit` wrote; with
`--expect-body-hash HEX` it also checks that the file's body hashes to the
`body sha256` line `emit` printed when you wrote it; with `--admin` (which needs
`--config`) it fetches the live configuration from the gateway's admin API and
compares the live document with that file; and unless `--no-probe` is given it
sends one `tools/call` without a JSON-RPC id to see whether the gateway forwards
unhooked calls (decisions D12, D13 and D14), which with `--expect-unhooked` is
the declared answer (D18). The file named by `--config` must
be a regular file: a symbolic link, directory, device, socket or named pipe at
that path is refused before it is opened, because a read of a named pipe
blocks until a writer appears and a canary that blocks prints no verdict and
exits nothing (D14; the fourth review planted a FIFO and the canary ignored
SIGTERM and SIGINT until it was killed; cmd
`TestVerifyGatewayReportsAFIFOAtConfigAsEdited`):

```sh
toolwarrant verify-gateway --server github \
  --url http://127.0.0.1:3000/github/mcp \
  --config /etc/agentgateway/gateway.yaml \
  --expect-body-hash BODY_SHA256_PRINTED_BY_EMIT \
  --admin 127.0.0.1:15000 \
  --expect-unhooked \
  --every 1m --keep-going
```

The example passes `--expect-unhooked` because agentgateway v1.6.0 forwards the
id-less probe on every check (limit L17): without a probe flag every check of
this gateway prints UNHOOKED-CALLS and exits 1. Run the canary once that way to
see the verdict for yourself and record the limit in your runbook, then run it
with `--expect-unhooked`: the probe stays on, the 202 is printed as
`KNOWN-LIMIT`, the OK line names it, and the check exits 0; the moment the
gateway answers the probe with anything else it can classify, a bare 400 or one
of the PROBE-INCONCLUSIVE shapes, the check fails as PROBE-CHANGED, exit 1,
because the pin moved or the gateway changed under it and the deployment must
be re-qualified (limit L7) before the flag describes it again (D18; cmd
`TestExpectUnhookedTurnsThe202IntoAKnownLimitLine`,
`TestExpectUnhookedFailsWhenTheGatewayStopsForwarding`,
`TestExpectUnhookedAndNoProbeAreExclusive`). Before D18 the advice was
`--no-probe`, which switches the probe off; it is still accepted and is
exclusive with `--expect-unhooked`, but prefer the flag: a canary that sends no
probe cannot notice the gateway changing, and a canary that fails on every run
trains its readers to ignore it. The probe proves the fail-open shape of v1.6.0
and nothing else: it cannot prove that the hook ran, because an answer other
than 202 may have been written by the gateway or by the upstream behind a
forwarding gateway,
and since the seventh round it says so instead of attributing the answer (D17;
before, a 400 with an empty or non-JSON body was reported as `rejected by the
gateway`, which a go-sdk upstream behind a forwarding gateway writes itself).
On a gateway that does not answer 202, leave the probe on without either flag
and read its line as what it is: the one shape known to bypass the hook did
not occur.

Verdicts, one line per tool or per check:

- `LEAK name live DIGEST approved DIGEST`: the gateway serves a definition the
  catalog would not serve: an unapproved tool, a disabled or paused one, a
  drifted or rejected definition, a definition that cannot be used. Exit code
  1. Two sub-labels say more. MISMATCH: an approved, enabled tool whose live
  digest differs from the approved one while the latest crawl saw the approved
  digest; both digests are printed so the owner can see whether the served
  definition is legitimate and approve it if it is. A client can only see such
  a definition on a route that has lost its processor: with the processor in
  place the mismatched tool is hidden and shows as MISSING. UNVERIFIED: the
  tool is served at its approved digest but the latest crawl left the unusable
  marker (an invalid or duplicated live definition, or the exhausted proposal
  budget of limit L6), which the processor treats as "neither listed nor
  callable" through the same predicate (`lifecycle.LastSeenVerifiable`), so a
  route that serves it has no processor (D13; before the fourth round the
  canary counted such a tool as approved and current).
- `MISSING name digest`: the catalog approves the tool and the latest crawl saw
  the approved digest, but the gateway does not serve it. Either the allow
  rule in the gateway file is stale (run `emit` again) or the gateway
  re-serialises the definition before the hook (limit L2); the processor's
  `digest mismatch` log line and `mismatched` counter tell the two apart.
  Scenario L printed `MISSING vendor_tool` for the re-serialised tool. Which
  key paths the pinned gateway drops, keeps and adds is the golden
  `e2e/testdata/gateway_tool_keys.json` (dropped: unknown top-level keys,
  unknown `annotations` members, `execution` and the `_meta` member `ui`;
  kept: `title`, `outputSchema`, `icons`, members inside `inputSchema` and the
  other `_meta` members); scenario L fails when a run differs, naming the list
  and the entries, and writes what it saw to
  `logs/gateway_tool_keys.observed.json` in its work directory, the file to
  copy over the golden when the gateway pin moves (L7). A tool whose latest
  crawl left the unusable marker is not MISSING when the gateway does not list
  it: a working processor hides it.
- `CONFIG-EDITED`: the file named by `--config` fails `emit.Verify` (its body
  no longer matches the hash in its header, or the header is missing), cannot
  be read at all or is not a regular file, because a canary that cannot read
  the file it is meant to compare must not report OK, or hashes to something
  other than the value you passed with `--expect-body-hash`, which is how an
  edit that recomputed the header line is caught (limit L19; D13). Exit code
  1. Regenerate the file with `emit` and record the new body hash; the
  processor addresses `emit` writes come from the catalog's servers row, never
  from the file it replaces, so a re-emit after a CONFIG-EDITED cannot adopt
  an address the editor chose (D14; check `server list` if you want to see
  them), and since the seventh round that row must agree with the newest
  verified `server.processor_set` audit entry about the server, else `emit`
  refuses with `ErrCorrupt`, and `emit` prints a change line whenever the
  address it writes differs from that entry (D17; before, the row was read
  with no check, so one `UPDATE` of the column made this remedy write a
  forger's address into the configuration in silence). A file
  written by an older emitter whose header text changed also fails and must be
  re-emitted (scenario F); a file the gateway rewrote through the admin API
  keeps the header lines and is replaced by the re-emit, while a regular file
  at `--out` whose header lines are not emit's is refused (D17).
- `LIVE-CONFIG-MISMATCH`: with `--admin HOST:PORT` (or an http or https URL;
  the address given to `emit --admin-addr`, default `127.0.0.1:15000`), the
  configuration the gateway is running (`GET /api/config`) is not the file
  named by `--config`. What is compared, exactly: the live document is decoded
  as a map of top-level sections, and every non-empty section other than
  `config`, `gateways` and `routes` is a mismatch on its own, one line per
  section (a section that is null, an empty object or an empty array is not
  reported),
  because the pinned gateway loads fourteen top-level sections (its own
  `--validate-only` lists them: `config`, `binds`, `frontendPolicies`,
  `policies`, `workloads`, `services`, `backends`, `routeGroups`, `gateways`,
  `routes`, `tcpRoutes`, `llm`, `mcp`, `ui`) and a `binds` listener or a
  top-level `mcp` shortcut carries routes with no processor; the `config`
  block's admin, stats and readiness addresses must be the emitted ones and no
  other field may be in that block; every
  gateway and every route the file carries must be present exactly once with
  the same bind address, port, allow rules, backend hosts and match path, and
  with the same processors, each compared by host, kind, failure mode,
  methods, `requestHeaders` filter (the allowed and the disallowed list), the
  `backendTLS` block under the processor's `policies` (its `cert`, `key`,
  `root` and `hostname`, which are paths on the gateway host and the name the
  processor's certificate is verified against, so the line shows them; a
  block only one side carries is one line of its own, since without it the
  gateway dials the processor in plaintext, limit L11) and a
  hash of its canonical metadata, which holds the shared secret and is never
  printed; the MCP backend target's name is compared as well as its host
  (D17; the name is the server name, so the line may show it: before the
  seventh round only the host was read on either side, so a target renamed
  through the admin API, which the pinned binary accepts, compared as a match
  while the processor denied every hook about the renamed backend as `wrong
  backend` and the operator saw MISSING lines); every live route is decoded
  generically, and a route key other than
  `name`, `gateways`, `matches`, `policies` and `backends`, a policy other
  than `mcpAuthorization` and `mcpGuardrails`, a match that is not a single
  exact path and a backend that is not the one `mcp` backend with the emitted
  target are each a mismatch of their own, one line per item with the names
  escaped (D15; the fifth review posted the emitted document plus an
  `extProc` policy, a `requestMirror` to another host, a response
  transformation, a `urlRewrite`, a second host backend and a `config.mcp`
  block, each of which the pinned binary's `--validate-only` accepts, and the
  comparison, which decoded the known fields only, reported nothing; such a
  policy on the route would put a body processor or a mirror of every client
  request next to the hook). The line for such an item names its place:
  `policy requestMirror: not in the emitted file; the gateway applies it to
  this route` for a policy on the route of `--server` (`route NAME: ` is
  prefixed for another emitted route), `field KEY: not in the emitted file`
  for a route key, `match 1: field KEY: not in the emitted file` for a match,
  `backend 2: field host: not in the emitted file` for a backend,
  `config KEY: not in the emitted file` for a `config` field and
  `gateway NAME: field KEY: not in the emitted file` for a gateway field,
  `processor 1: backendTLS field insecure: not in the emitted file` for a
  `backendTLS` field `emit` does not write (`insecure`, `insecureHost`,
  `alpn`, `subjectAltNames`, `keyExchangeGroups`, `spiffe`) and `processor 1:
  policy backendAuth: not in the emitted file; the gateway applies it to the
  link to this processor` for a processor policy other than `backendTLS`
  (`requestHeaderModifier`, `transformations`, `backendAuth`); a
  place that is not the object or list the file has there is reported as a
  whole (`not an object as in the emitted file`), keys are escaped and values
  are never shown (cmd
  `TestLiveComparisonReportsWhatTheFileCannotCarryInsideAKnownSection`,
  `TestCompareDocumentsReportsAPolicyOrBackendTheFileCannotCarry`,
  `TestShapeWalkFailsClosedOnWhatItCannotRead`;
  `TestGatewayAcceptsExtraRoutePoliciesAndBackends` shows that the pinned
  binary loads them; e2e scenario P posts a `requestMirror` policy and a
  second backend through the admin API and records what the running gateway
  does with each against a mirror target it runs; on agentgateway v1.6.0 the
  `requestMirror` policy made new sessions on the route fail, the canary's own
  listing included, and the comparison still named the policy because since
  the sixth round it runs even when the listing fails). Nothing the file does not
  carry may exist (an added route, an added gateway); no path may appear
  twice; the path of `--url` must be the
  match of the emitted route for `--server` (D13 and D14; before the fourth
  round only the route named after the server was compared, so a shadow route
  that owned the path compared healthy, and before the fifth round only the
  `gateways` and `routes` sections were decoded and neither the filter nor
  the metadata was compared, so a `binds` or `mcp` section and a stripped
  filter compared healthy); and the port of `--url` must be the emitted
  gateway's port and the port of `--admin` the port of the emitted admin
  address, and the hosts: two IP literals must be equal (a gateway bound to
  127.0.0.1 does not listen on 127.0.0.2 or ::1), and a name must be loopback
  when the emitted bind is loopback, so that the
  listing and the live document the canary compares come from the gateway
  the file describes (D17; before the seventh round only the path of `--url`
  was held against the file, so a canary pointed at another listener, a
  second gateway instance on the same host or a staging port, reported this
  file as matching while it listed through another). The lines of the
  seventh round read `backend target name: emitted NAME, live NAME`, `the
  port of --url (P) is not the serving port of the emitted gateway NAME (Q);
  the listing above went through another listener` and `the port of --admin
  (P) is not the port of the emitted adminAddr (ADDR); the live configuration
  above came from another admin API`, with a `host of --url` and a `host of
  --admin` twin when the emitted address is loopback and the canary's is
  not (cmd `TestLiveComparisonComparesTheBackendTargetName`,
  `TestLiveComparisonHoldsTheURLAndAdminPortsAgainstTheEmittedFile`,
  `TestCompareCanaryAddresses`). The line for an extra section reads `section
  binds: not in the emitted file; it may bind ports and routes the comparison
  cannot see`; the line for a stripped filter reads `processor requestHeaders
  allowed: emitted :method, live (none)` with its `disallowed` twin; the lines
  for the TLS block read `processor backendTLS hostname: emitted NAME, live
  NAME` (one per field that differs, in file order), `processor backendTLS:
  the live processor has none while the emitted file carries it; the gateway
  dials this processor without TLS` and `processor backendTLS: the live
  processor carries backendTLS the emitted file does not` (cmd
  `TestLiveComparisonComparesTheProcessorTLS`,
  `TestLiveComparisonReportsAnInsecureTLSFlag`,
  `TestCompareProcessorsSeesAMissingBackendTLS`,
  `TestEmittedConfigReadsTheProcessorTLS`; `emit` writes no `backendTLS`
  block yet, so those tests hand-build the block where `emit` will write it,
  and what the running gateway renders for it in `GET /api/config` is not yet
  observed). Scenario
  P posted the emitted document plus a `binds` section with a listener on
  another port, and plus a top-level `mcp` shortcut, through the admin API of
  the running gateway: each was accepted with status 200 and rendered by
  `GET /api/config`, and through each new listener a fresh session listed
  every tool of the upstream, unapproved `wipe_database` included, and
  `tools/call echo` was allowed, so such a section is a route with no
  processor and no allow rule that only this comparison can see (cmd
  `TestLiveComparisonReportsASectionTheFileDoesNotCarry`,
  `TestLiveComparisonComparesTheConfigListeners`,
  `TestLiveComparisonComparesTheRequestHeaderFilter`,
  `TestLiveComparisonComparesTheProcessorMetadataWithoutShowingIt`). Exit
  code 1. This is what a processor-less route
  looks like in steady state: the allow rule hides the unapproved names, so
  the listing alone says OK until something drifts. It also catches a
  configuration replaced through the admin API (limit L18) and an operator
  pointing `--config` at the wrong file. The check needs the admin API on,
  which is the emitter's default; a file emitted with `--disable-admin` has
  nothing to compare against. Scenario P printed `LIVE-CONFIG-MISMATCH mock:
  processor: the live route has none` with exit code 1 after the processors
  were removed through the admin API, against a byte-identical copy of the
  emitted file; the gateway had rewritten the watched file with the header
  lines kept, so the same check against that file printed CONFIG-EDITED.
- `UNHOOKED-CALLS`: the gateway accepted the probe, a `tools/call` without an
  id for the tool name `toolwarrant.probe.<random>`, which no catalog can hold,
  as a notification (HTTP 202), which is the fail-open shape of agentgateway
  v1.6.0: it forwards such a call without the hook and without the allow rule
  (limit L17). Exit code 1. The probe
  reaches the upstream exactly when the gateway is unhooked, which is why
  `--no-probe` exists; with `--expect-unhooked` the same answer is the
  `KNOWN-LIMIT` line below instead (D18). Scenario O printed this verdict
  against the pinned binary, the hostile upstream's request log showed the
  probe arriving, and with `--no-probe` the OK line said `unhooked-call probe
  skipped (--no-probe)`.
- `PROBE-INCONCLUSIVE`: the gateway answered the probe with a 2xx status other
  than 202 and a body, or with a 400 whose body is JSON (an object, an array
  or a scalar), an SSE event whose joined `data:` lines are JSON, a body with
  a UTF-8 byte-order mark before JSON, or a body cut off at the probe's 1 MiB
  cap. Such an answer is a JSON-RPC answer somebody wrote, or an answer the
  probe did not read to the end, and the canary cannot tell whether the
  gateway or the upstream wrote it, so it reports that it proved nothing and
  fails the check (D13, D14, D15 and D17; before the sixth round only a
  single JSON-RPC error object was recognised, so a batch of errors on a 400
  was called healthy, and before the seventh round the three shapes after the
  first passed as non-JSON). Exit code 1. The one-line account
  then reads `id-less tools/call answered by someone (PROBE-INCONCLUSIVE)`.
  Not reachable on agentgateway v1.6.0,
  which answers 202 itself; after a move of the pin it means the probe's
  shapes must be re-derived against that release (limit L7). A 400 whose body
  is empty or is not JSON, read to the end, is not a verdict and not a
  failure: the probe cannot tell the gateway's own refusal from an upstream's
  refusal relayed by a forwarding gateway, so since the seventh round it
  reports what it saw without attributing it, `the id-less tools/call was not
  accepted as a notification (HTTP 400, by the gateway or by the upstream)`,
  and the check exits 0 on that account (D17; before, such a 400 was
  `rejected by the gateway`, which the seventh review produced from a go-sdk
  upstream behind a forwarding stand-in that had received the probe). A 2xx
  without a body and every other status is a `check failed` line, not a
  verdict; the line names the status and says whether the answer carried a
  body (`the gateway answered http status N with a body of M bytes`; D14;
  before the fifth round it said "without a body" whatever the body was; cmd
  `TestProbeReportsARelayed400WithAJSONRPCErrorAsInconclusive`,
  `TestProbeReportsA400WithABatchOfJSONRPCErrorsAsInconclusive`,
  `TestProbeErrorSaysWhetherTheAnswerHadABody`,
  `TestProbeDoesNotAttributeARelayedPlainTextRefusalToTheGateway`,
  `TestProbeReadsTheJSONShapesAnUpstreamCanRelayOnA400`).
- `KNOWN-LIMIT name: the gateway forwarded the id-less tools/call (HTTP 202),
  as agentgateway v1.6.0 does (L17)`: the probe's line under
  `--expect-unhooked` when the gateway answered 202, the shape the flag
  declares. A report, not a failure: exit code 0, not counted as a failing
  verdict line, and the OK line's third clause reads `id-less tools/call
  forwarded unhooked as declared with --expect-unhooked (KNOWN-LIMIT L17)`.
  The probe still reached the upstream; the line is there so that every check
  records the limit instead of silencing the probe (D18). Scenario O printed
  it against the pinned binary with exit 0, and the hostile upstream's request
  log gained the probe (run of 2026-10-14; cmd
  `TestExpectUnhookedTurnsThe202IntoAKnownLimitLine`).
- `PROBE-CHANGED name: the gateway no longer answers the probe with 202 (the
  id-less tools/call came back HTTP N); the pin moved or the gateway changed
  under it; re-qualify (L7) and drop --expect-unhooked once the probe's answer
  is understood`: under `--expect-unhooked`, any answer the probe can classify
  other than 202, a bare 400 and the PROBE-INCONCLUSIVE shapes alike. Exit
  code 1, and the one-line account reads `the id-less tools/call was not
  forwarded with HTTP 202 as --expect-unhooked declared (HTTP N,
  PROBE-CHANGED)`. The declaration no longer describes the gateway, so the
  deployment is re-qualified against the release that answered (limit L7)
  before the flag is passed again, or the flag is dropped and the probe's line
  read as it is (D18). An answer the probe cannot classify (a 2xx without a
  body, any other status) stays a `check failed` line on both paths. Not
  reachable on the pinned gateway, which answers 202 (cmd
  `TestExpectUnhookedFailsWhenTheGatewayStopsForwarding`: the go-sdk
  upstream's bare 400 and the four inconclusive shapes each printed it).
- `OK: the gateway serves N tool(s), N approved and current; live configuration
  matches the emitted file; id-less tools/call forwarded unhooked as declared
  with --expect-unhooked (KNOWN-LIMIT L17)` is the healthy line as printed with
  the flags of the example above, after the `KNOWN-LIMIT` line; the first
  clause gains counts such as `, 1 approved but not listed (MISSING)` when
  there are any, the second reads `live configuration not compared (no
  --admin)` without `--admin`, and the third reads `unhooked-call probe skipped
  (--no-probe)` with `--no-probe`, or `the id-less tools/call was not accepted
  as a notification (HTTP 400, by the gateway or by the upstream)` when the
  probe ran without either flag and the gateway answered 400 with an empty or
  non-JSON body (D17; the clause never says `rejected by the gateway`, because
  the probe cannot know that). Exit code 0 is OK, MISSING or KNOWN-LIMIT only.

Why a canary and not a one-off check: the gateway binds the processor chain per
MCP session. A reload that drops the processor leaves existing sessions guarded
and their statistics moving, and unguards only new sessions. Only a fresh
session can see that, which is what every `verify-gateway` run opens. With
`--every DURATION` (at least 1 s) the command repeats. Without `--keep-going`
the run ends with exit 1 at the first check that printed a failing verdict,
whatever a later step of that check did (D14; before the fifth round a check
that printed a LEAK and then hit a probe or listing error was printed as
`check failed` and the run went on; cmd
`TestEveryWithoutKeepGoingStopsAtALeakWhenTheProbeErrors`,
`TestEveryWithoutKeepGoingStopsAtAnEditedConfigWhenTheListingFails`); a
`check failed` line alone (the gateway could not be listed, the probe or the
admin fetch errored) is printed, counted and does not end an un-flagged run,
because a gateway that is down for a while is not a verdict about what it
serves. With `--keep-going` the run keeps
checking after a failed check instead of exiting, so a supervisor can keep it
up and alert on its output. The run as a whole exits 1 when it is stopped if
any check failed, if any failing verdict line was printed, or if no check
completed. Every check is tallied before the stop signal is looked at, and the
verdict lines of the listing are printed before the admin fetch and the probe
run, so a SIGTERM that arrives while the admin API is slow to answer cannot turn
a check that printed a LEAK into exit 0 (D13; the third review stopped a
`--keep-going` run during exactly that window and got exit 0 under a LEAK
line). A `--config` file it cannot read, an unknown `--server` or a catalog
error stops the run at once rather than being retried (scenario F: the
`--every 1s --keep-going` canary printed healthy checks, one LEAK and one
CONFIG-EDITED line across a hand edit and exited 1 on SIGTERM; cmd
`TestKeepGoingExits1WhenStoppedDuringACheckThatFoundALeak`,
`TestVerifyGatewayComparesTheRecordedBodyHash`,
`TestVerifyGatewayReportsAnUnverifiedToolAsALeak`,
`TestProbeReportsARelayedUpstreamAnswerAsInconclusive`). Treat a
`check failed` line (the gateway could not be listed) as an incident too: a
canary that cannot reach the gateway has proven nothing about what it serves.

`--bearer-env VAR` sends a bearer token when the route requires one; the token
is never printed or stored. Listing errors are printed as a class (`http status
401`, `timeout`), never as the raw text, because that text could carry the URL.

## Rotating the shared secret

The secret lives in two places: the gateway file (written by `emit`) and the
environment of the processor (`serve --secret-env`). Because the gateway binds
a processor to each session when the session starts, rotate by running a second
processor rather than restarting the first:

1. Generate a new secret of 16 to 256 printable ASCII characters and put it in a
   new environment variable, for example `TOOLWARRANT_SECRET_GITHUB_2`.
2. Start a second processor for the same server on a new address with the new
   secret: `serve --server github --listen 127.0.0.1:9101 --secret-env
   TOOLWARRANT_SECRET_GITHUB_2`.
3. Re-emit the gateway file pointing the server at the new address and secret:
   `emit --out gateway.yaml --processor github=127.0.0.1:9101 --secret-env
   TOOLWARRANT_SECRET_GITHUB_2`. The file is written 0600, as every emitted
   file is, and a warning says that it carries a secret; keep it readable by
   the gateway's user only. Record the new `body sha256` line for the canary.
   The gateway reloads the file (266 to 373 ms in every observation of the
   end-to-end test; a file it cannot parse keeps the previous state, seam test
   13).
4. Run `verify-gateway` against the route with the new body hash. New sessions
   now use the new processor and secret.
5. After the longest session lifetime you tolerate, stop the old processor. Its
   `unauthenticated` counter stays at zero throughout because the old sessions
   keep sending the old secret to it.

Never rotate by editing the file: the header hash fails `Verify` and the canary
reports CONFIG-EDITED. Rotate as well whenever another user could have reached
the gateway host's loopback interface while the admin API was on: the admin API
hands the loaded configuration, secret included, to any local user (limit L18).

A processor certificate (`serve --tls-cert`, `--tls-key`) and the client
authority it requires (`--tls-client-ca`) are rotated the same way: a second
processor on a new port with the new files, a re-emit that points the server at
it (with the gateway's `backendTLS` block, once `emit` writes it; D19 planned),
and the old processor stopped after the longest session lifetime you tolerate.

## Reading the audit log and recording its head

```sh
toolwarrant audit verify
toolwarrant audit verify --expect-head HEAD_YOU_RECORDED
toolwarrant audit list --after 1200 --limit 50
toolwarrant audit list --json
```

Every entry carries a sequence number, a UTC timestamp, the actor and actor type
(`human` or `system`), the event, the subject (`server/tool`, or a server), a
before and after hash where a version changed, a detail string, the previous
entry's hash and its own hash. Events are `server.added`, `server.paused`,
`server.resumed`, `crawl.completed`, `crawl.failed`, `tool.discovered`,
`tool.drifted`, `tool.reverted`, `tool.returned`, `tool.missing`,
`tool.deprecated`, `tool.reappeared`, `tool.unusable`, `tool.rejected`,
`tool.disabled`, `tool.enabled`, `tool.budget_reset`, `version.proposed`,
`version.superseded`, `version.approved`, `version.rejected` and
`version.rolled_back`. Detail strings hold classes and quoted, capped fragments,
never raw upstream text. Every entry about a tool starts with four `key=value`
tokens, `digest=D state=A->B last_seen=L proposals=A->B` (schema v4 added the
proposals field; D13), a `server.added` entry carries `allow_private=` and
`url_sha256=` (a hash, never the URL), and `server.paused` and `server.resumed`
carry `paused=`, so that the integrity check below can compare every mutable
column of the tools and servers tables with the log.

`audit verify` checks every link from entry 1 to the head and prints
`audit log ok: N entries, head HASH`, followed by a reminder to record the head
outside the database. Do that after every verify, in a ticket, a notebook or a
monitoring system: the chain proves that nothing inside it was altered, deleted,
inserted or reordered, but a rewritten log that stops earlier is internally
valid, and only a head recorded elsewhere betrays it. `--expect-head HASH` fails
when the head differs, with the note that either the log grew since you recorded
the head or it was rewritten; compare with `audit list --after N` from your
recorded sequence number (scenario D runs all three forms).
`audit list [--after N] [--limit N] [--json]` prints entries in sequence order.

### What the catalog checks before it trusts the file

Every state change is one or more entries in `audit_log`, written in the same
SQLite transaction as the change. Each entry hashes every field of itself plus
the previous entry's hash, as RFC 8785 canonical JSON, so changing, deleting,
reordering or inserting any row breaks `audit verify` from that row on.
Triggers in the database refuse ordinary SQL updates and deletes on the history
tables (tools, versions, proposers and approvals included, decision D14), and
the catalog checks the file before it trusts it: guard objects must be present
with the definition `init` wrote (compared by their DDL text at open, on every
snapshot load and at the end of every write transaction, so a same-named no-op
trigger is corruption and a long-running crawl schedule cannot keep writing
into a file whose trigger was dropped); no trigger, view or unique index the
schema did not create may exist (a foreign trigger can undo a decision inside
the operator's own transaction, and a foreign unique index makes writes fail,
so both are corruption, decisions D13 and D14); every approved version it hands
out is re-hashed and must be what the newest decision about the tool says:
among all versions of the tool, the approve or rollback row with the highest
id in the append-only approvals table must point at the approved version and
carry `hash_seen` equal to its digest (decision D13; before the fourth round
any historic approve row about the version counted, so a pointer flipped back
to a superseded version reached the serving path); and the newest
`version.approved` or `version.rolled_back` entry about the tool in the audit
log must carry the same digest and must be part of the chain the catalog
verified (decision D14 for the entry, D15 for the chain; before the fifth
round a definition and its `hash_seen` rewritten together under two dropped
and re-created guard triggers reached the serving path, because the approvals
table was the only evidence).

What "part of the verified chain" means, since the sixth round: a `Store`
verifies the whole audit chain once when it opens, from the first entry to the
head, and pins the head; it keeps in memory the hash it computed itself for
every decision entry it walked (`version.proposed`, `version.superseded`,
`version.rejected`, `version.approved`, `version.rolled_back`,
`tool.budget_reset`, `server.processor_set` and, since the seventh round,
`server.added`) and for the head; every reload verifies the suffix after the
pin and extends that memory; and the serving path (`Snapshot`, `Approved`,
`Versions`, `Tools`, `Tool`) and the decision path (every `Apply`, the proposer
list `approve` consults included) trust an audit entry only when the hash
computed from its fields equals the hash the walk recorded for its sequence
number. The hash column stored in the file is never consulted for trust and
never keys a memory; a mismatch is `ErrCorrupt` (decision D15; before the sixth
round the entry was re-sealed against its predecessor only, the pin verified
the head and the suffix after it only, and the verifier memory was keyed by the
stored hash column, so the fifth review rewrote one approval entry in place
below the head, re-sealed from its real predecessor, and the serving path, the
decision path and `Store.Integrity` all accepted it while only the full walk of
`audit verify` broke at the successor). The serving snapshot refuses a file
that was deleted or replaced under it: the random identity `init` wrote and
the file's device and inode are compared on every read (decision D14 for the
device and inode, D15 for the identity on every read; before the sixth round
only the generation read compared the stored identity). The stored DDL of
every table is compared with the schema's, as the triggers and indexes are,
and an automatic index that the schema's own tables do not account for is a
foreign object (decision D15; the fifth review re-created `audit_log` with an
extra `UNIQUE` constraint, which gave SQLite an automatic index with no DDL
text that no check saw, and every later write failed with an `ErrCorrupt` that
named no cause while `audit verify` was clean; the error now names the table
and the constraint).

Since the seventh round the rules reach the rows the earlier rounds did not:
every chain walk starts at the smallest possible sequence number, bound
included, so a row at seq 0 or below is a chain break (expected seq 1) at
open, in `audit verify` and in `Store.Integrity`, which also compares the row
count of `audit_log` with the entries it walked, and `audit list` shows such a
row in forensic mode (decision D17; before, every walk and every page started
at seq 0, so a row inserted at seq 0 or below under a re-created
`audit_log_sequential` was invisible to `audit verify`, `audit list` and
`Integrity` while every decision about its tool was `ErrCorrupt`); an
approvals row or a history row with id below 1 is corruption: every checked
read and every write refuses a file that holds one (`ErrCorrupt`, naming the
table and the column; a forensic open reads past such a row, as it reads past
a missing guard, so `list`, `show` and `audit list` can inspect the file while
`audit verify` names the row), two `AFTER INSERT` guards
(`approvals_positive_id`, `tool_versions_positive_id`) refuse the insert, and
`Integrity` reports it (decision D17; before, such a row counted as a historic
approval, and a row at id -1 made every later insert fail under the no-replace
guards' message, because SQLite evaluates `NEW.id` as -1 in a `BEFORE INSERT`
trigger when no id is supplied, which is also why the new guards run after the
insert); the server views that `emit`, the crawler, `serve`, `server list`,
`list` and `show` read run the same file check as every other view and anchor
the processor address to the newest verified `server.processor_set` entry and
the URL (by its SHA-256) and the allow-private flag to the verified
`server.added` entry, and the paused flag to the newest verified
`server.paused` or `server.resumed` entry (no entry means not paused), else
`ErrCorrupt`; the paused flag is anchored wherever it is acted on, by the
snapshot the processor serves from, by `crawl`, and by `server pause` and
`server resume`, so an un-pause by one `UPDATE` serves nothing and turns a
resume into `ErrCorrupt` (decision D17; before, they ran no check at all, so a
processor address rewritten with one `UPDATE` was returned as fact and the
next `emit` wrote it into the gateway configuration with no change line); the
state column of every tool is anchored to the newest verified lifecycle entry
about it on every path that acts on it (the snapshot the processor serves
from, `list`, `show`, `export`, `emit`, every decision and the crawl), so a
disabled tool re-enabled by one `UPDATE` is refused rather than served, and a
tool hidden by a flip to `disabled` or `deprecated` is refused rather than
dropped from the configuration or the served policy (found by the
verification of the released v0.1.0 binary), and the server
row is anchored to the first `server.added` entry, so an appended second
registration cannot re-point it (decision D17, extended after the eighth
review); `Approved` takes the approver's name and the time of approval from
the verified entry and reports a disagreement with the approvals row as
`ErrCorrupt`, so the git export carries the name the chain carries (decision
D17); and every checked read takes the `Store`'s walk lock before its first
statement, so a reader's snapshot never predates the pin it is compared with
and no reader is told that the log was truncated by a commit it could not see
(decision D17). A file that fails any of these is reported as corrupt and
nothing is served, listed or shown from it: `list` and `show` apply the same
evidence as the serving path (decision D14).

### What the two audit commands read, and what the integrity report compares

Both commands open the database in forensic mode: a file whose guard objects
were dropped or redefined, that holds a trigger, view or unique index the
schema did not create, or whose journal mode was switched away from WAL, is
still read, read-only, so that `audit verify` can name the broken entry (`the
audit log is broken at entry N`), and a file holding a history row below id 1
is read past that row too, which the report then names. Nothing is ever served
or written from such an open. Read `audit log ok` in that mode as "the chain is
consistent", not as "the file is intact": every other command refuses a database
whose guard objects are missing or do not have the definition `init` wrote, or
that holds a foreign trigger, view or unique index (`ErrCorrupt`), and
`audit verify` runs `Store.Integrity`'s cross-check after the chain check: it
verifies every entry's seal from its predecessor and its link to its successor
as it streams the log and reports each break as a problem (D15; before the
sixth round it read the entries without verifying them, so its cross-checks
agreed with a rewritten log), then compares
every approved digest against the newest decision and the newest
`version.approved` or `version.rolled_back` entry, every tool's last-seen
digest, state and proposal budget and every server's paused flag,
allow-private flag and URL hash against the latest audit entry about it, every
approval row against the decision entries, every version's status against the
status the log implies and its proposers against its `version.proposed`
entries, every subject the log describes against the rows that exist (a
vanished tool row, a tool row the log never discovered, a second discovery of
one subject, a version whose tool is gone), every server's processor address
against the newest verified `server.processor_set` entry, every approval's
approver and time against the verified entry, every approvals and history row
for an id below 1, the row count of `audit_log` against the entries the walk
saw, and the guard objects, every
table's DDL and the foreign objects (an automatic index the schema's tables do
not account for included) against the schema (D13, D14, D15 and D17). It prints
`integrity ok: guard
objects intact, every approval recorded in the log` or one
`integrity problem:` line per disagreement (`tool X: state is disabled but the
latest audit entry (seq N) left it as enabled`, `server X: paused is false but
the latest server entry (seq N) left it as true`, `unexpected trigger X: the
schema did not create it`, since the sixth round `audit entry N does not
re-seal: its hash is not the hash of its fields; the entry was rewritten in
place`, and since the seventh round `audit entry N has a sequence number
below 1, which the catalog never writes (the chain starts at seq 1); the row
was inserted by hand and is not part of the chain`, `audit_log holds N rows
but the walk from the first sequence number read M` and `approvals row N has
an id below 1, which the catalog never assigns; the row was inserted by hand
and is not a decision`) with exit code 1. The report runs whether or not
`--expect-head` matched, and also when the chain itself is broken: a head that
moved or a broken entry is exactly when you want to know which rows disagree
with the log and which foreign objects exist, so both findings are printed
together and the head reminder is withheld when either fails; with a broken
chain the `audit log ok` line is not printed and `--expect-head` is not
compared, since the head is then meaningless (D13 and D14; before the fourth
round a mismatching head returned before the report, and before the fifth
round a broken chain did; cmd
`TestAuditVerifyReportsIntegrityWhenTheHeadMismatches`,
`TestAuditVerifyReportsIntegrityWhenTheChainIsBroken`, catalog
`TestIntegrity_StateFlipReenablingADisabledToolIsReported`,
`TestIntegrity_PausedFlagFlipUnpausingAServerIsReported`,
`TestIntegrity_BudgetColumnResetByRawSQLIsReported`,
`TestOpen_ForeignTriggerIsCorrupt`). The forensic open also accepts a file
whose journal mode is not WAL (it opens the file with `mode=ro` and
`immutable=1`), so a tamperer who switched the journal mode cannot lock the
two commands out (D14; catalog `TestOpenWith_ForensicOpensANonWALFile`).
`list` and `show` are not checks: since the fifth round they apply the same
evidence as the serving path and refuse a tampered file with `ErrCorrupt` like
every other command, so on a suspect database use `audit verify` and
`audit list` (D14; before, `list` printed a forged approved pointer as fact
while `Snapshot`, `Approved` and `Versions` refused the file; catalog
`TestTools_ForgedApprovedPointerIsCorrupt`,
`TestTools_ApplyTheServingPathEvidence`). The integrity passes added in the
fifth round are pinned by catalog
`TestIntegrity_DeletedToolRowIsRefusedAndReported`,
`TestIntegrity_ProposerHistoryRewrittenUnderRecreatedGuardsIsReported`,
`TestIntegrity_RejectedVersionFlippedToPendingIsReported`,
`TestIntegrity_RowsTheLogDoesNotDescribeAreReported`,
`TestOpen_ForeignUniqueIndexIsCorrupt` and `TestInTx_ConstraintFailureIsCorrupt`;
the chain anchor and the pin by `TestSnapshot_RewritingHashSeenUnderRecreatedGuardsIsCorrupt`,
`TestSnapshot_ReChainedLogIsCaughtByThePinAndTheRecordedHead` and
`TestSnapshot_LogChangedAfterThePinIsCorrupt`; the verified chain of the sixth
round by `TestOpen_VerifiesTheWholeChainAndPagesThroughIt`,
`TestSnapshot_InPlaceRewriteOfTheApprovalEntryBelowTheHeadIsCorrupt`,
`TestSnapshot_InPlaceEditOfAfterHashUnderAWarmMemoryIsCorrupt`,
`TestApprove_ProposerLaunderedByInPlaceRewriteIsCorrupt`,
`TestOpen_RewrittenHeadEntryIsCaughtOnlyByThePinAndTheRecordedHead` (the
pin-bootstrap limit) and `TestIntegrity_ReportsEveryChainBreak`, the identity
on every read by `TestSnapshot_ComparesTheStoredIdentityOnEveryRead`, and the
table DDL and automatic indexes by
`TestOpen_TableRecreatedWithAnExtraConstraintIsCorrupt`,
`TestSchema_AutomaticIndexesArePinned` and
`TestDisable_CheckConstraintFromARecreatedTableIsNamed` (D15); the seventh
round's rules by `TestAudit_RowBelowSeqOneIsAChainBreakOnEveryWalk`,
`TestGuards_RowsBelowIdOneAreRefusedByThePositiveIdGuards`,
`TestDecisions_VersionColumnsMustMatchTheVerifiedChain`,
`TestRollback_TargetForgedWithAGhostApprovalsRowIsCorrupt`,
`TestServers_ColumnsAreAnchoredToTheVerifiedChain`,
`TestApproved_ApproverAndTimeComeFromTheVerifiedEntry`,
`TestSnapshot_ConcurrentReadersAndAWriterNeverSeeAFalseTruncation` and, for
the pin limit as the code has it,
`TestOpen_SuffixRewrittenWhileNoStoreHeldAPinIsCaughtByTheRecordedHeadAlone`
(D17).

### The recorded head, the export and backups

The one operational rule: record the head hash outside the database. The chain
proves that nothing inside it was altered since the first entry; it cannot
prove that the whole log was not replaced by a shorter, internally valid one,
and nothing inside the file can prove that an entry was not appended by
whoever can write the file (decision D14, known limit L19). What the checks
inside the file cannot do: whoever can write the 0600 file can append a new,
correctly sealed audit entry that approves a definition, and nothing inside the
file can refute it; only the head you recorded, the git export of approved
definitions (`export --dir`) and your backups betray it. Since the sixth round
an audit entry is trusted only when it is part of the chain the store
verified: a store verifies the whole chain once when it opens and the suffix
after its pin on every reload, and the serving path and the decision path
accept an entry only when the hash computed from its fields equals the one
that walk recorded for its sequence number (D15; before, the newest approval
entry was re-sealed against its predecessor only, so the fifth review rewrote
it in place below the head and it was served); since the seventh round the
same holds for every column a decision or a server view acts on: a version's
status and ever-approved flag, a rollback target's prior approval, a server's
processor address, URL hash and allow-private flag and an export's approver are
taken from or checked against the verified entries, never from a table alone
(D17). A forger must therefore rewrite every entry from the forged one to the
head. A running store catches that through the head it pinned. While no store
holds a pin, which is the CLI's state between commands and the processors'
state while they are stopped, any such rewrite verifies clean on the next open
and is caught by the head you recorded alone (the pin limit; D15 as corrected
by D17: the sixth round's documents said a chain rewritten completely before
any store opened it, but any suffix from the forged entry to the head does,
with the entries before it byte for byte unchanged: the seventh review rewrote
the entries about one tool from its first version entry to the head with the
store closed, left the entries before them byte for byte unchanged, and fresh
stores served the result with `audit verify` and the integrity report clean).
The processor's pin protects only while a processor runs; the CLI is never
protected by a pin. So: record the head after every verify, and compare it
with `audit verify --expect-head` before every decision you make after the
processors were stopped. The git export of approved definitions
(`export --dir`) and your backups are the other two anchors. Record the head,
keep the export, keep backups.

Every connection the catalog opens runs with the journal in WAL mode,
`synchronous` at FULL and foreign keys on: the one writer and the eight readers
of a read-write store, the eight readers of a read-only store (the processor)
and the connections of a forensic open. The three settings travel in the
connection string, so the pool cannot hand out a connection that was left at a
build's default
(`TestOpen_EveryPooledConnectionIsSynchronousFullWithForeignKeysInWAL` borrows
every connection of every pool at once and reads the three pragmas back from
each). FULL is also SQLite's compile-time default; it is pinned on purpose
rather than inherited (owner decision O-3): in WAL mode it syncs the WAL file
after every commit, so an approval, a rollback or a crawl is in the synced log
before its command returns, which is what SQLite documents as making a
transaction durable across a power loss and not only across a crash of the
process. NORMAL would skip that sync and sync only around checkpoints, which
SQLite's own matrix marks "maybe not durable": the newest commits can be lost
with the power, so it is not used, and a measured benchmark on the target file
system is the condition for ever changing it. The cost is one sync per commit,
nothing at the rate at which people make decisions. The reads that anchor a
tool's state and approval, a server's row and a version's history to the
newest audit entry about them rest on the `audit_log_by_subject` index;
`TestAnchorQueries_StayOnTheAuditLogBySubjectIndex` runs `EXPLAIN QUERY PLAN`
over each of those reads and fails when any one reaches the log without that
index, because without it every probe walks the log in sequence order instead
of seeking the subject's own entries (the research pass of 2026-10-14 measured
ten thousand such probes at 0.07 s with the index and 58.9 s without it).

## Recovering from ErrCorrupt and ErrSchema

`catalog: database integrity check failed` (`ErrCorrupt`) means the file
contradicts itself: a stored definition no longer hashes to its digest, an
approved pointer dangles or points at a version that is not what the newest
approve or rollback decision about the tool names or what the newest
`version.approved` or `version.rolled_back` audit entry about it says, the
audit chain does not verify when the store opens, an audit entry the serving
or decision path relies on does not hash to the value the store's verified
walk recorded for its sequence number (D15), the newest audit entry a running
store had verified changed or the entries since it do not re-seal (the chain
pin), a status disagrees with its tool row, a version's status or ever-approved
column disagrees with the verified `version.*` entries about it (`version D
of S/T is in status X (ever_approved B) but the verified audit entries
(latest seq N) leave it Y (ever_approved B); the status columns were edited`)
or a rollback target has no verified approval or rollback entry naming its
digest (D17), a server's processor address, URL, allow-private or paused flag
disagrees with the verified `server.processor_set`, `server.added`,
`server.paused` or `server.resumed` entry
(D17; `server list`, `emit`, `crawl`, `serve`, `list` and `show` all refuse
the file; the URL itself is never printed, the report says that its hash
differs), a tool's state column disagrees with the newest audit entry about
the tool (`state of tool S/T is "X" but its newest audit entry (seq N,
EVENT) left it "Y"; the state column was edited`; D17; the snapshot, `list`,
`show`, `export`, `emit`, every decision and the crawl refuse the file), an approver in the approvals table differs from the verified entry
(`the approver or time of the newest approvals row of T is not what its
approval entry (seq N) recorded; the approvals row was rewritten`, D17), an
audit row sits at seq 0 or below or an approvals or history row at an id
below 1 (`TABLE holds a row whose COLUMN is below 1, which the catalog never
assigns; the file was edited outside toolwarrant, run audit verify`, D17),
a guard trigger, table or index is
missing or has another definition than the one `init` wrote, a constraint on
a guarded table failed inside a write (the error names the table and the
constraint SQLite reported, for example `a write to table audit_log failed a
constraint (UNIQUE constraint failed: audit_log.event): the schema's own
writes never do, so the table was re-created with another definition or a bug
wrote the row`, D15; before the sixth round it named no cause, so a table
re-created with an extra constraint was invisible until a write failed, and
`audit verify` now reports such a table as redefined and its automatic index
as a foreign object), or the file holds a trigger, view, unique index or
unaccounted automatic index that `init` never created (D13, D14 and D15: a
foreign trigger can undo a decision inside the operator's own transaction, so
one is never benign). It is also what a processor reports when the catalog
file at its path
was deleted, replaced or re-initialised while it ran (the catalog identity or
the file's device and inode no longer match the ones it opened; D14): the
remedy for that case is to restart the processor, after checking why the file
changed. The CLI adds "do not serve from this database, restore it from a
backup". Someone edited the file outside toolwarrant, or a bug wrote it.
Procedure:

1. Stop the processors for every server in that database. A processor whose
   catalog read fails denies every hook, so the gateway is already failing
   closed, but a reader that still holds an older snapshot keeps serving it.
2. Run `audit verify` (forensic mode) to learn whether the audit chain is intact
   and at which entry it breaks, which registry columns disagree with the log
   and which foreign objects exist (the integrity report is printed whether or
   not the chain verified, D14), and `audit list` to see the last entries,
   rows at seq 0 or below included (D17).
   Compare the head with the one you recorded: with the processors stopped no
   store holds a pin, so a rewrite of any suffix of the log, from the forged
   entry to the head, verifies clean, `audit verify` prints `audit log ok`
   with the same entry count, the integrity report may be clean, and only the
   head you recorded catches it (the pin limit, D15 as corrected by D17). Do
   not read `list` or `show` as evidence: they refuse the file like every
   other command.
3. Restore the most recent backup whose `audit verify` head equals a head you
   recorded, re-run the crawls, and review anything the audit log shows between
   the backup and the corruption.
4. Keep the corrupt file for investigation; it opens only in forensic mode.

`catalog: unsupported schema version` (`ErrSchema`) means the file was not
written by this build: an older unreleased schema (v2, v3, v4 or v5), a newer
build, or another application's SQLite file ("not a toolwarrant database",
"the file holds another application's tables"). This build writes schema v6
(D17: the positive-id guards `approvals_positive_id` and
`tool_versions_positive_id`, which refuse a row with an id below 1, join the
guard set, and a file without them would otherwise be refused as redefined;
D14 had moved it to v5 for the processor address column, the catalog identity
in `meta` and the no-delete guards, and D13 to v4 for the audit detail
fields). The CLI
adds "the file was written by another schema version; the message says whether
it came from an unreleased build (delete it and run init again) or from a
release (read it with a build of that schema, never delete it)". Schema v6 is
the first released schema: a file below it belongs to an unreleased build and
is deleted, and the first bump after v0.1.0 will name the build that reads a
v6 file or carry a migration; it will never advise deleting a released
catalog (catalog `TestSchemaMessage_AdvisesDeletionOnlyForUnreleasedSchemas`).
For a pre-release file: stop every processor of the file, back it up, delete it,
run `init`, register the servers again, crawl, re-approve from your git export
or from the backup read with a build of the matching schema, and start the
processors again; a processor left running on the old handle denies every hook
once the file is replaced (D14). A foreign file is left untouched; point
`--db` at the right path.

`catalog: the store is read-only` from a decision means the command opened the
database read-only (the processor's mode); the CLI adds "the database was
opened read-only, so nothing can be changed through it". Decisions are made with
the CLI's normal open.

## Recovering a server that hit a growth cap

Besides the per-crawl caps of D6, the catalog holds a fixed cap on the number of
tool rows a server may have, live and deprecated together
(`catalog.MaxToolsPerServer`, 50000, five full crawls of fresh names), and on
the canonical bytes stored across every version of every tool of a server
(`catalog.MaxServerBytes`, 1 GiB, thirty-two crawls of entirely new definitions
at the per-crawl cap; the raw definition is stored next to the canonical form,
so the file can hold about twice that per server). A crawl that would push the
server over either cap is recorded as a failed crawl under its own class
(`server-tools-cap` or `server-bytes-cap`), like a listing over a per-crawl
cap, and adds no rows; nothing already stored changes, nothing is approved or served that was
not, and the next crawl is refused the same way until the live set shrinks
below the cap, which an upstream that lists fresh names on every crawl never
does. Deprecated rows are not loaded on every crawl (a deprecated tool that
still carries the unusable marker is loaded once more, by the first crawl that
does not list it, which clears the marker), so the cost of a crawl follows the
live set, not the history (D13; the third review listed 1500 fresh
names per crawl and reached 9000 rows and an 18 MB file in six crawls while
each crawl held the write lock longer than the one before; catalog
`TestRecordCrawl_RenamedToolsStopAtTheServerCap`,
`TestRecordCrawl_NewDefinitionsStopAtTheServerByteCap`,
`TestRecordCrawl_DeprecatedToolsAreLoadedOnlyWhenListed`,
`TestRecordCrawl_DeprecatedToolWithAMarkerIsClearedOnce`).

The caps bound rows and bytes. The audit log grows with observed changes: one
`tool.rejected` entry per listed name that no tool row describes, one
`tool.drifted` or `tool.reverted` entry per change of a known tool, and a
`crawl.completed` or `crawl.failed` entry per crawl. That growth is bounded by
the crawl cadence and by a per-crawl cap on rejected entries
(`catalog.MaxRejectedPerCrawl`): a crawl that would exceed it is recorded as a
failed crawl under its own class and adds no entries, like a crawl over any
other cap, `rejected-cap` (D14; the fourth review listed fresh unusable names
on every crawl, which created no row and tripped no cap but added about 258
bytes of log per name, about 2.6 MB per crawl at the per-crawl cap; catalog
`TestRecordCrawl_RejectedEntriesStopAtTheCap`,
`TestRecordCrawl_RejectedCapConstant`). An upstream whose known
tools alternate between two digests on every crawl still adds two entries per
tool per crawl; slow the cadence or pause the server.

There is no prune in v0.1: versions are immutable and the history tables are
append-only by design, so nothing reclaims the rows. The recovery is:

1. `server pause NAME`, so the server is neither crawled nor served while you
   decide (decisions on its tools keep working).
2. Decide whether the upstream is hostile or merely badly behaved. A hostile
   upstream is not an upstream to pin tools from; leave it paused or remove the
   database.
3. To start over: stop every processor of the file, back up the database and
   its audit head, delete the file, run `init`, register the servers again,
   crawl, re-approve from your git export (`export --dir`) or from the backup,
   and start the processors again. Every server in the file starts over with
   it, and so does every processor: a processor left running keeps the old
   file open, detects on its next generation read that the file at its path
   was replaced, and denies every hook with an Error log line until it is
   restarted (D14; before the fifth round it kept serving the deleted file's
   approvals, so a tool you chose not to re-approve stayed listed and
   callable). Keep one database per operator and consider one per upstream
   when an upstream is likely to hit the cap.

## Resetting a tool's proposal budget

A tool stops gaining versions after twenty proposals without a decision (D6),
and an upstream that then goes back to the approved definition leaves nothing
to approve, reject or roll back (limit L6). The decision that is always
available is

```sh
toolwarrant budget reset SERVER TOOL [--by NAME]
```

It forgets the proposals the tool gained since its last decision, so the next
crawl may store a new digest; nothing else changes and nothing is approved. It
is a human decision: `--by` names the person (default: the global `--as`,
`TOOLWARRANT_ACTOR` or the OS user) and the system actor is refused as a usage
error. It writes exactly one audit entry, `tool.budget_reset`, and prints it:

```
reset the proposal budget of SERVER/TOOL by NAME; the next crawl may store a new digest
audit entry 42: tool.budget_reset SERVER/TOOL by NAME (human) at 2026-10-11T17:20:00Z, detail digest=- state=enabled->enabled last_seen=unusable proposals=20->0, hash <hex>
```

A budget that is already at zero is refused (nothing to reset), as is a
read-only or missing database. A budget reset by plain SQL instead of this
command is reported by `audit verify` as an integrity problem, because the
proposal budget is one of the columns the log describes (D13). Covered by
`TestBudgetResetUnblocksATool` and `TestBudgetResetNeedsAWritableDatabase` in
`cmd/toolwarrant`, and by the catalog's
`TestReview_BudgetDeadlockAfterRevertLeavesNoDecisionToResetIt`.

## Pausing a server

```sh
toolwarrant --as alice server pause github
toolwarrant --as alice server resume github
```

A paused server is not contacted by `crawl` at all (the CLI checks the flag
before listing and prints, literally, `the server is paused; run "toolwarrant
server resume NAME" before crawling it again`), the catalog refuses an
observation of it (`catalog: server is paused`), and its serving snapshot is
empty, so the processor hides every tool of that server and denies every call
on the next hook. Decisions on its tools keep working. `server list` marks the
server `PAUSED`. Both commands require a human actor and write `server.paused`
and `server.resumed` audit entries; a paused flag flipped by plain SQL is
reported by `audit verify` (D13). The processor keeps the evidence of the
gateway's listings across a pause, so a contradiction it recorded before the
pause still denies the call after the resume until a clean listing or a crawl
records the approved digest (D14), and a listing the gateway makes during the
pause is judged against the names the processor already tracks: a readable
page records its digests for them and an unreadable page marks every one, so
a definition that changed during the pause is denied after the resume as well
(D15; before the sixth round such a page was judged against the empty
snapshot of the paused server and recorded nothing, so the pre-pause agreeing
digest survived and the call passed after the resume). Use pause when an
upstream is compromised
or under investigation and you want nothing of it served without disabling
every tool one by one, and as the first step of the growth-cap recovery above
(catalog `TestPauseAndResumeServer`, cmd `TestPauseBlocksCrawlingAndServing`,
scenario E through the real gateway).

## Re-emitting the gateway configuration

Run `emit` whenever the set of approved tool names changes, a server is added,
or a processor address, a listener address or a secret changes:

```sh
toolwarrant emit --out /etc/agentgateway/gateway.yaml \
  --listen-port 3000 --bind-address 127.0.0.1 \
  --processor-base-port 9001 \
  --processor github=127.0.0.1:9101 \
  --secret-env TOOLWARRANT_SECRET_GITHUB \
  --gateway-binary /usr/local/bin/agentgateway
```

- Processor addresses are stable across re-emits and live in the catalog
  (D13 and D14). Each server's address is a column of the servers table,
  written by `emit` when it assigns one and by `emit --processor
  NAME=HOST:PORT` when you choose one, each change with the audit entry
  `server.processor_set`; the PROCESSOR column of `server list` shows the
  address of every server (`-` before the first emit; catalog
  `TestSetProcessorAddr_RecordsTheAddressAndTheEntry`,
  `TestIntegrity_ProcessorAddrRewrittenIsReported`, cmd
  `TestReEmitIgnoresAForgedAddressInTheFileAtOut`,
  `TestPlanEmitKeepsPreviousAddresses`,
  `TestEmitKeepsProcessorAddressesAcrossReEmits`). A
  server with no address yet takes the next free port at or above
  `--processor-base-port` and above every port already in use;
  `--processor` wins over the stored address and is stored in turn. The
  addresses are recorded, and their `server.processor_set` entries written,
  only after the file was validated and renamed into place, so an emit the
  gateway refuses or that cannot write the file records nothing and the next
  emit still prints its change lines (D15; before the sixth round the record
  came first, so a refused emit left the address and the entry behind for a
  file that never existed and the next emit printed no change line; cmd
  `TestEmitRecordsProcessorAddressesOnlyAfterTheFileIsWritten`). `emit`
  prints `processor address of server NAME is new: ADDR` for a server that
  had none and `processor address of server NAME changed from OLD to NEW;
  restart its processor on the new address` for a moved one, so you know
  which processors to restart before the gateway reloads; with no such line
  the running processors are untouched. The stored address is trusted only
  through the audit log: since the seventh round the server views that
  `emit`, `server list`, `crawl`, `serve`, `list` and `show` read run the
  same file check as every other view and require the servers row to agree
  with the newest verified `server.processor_set` entry about the server (and
  its URL, by hash, and allow-private flag with the verified `server.added`
  entry, and its paused flag with the newest verified `server.paused` or
  `server.resumed` entry, which `Snapshot`, `crawl`, `server pause` and
  `server resume` check too), else `ErrCorrupt`, so `emit` refuses to emit, and `emit` prints a
  change line whenever the address it writes differs from that entry (D17;
  the seventh review rewrote the column with one `UPDATE`, `server list`
  showed the forged address, and the next `emit` wrote it into the gateway
  configuration, which the pinned binary validated, with no line and no audit
  entry; catalog `TestServers_ColumnsAreAnchoredToTheVerifiedChain`,
  `TestServers_RunTheFileCheckLikeEveryOtherView`,
  `TestSetProcessorAddr_ForgedColumnEqualToTheNewAddressIsCorrupt`, cmd
  `TestEmitRefusesACatalogWhoseProcessorAddressIsNotTheOneTheChainRecords`).
  `emit` never reads addresses from the
  file at `--out`: before the fifth round it kept the addresses of an existing
  file whose header hash verified, and the fourth review re-sealed a file with
  a forged address (the unkeyed hash of limit L19) and planted a symbolic link
  at `--out`, so that the documented CONFIG-EDITED remedy, running `emit`
  again, wrote the attacker's address back with no change line (D14). The
  file at `--out` must be absent or a regular file: a symbolic link, directory,
  device, socket or named pipe there is refused before anything is opened (a
  read of a named pipe would block `emit` for ever; cmd
  `TestEmitRefusesAnIrregularOut`), and since the seventh round `emit` also
  refuses an `--out` that is the catalog database, its `-wal` or `-shm`
  sibling or the `--gateway-binary` path (compared by canonical path, so a
  sibling that does not exist at that moment is refused too, and by device and
  inode when the file exists, however spelled), and refuses to replace an existing regular file whose
  header lines are not emit's own; a file the gateway rewrote through the
  admin API keeps the header lines and stays replaceable, so the re-emit after
  a CONFIG-EDITED still works. Each is a usage error naming the fix (D17; the
  seventh review ran `emit --out` with the `--db` path, and `emit` renamed the
  YAML over the hash-chained catalog, printed `wrote` and the `is new` line
  and exited 0, after which every command refused the file as not a
  database; only a backup recovers from that; cmd
  `TestEmitRefusesToReplaceTheCatalogOrAFileItDidNotWrite`). Before the fourth round the i-th server in name order got
  `base + i`, so adding a server renumbered every later server and darkened
  its route (every hook went to the wrong processor or to nobody) until each
  processor was restarted (e2e scenario J re-emits a side file as servers are
  added and checks that no address moves). One address per server; a repeated
  address is refused, and so is an address on one of the gateway's own sockets
  (the serving port or the admin, stats or readiness listener), which the
  gateway's own validation accepts and which would make every hook dial the
  gateway itself; a host that is all digits, dotted digits or hex-looking must
  parse as an IP literal or is refused, and the socket rule compares the
  address with the bind address and listener addresses of this very emit, not
  only with the loopback class (D14; the fourth review passed `127.1`,
  `0x7f.0.0.1` and `2130706433`, which the resolver reads as 127.0.0.1, and a
  processor on the exact address given to `--bind-address`; emit
  `TestAmbiguousProcessorHostSpellingsAreRefused`,
  `TestProcessorOnTheGatewaysOwnSpecificAddressIsRefused`). A processor whose
  host is a name rather than an IP literal is refused when its port is one the
  gateway binds, because a name may resolve to this host (D15; the fifth
  review passed `localhost.localdomain`, `localhost4`, `localhost6` and
  `ip6-loopback`, which resolvers map to loopback from the hosts file without
  DNS, with the serving and the admin port, each with a wrong non-loopback
  warning; emit `TestProcessorNameOnAGatewayPortIsRefused`,
  `TestLoopbackAliasOnAGatewaySocketIsRefused`,
  `TestLoopbackAliasOnAFreePortIsQuiet`). An override that names a host other
  than a loopback literal,
  `localhost` or one of the loopback aliases (`localhost.localdomain`,
  `localhost4`, `localhost4.localdomain4`, `localhost6`,
  `localhost6.localdomain6`, `ip6-localhost`, `ip6-loopback`; D15) makes that
  processor reachable from the network: `emit` prints a warning for it and the
  printed `serve` command carries `--allow-non-loopback`, which `serve`
  accepts only together with `--secret-env` or `--tls-client-ca`, or the
  explicit `--insecure-no-secret` (limit L11).
- `--bind-address ADDR` (default `127.0.0.1`) is the address the gateway binds
  the serving port to (`gateways.bindAddress`). A wildcard (`0.0.0.0` or `::`)
  also needs `--allow-all-interfaces`, a permission that changes nothing for
  any other address. Any address other hosts can reach prints a warning on
  stderr, because every route is then exposed to that network with the
  processor and the allow rule as the only guards (cmd
  `TestEmitBindsLoopbackUnlessAsked`; scenario I proved the default bind on the
  real gateway).
- The gateway's admin, stats and readiness listeners are `--admin-addr`,
  `--stats-addr` and `--readiness-addr`, with the defaults `127.0.0.1:15000`,
  `127.0.0.1:15020` and `127.0.0.1:15021`. Each must be an IP literal and a
  port, loopback unless `--allow-all-interfaces` is given (a listener other
  hosts can reach adds a warning line), and the four ports (serving plus three)
  must be distinct, which the gateway's own validation does not check.
  `--disable-admin` turns the admin API off (the gateway's own
  `adminAddr: off`) instead of binding it; `verify-gateway --admin` then has
  nothing to ask. Keep the listeners on loopback: the admin API is
  unauthenticated and part of the trusted computing base (limit L18), and
  `verify-gateway --admin` must be given the same address as `--admin-addr`.
  Whether the gateway re-binds those listeners on a reload or only at start-up
  was not observed; plan a gateway restart when they change.
- `--gateway-binary PATH` (or the environment variable
  `TOOLWARRANT_AGENTGATEWAY`) stages the file under a temporary name, runs the
  gateway's own `--validate-only` on it and renames it into place only if the
  gateway accepts it; a refusal exits 1, prints the gateway's message, leaves
  no file and records no processor address (D15). Without it a file the
  gateway cannot load would freeze every
  server's configuration on the next reload (the gateway keeps its previous
  state) with nothing in `emit`'s output to say so.
- Server names and upstream URLs follow the gateway's rules, which are
  stricter than a reviewer's intuition: an MCP target name is lower-case
  letters, digits and hyphens, neither starting nor ending with a hyphen, at
  most 63 bytes (`_` and `+` are reserved MCP delimiters; a dot, which the
  gateway would accept, is refused on purpose because the name becomes a route
  path and a file name), and a URL may carry only letters, digits, the RFC 3986
  characters and the percent sign, because the gateway's URI parser refuses
  anything else. `server add` applies the same rules, so a name or URL the
  gateway would refuse never reaches `emit`.
- The file is written atomically (temporary file and rename) so the gateway
  never reads a half-written file, and it is always written 0600 (D13; before
  the fourth round it was 0644 unless it carried a secret or a query string,
  and a credential in a URL path went into a world-readable file in silence).
  The gateway usually runs as another user: `chown` the file to that user, or
  grant that user a read ACL, and nobody else. `emit` still prints a warning
  when the file carries a secret and when any server URL has a query string,
  which is where credentials usually live (cmd
  `TestEmitAlwaysWritesAnOwnerOnlyFile`,
  `TestEmitWithASecretWritesAPrivateFileAndWiresServe`; scenario H).
- The output lists each server's route (`/<server>/mcp`), processor and number
  of approved tools, prints a warning for every approved tool that had to be
  left out of the allow rule (a name outside printable ASCII cannot be written
  into a reviewable CEL rule; the tool stays hidden), prints the body hash as
  `body sha256 HEX`, and prints the `serve` command for each server. Record the
  body hash outside the gateway host, the way you record the audit head, and
  pass it to the canary as `--expect-body-hash HEX`: the header hash in the
  file is unkeyed, and only a hash you recorded elsewhere catches an edit that
  recomputed it (limit L19).

The processor needs no restart after an `emit` unless `emit` printed that its
address changed: the allow rule in the file only narrows which names the
gateway may show, the processor enforces the digests, and it reads the
catalog's generation on every hook while the catalog file is the same file
(a replaced file is refused, see the processor section). Run `verify-gateway`
after the gateway has reloaded (266 to 373 ms after the rename in every
observation of the end-to-end test).

## Crawling on a schedule

```sh
toolwarrant crawl github --every 1m --bearer-env GITHUB_MCP_TOKEN --json
toolwarrant crawl github --strict
```

`--every` repeats until SIGINT or SIGTERM (at least 1 s) and prints one line per
crawl; a failed crawl (the upstream is down, a cap was exceeded) is recorded as
incomplete with its error class and the schedule continues. Before every crawl
the schedule re-checks the catalog the way the canary does (a snapshot load,
which verifies the guard objects), and a catalog error stops the schedule at
once with exit 1: a corrupt or wrong-schema database, or a server the catalog
does not know (D13; before the fourth round a schedule kept printing
`crawl N complete` into a file whose guard trigger was gone, which every other
command refused, and exited 0). When the schedule is stopped by a signal it
exits 1 if no crawl completed during the run (`no crawl of this run completed
(N failed, N refused by the catalog); nothing was recorded about the upstream's
tools`) or if the catalog refused any crawl as a whole because a per-crawl or
per-server cap was exceeded (`N crawl(s) of this run were refused by the
catalog (a cap was exceeded) and added no rows`), and 0 otherwise; an upstream
that was down for a while is counted but does not fail a run in which other
crawls completed (cmd `TestCrawlEveryStopsAtOnceOnACorruptCatalog`,
`TestCrawlEveryExits1WhenNoCrawlCompleted`). `--strict` exits 1 when the crawl
reports any rejected or unusable tool, after the crawl was recorded and the
report printed, for use in a pipeline that must not proceed on hostile input;
with `--every` it stops the schedule at the first such crawl. A crawl without
`--as` and without `TOOLWARRANT_ACTOR` runs as the system actor `crawler`; a
crawl run as a person proposes as that person, who then cannot approve those
proposals. The crawler does not announce the program name to the upstream
(neutral clientInfo); see limit L4 for why that is only a partial measure. The
call-time gap of limit L1 is bounded by this cadence, and so is the time until
a reverted or rolled-back tool is callable again (decision D9): crawl right
after a rollback.

## Releasing

A release is one tag (decision D16). Before the tag, on the maintainer's
machine:

```sh
make release-check                # the release configuration parses and is consistent; go.mod has no replace or exclude; CHANGELOG.md has an Unreleased section
make release-check VERSION=X.Y.Z  # and CHANGELOG.md has the `## [X.Y.Z] - YYYY-MM-DD` heading the release commit added
make release-snapshot             # four archives, four SBOMs and the checksums into dist/, unsigned
make test && make e2e && demo/run.sh
```

The release commit moves the lines under `## [Unreleased]` in `CHANGELOG.md`
to a `## [X.Y.Z] - YYYY-MM-DD` heading and leaves an empty `## [Unreleased]`
above it. `make release-check` runs three guards before `goreleaser check`,
also in the `ci` release-check job on every pull request: `go.mod` can be read
and carries no `replace` or `exclude` directive, since a release must build
from published modules only (a `retract`, the remedy for a bad tag, is allowed;
`TestReleaseGuards_refuseAReplaceOrExcludeDirectiveInGoMod`); `CHANGELOG.md`
keeps the Unreleased heading
(`TestReleaseGuards_refuseAChangelogWithoutAnUnreleasedSection`); and, run as
`make release-check VERSION=X.Y.Z` with the version as the heading spells it,
without the `v`, the heading for that version exists
(`TestReleaseGuards_refuseAVersionWithoutADatedChangelogEntry`). The guards
are `make release-guards` on their own, and
`TestReleaseGuards_runFirstInReleaseCheck` pins that `release-check` runs them
first.

Then push `main`, let the `ci` workflow pass, tag `vX.Y.Z` on that commit and
push the tag. The `release` workflow refuses a tag whose commit has no
successful `ci` run, builds the `toolwarrant` binary for darwin/arm64,
darwin/amd64, linux/amd64 and linux/arm64 with CGO off and `-trimpath`, writes
one SPDX SBOM per archive with syft, signs the checksums file keyless with
cosign under the workflow's own identity, and creates a draft release whose
notes open with the pinned gateway version and the catalog schema version and
group the commits since the previous tag by type. Inspect the draft (the four
archives, the `.spdx.json` files, the `.txt` and its `.txt.sigstore.json`),
then publish it. The seam and mock binaries are never released.

A user verifies a release before running it:

```sh
cosign verify-blob --bundle toolwarrant_0.1.0_checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/sairam0424/toolwarrant/.github/workflows/release.yml@refs/tags/v0.1.0" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  toolwarrant_0.1.0_checksums.txt
shasum -a 256 -c --ignore-missing toolwarrant_0.1.0_checksums.txt
```

The first command proves the checksums file was produced by this repository's
release workflow at that tag; the second proves the downloaded archive is the
one it lists. The binary prints its version with `toolwarrant version`.

Right after publishing, from a scratch directory outside any module, fetch the
tag through the module proxy, check the record the fetch leaves, and run the
two verification commands above with the new version in place of 0.1.0:

```sh
GOFLAGS= GOPRIVATE= GONOSUMDB= GOSUMDB=sum.golang.org GOPROXY=https://proxy.golang.org,direct \
  GOBIN="$PWD/bin" go install github.com/sairam0424/toolwarrant/cmd/toolwarrant@vX.Y.Z
go version -m bin/toolwarrant    # the mod line names the module version and its go.sum hash
bin/toolwarrant version          # toolwarrant vX.Y.Z, then the pinned gateway line
curl -fsS "https://sum.golang.org/lookup/github.com/sairam0424/toolwarrant@vX.Y.Z"
```

The `go install` makes proxy.golang.org fetch the tag and sum.golang.org record
the module's `go.sum` lines for it, so the record exists before any user's
first download and the go command checks every later download of that version
against it (SECURITY.md, Release integrity). The variables are set on the
command because a shell that carries `GOPRIVATE` or `GONOSUMDB` for the
maintainer's own namespace, or `GOSUMDB=off`, makes the go command skip the
checksum database (and, with `GOPRIVATE`, the proxy as well), and
`go install` exits 0 either way; `GOFLAGS` is cleared so the build flags this
repository's shells export play no part. The `curl` is what proves the
record: the lookup must return a record whose first line carries the same
`h1:` hash as the `mod` line (the second line is the `go.mod` hash); a 404,
which `curl -f` turns into a failure, or a different hash means the record is
missing or wrong: stop and find out why before announcing the release. The
binary the install leaves has no link-time version, so its `version` falls
back to the module version the go command embedded and prints
`toolwarrant vX.Y.Z`, the tag with its `v` (a release archive's binary prints
`X.Y.Z`, set at link time; cmd `TestVersionFallsBackToTheModuleVersion` holds
the decision). A `dev` from a tag after v0.1.1 means the fallback broke: stop
and find out why. The binaries installed from v0.1.0 and v0.1.1 predate the
fallback and print `dev`; for those the `mod` line of `go version -m` is what
names the tag. The record for v0.1.0 exists and lists the same `h1:` hash the
`mod` line shows.

Then, with the verified archive in the directory you clone into, rebuild one
platform and compare it with the archive. The build is reproducible (CGO
disabled, `-trimpath`, no date in the link flags, archive timestamps taken
from the commit), so a clean clone at the tag built with the toolchain
`go.mod` names gives the archive's binary byte for byte; the checkout must be
clean, since the version control state is a build input:

```sh
git clone --branch vX.Y.Z https://github.com/sairam0424/toolwarrant.git && cd toolwarrant
git status --short   # prints nothing
CGO_ENABLED=0 GOFLAGS=-mod=readonly GOTOOLCHAIN=go1.27.2 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags "-s -w -X main.version=X.Y.Z" -o rebuilt ./cmd/toolwarrant
tar -xzf ../toolwarrant_X.Y.Z_linux_amd64.tar.gz toolwarrant
cmp rebuilt toolwarrant
```

`cmp` prints nothing when the two files are equal; a difference is an incident,
not a note. v0.1.0 rebuilt this way on 2026-10-14 gave the released binaries
byte for byte for linux/amd64 and darwin/arm64 (SECURITY.md, Release integrity,
records the hashes). `GOTOOLCHAIN` names the toolchain `go.mod` pins; a later
`go.mod` that moves it changes this command and SECURITY.md's in the same
commit.

A published release is never re-run: the workflow keeps an existing
release's notes and the existing assets make a second upload fail, so a fix
is a new tag. The gate accepts only the newest `ci` run that a push to `main`
triggered for the tagged commit; a commit that reached `main` through a pull
request has such a run, a tag on any other commit is refused, and the release
job stops if the commit it checked out is not the one the gate verified. The
gate lives in the workflow file of the tagged commit, so it binds only tags
created by someone who could not also change that file; who can create a tag
is limited by write access and by the tag ruleset `v* tags: owner only`
(id 24941252) listed below.

A tag is never moved or deleted. The Go module system treats a tag as
immutable: a tag re-pointed to another commit gives every `go install` user a
`SECURITY ERROR` from the go command, because the download no longer matches
what sum.golang.org recorded for that version, and a deleted tag's content
stays on proxy.golang.org. A bad release is a new tag plus a
`retract vX.Y.Z // reason` directive in `go.mod`; a `retract` changes nothing
in `THIRD_PARTY_NOTICES.md`, since `scripts/gen-third-party-notices.sh` reads
only the `require` blocks. The tag ruleset blocks the creation, update and
deletion of `v*` tags for everyone but the repository owner, who holds to the
same rule.

A release candidate (`vX.Y.Z-rc.N`) exercises the same workflow and is marked
a pre-release by goreleaser. The notes of a release list the commits since
the previous tag by version, and a candidate tag counts as one, so the notes
of a final release start at the last candidate. Candidate tags and their
releases are kept: a candidate tag is a `v*` tag, so the tag policy above
covers it, and the owner has decided so ahead of the move to immutable
releases listed below. That supersedes the rule of D16 (d) that deleted the
candidates before a final tag; the rule is retired in docs/decisions.md with
D18, when the notes come from `CHANGELOG.md` instead of the tag range.
goreleaser's `smartsemver` sort, which would skip the candidates, is a
GoReleaser Pro feature and fails the open-source build (D16).

The repository settings as they stand, read with `gh api` on 2026-10-14 (the
repository has been public since v0.1.0 was published on 2026-10-12; rulesets,
private vulnerability reporting and secret scanning with push protection exist
only for a public repository on the free plan):

- Description: toolwarrant for MCP: a control plane that approves exact
  tool-definition digests and enforces them at agentgateway v1.6.0 as an
  ExtMCP processor. Topics: agentgateway, ai-agents, audit-log, go, mcp,
  model-context-protocol, sqlite, supply-chain-security, tool-poisoning. No
  website.
- Rulesets, both active. `main: pull request and ci` (id 24941251) on the
  default branch forbids deletion and non-fast-forward pushes, requires a pull
  request (no approving review is required: there is one maintainer) and
  requires the nine `ci` job names as status checks (`gofmt, go vet,
  golangci-lint v2.14.0`; `go build and go vet`; `go test -race -short`; `full
  textdiff Unicode walk, slow catalog tests and the processor gRPC size test`;
  `govulncheck`; `gitleaks`; `scripts/gen-third-party-notices.sh --check`;
  `goreleaser check and the schema version in the release notes`; `cited tests
  and relative links exist`), with no bypass actor, so a renamed job blocks
  every merge until the ruleset is edited. `v* tags: owner only` (id 24941252)
  blocks the creation, update and deletion of `v*` tags for everyone but the
  repository owner, whose Admin role bypasses it always and who holds to the
  tag policy above.
- Security: private vulnerability reporting on; secret scanning on with push
  protection; Dependabot alerts on, with weekly version updates for the GitHub
  Actions and the Go modules from `.github/dependabot.yml`; Dependabot
  security updates off (a Dependabot `go.mod` pull request fails the `notices`
  job until `THIRD_PARTY_NOTICES.md` is regenerated on its branch, as the
  dependabot file says).
- Wiki off; issues on (the issue chooser routes security reports to the
  policy).
- Immutable releases: not yet enabled. The owner enables them (Settings,
  General, Releases) before the first v0.2.0 release candidate. From then on
  GitHub locks each published release's tag to its commit and freezes its
  assets while the release exists, irreversibly per published release (a
  draft is unaffected until published), and issues a release attestation that
  `gh release verify` (gh 2.81 or later) checks; a fix stays a new tag.
  Releases published before that are governed by the ruleset and the tag
  policy alone.

## Moving the gateway pin (L7)

agentgateway is pinned to one release (v1.6.0) because its configuration
schema is unversioned, its ExtMCP protocol is young and a release breaks
something about every five weeks; every other release is unqualified until the
seventeen items below have been checked against it (known limit L7). The
check is `scripts/requalify-gateway.sh`: it fetches what the items compare,
runs the binary-backed tests and the end-to-end test against the candidate
binary, and prints one line per item, `PASS` when the candidate behaves as
the documents say of v1.6.0 and `CHANGED` when something must be rewritten
before the pin moves. `CHANGED` is work to do, not a verdict on the release; a
candidate that closes a known limit is `CHANGED` too, because the documents
that describe the limit must change with the pin. Nothing moves the pin but a
pull request that carries the bump list of item 17.

```sh
scripts/requalify-gateway.sh v1.7.0 SHA256_OF_agentgateway-linux-amd64 --e2e
```

The first argument is the release tag; the second is the SHA-256 of that
release's `agentgateway-linux-amd64` asset, the value `AGENTGATEWAY_SHA256` in
`.github/workflows/ci.yml` takes when the pin moves. The script refuses a
digest the release does not publish beside that asset and, on a linux/amd64
host, hashes the downloaded binary against it, as the `e2e` job does. The
binary for the host it runs on (linux/amd64, linux/arm64 or darwin/arm64, the
three the release ships) is downloaded into `.cache/candidate/<version>/`,
used from there when already present, and checked against its own published
digest; everything else the run produced is kept beside it: the three
upstream files at both tags under `upstream/`, every diff under `diffs/`, the
`go test -v` log in `tests.log`, and with `--e2e` the `make e2e` log in
`e2e.log`, the scenario notes in `e2e-report.log` and the process logs under
`e2e-work/logs/`. Without `--e2e` the items that need a running gateway are
`SKIPPED`; `--reuse` runs nothing and re-reads the artefacts of an earlier
run. The gateway binary is run only through the binary-backed tests
(`--validate-only`) and, with `--e2e`, inside `make e2e`. Exit status 0 means
every item that ran is `PASS` (item 15 is `PENDING` until the processor-TLS
pull requests land), 1 that an item is `CHANGED` or a test run failed, 2 a
usage error, 3 that nothing is `CHANGED` but items were `SKIPPED`. Two `RUN`
lines before the items name every failed test of the two runs, so a failure
no item reads is never hidden behind a `PASS`.

The same run is the `requalify` job of the `ci` workflow: Actions, `ci`, Run
workflow, with `gateway_version` and `gateway_sha256` filled in; the job runs
only on a dispatch that fills them, calls the script with `--e2e` on the
linux runner, prints the scenario notes and the head of every diff, and the
process logs on failure. The pinned `e2e` job keeps running against v1.6.0 on
every dispatch. `TestRequalifyCI_dispatchJobRunsTheScript` in
`internal/requalifypolicy` fails when the job, its two inputs or the command
disappear from `ci.yml`.

The seventeen items, with what the script compares and where the documents
record the pinned behaviour:

1. The unhooked-call probe answers 202 (L17). Scenario O notes whether the
   id-less `tools/call` reached the hostile upstream; `PASS` means it still
   does, as README.md (canary step 7), SECURITY.md (hardening checklist),
   Running the canary above, docs/threat-model.md (L17 and row 25) and the
   `--no-probe` help in `cmd/toolwarrant/verify.go` say. Needs `--e2e`.
2. `schema/config.json`, filtered to the definitions the emitted file writes
   into or the canary reads: the root section list, `RawConfig`,
   `LocalGateway`, `LocalAttachedRoute`, `RouteMatch`, `FilterOrPolicy`,
   `McpAuthorization`, `McpGuardrails`, `Processor`, `FailureMode`, `Phase`,
   `HeaderFilter`, `SimpleLocalBackendPolicies`, `LocalBackendTLS`,
   `LocalRouteBackend`, `LocalMcpBackend`, `LocalMcpTarget` and their leaf
   definitions, each extracted from the pretty-printed schema and compared
   between the tags; a change anywhere else is reported by size only. The
   line also counts the root sections, the route policies (`FilterOrPolicy`)
   and the config fields (`RawConfig`), which `cmd/toolwarrant/liveshape.go`
   and `liveadmin.go` state: at v1.6.0 the schema has 14 sections, 32 route
   policies and 36 config fields.
3. `crates/protos/proto/ext_mcp.proto`: identical at both tags and to the
   vendored copy. When it differs: copy it into `third_party/agentgateway/`,
   record the tag's commit in `NOTICE`, `go generate ./internal/extmcpv1`,
   `scripts/gen-proto.sh --check`, and review `McpRequest.headers` and
   `metadata_context` in `internal/processor`; the line names which of those
   the diff touches.
4. The enumerations the emitted processor entry depends on: the processor
   `kind` constants (`remote` at v1.6.0; agentgateway main has gained a CEL
   kind), `FailureMode` (`failClosed`, `failOpen`) and the method `Phase`
   values (`off`, `request`, `response`, `full`).
5. The versions of the `rmcp` crate in `Cargo.lock`, the typed model whose
   re-serialisation drops keys (L2): 0.10.0 and 3.4.0 at v1.6.0, both
   dependencies of the agentgateway crate.
6. Scenario L against the L2 golden `e2e/testdata/gateway_tool_keys.json`.
   When it fails, re-record the golden from the lists the test names, then
   docs/threat-model.md L2 and L9, docs/decisions.md D10 and this document.
   Needs `--e2e`.
7. The MCP revision: the probe (`probeProtocolVersion` in
   `cmd/toolwarrant/probe.go`) and the crawler (`requestedProtocolVersion` in
   `internal/crawl/crawl.go`) send the same one, and scenario L notes the one
   the gateway negotiated with its raw client (`L: the gateway negotiated MCP
   protocol version ...`); the line also prints the revisions the hostile
   upstream saw in `initialize` requests, read from its request log, which
   are each client's own: the gateway relays them (2025-06-18 from the
   crawler, the probe and the raw client, 2025-11-25 from the go-sdk client
   of the e2e test). Needs `--e2e`.
8. A raw `$NAME` is refused and the escaped `$` is accepted:
   `TestGatewaySubstitutesEnvironmentIntoTheRawFile`,
   `TestGoldenFilesValidateWithRealGateway` (the `dollar_sign` golden),
   `TestDollarEscapeIsPinned` and `TestDollarSignNeverReachesTheFile`.
9. The reload log markers `e2e/stack_test.go` waits for (`loaded config from
   File`, `Failed to reload config`): every scenario that re-emits waits for
   them, so the line counts the reloads seen and fails on `did not reload`.
   Needs `--e2e`.
10. The admin API (L18): the cmd tests against
    `testdata/admin_config.json`
    (`TestVerifyGatewayComparesTheLiveConfigurationWithTheEmittedFile`,
    `TestLiveComparisonCatchesAnAddedOpenGateway`,
    `TestVerifyGatewayLiveComparisonFailsClosed`) and scenario P's notes:
    `GET /api/config` renders `config`, `gateways` and `routes`, `POST
    /api/config` takes JSON (200) and refuses the emitted YAML (415), and
    `GET /config_dump` answers 200 without authentication. A candidate that
    authenticates the API is `CHANGED`: L18 in SECURITY.md, docs/threat-model.md
    row 26 and the admin warning in `internal/emit/listeners.go` would have to
    be rewritten. Needs `--e2e` for the notes.
11. An oversized `tools/list` page (the 9437184-byte page of scenario J) is
    answered 500 by the gateway before the hook and the processor logs
    nothing, as decision D15 (f) records. Needs `--e2e`.
12. The request-header filter, the target name and the metadata on both
    hooks: `TestGatewayParsesTheRequestHeaderFilter` and
    `TestGatewayAcceptsEachHalfOfTheFilterAlone` against the binary; scenario
    H's note that `metadata_context` is delivered on both hooks, scenario J
    (the cross-server denial names the target) and scenario P's note that the
    live processor entry carries the filter. Needs `--e2e` for the scenarios.
13. The listener addresses: `TestGatewayReadsListenerPinsExactly` (the exact
    spelling of `off`), `TestGatewayParsesListenerAddresses`,
    `TestGatewayParsesBindAddress` and `TestEveryBindAddressClassValidates`.
    What the gateway binds when the fields are absent (`[::]:15020` and
    `[::]:15021`, `internal/emit/listeners.go`) is not re-observed, because
    the emitter always writes all three.
14. The lenient acceptances `internal/emit/testdata/README.md` explains, which
    the emitter refuses itself: `TestGatewayAcceptsAProcessorOnItsOwnSocket`,
    `TestGatewayAcceptsAProcessorNamedForItsOwnSocket`,
    `TestGatewayAcceptsAmbiguousProcessorSpellings`,
    `TestEmitterBindRulesAreStricterThanTheGateway`,
    `TestEmitterNameRuleIsStricterThanTheGateway`,
    `TestEmitterURLRuleIsStricterThanTheGateway`,
    `TestGatewayAcceptsTheShadowRouteDocument`,
    `TestGatewayAcceptsAMixedGatewaysAndBindsDocument` and
    `TestGatewayAcceptsExtraRoutePoliciesAndBackends`. A candidate that
    tightens fails them, and the README's list shrinks with it.
15. The `backendTLS` fields and the scenario Q handshake: `PENDING` until the
    processor-TLS pull requests land, which will give the item its tests.
16. The release asset names and checksum: the published digests of
    `agentgateway-linux-amd64` (the `e2e` job's asset), `agentgateway-darwin-arm64`
    (the laptops' default in README.md, `e2e/main_test.go`,
    `internal/emit/binary_test.go` and `cmd/toolwarrant/emit_validate_test.go`)
    and the host's own asset exist at the tag; the digest given is the linux
    one and the host's binary hashes to its own.
17. The bump list: every tracked file that spells the pinned version
    (`git ls-files | xargs grep -c v1.6.0`; 161 mentions in 51 files on
    2026-10-14), plus `AGENTGATEWAY_SHA256` in `ci.yml` and the tag's commit in
    `third_party/agentgateway/NOTICE`. `PASS` only when the candidate is the
    pin itself; for any other candidate the line lists the files to edit.

The two runs of the binary-backed tests and of `make e2e` are the ones
CLAUDE.md names; the script runs the whole of `internal/emit` and
`cmd/toolwarrant` rather than a name pattern, so no binary-backed test is
left out, and refuses a run in which a gateway test skipped.
`TestRequalifyScript_citesExistingTestsAndScenarios` and
`TestRequalifyScript_reportsEveryItemOnce` in `internal/requalifypolicy` fail
when the script names a test or a scenario that no longer exists or reports
an item number outside 1 to 17, so a rename cannot turn into a `CHANGED` line
at the next move of the pin.

Proof on the pinned version, 2026-10-14, darwin/arm64, with the pinned
binary placed at `.cache/candidate/v1.6.0/agentgateway-darwin-arm64` so
nothing was downloaded: `scripts/requalify-gateway.sh v1.6.0
496ed27e6a96b55a9ad7cabe5c2be7172511f44a3cb113e533d22bf93a7f079d` printed
`PASS` for items 2, 3, 4, 5, 8, 13, 14, 16 and 17, `SKIPPED` for 1, 6, 7, 9,
10, 11 and 12 and `PENDING` for 15, exit 3 (9 PASS, 0 CHANGED, 7 SKIPPED, 1
PENDING); the same command with `--e2e` printed `PASS` for every item but 15,
exit 0 (16 PASS, 0 CHANGED, 0 SKIPPED, 1 PENDING), both `RUN` lines at exit 0,
`TestEndToEnd` in 31 s. Its notes: `L: the gateway negotiated MCP protocol
version 2025-06-18 with a raw client that asked for 2025-06-18`; `P: POST
/api/config with Content-Type application/yaml -> status 415, 54-byte answer`;
`P: GET /config_dump -> status 200, 13432-byte answer`; `O: the hostile
upstream's request log gained 1 tools/call request(s) named
toolwarrant.probe.*`; 26 reloads seen; the schema counts 14, 32 and 36. The
item lines are quoted in the commit that added the script.

When every item is `PASS`: open a branch, make the item 17 edits (the version
in CLAUDE.md, ci.yml, `.goreleaser.yaml`, `cmd/toolwarrant/main.go`, the
`NOTICE`, `internal/emit`, `cmd/toolwarrant`, README.md, SECURITY.md and the
three documents under docs/; the checksum in `ci.yml`; the asset name in
`e2e/main_test.go` and the three test files if it changed), re-record what
items 1, 6, 10 and 11 observed where the documents quote it, dispatch the `ci`
workflow on the branch with the candidate's inputs and read the `requalify`
job's lines, then merge. A candidate that stays `CHANGED` on an item is not
pinned; the documents keep describing v1.6.0 until one is.

## Exit codes

- `0`: success. For `verify-gateway`, OK, MISSING or KNOWN-LIMIT only. For
  `crawl --every`, a run that was stopped after at least one complete crawl
  and in which the catalog refused none.
- `1`: the operation failed: a lifecycle refusal (self-approval, stale digest,
  invalid transition), a crawl failure, a corrupt or wrong-schema database, a
  processor that stopped with an error, `verify-gateway` with a LEAK,
  CONFIG-EDITED (a body hash other than `--expect-body-hash` included),
  LIVE-CONFIG-MISMATCH, UNHOOKED-CALLS, PROBE-INCONCLUSIVE or PROBE-CHANGED, a
  `verify-gateway --every` run that was stopped after any check failed, any
  failing verdict line was printed or no check completed, or that ended at a
  check with a failing verdict without `--keep-going`, a `crawl --every`
  run stopped by a catalog error or with no complete crawl, `emit` when the
  gateway binary refuses the file, a processor address falls on one of the
  gateway's own sockets, its host does not parse as an IP literal although
  it looks like one or is a name on a port the gateway binds (D15), or the
  path at `--out` is not a regular file,
  `crawl --strict` with a rejected or unusable tool, `audit verify` with a
  broken chain, another head or integrity problems, `init` on a path whose
  directory is reached through a symbolic link that root does not own (cmd
  `TestInitRefusesADirectorySymlink`), and any command on a catalog file that
  was replaced under a running store. A
  command whose stdout or stderr returned a write error also exits 1 even when
  its work succeeded: the output is part of the work. A reader that closes a
  pipe early ends the process by SIGPIPE instead (shell status 141), which is
  not an exit code of this program.
- `2`: the command line was wrong: unknown command or flag, missing argument,
  `--every` under 1 s, `verify-gateway --admin` or `--expect-body-hash` without
  `--config`, `verify-gateway --expect-unhooked` with `--no-probe` (D18), and
  the policy refusals whose fix is a flag: the system actor
  trying to decide (pass `--as` with your own name), `serve` on a non-loopback
  address without `--allow-non-loopback`, `serve` with `--allow-non-loopback`
  but without `--secret-env`, `--tls-client-ca` or `--insecure-no-secret`,
  `serve` with one of `--tls-cert` and `--tls-key` without the other, with
  `--tls-client-ca` alone or with a TLS flag on a unix socket, `emit` with a
  wildcard `--bind-address` without `--allow-all-interfaces`, and `emit` with
  an `--out` that is the catalog database, its `-wal` or `-shm` sibling, the
  `--gateway-binary` path or an existing regular file whose header lines are
  not emit's (D17; name another path, or remove the foreign file yourself).

Every error is one sentence on stderr with advice where a sentinel is known
(`your crawl proposed this version; another person must approve it, or pass
--allow-self-approval`; `the proposal changed since you looked; run diff
again`; `give more characters of the hash`; `only a named person decides; pass
--as with your own name`). Upstream-controlled text in an error is escaped
before it is printed.
