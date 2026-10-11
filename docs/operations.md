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
`audit verify` and the recovery procedures; the sections below describe the
behaviour since then.

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
  unless `--allow-non-loopback` is given, and with that flag `serve` still
  refuses to listen without `--secret-env` unless `--insecure-no-secret` is
  passed as well, because anyone who reaches an unauthenticated processor
  decides what the gateway serves; a `--secret-env` always wins over
  `--insecure-no-secret`. Use the pairing only on a network nobody but the
  gateway can reach. A unix socket is created 0600, with a warning when its
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
  the very next hook without a restart (scenarios D and E). Every reload
  re-checks the guard objects, refuses a trigger or view the schema did not
  create, and requires the newest approve or rollback decision about every
  approved tool to name the approved version and digest (D13); a catalog it
  cannot read or trust denies every hook (`source errors`).
- The evidence the processor remembers from the gateway's own listings lives
  in a table sized from the snapshot. It records only tools the catalog could
  serve, and when it is full it evicts an entry that agrees with its approval,
  never a conflict marker or a changed digest (D13), so a full table cannot
  make a changed tool callable; when nothing agreeing is left the new evidence
  is dropped and counted (`Stats.EvidenceDropped`), and while that count is
  above zero a servable tool with no listing evidence is denied as not yet
  verified until a listing records it. A page the processor cannot read through
  to the end marks every servable catalog tool of the server as conflicting
  until a clean page shows the approved digest; expect `tools/call` denials with the reason
  `changed since approval` after such a page until the upstream serves a clean
  listing (limit L1).
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

## Running the canary

`verify-gateway` is the deploy-time self-test and the canary. It opens a new
MCP session through the gateway route like a client would, lists the tools and
compares each served definition with the catalog's serving policy. With
`--config` it checks that the file on disk is the one `emit` wrote; with
`--expect-body-hash HEX` it also checks that the file's body hashes to the
`body sha256` line `emit` printed when you wrote it; with `--admin` (which needs
`--config`) it fetches the live configuration from the gateway's admin API and
compares the whole document with that file; and unless `--no-probe` is given it
sends one `tools/call` without a JSON-RPC id to see whether the gateway forwards
unhooked calls (decisions D12 and D13):

```sh
toolwarrant verify-gateway --server github \
  --url http://127.0.0.1:3000/github/mcp \
  --config /etc/agentgateway/gateway.yaml \
  --expect-body-hash BODY_SHA256_PRINTED_BY_EMIT \
  --admin 127.0.0.1:15000 \
  --no-probe \
  --every 1m --keep-going
```

The example passes `--no-probe` because agentgateway v1.6.0 forwards the id-less
probe on every check (limit L17), so with the probe on every check of this
gateway prints UNHOOKED-CALLS and exits 1. Run the canary once without
`--no-probe` to see that verdict for yourself, record the limit in your runbook,
and drop `--no-probe` when the gateway pin moves to a release that answers the
probe with 400; a canary that fails on every run trains its readers to ignore
it. On a gateway that refuses the shape, leave the probe on.

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
  Scenario L printed `MISSING vendor_tool` for the re-serialised tool. A tool
  whose latest crawl left the unusable marker is not MISSING when the gateway
  does not list it: a working processor hides it.
- `CONFIG-EDITED`: the file named by `--config` fails `emit.Verify` (its body
  no longer matches the hash in its header, or the header is missing), cannot
  be read at all, because a canary that cannot read the file it is meant to
  compare must not report OK, or hashes to something other than the value you
  passed with `--expect-body-hash`, which is how an edit that recomputed the
  header line is caught (limit L19; D13). Exit code 1. Regenerate the file
  with `emit` and record the new body hash; a file written by an older emitter
  whose header text changed also fails and must be re-emitted (scenario F).
- `LIVE-CONFIG-MISMATCH`: with `--admin HOST:PORT` (or an http or https URL;
  the address given to `emit --admin-addr`, default `127.0.0.1:15000`), the
  configuration the gateway is running (`GET /api/config`) is not the file
  named by `--config`. The comparison covers the whole document: every gateway
  and every route the file carries must be present exactly once with the same
  bind address, port, allow rules, processors, backend hosts and match path,
  nothing the file does not carry may exist (an added route, an added
  gateway), no path may appear twice, and the path of `--url` must be the
  match of the emitted route for `--server` (D13; before the fourth round only
  the route named after the server was compared, so a shadow route that owned
  the path compared healthy). Exit code 1. This is what a processor-less route
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
- `UNHOOKED-CALLS`: the gateway forwarded the probe, a `tools/call` without an
  id for the tool name `toolwarrant.probe.<random>`, which no catalog can hold,
  instead of rejecting it with a 400 (limit L17). Exit code 1. The probe
  reaches the upstream exactly when the gateway is unhooked, which is why
  `--no-probe` exists. Scenario O printed this verdict against the pinned
  binary, the hostile upstream's request log showed the probe arriving, and
  with `--no-probe` the OK line said `unhooked-call probe skipped
  (--no-probe)`.
- `PROBE-INCONCLUSIVE`: the gateway answered the probe with a 2xx status other
  than 202 and a body. A JSON-RPC error in such an answer may be the gateway's
  own refusal or an upstream's reply relayed by a forwarding gateway, and the
  canary cannot tell which, so it reports that it proved nothing and fails the
  check (D13). Exit code 1. The one-line account then reads `id-less
  tools/call answered by someone (PROBE-INCONCLUSIVE)`. Not reachable on
  agentgateway v1.6.0, which answers 202 itself; after a move of the pin it
  means the probe's healthy shapes must be re-derived against that release
  (limit L7). Any other answer (a non-2xx status other than 400, or a 2xx
  without a body) is a `check failed` line, not a verdict.
- `OK: the gateway serves N tool(s), N approved and current; live configuration
  matches the emitted file; unhooked-call probe skipped (--no-probe)` is the
  healthy line as printed with the flags of the example above; the first clause
  gains counts such as `, 1 approved but not listed (MISSING)` when there are
  any, the second reads `live configuration not compared (no --admin)` without
  `--admin`, and the third reads `id-less tools/call rejected by the gateway`
  when the probe ran and the gateway answered 400. Exit code 0 is OK or
  MISSING only.

Why a canary and not a one-off check: the gateway binds the processor chain per
MCP session. A reload that drops the processor leaves existing sessions guarded
and their statistics moving, and unguards only new sessions. Only a fresh
session can see that, which is what every `verify-gateway` run opens. With
`--every DURATION` (at least 1 s) the command repeats; with `--keep-going` it
keeps running after a failed check instead of exiting, so a supervisor can keep
it up and alert on its output. The run as a whole exits 1 when it is stopped if
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

Both commands open the database in forensic mode: a file whose guard objects
were dropped or redefined, or that holds a trigger or view the schema did not
create, is still read, read-only, so that `audit verify` can name the broken
entry (`the audit log is broken at entry N`). Nothing is ever served or written
from such an open. Read `audit log ok` in that mode as "the chain is
consistent", not as "the file is intact": every other command refuses a database
whose guard objects are missing or do not have the definition `init` wrote, or
that holds a foreign trigger or view (`ErrCorrupt`), and `audit verify` runs
`Store.Integrity`'s cross-check after the chain check: every approved digest
against the newest decision, every tool's last-seen digest, state and proposal
budget and every server's paused flag, allow-private flag and URL hash against
the latest audit entry about it, every approval row against the decision
entries, and the guard objects and foreign objects against the schema. It
prints `integrity ok: guard objects intact, every approval recorded in the
log` or one `integrity problem:` line per disagreement (`tool X: state is
disabled but the latest audit entry (seq N) left it as enabled`, `server X:
paused is false but the latest server entry (seq N) left it as true`,
`unexpected trigger X: the schema did not create it`) with exit code 1. The
report runs whether or not `--expect-head` matched: a head that moved is
exactly when you want to know which rows disagree with the log, so both
findings are printed together and the head reminder is withheld when either
fails (D13; before the fourth round a mismatching head returned before the
report; cmd `TestAuditVerifyReportsIntegrityWhenTheHeadMismatches`, catalog
`TestIntegrity_StateFlipReenablingADisabledToolIsReported`,
`TestIntegrity_PausedFlagFlipUnpausingAServerIsReported`,
`TestIntegrity_BudgetColumnResetByRawSQLIsReported`,
`TestOpen_ForeignTriggerIsCorrupt`). Run `list` against a suspect database as well, and compare `show`
with `audit list` for the tool in question.

## Recovering from ErrCorrupt and ErrSchema

`catalog: database integrity check failed` (`ErrCorrupt`) means the file
contradicts itself: a stored definition no longer hashes to its digest, an
approved pointer dangles or points at a version that is not what the newest
approve or rollback decision about the tool names, a status disagrees with its
tool row, a guard trigger or index is missing or has another definition than
the one `init` wrote, or the file holds a trigger or view that `init` never
created (D13: a foreign trigger can undo a decision inside the operator's own
transaction, so one is never benign). The CLI adds "do not serve from this
database, restore it from a backup". Someone edited the file outside
toolwarrant, or a bug wrote it. Procedure:

1. Stop the processors for every server in that database. A processor whose
   catalog read fails denies every hook, so the gateway is already failing
   closed, but a reader that still holds an older snapshot keeps serving it.
2. Run `audit verify` (forensic mode) to learn whether the audit chain is intact
   and at which entry it breaks, which registry columns disagree with the log
   and which foreign objects exist, and `audit list` to see the last entries.
   Compare the head with the one you recorded.
3. Restore the most recent backup whose `audit verify` head equals a head you
   recorded, re-run the crawls, and review anything the audit log shows between
   the backup and the corruption.
4. Keep the corrupt file for investigation; it opens only in forensic mode.

`catalog: unsupported schema version` (`ErrSchema`) means the file was not
written by this build: an older unreleased schema (v2 or v3), a newer build, or
another application's SQLite file ("not a toolwarrant database", "the file
holds another application's tables"). This build writes schema v4 (D13: the
audit detail format gained the fields the integrity check compares). The CLI
adds "the file was written by another schema version and there is no
migration: for a database from an unreleased build, delete the file and run
init again". There is no migration code because nothing has been released. For
a pre-release file: back it up, delete it, run `init`, register the servers
again, crawl, and re-approve from your git export or from the backup read with
a build of the matching schema. A foreign file is left untouched; point `--db`
at the right path.

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

There is no prune in v0.1: versions are immutable and the history tables are
append-only by design, so nothing reclaims the rows. The recovery is:

1. `server pause NAME`, so the server is neither crawled nor served while you
   decide (decisions on its tools keep working).
2. Decide whether the upstream is hostile or merely badly behaved. A hostile
   upstream is not an upstream to pin tools from; leave it paused or remove the
   database.
3. To start over: back up the database and its audit head, delete the file, run
   `init`, register the servers again, crawl, and re-approve from your git
   export (`export --dir`) or from the backup. Every server in the file starts
   over with it; keep one database per operator and consider one per upstream
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
reported by `audit verify` (D13). Use pause when an upstream is compromised or
under investigation and you want nothing of it served without disabling every
tool one by one, and as the first step of the growth-cap recovery above
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

- Processor addresses are stable across re-emits (D13). When the output file
  already exists and is `emit`'s own output (header and body hash intact),
  `emit` reads it first and every server keeps the processor address it had; a
  server that is new to the file takes the next free port at or above
  `--processor-base-port` and above every port the file uses; `--processor
  NAME=HOST:PORT` overrides one server's address and wins over the kept one.
  `emit` prints `processor address of server NAME is new: ADDR` for a new
  server and `processor address of server NAME changed from OLD to NEW; restart
  its processor on the new address` for a moved one, so you know which
  processors to restart before the gateway reloads; with no such line the
  running processors are untouched. A file at `--out` that is not what `emit`
  wrote (edited, or another file) is not trusted for addresses: a warning says
  so and every server is numbered afresh, because whoever wrote that file would
  otherwise choose where your processors listen (cmd
  `TestEmitKeepsProcessorAddressesAcrossReEmits`; e2e scenario J re-emits a
  side file as servers are added and checks that no address moves). Before the fourth round
  the i-th server in name order got `base + i`, so adding a server renumbered
  every later server and darkened its route (every hook went to the wrong
  processor or to nobody) until each processor was restarted. One address per
  server; a repeated address is refused, and so is an address on one of the
  gateway's own sockets (the serving port or the admin, stats or readiness
  listener), which the gateway's own validation accepts and which would make
  every hook dial the gateway itself. An override that names a host other than
  `localhost` or a loopback literal makes that processor reachable from the
  network: `emit` prints a warning for it and the printed `serve` command
  carries `--allow-non-loopback`, which `serve` accepts only together with
  `--secret-env` (limit L11).
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
  gateway accepts it; a refusal exits 1, prints the gateway's message and
  leaves no file. Without it a file the gateway cannot load would freeze every
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
gateway may show, the processor enforces the digests. Run `verify-gateway`
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

## Exit codes

- `0`: success. For `verify-gateway`, OK or MISSING only. For
  `crawl --every`, a run that was stopped after at least one complete crawl
  and in which the catalog refused none.
- `1`: the operation failed: a lifecycle refusal (self-approval, stale digest,
  invalid transition), a crawl failure, a corrupt or wrong-schema database, a
  processor that stopped with an error, `verify-gateway` with a LEAK,
  CONFIG-EDITED (a body hash other than `--expect-body-hash` included),
  LIVE-CONFIG-MISMATCH, UNHOOKED-CALLS or PROBE-INCONCLUSIVE, a
  `verify-gateway --every` run that was stopped after any check failed, any
  failing verdict line was printed or no check completed, a `crawl --every`
  run stopped by a catalog error or with no complete crawl, `emit` when the
  gateway binary refuses the file or a processor address falls on one of the
  gateway's own sockets, `crawl --strict` with a rejected or unusable tool,
  `audit verify --expect-head` with another head or with integrity problems. A
  command whose stdout or stderr returned a write error also exits 1 even when
  its work succeeded: the output is part of the work. A reader that closes a
  pipe early ends the process by SIGPIPE instead (shell status 141), which is
  not an exit code of this program.
- `2`: the command line was wrong: unknown command or flag, missing argument,
  `--every` under 1 s, `verify-gateway --admin` or `--expect-body-hash` without
  `--config`, and the policy refusals whose fix is a flag: the system actor
  trying to decide (pass `--as` with your own name), `serve` on a non-loopback
  address without `--allow-non-loopback`, `serve` with `--allow-non-loopback`
  but without `--secret-env` or `--insecure-no-secret`, and `emit` with a
  wildcard `--bind-address` without `--allow-all-interfaces`.

Every error is one sentence on stderr with advice where a sentinel is known
(`your crawl proposed this version; another person must approve it, or pass
--allow-self-approval`; `the proposal changed since you looked; run diff
again`; `give more characters of the hash`; `only a named person decides; pass
--as with your own name`). Upstream-controlled text in an error is escaped
before it is printed.
