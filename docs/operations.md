# Operations

This guide covers the day-to-day running of toolwarrant v0.1 against
agentgateway v1.6.0. Command names and flags are those of the CLI's command
table in `cmd/toolwarrant/main.go`; where a flag or behaviour is being wired in
the current wave and has no in-process test yet, the text says "to be verified
by the end-to-end test". The package behaviour behind every command is tested;
see [threat-model.md](threat-model.md) for the test names.

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
  unless `--allow-non-loopback` is given; pass that only together with
  `--secret-env` (advised by the help text, not enforced) and only on a network
  nobody but the gateway can reach. A unix socket is created 0600. The refusal
  is a usage error (exit code 2) because the fix is a flag.
- `--target NAME` is the backend name the gateway reports in `service_names`;
  it defaults to the server name, which is what the emitted configuration uses.
  Set it only if the gateway log shows another value; the processor logs the
  first mismatch once at Debug as `hook names another backend` and counts the
  rest in `wrong backend`. To be verified by the end-to-end test.
- `--secret-env VAR` names the environment variable holding the shared secret
  that `emit --secret-env` wrote into the gateway file. It is read from the
  environment so that it never appears in a process listing, and it is checked
  up front against the emitter's rule (16 to 256 printable ASCII characters).
  To be verified by the end-to-end test.
- `--max-evidence-age DURATION` expires the digests the processor remembers
  from gateway listings; 0 (the default) keeps them until the next listing or a
  catalog change. It ages conflict markers too (limit L15).
- The processor opens the catalog read-only and can never change it (current
  wave; the package test is `TestOpenWith_ReadOnly`). SQLite still needs the
  `-shm` file next to the database to exist and be writable by the processor's
  user, or the directory must allow creating it. Run the CLI once as the owner
  after `init` so the WAL and SHM files exist, or let the processor's user
  write to the directory.
- The processor reloads its snapshot only when the catalog's generation counter
  moves, so approvals, rejects, rollbacks, disables and pauses take effect on
  the very next hook without a restart. A catalog it cannot read denies every
  hook (`source errors`).
- Logs are JSON lines on stderr. Tool names in log lines are quoted, so a name
  cannot forge a log line. Denials and hides are logged; the shared secret and
  catalog contents never are.
- On SIGINT or SIGTERM the processor stops gracefully, prints its counters and
  exits 0; an error that stops it exits 1. The stats line is:
  `stats: lists served=N denied=N, tools hidden=N (mismatched=N unapproved=N
  oversized=N), calls allowed=N denied=N, wrong backend=N, unauthenticated=N,
  throttled=N, source errors=N` (the breakdown fields are current-wave wiring).
  Tools the catalog has never heard of are `hidden` minus the three categories.
- Interpretation. `mismatched` on a tool you just approved is the gateway
  re-serialisation case (limit L2), not drift. `unauthenticated` above zero
  with a secret configured means the gateway is not sending it, or is sending
  another one: every such hook was denied. `throttled` means more than 32 hooks
  were in flight; the surplus was denied, never queued. `wrong backend` means
  the route sends hooks about another backend to this processor: check the
  emitted file.

Start the processors before the gateway, or accept that the gateway denies
every hooked request until they are up (`failureMode: failClosed`).

## Running the canary

`verify-gateway` is the deploy-time self-test and the canary. It opens a new
MCP session through the gateway route like a client would, lists the tools and
compares each served definition with the catalog's serving policy:

```sh
toolwarrant verify-gateway --server github \
  --url http://127.0.0.1:3000/github/mcp \
  --config /etc/agentgateway/gateway.yaml \
  --every 1m --keep-going
```

Verdicts, one line per tool:

- `LEAK name digest`: the gateway serves a definition the catalog would hide.
  This is what a route without its processor looks like. Exit code 1.
- `MISMATCH name digest`: the gateway serves an approved tool with a definition
  that does not hash to the approved digest, the re-serialisation case of
  limit L2. Current-wave verdict; to be verified by the end-to-end test.
- `MISSING name digest`: the catalog approves the tool and the latest crawl saw
  the approved digest, but the gateway does not serve it. Usually the allow
  rule in the gateway file is stale: run `emit` again.
- `CONFIG-EDITED`: the file named by `--config` fails `emit.Verify`: its body
  no longer matches the hash in its header, or the header is missing. Exit
  code 1. Regenerate the file with `emit`; a file written by an older emitter
  whose header text changed also fails and must be re-emitted. To be verified
  by the end-to-end test.
- `OK: the gateway serves N tool(s), every one approved and current`.

Why a canary and not a one-off check: the gateway binds the processor chain per
MCP session. A reload that drops the processor leaves existing sessions guarded
and their statistics moving, and unguards only new sessions. Only a fresh
session can see that, which is what every `verify-gateway` run opens. With
`--every DURATION` (at least 1 s) the command repeats; with `--keep-going` it
keeps running after a LEAK or CONFIG-EDITED instead of exiting, so a supervisor
can keep it up and alert on its output. Both flags are current-wave wiring.

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
   TOOLWARRANT_SECRET_GITHUB_2`. The file is written 0600 because it carries a
   secret; a warning says so. The gateway reloads the file (seam test 13
   observed a reload under 0.5 s; a file it cannot parse keeps the previous
   state).
4. Run `verify-gateway` against the route. New sessions now use the new
   processor and secret.
5. After the longest session lifetime you tolerate, stop the old processor. Its
   `unauthenticated` counter stays at zero throughout because the old sessions
   keep sending the old secret to it.

Every step of this procedure that depends on `--secret-env` is to be verified
by the end-to-end test. Never rotate by editing the file: the header hash fails
`Verify` and the canary reports CONFIG-EDITED.

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
`tool.disabled`, `tool.enabled`, `version.proposed`, `version.superseded`,
`version.approved`, `version.rejected` and `version.rolled_back`. Detail strings
hold classes and quoted, capped fragments, never raw upstream text.

`audit verify` checks every link from entry 1 to the head and prints
`audit log ok: N entries, head HASH`, followed by a reminder to record the head
outside the database. Do that after every verify, in a ticket, a notebook or a
monitoring system: the chain proves that nothing inside it was altered, deleted,
inserted or reordered, but a rewritten log that stops earlier is internally
valid, and only a head recorded elsewhere betrays it. `--expect-head HASH` fails
when the head differs, with the note that either the log grew since you recorded
the head or it was rewritten; compare with `audit list --after N` from your
recorded sequence number.

Both commands open the database in forensic mode (current wave): a file whose
guard triggers were dropped is still read, read-only, so that `audit verify` can
name the broken entry (`the audit log is broken at entry N`). Nothing is ever
served or written from such an open.

## Recovering from ErrCorrupt and ErrSchema

`catalog: database integrity check failed` (`ErrCorrupt`) means the file
contradicts itself: a stored definition no longer hashes to its digest, an
approved pointer dangles, a status disagrees with its tool row, or a guard
trigger or index is missing. The CLI adds "do not serve from this database,
restore it from a backup". Someone edited the file outside toolwarrant, or a bug
wrote it. Procedure:

1. Stop the processors for every server in that database. A processor whose
   catalog read fails denies every hook, so the gateway is already failing
   closed, but a reader that still holds an older snapshot keeps serving it.
2. Run `audit verify` (forensic mode) to learn whether the audit chain is intact
   and at which entry it breaks, and `audit list` to see the last entries.
   Compare the head with the one you recorded.
3. Restore the most recent backup whose `audit verify` head equals a head you
   recorded, re-run the crawls, and review anything the audit log shows between
   the backup and the corruption.
4. Keep the corrupt file for investigation; it opens only in forensic mode.

`catalog: unsupported schema version` (`ErrSchema`) means the file was not
written by this build: an older unreleased schema, a newer build, or another
application's SQLite file ("not a toolwarrant database", "the file holds another
application's tables"). The CLI adds "the file was written by another schema
version and there is no migration: for a database from an unreleased build,
delete the file and run init again". There is no migration code because nothing
has been released. For a pre-release file: back it up, delete it, run `init`,
register the servers again, crawl, and re-approve from your git export or from
the backup read with a build of the matching schema. A foreign file is left
untouched; point `--db` at the right path.

`catalog: the store is read-only` from a decision means the command opened the
database read-only (the processor's mode); the CLI adds "the database was
opened read-only, so nothing can be changed through it". Decisions are made with
the CLI's normal open.

## Pausing a server

```sh
toolwarrant --as alice server pause github
toolwarrant --as alice server resume github
```

A paused server is not contacted by `crawl` at all (the CLI checks the flag
before listing and prints "the server is paused; run toolwarrant server resume
NAME before crawling it again"), the catalog refuses an observation of it
(`catalog: server is paused`), and its serving snapshot is empty, so the
processor hides every tool of that server and denies every call on the next
hook. Decisions on its tools keep working. `server list` marks the server
`PAUSED`. Both commands require a human actor and write `server.paused` and
`server.resumed` audit entries. Use pause when an upstream is compromised or
under investigation and you want nothing of it served without disabling every
tool one by one. The commands exist in the CLI's command table (package test
`TestPauseAndResumeServer`); the CLI path is to be verified by the end-to-end
test.

## Re-emitting the gateway configuration

Run `emit` whenever the set of approved tool names changes, a server is added,
or a processor address or secret changes:

```sh
toolwarrant emit --out /etc/agentgateway/gateway.yaml \
  --listen-port 3000 --processor-base-port 9001 \
  --processor github=127.0.0.1:9101 \
  --secret-env TOOLWARRANT_SECRET_GITHUB
```

- Servers are taken in name order; the i-th gets processor
  `127.0.0.1:(base + i)` unless `--processor NAME=HOST:PORT` overrides it. One
  address per server; a repeated address is refused.
- The file is written atomically (temporary file and rename) so the gateway
  never reads a half-written file; 0644 without a secret, 0600 with one, plus a
  warning (current wave).
- The output lists each server's route (`/<server>/mcp`), processor and number
  of approved tools, prints a warning for every approved tool that had to be
  left out of the allow rule (a name outside printable ASCII cannot be written
  into a reviewable CEL rule; the tool stays hidden), and prints the `serve`
  command for each server.
- The emitted file pins the gateway's admin, stats and readiness listeners to
  127.0.0.1:15000, 15020 and 15021. Whether the gateway re-binds those on a
  reload or only at start-up was not observed; plan a gateway restart when
  they are first introduced.
- The route bind listens on every interface (limit L10); firewall the listen
  port.

The processor needs no restart after an `emit`: the allow rule in the file only
narrows which names the gateway may show, the processor enforces the digests.
Run `verify-gateway` after the gateway has reloaded.

## Crawling on a schedule

```sh
toolwarrant crawl github --every 1m --bearer-env GITHUB_MCP_TOKEN --json
toolwarrant crawl github --strict
```

`--every` repeats until SIGINT or SIGTERM (at least 1 s) and prints one line per
crawl; a failed crawl is recorded as incomplete with its error class and the
schedule continues. `--strict` exits 1 when the crawl reports any rejected or
unusable tool, after the crawl was recorded and the report printed, for use in
a pipeline that must not proceed on hostile input; with `--every` it stops the
schedule at the first such crawl. A crawl without `--as` and without
`TOOLWARRANT_ACTOR` runs as the system actor `crawler`; a crawl run as a person
proposes as that person, who then cannot approve those proposals. The crawler
does not announce the program name to the upstream (neutral clientInfo); see
limit L4 for why that is only a partial measure. The call-time gap of limit L1
is bounded by this cadence.

## Exit codes

- `0`: success. For `verify-gateway`, OK or MISSING only.
- `1`: the operation failed: a lifecycle refusal (self-approval, stale digest,
  invalid transition), a crawl failure, a corrupt or wrong-schema database, a
  processor that stopped with an error, `verify-gateway` with a LEAK or
  CONFIG-EDITED, `crawl --strict` with a rejected or unusable tool,
  `audit verify --expect-head` with another head. A command whose stdout or
  stderr could not be written also exits 1 even when its work succeeded: the
  output is part of the work, and a closed pipe must not look like success.
- `2`: the command line was wrong: unknown command or flag, missing argument,
  `--every` under 1 s, and the two policy refusals whose fix is a flag: the
  system actor trying to decide (pass `--as` with your own name), and `serve`
  on a non-loopback address without `--allow-non-loopback`.

Every error is one sentence on stderr with advice where a sentinel is known
(`your crawl proposed this version; another person must approve it, or pass
--allow-self-approval`; `the proposal changed since you looked; run diff
again`; `give more characters of the hash`; `only a named person decides; pass
--as with your own name`). Upstream-controlled text in an error is escaped
before it is printed.
