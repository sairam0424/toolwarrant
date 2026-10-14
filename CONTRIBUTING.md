# Contributing

toolwarrant is a small, security-sensitive control plane. The rules below keep
its evidence trustworthy and its history readable.

## Build and check

```sh
export GOFLAGS=-mod=readonly  # the Makefile sets it; nothing may edit go.mod by accident
make build    # go build ./... && go vet ./...
make test     # go test -race -count=1 -timeout 1500s -cover ./...
make test-timings  # the same run under gotestsum v1.13.0, then every test slower than 1s (go install gotest.tools/gotestsum@v1.13.0 first)
make lint     # gofmt, go vet (also -tags e2e), golangci-lint v2.14.0
make e2e      # needs the agentgateway v1.6.0 binary at .cache/ (README, Quickstart); CI runs it on dispatch only
```

## Branches and commits

- Work on a short-lived branch off `main`: `fix/<topic>`, `feat/<topic>`,
  `docs/<topic>`, `build/<topic>` or `ci/<topic>`. `main` is only ever merged
  into and tagged.
- Small atomic commits in the conventional form `type(scope): subject`, with a
  body paragraph that says why. No `Co-Authored-By` trailer.
- Open a pull request to `main`; the `ci` checks must pass. Keep the branch's
  commits as they are and merge with a merge commit: the design records in
  `docs/decisions.md` cite commit hashes.
- A tag is never moved or deleted ([SECURITY.md](SECURITY.md), Release
  integrity): a bad release is a new tag plus a `retract vX.Y.Z // reason`
  directive in `go.mod`. The tag ruleset lets only the owner create, update
  or delete a `v*` tag, and the owner holds to the same rule.

## Before you open a pull request

- Every behaviour change has a test, `go test -race` passes on the packages you
  touched, and a bug fix carries a regression test that fails on the old code.
- A change to `go.mod` regenerates `THIRD_PARTY_NOTICES.md` with
  `scripts/gen-third-party-notices.sh` in the same commit; the `notices` job
  fails otherwise.
- A renamed test updates every document that cites it; the `docs` job checks
  that every cited test name exists and every relative link resolves.
- Test files carry no literal invisible or format characters; build such
  strings at run time or use `\u` escapes.
- A test may consult `testing.Short()` only when its full run exceeds thirty
  seconds on the runner per the timing table; every such test is named in
  CLAUDE.md and runs in full in `test-full`. The timing table is the "tests
  slower than 1s" step summary of the `test` and `test-full` jobs, or
  `make test-timings` locally.
- Documents: plain prose, no em dashes, state what the logs show, cite tests by
  their exact names.

## Scope

- The Non-goals in [README.md](README.md) are binding for v0.1; a pull request
  that adds one is out of scope until a later version says otherwise.
- Changes to `internal/emit`, `internal/processor`, `internal/extmcpv1`,
  `cmd/toolwarrant/verify.go` or `cmd/toolwarrant/liveadmin.go` need a read of
  [docs/decisions.md](docs/decisions.md) (D10 to D17) and
  [seam/RESULTS.md](seam/RESULTS.md) first: the gateway's behaviour on v1.6.0
  is pinned there.

## Security problems

Go through [SECURITY.md](SECURITY.md), never a public issue.

## Licence

Apache-2.0. By contributing you agree that your contribution is licensed under
it (section 5 of the licence).
