# toolwarrant developer targets. Every go command runs with
# GOFLAGS=-mod=readonly so that no build or test can edit go.mod; a dependency
# change is a deliberate commit that also regenerates THIRD_PARTY_NOTICES.md.
#
#   make test              unit and property tests of every package under -race
#   make test-timings      the same run under gotestsum, then every test slower than 1s (needs gotestsum on PATH:
#                          go install gotest.tools/gotestsum@v1.13.0, the version CI pins)
#   make lint              gofmt, go vet and golangci-lint, including the e2e package
#   make vuln              govulncheck (install: go install golang.org/x/vuln/cmd/govulncheck@v1.9.0, the version CI pins)
#   make e2e               the end-to-end test against the real agentgateway v1.6.0 binary
#   make demo              demo/run.sh: builds, runs the e2e test, keeps demo/last-run.log
#   make release-guards    go.mod has no replace or exclude directive, CHANGELOG.md has an Unreleased section and,
#                          with VERSION=x.y.z, the entry for that version exists (release-check runs these first)
#   make release-schema-line  the release notes header of .goreleaser.yaml names the schema version internal/catalog/schema.go
#                          writes (release-check runs it after the guards)
#   make release-check     release-guards and release-schema-line, then goreleaser check, the platform list and the signing flag
#   make release-snapshot  goreleaser release --snapshot: the four archives, SBOMs and checksums
#                          into dist/ without signing or publishing (dist/ is gitignored)

export GOFLAGS = -mod=readonly

# The one go test command of the full suite; test and test-timings share it so
# that the timing table is measured on exactly what make test runs.
GO_TEST_ARGS = -race -count=1 -timeout 1500s -cover ./...

.PHONY: build test test-timings lint vuln e2e demo release-guards release-schema-line release-check release-snapshot

build:
	go build ./... && go vet ./...

test:
	go test $(GO_TEST_ARGS)

# The timing table CLAUDE.md's -short policy reads: the ci test jobs write the
# same table to their step summary. gotestsum is not a module dependency (go.mod
# stays as it is), so the recipe asks for it on PATH at the version ci pins.
# The json file is kept and named so that other gotestsum tool queries can run
# on it; the exit status is the test run's, or the table's when the run passed,
# so a table that could not be printed (unreadable json, a gotestsum without
# the tool) is never a silent success.
test-timings:
	@command -v gotestsum >/dev/null 2>&1 || { echo "gotestsum is not on PATH; install the version ci pins: go install gotest.tools/gotestsum@v1.13.0"; exit 1; }
	@json="$$(mktemp "$${TMPDIR:-/tmp}/toolwarrant-test-timings.XXXXXX")"; gotestsum --format pkgname --jsonfile "$$json" -- $(GO_TEST_ARGS); status=$$?; echo; echo "tests slower than 1s, slowest first (go test -json stream kept in $$json):"; gotestsum tool slowest --jsonfile "$$json" --threshold 1s; slow=$$?; [ $$status -ne 0 ] || status=$$slow; exit $$status

lint:
	@unformatted="$$(gofmt -l cmd internal e2e)"; if [ -n "$$unformatted" ]; then echo "gofmt: $$unformatted"; exit 1; fi
	go vet ./... && go vet -tags e2e ./e2e/...
	golangci-lint run ./... && golangci-lint run --build-tags e2e ./e2e/...

vuln:
	govulncheck ./...

e2e:
	go test -tags e2e -count=1 -timeout 900s -v ./e2e

demo:
	demo/run.sh

# The guards release-check runs before goreleaser check, in their own target
# so that internal/releaseguards can run them against scratch copies of the
# Makefile, go.mod and CHANGELOG.md without goreleaser on PATH. A replace or
# exclude directive would build the release from a module nobody else can
# fetch (a retract is allowed: it is how a bad tag is withdrawn, CONTRIBUTING.md),
# and leading blanks count, since the go.mod parser skips them; a changelog
# without an Unreleased heading has nowhere for the next change to go; and the
# release commit, checked with make release-check VERSION=x.y.z, must carry the
# heading whose lines the tag publishes. VERSION is read from the environment
# make exports a command-line variable to, never spliced into the shell text,
# and must look like a version before it is compared. The go.mod grep is
# judged by its exit status, not its truth value: 1 is no match, and anything
# else (2: no go.mod, or one grep cannot read) is a refusal, since a guard
# that never read the file has checked nothing.
release-guards:
	@grep -qE '^[[:space:]]*(replace|exclude)([[:space:]]|\()' go.mod; s=$$?; if [ "$$s" -eq 0 ]; then echo "go.mod carries a replace or exclude directive; a release builds from published modules only (a retract is allowed)"; exit 1; elif [ "$$s" -ne 1 ]; then echo "go.mod could not be read (grep exited $$s); the release guards need the module's go.mod beside the Makefile"; exit 1; fi; echo "go.mod carries no replace or exclude directive"
	@grep -qxF '## [Unreleased]' CHANGELOG.md || { echo "CHANGELOG.md has no '## [Unreleased]' heading; a change an operator can see adds its line under one (CONTRIBUTING.md)"; exit 1; }; echo "CHANGELOG.md has an Unreleased section"
	@if [ -z "$$VERSION" ]; then echo "VERSION not set; the release entry is checked by make release-check VERSION=x.y.z"; exit 0; fi; case "$$VERSION" in *[!0-9A-Za-z.+-]*) echo "VERSION must be the version as the changelog heading spells it, such as 0.2.0 or 0.2.0-rc.1, without the v"; exit 1;; esac; grep -E '^## \[[^]]+\] - [0-9]{4}-[0-9]{2}-[0-9]{2}$$' CHANGELOG.md | grep -qF "## [$$VERSION] - " || { echo "CHANGELOG.md has no '## [$$VERSION] - YYYY-MM-DD' heading; the release commit adds it above the Unreleased lines it moves (pass VERSION without the v)"; exit 1; }; echo "CHANGELOG.md has the entry for $$VERSION"

# The release notes header is where an operator learns whether this build
# migrates or refuses their catalog, so it must name the schema version the
# code writes. Its own target, so that internal/releaseguards can run it on
# scratch copies of the two files it reads without goreleaser on PATH
# (TestReleaseGuards_schemaLineNamesTheMigration); release-check runs it after
# the guards.
release-schema-line:
	@want="$$(sed -n 's/^const schemaVersion = \([0-9]*\).*/\1/p' internal/catalog/schema.go)"; got="$$(sed -n 's/^ *v\([0-9]*\); a catalog from an earlier build.*/\1/p' .goreleaser.yaml)"; if [ -z "$$want" ] || [ "$$want" != "$$got" ]; then echo "release notes name schema v$$got but internal/catalog/schema.go writes v$$want"; exit 1; fi; echo "release notes name schema v$$got, as the code writes"

release-check: release-guards release-schema-line
	goreleaser check
	@os="$$(awk '/^builds:/{b=1} /^archives:/{b=0} b && /^ *goos:/{m="os"; next} b && /^ *goarch:/{m="arch"; next} b && m != "" && /^ *- [a-z0-9]+ *$$/{print m, $$2; next} b && /^ *[a-z_]+:/{m=""}' .goreleaser.yaml)"; want="$$(for o in $$(echo "$$os" | awk '$$1=="os"{print $$2}'); do for a in $$(echo "$$os" | awk '$$1=="arch"{print $$2}'); do echo "$$o/$$a"; done; done | sort | tr '\n' ' ')"; got="$$(sed -n 's/^release_platforms="\(.*\)"/\1/p' scripts/gen-third-party-notices.sh | tr ' ' '\n' | sort | tr '\n' ' ')"; if [ -z "$$want" ] || [ "$$want" != "$$got" ]; then echo "goreleaser builds [$$want] but scripts/gen-third-party-notices.sh lists [$$got]; release_platforms must equal the goos x goarch of .goreleaser.yaml or the notices miss a platform's modules"; exit 1; fi; echo "release platforms agree: $$want"
	@grep -qF -- '--bundle=$${signature}' .goreleaser.yaml || { echo ".goreleaser.yaml signs the checksums file without --bundle; cosign v3 writes nothing without it (D16 (c))"; exit 1; }; echo "checksums are signed as a sigstore bundle"

release-snapshot:
	@git check-ignore -q dist || { echo "dist/ is not gitignored; add it before building a snapshot"; exit 1; }
	goreleaser release --snapshot --clean --skip=sign,publish,announce
	@echo "snapshot in dist/: $$(ls dist/*.tar.gz | wc -l | tr -d ' ') archives, $$(ls dist/*.spdx.json | wc -l | tr -d ' ') SBOMs"
