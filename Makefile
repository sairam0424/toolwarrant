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
#   make release-check     goreleaser check, and the release notes name the schema version the code writes
#   make release-snapshot  goreleaser release --snapshot: the four archives, SBOMs and checksums
#                          into dist/ without signing or publishing (dist/ is gitignored)

export GOFLAGS = -mod=readonly

# The one go test command of the full suite; test and test-timings share it so
# that the timing table is measured on exactly what make test runs.
GO_TEST_ARGS = -race -count=1 -timeout 1500s -cover ./...

.PHONY: build test test-timings lint vuln e2e demo release-check release-snapshot

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

release-check:
	goreleaser check
	@want="$$(sed -n 's/^const schemaVersion = \([0-9]*\).*/\1/p' internal/catalog/schema.go)"; got="$$(sed -n 's/^ *v\([0-9]*\); a catalog from an earlier build.*/\1/p' .goreleaser.yaml)"; if [ -z "$$want" ] || [ "$$want" != "$$got" ]; then echo "release notes name schema v$$got but internal/catalog/schema.go writes v$$want"; exit 1; fi; echo "release notes name schema v$$got, as the code writes"
	@os="$$(awk '/^builds:/{b=1} /^archives:/{b=0} b && /^ *goos:/{m="os"; next} b && /^ *goarch:/{m="arch"; next} b && m != "" && /^ *- [a-z0-9]+ *$$/{print m, $$2; next} b && /^ *[a-z_]+:/{m=""}' .goreleaser.yaml)"; want="$$(for o in $$(echo "$$os" | awk '$$1=="os"{print $$2}'); do for a in $$(echo "$$os" | awk '$$1=="arch"{print $$2}'); do echo "$$o/$$a"; done; done | sort | tr '\n' ' ')"; got="$$(sed -n 's/^release_platforms="\(.*\)"/\1/p' scripts/gen-third-party-notices.sh | tr ' ' '\n' | sort | tr '\n' ' ')"; if [ -z "$$want" ] || [ "$$want" != "$$got" ]; then echo "goreleaser builds [$$want] but scripts/gen-third-party-notices.sh lists [$$got]; release_platforms must equal the goos x goarch of .goreleaser.yaml or the notices miss a platform's modules"; exit 1; fi; echo "release platforms agree: $$want"
	@grep -qF -- '--bundle=$${signature}' .goreleaser.yaml || { echo ".goreleaser.yaml signs the checksums file without --bundle; cosign v3 writes nothing without it (D16 (c))"; exit 1; }; echo "checksums are signed as a sigstore bundle"

release-snapshot:
	@git check-ignore -q dist || { echo "dist/ is not gitignored; add it before building a snapshot"; exit 1; }
	goreleaser release --snapshot --clean --skip=sign,publish,announce
	@echo "snapshot in dist/: $$(ls dist/*.tar.gz | wc -l | tr -d ' ') archives, $$(ls dist/*.spdx.json | wc -l | tr -d ' ') SBOMs"
