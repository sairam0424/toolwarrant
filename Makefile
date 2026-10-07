# toolwarrant developer targets. Every go command runs with
# GOFLAGS=-mod=readonly so that no build or test can edit go.mod; a dependency
# change is a deliberate commit that also regenerates THIRD_PARTY_NOTICES.md.
#
#   make test   unit and property tests of every package under -race
#   make lint   gofmt, go vet and golangci-lint, including the e2e package
#   make vuln   govulncheck (install: go install golang.org/x/vuln/cmd/govulncheck@latest)
#   make e2e    the end-to-end test against the real agentgateway v1.6.0 binary
#   make demo   demo/run.sh: builds, runs the e2e test, keeps demo/last-run.log

export GOFLAGS = -mod=readonly

.PHONY: build test lint vuln e2e demo

build:
	go build ./... && go vet ./...

test:
	go test -race -count=1 -timeout 1500s -cover ./...

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
