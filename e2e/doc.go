// Package e2e is the end-to-end acceptance test of toolwarrant against the
// real agentgateway v1.6.0 binary.
//
// It builds bin/toolwarrant and bin/mockupstream from this module, starts the
// mock upstream, the processor (toolwarrant serve) and the gateway on free
// loopback ports, and drives the whole chain the way an operator and an MCP
// client would: the CLI as a subprocess with a temporary catalog, MCP through
// the gateway with the go-sdk client, and the upstream's definitions changed
// behind the gateway's back. Every "to be verified by the end-to-end test"
// statement in README.md and docs/ is covered by a named subtest of
// TestEndToEnd (scenarios A to N).
//
// The test files carry the build tag e2e, so the default go test ./... skips
// them. Run them with
//
//	go test -tags e2e -count=1 -timeout 900s -v ./e2e
//
// or make e2e; demo/run.sh runs them unattended and keeps the output in
// demo/last-run.log. The gateway binary is expected at
// .cache/agentgateway-darwin-arm64 (TOOLWARRANT_GATEWAY_BIN overrides the
// path); the test skips loudly when it is missing. Nothing but loopback
// listeners started by the test itself is used, and every process the test
// starts is stopped when it ends.
package e2e
