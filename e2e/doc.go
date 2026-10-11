// Package e2e is the end-to-end acceptance test of toolwarrant against the
// real agentgateway v1.6.0 binary.
//
// It builds toolwarrant and mockupstream from this module into its work
// directory, starts the mock upstreams, the processors (toolwarrant serve) and
// the gateway on free loopback ports, and drives the whole chain the way an
// operator and an MCP client would: the CLI as a subprocess with a temporary
// catalog, MCP through the gateway with the go-sdk client, the upstream's
// definitions changed behind the gateway's back, the gateway's file edited by
// hand and its running configuration replaced through the admin API, and the
// catalog deleted and initialised again under the running processors. Every
// "to be verified by the end-to-end test" statement in README.md and docs/ is
// covered by a named subtest of TestEndToEnd (scenarios A to P; N runs last
// because it re-initialises the catalog and stops every processor).
//
// The gateway's serving port and its admin, stats and readiness listeners are
// all ports the test picks at run time and passes through emit (--listen-port,
// --admin-addr, --stats-addr, --readiness-addr), never the emitter's defaults
// 15000, 15020 and 15021, so two gateways can run on one host and the serving
// port never collides with a listener port.
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
