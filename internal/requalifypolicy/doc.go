// Package requalifypolicy holds no code, only the test that keeps
// scripts/requalify-gateway.sh honest: every test the script names must exist
// as a test function of this module, every e2e scenario it reads must be one
// scenario of TestEndToEnd, the seventeen items of docs/operations.md "Moving
// the gateway pin (L7)" must each be reported exactly once, and the dispatch
// job of ci.yml must run the script with the inputs the document names. The
// script reads a go test -v log by test name, so a renamed test would
// otherwise turn into a CHANGED line at the next move of the pin, long after
// the rename.
package requalifypolicy
