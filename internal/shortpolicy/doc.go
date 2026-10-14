// Package shortpolicy holds no code, only the test that enforces the -short
// policy CLAUDE.md and CONTRIBUTING.md state: a test may consult
// testing.Short() only when its full run exceeds thirty seconds on the runner
// per the timing table, and every such test is named in CLAUDE.md and runs in
// full in the ci test-full job. The thirty seconds are read off the timing
// table by a person; the two mechanical halves (named in CLAUDE.md, run in
// full) are what the test checks, so that the sentence cannot drift from the
// tree the way a doc claim does when nothing fails.
package shortpolicy
