package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/catalog"
)

// Limit L6: an upstream that burns the proposal budget and then returns to
// the approved definition leaves a tool no approve, reject or rollback can
// unblock. budget reset is that decision: a named person only, the audit
// entry printed back, and the next new digest stored again.
func TestBudgetResetUnblocksATool(t *testing.T) {
	t.Parallel()
	c, u := fixture(t)
	v1 := c.tool("s1", "echo").Pending
	c.approve("alice", "s1", "echo", v1)
	for i := 0; i < catalog.MaxProposalsPerDecision; i++ {
		u.set("echo", fmt.Sprintf("Garbage %02d.", i))
		c.ok("crawl", "s1")
	}
	u.set("echo", echoV1)
	wantContains(t, "revert", c.ok("crawl", "s1"), "reverted=1")
	u.set("echo", echoV2)
	wantContains(t, "over budget", c.ok("crawl", "s1"), "UNUSABLE", "proposal-budget-exhausted")
	tv := c.tool("s1", "echo")
	if !tv.Unusable || tv.Approved != v1 || tv.Pending != "" || len(tv.History) != catalog.MaxProposalsPerDecision+1 {
		t.Fatalf("over budget: %+v, %d versions", tv.toolJSON, len(tv.History))
	}
	budget := func() int {
		var n int
		queryRow(t, c.db, "SELECT proposals_since_decision FROM tools WHERE name = 'echo'", &n)
		return n
	}
	if budget() != catalog.MaxProposalsPerDecision {
		t.Fatalf("budget = %d", budget())
	}

	// Refusals change nothing.
	r := c.fail(exitFailure, "--as", "alice", "budget", "reset", "s1", "ghost")
	wantContains(t, "unknown tool", r.stderr, "not found")
	r = c.fail(exitFailure, "--as", "alice", "budget", "reset", "nope", "echo")
	wantContains(t, "unknown server", r.stderr, "not found")
	r = c.fail(exitUsage, "budget", "reset", "s1", "echo", "--by", "crawler")
	wantContains(t, "system actor by flag", r.stderr, "the system actor cannot reset a proposal budget; pass --by with your own name")
	c.fail(exitUsage, "--as", "crawler", "budget", "reset", "s1", "echo")
	c.env[envActor] = "Crawler"
	c.fail(exitUsage, "budget", "reset", "s1", "echo")
	delete(c.env, envActor)
	if budget() != catalog.MaxProposalsPerDecision {
		t.Fatalf("a refusal changed the budget to %d", budget())
	}

	out := c.ok("budget", "reset", "s1", "echo", "--by", "Alice")
	entries := c.auditEntries()
	last := entries[len(entries)-1]
	if last.Event != eventBudgetReset || last.Actor != "alice" || last.ActorType != "human" || last.Subject != "s1/echo" {
		t.Fatalf("last audit entry = %+v", last)
	}
	wantContains(t, "reset", out, "reset the proposal budget of s1/echo by alice; the next crawl may store a new digest",
		fmt.Sprintf("audit entry %d: tool.budget_reset s1/echo by alice (human) at ", last.Seq),
		fmt.Sprintf(", detail digest=- state=enabled->enabled last_seen=unusable proposals=%d->0, hash ", catalog.MaxProposalsPerDecision))
	if budget() != 0 {
		t.Errorf("budget after the reset = %d", budget())
	}
	after := c.tool("s1", "echo")
	if after.Approved != v1 || after.State != "enabled" || len(after.History) != len(tv.History) {
		t.Errorf("the reset changed the tool: %+v", after.toolJSON)
	}
	r = c.fail(exitFailure, "--as", "alice", "budget", "reset", "s1", "echo")
	wantContains(t, "second reset", r.stderr, "no proposals since its last decision")
	resets := 0
	for _, e := range c.auditEntries() {
		if e.Event == eventBudgetReset {
			resets++
		}
	}
	if resets != 1 {
		t.Errorf("%d budget reset entries, want 1", resets)
	}

	// The next crawl stores the new digest as a proposal again.
	wantContains(t, "after the reset", c.ok("crawl", "s1"), "CHANGED", "changed=1")
	tv = c.tool("s1", "echo")
	if tv.Pending == "" || tv.Unusable || tv.Approved != v1 || len(tv.History) != catalog.MaxProposalsPerDecision+2 || budget() != 1 {
		t.Fatalf("after the reset and a crawl: %+v, %d versions, budget %d", tv.toolJSON, len(tv.History), budget())
	}
	c.approve("alice", "s1", "echo", tv.Pending)
	wantContains(t, "audit verify", c.ok("audit", "verify"), "audit log ok", "integrity ok")
}

// The reset is a write: a missing database and a database the process cannot
// write are refused, and the budget stays as it was.
func TestBudgetResetNeedsAWritableDatabase(t *testing.T) {
	t.Parallel()
	missing := &cli{t: t, db: filepath.Join(t.TempDir(), "none.db"), env: map[string]string{}}
	r := missing.fail(exitFailure, "--as", "alice", "budget", "reset", "s1", "echo")
	wantContains(t, "missing database", r.stderr, "does not exist", programName+" init")
	if _, err := os.Stat(missing.db); !os.IsNotExist(err) {
		t.Error("a refused reset created the database")
	}

	if os.Geteuid() == 0 {
		t.Skip("root is not bound by file modes")
	}
	c, _ := fixture(t)
	// SQLite gives the -wal and -shm files the database's mode, so the
	// sidecars are restored as well once the refusal has been seen.
	restore := func(mode os.FileMode) {
		for _, suffix := range []string{"", "-wal", "-shm"} {
			if _, err := os.Stat(c.db + suffix); err == nil {
				if err := os.Chmod(c.db+suffix, mode); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	restore(0o400)
	t.Cleanup(func() { restore(dbFileMode) })
	r = c.fail(exitFailure, "--as", "alice", "budget", "reset", "s1", "echo")
	wantContains(t, "read-only database", r.stderr, "readonly")
	restore(dbFileMode)
	var budget int
	queryRow(t, c.db, "SELECT proposals_since_decision FROM tools WHERE name = 'echo'", &budget)
	if budget != 1 {
		t.Errorf("budget = %d after a refused reset, want the 1 proposal of the first crawl", budget)
	}
	wantContains(t, "reset once writable", c.ok("--as", "alice", "budget", "reset", "s1", "echo"), "audit entry")
}
