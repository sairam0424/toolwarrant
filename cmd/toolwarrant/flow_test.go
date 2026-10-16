package main

import (
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/gate"
	"github.com/sairam0424/toolwarrant/internal/signing/sigtest"
)

const (
	echoV1 = "Echoes the message back."
	echoV2 = "Echoes the message back, now with extras."
	echoV3 = "Echoes everything, including secrets."
)

// fixture is a catalog with server s1 crawled once by the system crawler.
func fixture(t *testing.T) (*cli, *upstream) {
	t.Helper()
	c := newCLI(t)
	u := newUpstream(t, map[string]string{"echo": echoV1, "add": "Adds two numbers.", "wipe_database": "Deletes every row."})
	c.ok("server", "add", "s1", u.url(), "--allow-private", "--owner", "platform")
	c.ok("crawl", "s1")
	return c, u
}

func (c *cli) tool(server, name string) showJSON {
	c.t.Helper()
	var v showJSON
	c.jsonInto(&v, "show", server, name, "--json")
	return v
}

func (c *cli) approve(as, server, tool, hash string) string {
	c.t.Helper()
	return c.ok("--as", as, "approve", server, tool, "--hash", hash)
}

func TestFirstCrawlListShowAndDiff(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	u := newUpstream(t, map[string]string{"echo": echoV1, "add": "Adds two numbers.", "wipe_database": "Deletes every row."})
	c.ok("server", "add", "s1", u.url(), "--allow-private")
	out := c.ok("crawl", "s1")
	wantContains(t, "crawl", out, "crawl 1 of s1 complete: 3 tools, new=3", "NEW", "echo", "pending_review")
	wantNotContains(t, "crawl", out, flagDrift, "REJECTED")

	out = c.ok("list")
	wantContains(t, "list", out, "SERVER/TOOL", "s1/echo", "s1/wipe_database", "pending_review")
	wantNotContains(t, "list", out, flagDrift)
	if filtered := c.ok("list", "s1"); filtered != out {
		t.Errorf("list s1 differs from list:\n%s\n%s", filtered, out)
	}
	r := c.fail(exitFailure, "list", "nope")
	wantContains(t, "stderr", r.stderr, "not found")

	var rows []toolJSON
	c.jsonInto(&rows, "list", "--json")
	if len(rows) != 3 || rows[1].Tool != "echo" || rows[1].Pending == "" || rows[1].Approved != "" || rows[1].Unusable {
		t.Fatalf("list --json = %+v", rows)
	}
	if !hexDigest.MatchString(rows[1].Pending) || rows[1].Live != rows[1].Pending {
		t.Errorf("pending %q live %q", rows[1].Pending, rows[1].Live)
	}

	out = c.ok("show", "s1", "echo")
	wantContains(t, "show", out, "state:          pending_review", "unusable:       false", "PROPOSERS", "PROFILE", gate.DigestProfile, "crawler", "pending", rows[1].Pending)
	tv := c.tool("s1", "echo")
	if len(tv.History) != 1 || tv.History[0].DigestProfile != gate.DigestProfile || strings.Join(tv.History[0].Proposers, ",") != systemActorName {
		t.Errorf("show --json history = %+v", tv.History)
	}
	out = c.ok("diff", "s1", "echo")
	wantContains(t, "diff", out, noApprovedLabel, "+", echoV1, "Suspicious characters", "none")

	out = c.ok("crawl", "s1")
	wantContains(t, "second crawl", out, "unchanged=3")
	var report crawlJSON
	c.jsonInto(&report, "crawl", "s1", "--json")
	if !report.Complete || len(report.Changes) != 3 || report.Changes[0].Kind != "unchanged" || len(report.Rejected) != 0 {
		t.Errorf("crawl --json = %+v", report)
	}
	r = c.fail(exitFailure, "show", "s1", "nope")
	wantContains(t, "stderr", r.stderr, "not found")
	r = c.fail(exitFailure, "crawl", "nope")
	wantContains(t, "stderr", r.stderr, "not found")
}

// The scenario follows D4: the person who ran enable proposed nothing and may
// approve what the crawl proposed; a person whose own crawl proposed a version
// is the one who is refused.
func TestApprovalFlowWithDriftRejectEnableAndRollback(t *testing.T) {
	t.Parallel()
	c, u := fixture(t)
	v1 := c.tool("s1", "echo").Pending
	out := c.approve("alice", "s1", "echo", v1[:shortDigestLen])
	wantContains(t, "approve", out, "approved s1/echo at "+v1)
	tv := c.tool("s1", "echo")
	if tv.State != "enabled" || tv.Approved != v1 || tv.Live != v1 || tv.Drifted {
		t.Fatalf("after approve: %+v", tv.toolJSON)
	}
	r := c.fail(exitFailure, "diff", "s1", "echo")
	wantContains(t, "stderr", r.stderr, "nothing to compare")

	u.set("echo", echoV2)
	out = c.ok("crawl", "s1")
	wantContains(t, "crawl", out, "CHANGED", flagDrift, "changed_pending_reapproval", "changed=1")
	wantContains(t, "list", c.ok("list"), flagDrift)
	tv = c.tool("s1", "echo")
	v2 := tv.Pending
	if !tv.Drifted || tv.State != "changed_pending_reapproval" || v2 == "" || v2 == v1 {
		t.Fatalf("after drift: %+v", tv.toolJSON)
	}
	out = c.ok("diff", "s1", "echo")
	wantContains(t, "diff", out, "from: "+v1, "to:   "+v2, "proposed by crawler", "-", echoV1, "+", echoV2, "Changed text", "extras")
	out = c.ok("diff", "s1", "echo", "--from", v1[:shortDigestLen], "--to", v2[:shortDigestLen])
	wantContains(t, "diff --from --to", out, echoV2)

	r = c.fail(exitFailure, "--as", "alice", "approve", "s1", "echo", "--hash", v1)
	wantContains(t, "stale", r.stderr, adviceStale)

	out = c.ok("--as", "alice", "reject", "s1", "echo", "--hash", v2)
	wantContains(t, "reject", out, "rejected s1/echo at "+v2)
	tv = c.tool("s1", "echo")
	if tv.State != "enabled" || tv.Pending != "" || !tv.Drifted || tv.History[1].Status != "rejected" {
		t.Fatalf("after reject: %+v history %+v", tv.toolJSON, tv.History)
	}
	wantContains(t, "list", c.ok("list"), flagDrift)
	wantContains(t, "diff after reject", c.ok("diff", "s1", "echo"), echoV2)

	u.set("echo", echoV1)
	c.ok("crawl", "s1")
	if tv = c.tool("s1", "echo"); tv.Drifted || tv.Live != v1 {
		t.Fatalf("after revert: %+v", tv.toolJSON)
	}
	wantNotContains(t, "list", c.ok("list"), flagDrift)

	out = c.ok("--as", "alice", "disable", "s1", "echo")
	wantContains(t, "disable", out, "disabled s1/echo")
	r = c.fail(exitFailure, "--as", "alice", "approve", "s1", "echo", "--hash", v1)
	wantContains(t, "approve while disabled", r.stderr, "run show")
	c.fail(exitFailure, "--as", "alice", "disable", "s1", "echo")
	out = c.ok("--as", "alice", "enable", "s1", "echo")
	wantContains(t, "enable", out, "state is now pending_review")
	if tv = c.tool("s1", "echo"); tv.Pending != v1 {
		t.Fatalf("after enable: %+v", tv.toolJSON)
	}
	// D4: alice only ran enable, she proposed nothing, so she may approve.
	c.approve("alice", "s1", "echo", v1)
	if tv = c.tool("s1", "echo"); tv.State != "enabled" || tv.Approved != v1 {
		t.Fatalf("after the enabler approved: %+v", tv.toolJSON)
	}

	// A person whose crawl proposed a version is the one who is refused.
	u.set("echo", echoV3)
	c.ok("--as", "bob", "crawl", "s1")
	tv = c.tool("s1", "echo")
	v3 := tv.Pending
	if len(tv.History) != 3 || strings.Join(tv.History[2].Proposers, ",") != "bob" {
		t.Fatalf("v3 proposers = %+v", tv.History)
	}
	wantContains(t, "show", c.ok("show", "s1", "echo"), "bob")
	r = c.fail(exitFailure, "--as", "bob", "approve", "s1", "echo", "--hash", v3)
	wantContains(t, "proposer approving", r.stderr, adviceSelfApproval)
	c.approve("alice", "s1", "echo", v3)
	if tv = c.tool("s1", "echo"); tv.Approved != v3 || tv.State != "enabled" {
		t.Fatalf("after approving v3: %+v", tv.toolJSON)
	}
	r = c.fail(exitFailure, "--as", "alice", "rollback", "s1", "echo", "--to", v2)
	wantContains(t, "rollback to rejected", r.stderr, "approved before")
	out = c.ok("--as", "alice", "rollback", "s1", "echo", "--to", v1[:shortDigestLen])
	wantContains(t, "rollback", out, "rolled back s1/echo to "+v1)
	tv = c.tool("s1", "echo")
	if tv.Approved != v1 || tv.State != "enabled" || !tv.Drifted || len(tv.History) != 3 || !tv.History[0].EverApproved {
		t.Fatalf("after rollback: %+v history %+v", tv.toolJSON, tv.History)
	}
	wantContains(t, "list", c.ok("list"), flagDrift)
}

func TestSelfApprovalAndSystemActorRefusals(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	u := newUpstream(t, map[string]string{"echo": echoV1})
	c.ok("server", "add", "s1", u.url(), "--allow-private")
	c.ok("--as", "bob", "crawl", "s1")
	tv := c.tool("s1", "echo")
	if tv.History[0].ProposedBy != "bob" {
		t.Fatalf("a crawl run with --as must propose as that person: %+v", tv.History)
	}
	r := c.fail(exitFailure, "--as", "bob", "approve", "s1", "echo", "--hash", tv.Pending)
	wantContains(t, "self approval", r.stderr, adviceSelfApproval)
	r = c.fail(exitUsage, "--as", "crawler", "approve", "s1", "echo", "--hash", tv.Pending)
	wantContains(t, "system actor", r.stderr, "system actor", "--as")
	c.fail(exitUsage, "--as", "CRAWLER", "disable", "s1", "echo")
	// With a trust list in force the proposer rule holds against the
	// operator the key names: bob's key signs as bob, whose crawl proposed.
	sock, add := sigtest.NewAgent(t)
	bob := sigtest.GenerateEd25519(t)
	add(bob)
	bobPub := sigtest.WritePublicKey(t, t.TempDir(), "bob.pub", bob)
	c.env[envAuthSock] = sock
	c.ok("--as", "bob", "--ssh-key", bobPub, "trust", "init")
	r = c.fail(exitFailure, "--ssh-key", bobPub, "approve", "s1", "echo", "--hash", tv.Pending)
	wantContains(t, "self approval through the key", r.stderr, adviceSelfApproval)
	c.fail(exitUsage, "--as", "crawler", "--ssh-key", bobPub, "approve", "s1", "echo", "--hash", tv.Pending)
	c.ok("--ssh-key", bobPub, "--allow-self-approval", "approve", "s1", "echo", "--hash", tv.Pending)
	entries := c.auditEntries()
	last := entries[len(entries)-1]
	if last.Event != "version.approved" || last.Actor != "bob" || last.ActorType != "human" || last.Subject != "s1/echo" {
		t.Errorf("last audit entry = %+v", last)
	}
	// without --as the crawler is the system actor
	c.ok("crawl", "s1")
	for _, e := range c.auditEntries() {
		if e.Event == "crawl.completed" && e.Actor == systemActorName && e.ActorType != "system" {
			t.Errorf("crawler entry has type %q", e.ActorType)
		}
	}
}

func TestHashPrefixHandling(t *testing.T) {
	t.Parallel()
	c, _ := fixture(t)
	v1 := c.tool("s1", "echo").Pending
	r := c.fail(exitFailure, "--as", "alice", "approve", "s1", "echo", "--hash", "abc")
	wantContains(t, "short prefix", r.stderr, "8 to 64 hex")
	r = c.fail(exitFailure, "--as", "alice", "approve", "s1", "echo", "--hash", "0000000000000000")
	wantContains(t, "unknown prefix", r.stderr, "not found")
	c.approve("alice", "s1", "echo", strings.ToUpper(v1[:16]))
	if tv := c.tool("s1", "echo"); tv.Approved != v1 {
		t.Fatalf("upper-case prefix not resolved: %+v", tv.toolJSON)
	}
}

func TestMissingToolsReturnAreDeprecatedAndReappear(t *testing.T) {
	t.Parallel()
	c, u := fixture(t)
	u.remove("add")
	out := c.ok("crawl", "s1")
	wantContains(t, "crawl", out, "missing=1")
	wantContains(t, "list", c.ok("list"), flagMissing)
	u.set("add", "Adds two numbers.")
	out = c.ok("crawl", "s1")
	wantContains(t, "return", out, "returned=1")
	wantNotContains(t, "list after return", c.ok("list"), flagMissing)
	u.remove("add")
	c.ok("crawl", "s1")
	c.ok("crawl", "s1")
	out = c.ok("crawl", "s1")
	wantContains(t, "third miss", out, "deprecated=1")
	if tv := c.tool("s1", "add"); tv.State != "deprecated" {
		t.Fatalf("state %q, want deprecated", tv.State)
	}
	u.set("add", "Adds two numbers.")
	out = c.ok("crawl", "s1")
	wantContains(t, "reappear", out, "REAPPEARED")
	if tv := c.tool("s1", "add"); tv.State != "pending_review" {
		t.Fatalf("state %q, want pending_review", tv.State)
	}
}

func TestPauseBlocksCrawlingAndServing(t *testing.T) {
	t.Parallel()
	c, u := fixture(t)
	v1 := c.tool("s1", "echo").Pending
	c.approve("alice", "s1", "echo", v1)
	out := c.ok("--as", "alice", "server", "pause", "s1")
	wantContains(t, "pause", out, "paused server s1", "server resume s1")
	wantContains(t, "server list", c.ok("server", "list"), "PAUSED", "true")
	var servers []serverJSON
	c.jsonInto(&servers, "server", "list", "--json")
	if len(servers) != 1 || !servers[0].Paused {
		t.Fatalf("server list --json = %+v", servers)
	}
	before := u.sessions.Load()
	r := c.fail(exitFailure, "crawl", "s1")
	wantContains(t, "stderr", r.stderr, "paused", "server resume")
	if u.sessions.Load() != before {
		t.Error("a paused server must not be contacted")
	}
	// The snapshot of a paused server is empty, so through a pass-through
	// gateway even the approved tool is a leak.
	r = c.fail(exitFailure, "verify-gateway", "--server", "s1", "--url", u.url())
	wantContains(t, "stdout", r.stdout, verdictLeak+" echo live "+v1[:shortDigestLen])
	wantNotContains(t, "stdout", r.stdout, " approved ", verdictMismatch)
	// Decisions keep working and the views still show the tools.
	wantContains(t, "list", c.ok("list"), "s1/echo", "enabled")
	c.fail(exitFailure, "--as", "alice", "server", "pause", "s1")
	c.fail(exitUsage, "--as", "crawler", "server", "resume", "s1")
	out = c.ok("--as", "alice", "server", "resume", "s1")
	wantContains(t, "resume", out, "resumed server s1")
	c.fail(exitFailure, "--as", "alice", "server", "resume", "s1")
	c.ok("crawl", "s1")
	events := map[string]bool{}
	for _, e := range c.auditEntries() {
		events[e.Event] = true
	}
	if !events["server.paused"] || !events["server.resumed"] {
		t.Errorf("audit events = %v, want server.paused and server.resumed", events)
	}
}
