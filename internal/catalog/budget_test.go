package catalog

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// D6 regression (reviewers' "unbounded catalog growth"): a tool gains at most
// MaxProposalsPerDecision versions between decisions; past that a new digest
// marks it unusable and stores nothing, and a decision resets the budget.
func TestRecordCrawl_ProposalBudgetCapsVersions(t *testing.T) {
	s, path := newStoreAt(t, defaultPolicyForTests())
	mustAddServer(t, s, "alpha")
	variant := func(i int) string { return fmt.Sprintf("v%03d", i) }
	for i := 0; i < MaxProposalsPerDecision; i++ {
		if k := kindsOf(mustCrawl(t, s, "alpha", tool("echo", variant(i))))["echo"]; k != ChangeNew && k != ChangeChanged {
			t.Fatalf("crawl %d: kind %s", i, k)
		}
	}
	if v := mustTool(t, s, "alpha", "echo"); v.Versions != MaxProposalsPerDecision {
		t.Fatalf("versions = %d", v.Versions)
	}

	// Over budget: the live definition is marked unusable, nothing is stored.
	rep := mustCrawl(t, s, "alpha", tool("echo", variant(MaxProposalsPerDecision)))
	if c := rep.Changes[0]; c.Kind != ChangeUnusable || c.Reason != reasonBudget || c.Digest != "" {
		t.Fatalf("over budget = %+v", c)
	}
	v := mustTool(t, s, "alpha", "echo")
	if v.Versions != MaxProposalsPerDecision || !v.Unusable || v.LastSeen != lifecycle.UnusableDigest {
		t.Fatalf("tool over budget = %+v", v)
	}
	if e := entryOf(t, s, "tool.unusable"); !strings.HasSuffix(e.Detail, fmt.Sprintf(" reason=%s budget=%d", reasonBudget, MaxProposalsPerDecision)) {
		t.Errorf("tool.unusable entry = %+v", e)
	}
	// Still over budget after a reopen: the budget is stored, not remembered.
	_ = s.Close()
	s = openStore(t, path, defaultPolicyForTests())
	if k := kindsOf(mustCrawl(t, s, "alpha", tool("echo", variant(MaxProposalsPerDecision+1))))["echo"]; k != ChangeUnchanged {
		t.Errorf("second over-budget digest: kind %s, want unchanged (still unusable)", k)
	}
	// A digest the tool already knows is still observed.
	last := variant(MaxProposalsPerDecision - 1)
	if k := kindsOf(mustCrawl(t, s, "alpha", tool("echo", last)))["echo"]; k != ChangeChanged {
		t.Errorf("known digest after the marker: kind %s, want changed", k)
	}
	if v := mustTool(t, s, "alpha", "echo"); v.Unusable || v.Pending != digestOf(t, "echo", last) {
		t.Errorf("tool = %+v", v)
	}
	// An approval resets the budget: the next new digest is stored again.
	mustApprove(t, s, "alpha", "echo", digestOf(t, "echo", last))
	if k := kindsOf(mustCrawl(t, s, "alpha", tool("echo", variant(MaxProposalsPerDecision))))["echo"]; k != ChangeChanged {
		t.Errorf("after an approval: kind %s, want changed", k)
	}
	if v := mustTool(t, s, "alpha", "echo"); v.Versions != MaxProposalsPerDecision+1 {
		t.Errorf("versions after the reset = %d", v.Versions)
	}
	if n := mustCount(t, rawDB(t, path), `SELECT proposals_since_decision FROM tools WHERE name = 'echo'`); n != 1 {
		t.Errorf("stored budget = %d, want 1", n)
	}
	if _, err := s.VerifyAudit(bg); err != nil {
		t.Fatal(err)
	}
}

// A reject resets the budget as well, and an unknown digest beyond the budget
// never becomes a version even while the tool is disabled.
func TestRecordCrawl_RejectResetsTheBudget(t *testing.T) {
	s := newStore(t)
	mustAddServer(t, s, "alpha")
	variant := func(i int) string { return fmt.Sprintf("r%03d", i) }
	for i := 0; i < MaxProposalsPerDecision; i++ {
		mustCrawl(t, s, "alpha", tool("echo", variant(i)))
	}
	if err := s.Disable(bg, "alpha", "echo", alice); err != nil {
		t.Fatal(err)
	}
	if k := kindsOf(mustCrawl(t, s, "alpha", tool("echo", variant(MaxProposalsPerDecision))))["echo"]; k != ChangeUnusable {
		t.Errorf("over budget while disabled: kind %s", k)
	}
	if err := s.Enable(bg, "alpha", "echo", alice); err != nil {
		t.Fatal(err)
	}
	// Enable is not a decision: still over budget.
	if k := kindsOf(mustCrawl(t, s, "alpha", tool("echo", variant(MaxProposalsPerDecision+1))))["echo"]; k != ChangeUnchanged {
		t.Errorf("over budget after enable: kind %s", k)
	}
	pending := mustTool(t, s, "alpha", "echo").Pending
	if pending == "" {
		// Enable with no live digest proposes nothing; propose a known one.
		mustCrawl(t, s, "alpha", tool("echo", variant(0)))
		pending = mustTool(t, s, "alpha", "echo").Pending
	}
	if err := s.Reject(bg, "alpha", "echo", pending, bob); err != nil {
		t.Fatal(err)
	}
	if k := kindsOf(mustCrawl(t, s, "alpha", tool("echo", variant(MaxProposalsPerDecision+2))))["echo"]; k != ChangeChanged {
		t.Errorf("after a reject: kind %s, want changed", k)
	}
	if v := mustTool(t, s, "alpha", "echo"); v.Versions != MaxProposalsPerDecision+1 {
		t.Errorf("versions = %d", v.Versions)
	}
}

// bigTools builds n definitions close to the per-tool cap.
func bigTools(n int, variant string) []CrawledTool {
	filler := strings.Repeat("a", MaxToolBytes-512)
	in := make([]CrawledTool, n)
	for i := range in {
		name := fmt.Sprintf("big-%03d", i)
		in[i] = CrawledTool{Name: name, Raw: []byte(fmt.Sprintf(`{"name":%q,"description":"%s%s","inputSchema":{"type":"object"}}`, name, filler, variant))}
	}
	return in
}

// Reviewers' "big crawl blocks approval", scaled down: an operator's decision
// in another handle waits for a large crawl and succeeds, because the write
// lock is held only for the inserts and the busy timeout is long enough.
func TestRecordCrawl_LargeCrawlDoesNotBlockADecision(t *testing.T) {
	if testing.Short() {
		t.Skip("writes about 10 MiB")
	}
	path := dbPath(t)
	writer := openStore(t, path, lifecycle.DefaultPolicy())
	other := openStore(t, path, lifecycle.DefaultPolicy())
	mustAddServer(t, writer, "alpha")
	mustAddServer(t, writer, "beta")
	mustCrawl(t, writer, "beta", tool("x", "v1"))
	dX := digestOf(t, "x", "v1")

	const tools = 40
	var wg sync.WaitGroup
	var otherErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(50 * time.Millisecond)
		otherErr = other.Approve(bg, "beta", "x", dX, bob)
	}()
	began := time.Now()
	rep, err := writer.RecordCrawl(bg, CrawlInput{Server: "alpha", Complete: true, Tools: bigTools(tools, "r0")}, crawler)
	wg.Wait()
	if err != nil || len(rep.Changes) != tools {
		t.Fatalf("crawl: %+v, %v", rep, err)
	}
	if otherErr != nil {
		t.Fatalf("a decision in another handle failed while a %d-tool crawl ran (%v): %v", tools, time.Since(began), otherErr)
	}
	if !mustSnapshot(t, other, "beta").Serves("x", dX) {
		t.Error("the approval did not land")
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d x %d KiB crawl took %v; database is %d MiB", tools, MaxToolBytes>>10, time.Since(began), fi.Size()>>20)
}
