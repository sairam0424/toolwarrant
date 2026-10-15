package catalog

import (
	"errors"
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
	t.Parallel()
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
	t.Parallel()
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

// K11 (review): the budget was reset only by approve, reject and rollback, but
// an upstream revert superseded the pending proposal without resetting it, so
// afterwards no decision was accepted and the tool could never take a new
// definition again. A revert still does not reset the budget (a hostile
// upstream could cycle garbage and a revert to grow the file); the explicit
// human decision ResetProposalBudget is the remedy that is always available.
func TestReview_BudgetDeadlockAfterRevertLeavesNoDecisionToResetIt(t *testing.T) {
	t.Parallel()
	s, path := newStoreAt(t, defaultPolicyForTests())
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("echo", "approved"))
	approved := digestOf(t, "echo", "approved")
	mustApprove(t, s, "alpha", "echo", approved)
	for i := 0; i < MaxProposalsPerDecision; i++ {
		mustCrawl(t, s, "alpha", tool("echo", fmt.Sprintf("garbage-%02d", i)))
	}
	// Upstream goes back to the approved definition: reverted, enabled, no
	// pending proposal, and the budget is still spent.
	rep := mustCrawl(t, s, "alpha", tool("echo", "approved"))
	v := mustTool(t, s, "alpha", "echo")
	if rep.Changes[0].Kind != ChangeReverted || v.Pending != "" || v.State != lifecycle.Enabled {
		t.Fatalf("after the revert: %+v, %+v", rep.Changes[0], v)
	}
	db := rawDB(t, path)
	budget := func() int { return mustCount(t, db, `SELECT proposals_since_decision FROM tools WHERE name = 'echo'`) }
	if budget() != MaxProposalsPerDecision {
		t.Fatalf("budget after the revert = %d; a revert must not reset it", budget())
	}
	// A legitimate update is refused as over budget, and every decision the
	// documentation named as the remedy is unavailable in this state.
	if ch := mustCrawl(t, s, "alpha", tool("echo", "legitimate-update")).Changes[0]; ch.Kind != ChangeUnusable || ch.Reason != reasonBudget {
		t.Fatalf("legitimate update = %+v, want unusable for %s", ch, reasonBudget)
	}
	versions, err := s.Versions(bg, "alpha", "echo")
	if err != nil {
		t.Fatal(err)
	}
	for _, ver := range versions {
		for name, decide := range map[string]func(string) error{
			"approve":  func(d string) error { return s.Approve(bg, "alpha", "echo", d, bob) },
			"reject":   func(d string) error { return s.Reject(bg, "alpha", "echo", d, bob) },
			"rollback": func(d string) error { return s.Rollback(bg, "alpha", "echo", d, bob) },
		} {
			if err := decide(ver.Digest); err == nil {
				t.Fatalf("%s of %s was accepted; the deadlock no longer exists and this test is stale", name, ver.Digest[:8])
			}
		}
	}

	// The reset: one human decision, one audit entry, nothing else changes.
	before := mustTool(t, s, "alpha", "echo")
	if err := s.ResetProposalBudget(bg, "alpha", "echo", alice); err != nil {
		t.Fatalf("ResetProposalBudget: %v", err)
	}
	if budget() != 0 {
		t.Errorf("budget after the reset = %d", budget())
	}
	after := mustTool(t, s, "alpha", "echo")
	if after != before {
		t.Errorf("the reset changed the tool: %+v -> %+v", before, after)
	}
	e := entryOf(t, s, evBudgetReset)
	if e.Actor != "alice" || e.Subject != "alpha/echo" || e.BeforeHash != approved || e.AfterHash != approved ||
		e.Detail != fmt.Sprintf("digest=- state=enabled->enabled last_seen=unusable proposals=%d->0", MaxProposalsPerDecision) {
		t.Errorf("tool.budget_reset entry = %+v", e)
	}
	// The next legitimate digest is stored and reviewed like any other.
	if ch := mustCrawl(t, s, "alpha", tool("echo", "legitimate-update")).Changes[0]; ch.Kind != ChangeChanged || ch.Digest != digestOf(t, "echo", "legitimate-update") {
		t.Fatalf("after the reset = %+v, want the update stored as a proposal", ch)
	}
	v = mustTool(t, s, "alpha", "echo")
	if v.Pending != digestOf(t, "echo", "legitimate-update") || v.Unusable || v.Versions != len(versions)+1 || budget() != 1 {
		t.Errorf("tool after the reset and a crawl = %+v, budget %d", v, budget())
	}
	mustApprove(t, s, "alpha", "echo", v.Pending)
	if !mustSnapshot(t, s, "alpha").Serves("echo", v.Pending) {
		t.Error("the legitimate update is not served after its approval")
	}
	mustBeClean(t, s, "after the reset")
	if _, err := s.VerifyAudit(bg); err != nil {
		t.Fatal(err)
	}
}

// The reset is a decision: a named person only, never a no-op, never on a
// read-only store, and only for a tool that exists.
func TestResetProposalBudget_Refusals(t *testing.T) {
	t.Parallel()
	s, path := newStoreAt(t, defaultPolicyForTests())
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("echo", "v1"))
	ro, err := OpenWith(path, OpenOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ro.Close() })
	before := takeTrace(t, s)
	for name, tc := range map[string]struct {
		err  error
		want error
	}{
		"system actor":   {s.ResetProposalBudget(bg, "alpha", "echo", crawler), ErrHumanRequired},
		"no actor":       {s.ResetProposalBudget(bg, "alpha", "echo", Actor{}), ErrInvalid},
		"unknown tool":   {s.ResetProposalBudget(bg, "alpha", "ghost", alice), ErrNotFound},
		"unknown server": {s.ResetProposalBudget(bg, "beta", "echo", alice), ErrNotFound},
		"read-only":      {ro.ResetProposalBudget(bg, "alpha", "echo", alice), ErrReadOnly},
	} {
		if !errors.Is(tc.err, tc.want) {
			t.Errorf("%s = %v, want %v", name, tc.err, tc.want)
		}
	}
	before.mustEqual(t, s, "refused resets")
	// One proposal since discovery: the reset forgets it, and a second reset
	// has nothing to forget.
	if err := s.ResetProposalBudget(bg, "alpha", "echo", alice); err != nil {
		t.Fatal(err)
	}
	if err := s.ResetProposalBudget(bg, "alpha", "echo", alice); !errors.Is(err, ErrInvalid) {
		t.Errorf("second reset = %v, want ErrInvalid", err)
	}
	if n := countEvents(t, s, evBudgetReset); n != 1 {
		t.Errorf("%d budget reset entries, want 1", n)
	}
	mustBeClean(t, s, "after the reset")
}
