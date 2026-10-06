package catalog

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// trace is a snapshot of everything a refused operation must leave alone.
type trace struct {
	gen    int64
	audits int
}

func takeTrace(t *testing.T, s *Store) trace {
	t.Helper()
	return trace{gen: mustGeneration(t, s), audits: auditCount(t, s)}
}

func (tr trace) mustEqual(t *testing.T, s *Store, what string) {
	t.Helper()
	if got := takeTrace(t, s); got != tr {
		t.Errorf("%s left a trace: generation %d -> %d, audit entries %d -> %d", what, tr.gen, got.gen, tr.audits, got.audits)
	}
}

func TestApprove_RecordsTheDecisionEverywhere(t *testing.T) {
	s, path := newStoreAt(t, defaultPolicyForTests())
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("echo", "v1"))
	d := digestOf(t, "echo", "v1")
	before := takeTrace(t, s)
	lo := time.Now().UTC().Add(-time.Second)

	if err := s.Approve(bg, "alpha", "echo", strings.ToUpper(d), bob); err != nil {
		t.Fatal(err)
	}

	v := mustTool(t, s, "alpha", "echo")
	if v.State != lifecycle.Enabled || v.Approved != d || v.Pending != "" || v.Drifted {
		t.Errorf("tool = %+v", v)
	}
	if vs, _ := s.Versions(bg, "alpha", "echo"); vs[0].Status != lifecycle.VersionApproved || !vs[0].EverApproved {
		t.Errorf("version = %+v", vs[0])
	}
	if got := takeTrace(t, s); got.gen != before.gen+1 || got.audits != before.audits+1 {
		t.Errorf("trace %+v -> %+v, want one write and one audit entry", before, got)
	}
	e := entryOf(t, s, "version.approved")
	if e.Actor != "bob" || e.ActorType != "human" || e.Subject != "alpha/echo" || e.BeforeHash != "" || e.AfterHash != d ||
		e.Detail != "digest="+d+" state=pending_review->enabled" {
		t.Errorf("audit entry = %+v", e)
	}

	db := rawDB(t, path)
	var decision, approver, actorType, seen, at string
	if err := db.QueryRowContext(bg, `SELECT decision, approver, actor_type, hash_seen, at FROM approvals`).
		Scan(&decision, &approver, &actorType, &seen, &at); err != nil {
		t.Fatal(err)
	}
	if decision != "approve" || approver != "bob" || actorType != "human" || seen != d {
		t.Errorf("approvals row = %s %s %s %s", decision, approver, actorType, seen)
	}

	list, err := s.Approved(bg)
	if err != nil || len(list) != 1 {
		t.Fatalf("Approved = %+v, %v", list, err)
	}
	a := list[0]
	if a.Server != "alpha" || a.Name != "echo" || a.Digest != d || a.VersionNo != 1 || a.ApprovedBy != "bob" ||
		len(a.Canonical) == 0 || a.ApprovedAt.Before(lo) || a.ApprovedAt.After(time.Now().Add(time.Second)) {
		t.Errorf("Approved[0] = %+v", a)
	}
	snap, _ := s.Snapshot(bg, "alpha")
	if !snap.Serves("echo", d) || snap.Serves("echo", digestOf(t, "echo", "other")) || snap.Serves("ghost", d) {
		t.Errorf("Serves is wrong for %+v", snap)
	}
}

func TestOperations_RefusedCommandsLeaveNoTrace(t *testing.T) {
	s := newStore(t)
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("pend", "v1"), tool("live", "v1"))
	mustApprove(t, s, "alpha", "live", digestOf(t, "live", "v1"))
	mustCrawl(t, s, "alpha", tool("pend", "v2"), tool("live", "v1")) // pend: v1 superseded, v2 pending
	full := func(n string) string { return strings.Repeat(n, 64) }
	dPend1, dPend2, dLive := digestOf(t, "pend", "v1"), digestOf(t, "pend", "v2"), digestOf(t, "live", "v1")

	for name, tc := range map[string]struct {
		run  func() error
		want error
	}{
		"approve a superseded proposal":  {func() error { return s.Approve(bg, "alpha", "pend", dPend1, bob) }, lifecycle.ErrStaleVersion},
		"approve an unknown digest":      {func() error { return s.Approve(bg, "alpha", "pend", full("a"), bob) }, lifecycle.ErrUnknownVersion},
		"approve by the proposer":        {func() error { return s.Approve(bg, "alpha", "pend", dPend2, crawler) }, lifecycle.ErrSelfApproval},
		"approve an enabled tool":        {func() error { return s.Approve(bg, "alpha", "live", dLive, bob) }, lifecycle.ErrInvalidTransition},
		"reject an enabled tool":         {func() error { return s.Reject(bg, "alpha", "live", dLive, bob) }, lifecycle.ErrInvalidTransition},
		"reject a superseded proposal":   {func() error { return s.Reject(bg, "alpha", "pend", dPend1, bob) }, lifecycle.ErrStaleVersion},
		"enable an enabled tool":         {func() error { return s.Enable(bg, "alpha", "live", bob) }, lifecycle.ErrInvalidTransition},
		"roll back in pending review":    {func() error { return s.Rollback(bg, "alpha", "pend", dPend1, bob) }, lifecycle.ErrInvalidTransition},
		"roll back to the live approval": {func() error { return s.Rollback(bg, "alpha", "live", dLive, bob) }, lifecycle.ErrNotRollbackTarget},
		"short digest":                   {func() error { return s.Approve(bg, "alpha", "pend", dPend2[:8], bob) }, ErrInvalid},
		"non-hex digest":                 {func() error { return s.Approve(bg, "alpha", "pend", full("z"), bob) }, ErrInvalid},
		"empty digest":                   {func() error { return s.Reject(bg, "alpha", "pend", "", bob) }, ErrInvalid},
		"long digest":                    {func() error { return s.Rollback(bg, "alpha", "live", dLive+"0", bob) }, ErrInvalid},
		"no actor":                       {func() error { return s.Approve(bg, "alpha", "pend", dPend2, Actor{Type: ActorHuman}) }, ErrInvalid},
		"bad actor type":                 {func() error { return s.Disable(bg, "alpha", "live", Actor{Name: "bob", Type: "x"}) }, ErrInvalid},
		"unknown tool":                   {func() error { return s.Approve(bg, "alpha", "ghost", dPend2, bob) }, ErrNotFound},
		"unknown server":                 {func() error { return s.Disable(bg, "ghost", "live", bob) }, ErrNotFound},
		"injection tool name":            {func() error { return s.Enable(bg, "alpha", "x' OR '1'='1", bob) }, ErrNotFound},
	} {
		t.Run(name, func(t *testing.T) {
			before := takeTrace(t, s)
			if err := tc.run(); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want errors.Is %v", err, tc.want)
			}
			before.mustEqual(t, s, name)
		})
	}
	if stateOf(t, s, "alpha", "pend") != lifecycle.PendingReview || stateOf(t, s, "alpha", "live") != lifecycle.Enabled {
		t.Error("states changed")
	}
}

func TestReject(t *testing.T) {
	s, path := newStoreAt(t, defaultPolicyForTests())
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("new", "v1"), tool("live", "v1"))
	dLive := digestOf(t, "live", "v1")
	mustApprove(t, s, "alpha", "live", dLive)
	mustCrawl(t, s, "alpha", tool("new", "v1"), tool("live", "v2"))

	if err := s.Reject(bg, "alpha", "new", digestOf(t, "new", "v1"), bob); err != nil {
		t.Fatal(err)
	}
	if v := mustTool(t, s, "alpha", "new"); v.State != lifecycle.PendingReview || v.Pending != "" || v.Approved != "" {
		t.Errorf("rejected new tool = %+v", v)
	}
	if err := s.Reject(bg, "alpha", "live", digestOf(t, "live", "v2"), bob); err != nil {
		t.Fatal(err)
	}
	v := mustTool(t, s, "alpha", "live")
	if v.State != lifecycle.Enabled || v.Approved != dLive || v.Pending != "" || !v.Drifted {
		t.Errorf("rejected drift = %+v (the old approval stays, and strict mode still hides the drifted definition)", v)
	}
	snap, _ := s.Snapshot(bg, "alpha")
	if snap.Serves("live", digestOf(t, "live", "v2")) {
		t.Error("a rejected definition must not be served")
	}
	if n := mustCount(t, rawDB(t, path), `SELECT COUNT(*) FROM approvals WHERE decision = 'reject' AND approver = 'bob'`); n != 2 {
		t.Errorf("%d reject rows, want 2", n)
	}
	if e := entryOf(t, s, "version.rejected"); e.Detail != "digest="+digestOf(t, "live", "v2")+" state=changed_pending_reapproval->enabled" {
		t.Errorf("entry = %+v", e)
	}
}

func TestDisableAndEnable_ReReviewPolicy(t *testing.T) {
	s := newStore(t)
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("echo", "v1"))
	d := digestOf(t, "echo", "v1")
	mustApprove(t, s, "alpha", "echo", d)

	if err := s.Disable(bg, "alpha", "echo", alice); err != nil {
		t.Fatal(err)
	}
	v := mustTool(t, s, "alpha", "echo")
	if v.State != lifecycle.Disabled || v.Approved != d {
		t.Fatalf("disabled tool = %+v", v)
	}
	snap, _ := s.Snapshot(bg, "alpha")
	if snap.Serves("echo", d) || snap.Tools["echo"].State != lifecycle.Disabled {
		t.Errorf("a disabled tool is served: %+v", snap)
	}
	if list, _ := s.Approved(bg); len(list) != 0 {
		t.Errorf("Approved lists a disabled tool: %+v", list)
	}
	if err := s.Disable(bg, "alpha", "echo", alice); !errors.Is(err, lifecycle.ErrInvalidTransition) {
		t.Errorf("second Disable = %v", err)
	}

	if err := s.Enable(bg, "alpha", "echo", alice); err != nil {
		t.Fatal(err)
	}
	v = mustTool(t, s, "alpha", "echo")
	if v.State != lifecycle.PendingReview || v.Approved != "" || v.Pending != d {
		t.Fatalf("re-enabled tool = %+v: the old approval must be gone and the live definition proposed", v)
	}
	if err := s.Approve(bg, "alpha", "echo", d, alice); !errors.Is(err, lifecycle.ErrSelfApproval) {
		t.Errorf("the person who re-enabled proposed it, so cannot approve: %v", err)
	}
	mustApprove(t, s, "alpha", "echo", d)
	if v := mustTool(t, s, "alpha", "echo"); v.State != lifecycle.Enabled || v.Approved != d {
		t.Errorf("after a fresh approval = %+v", v)
	}
	if vs, _ := s.Versions(bg, "alpha", "echo"); len(vs) != 1 || vs[0].Status != lifecycle.VersionApproved {
		t.Errorf("versions = %+v", vs)
	}
}

func TestEnable_WithoutReReviewRestoresTheApproval(t *testing.T) {
	p := lifecycle.DefaultPolicy()
	p.ReEnableRequiresReview = false
	s, _ := newStoreAt(t, p)
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("echo", "v1"))
	d := digestOf(t, "echo", "v1")
	mustApprove(t, s, "alpha", "echo", d)
	if err := s.Disable(bg, "alpha", "echo", alice); err != nil {
		t.Fatal(err)
	}
	if err := s.Enable(bg, "alpha", "echo", alice); err != nil {
		t.Fatal(err)
	}
	if v := mustTool(t, s, "alpha", "echo"); v.State != lifecycle.Enabled || v.Approved != d {
		t.Errorf("tool = %+v", v)
	}
	if e := entryOf(t, s, "tool.enabled"); e.Detail != "digest=- state=disabled->enabled" || e.BeforeHash != d || e.AfterHash != d {
		t.Errorf("entry = %+v", e)
	}
}

func TestRollback(t *testing.T) {
	s, path := newStoreAt(t, defaultPolicyForTests())
	mustAddServer(t, s, "alpha")
	dA, dB, dC := digestOf(t, "echo", "A"), digestOf(t, "echo", "B"), digestOf(t, "echo", "C")
	mustCrawl(t, s, "alpha", tool("echo", "A"))
	mustApprove(t, s, "alpha", "echo", dA)
	mustCrawl(t, s, "alpha", tool("echo", "B"))
	mustApprove(t, s, "alpha", "echo", dB)
	mustCrawl(t, s, "alpha", tool("echo", "C")) // pending, never approved

	for name, digest := range map[string]string{"never approved": dC, "unknown": strings.Repeat("e", 64)} {
		if err := s.Rollback(bg, "alpha", "echo", digest, alice); err == nil {
			t.Errorf("rollback to a version that is %s succeeded", name)
		}
	}

	if err := s.Rollback(bg, "alpha", "echo", dA, alice); err != nil {
		t.Fatal(err)
	}
	v := mustTool(t, s, "alpha", "echo")
	if v.State != lifecycle.ChangedPendingReapproval || v.Approved != dA || v.Pending != dC {
		t.Fatalf("tool after rollback = %+v", v)
	}
	vs, _ := s.Versions(bg, "alpha", "echo")
	want := []lifecycle.VersionStatus{lifecycle.VersionApproved, lifecycle.VersionSuperseded, lifecycle.VersionPending}
	for i, w := range want {
		if vs[i].Status != w {
			t.Errorf("version %d status = %s, want %s", i+1, vs[i].Status, w)
		}
	}
	list, err := s.Approved(bg)
	if err != nil || len(list) != 1 || list[0].Digest != dA || list[0].ApprovedBy != "alice" {
		t.Fatalf("Approved = %+v, %v; the approver of A is now whoever rolled back to it", list, err)
	}
	if n := mustCount(t, rawDB(t, path), `SELECT COUNT(*) FROM approvals WHERE decision = 'rollback' AND hash_seen = ?`, dA); n != 1 {
		t.Errorf("%d rollback rows", n)
	}
	e := entryOf(t, s, "version.rolled_back")
	if e.BeforeHash != dB || e.AfterHash != dA || e.Detail != "digest="+dA+" state=changed_pending_reapproval->changed_pending_reapproval" {
		t.Errorf("entry = %+v", e)
	}
}

func TestResolveDigest(t *testing.T) {
	s, path := newStoreAt(t, defaultPolicyForTests())
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("echo", "v1"), tool("other", "v1"))
	d := digestOf(t, "echo", "v1")

	for _, prefix := range []string{d[:8], strings.ToUpper(d[:12]), d} {
		if got, err := s.ResolveDigest(bg, "alpha", "echo", prefix); err != nil || got != d {
			t.Errorf("ResolveDigest(%q) = %q, %v", prefix, got, err)
		}
	}
	for name, tc := range map[string]struct {
		server, tool, prefix string
		want                 error
	}{
		"too short":            {"alpha", "echo", d[:7], ErrInvalid},
		"not hex":              {"alpha", "echo", "zzzzzzzz", ErrInvalid},
		"too long":             {"alpha", "echo", d + "0", ErrInvalid},
		"percent wildcard":     {"alpha", "echo", "%%%%%%%%", ErrInvalid},
		"no match":             {"alpha", "echo", "00000000", ErrNotFound},
		"digest of other tool": {"alpha", "echo", digestOf(t, "other", "v1")[:16], ErrNotFound},
		"unknown tool":         {"alpha", "ghost", d[:8], ErrNotFound},
		"unknown server":       {"ghost", "echo", d[:8], ErrNotFound},
	} {
		if _, err := s.ResolveDigest(bg, tc.server, tc.tool, tc.prefix); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.want)
		}
	}

	// Two versions that share a prefix: forge the second row the way only a test can.
	db := rawDB(t, path)
	fake := d[:12] + strings.Repeat("0", 52)
	mustExec(t, db, `INSERT INTO tool_versions (tool_id, version_no, digest, canonical, raw, status, proposed_by, ever_approved, first_seen_at, crawl_id)
		SELECT t.id, 2, ?, x'7b7d', x'7b7d', 'superseded', 'x', 0, '2030-01-01T00:00:00.000000000Z', MAX(c.id)
		FROM tools t, crawls c WHERE t.name = 'echo'`, fake)
	if _, err := s.ResolveDigest(bg, "alpha", "echo", d[:8]); !errors.Is(err, ErrAmbiguous) {
		t.Errorf("shared prefix: %v, want ErrAmbiguous", err)
	}
	got, err := s.ResolveDigest(bg, "alpha", "echo", d[:13])
	if d[12] == '0' {
		if !errors.Is(err, ErrAmbiguous) {
			t.Errorf("13-character prefix with a shared 13th digit: %v, want ErrAmbiguous", err)
		}
	} else if err != nil || got != d {
		t.Errorf("a longer prefix must disambiguate: %q, %v", got, err)
	}
}

func TestViews_ToolsVersionsAndOrdering(t *testing.T) {
	s := newStore(t)
	mustAddServer(t, s, "beta")
	mustAddServer(t, s, "alpha")
	mustAddServer(t, s, "empty")
	mustCrawl(t, s, "beta", tool("a", "v1"))
	mustCrawl(t, s, "alpha", tool("z", "v1"), tool("b", "v1"))
	mustApprove(t, s, "alpha", "b", digestOf(t, "b", "v1"))
	mustCrawl(t, s, "alpha", tool("z", "v1"), tool("b", "v2"))

	all, err := s.Tools(bg, "")
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, v := range all {
		order = append(order, v.Server+"/"+v.Name)
	}
	if strings.Join(order, " ") != "alpha/b alpha/z beta/a" {
		t.Errorf("order = %v", order)
	}
	b := all[0]
	if b.State != lifecycle.ChangedPendingReapproval || !b.Drifted || b.Versions != 2 || b.Approved == b.Pending || b.ID <= 0 {
		t.Errorf("alpha/b = %+v", b)
	}
	if onlyAlpha, _ := s.Tools(bg, "alpha"); len(onlyAlpha) != 2 {
		t.Errorf("Tools(alpha) = %+v", onlyAlpha)
	}
	for _, server := range []string{"empty", "ghost"} {
		if list, err := s.Tools(bg, server); err != nil || list == nil || len(list) != 0 {
			t.Errorf("Tools(%q) = %#v, %v; want an empty list", server, list, err)
		}
	}
	if _, err := s.Tool(bg, "alpha", "ghost"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Tool(ghost) = %v", err)
	}
	if _, err := s.Versions(bg, "alpha", "ghost"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Versions(ghost) = %v", err)
	}
	vs, err := s.Versions(bg, "alpha", "b")
	if err != nil || len(vs) != 2 || vs[0].No != 1 || vs[1].No != 2 || vs[0].Digest != digestOf(t, "b", "v1") {
		t.Errorf("Versions = %+v, %v", vs, err)
	}
}

func TestSnapshotAndApproved_AcrossServers(t *testing.T) {
	s := newStore(t)
	if _, err := s.Snapshot(bg, "ghost"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Snapshot(ghost) = %v", err)
	}
	mustAddServer(t, s, "beta")
	mustAddServer(t, s, "alpha")
	snap, err := s.Snapshot(bg, "alpha")
	if err != nil || snap.Tools == nil || len(snap.Tools) != 0 || snap.Server != "alpha" {
		t.Errorf("empty snapshot = %+v, %v", snap, err)
	}
	mustCrawl(t, s, "beta", tool("y", "v1"), tool("x", "v1"), tool("off", "v1"))
	mustCrawl(t, s, "alpha", tool("m", "v1"), tool("pending", "v1"))
	for _, tc := range [][2]string{{"beta", "y"}, {"beta", "x"}, {"beta", "off"}, {"alpha", "m"}} {
		mustApprove(t, s, tc[0], tc[1], digestOf(t, tc[1], "v1"))
	}
	if err := s.Disable(bg, "beta", "off", alice); err != nil {
		t.Fatal(err)
	}
	mustCrawl(t, s, "beta", tool("y", "v2"), tool("x", "v1"), tool("off", "v1")) // y drifts

	list, err := s.Approved(bg)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, a := range list {
		got = append(got, a.Server+"/"+a.Name)
	}
	if strings.Join(got, " ") != "alpha/m beta/x beta/y" {
		t.Errorf("Approved = %v; want enabled and drifted tools only, by server then name", got)
	}
	betaSnap, _ := s.Snapshot(bg, "beta")
	if len(betaSnap.Tools) != 3 || betaSnap.Tools["off"].State != lifecycle.Disabled {
		t.Errorf("beta snapshot = %+v", betaSnap.Tools)
	}
	if betaSnap.Generation != mustGeneration(t, s) {
		t.Errorf("snapshot generation %d != %d", betaSnap.Generation, mustGeneration(t, s))
	}
}
