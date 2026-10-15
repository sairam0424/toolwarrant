package catalog

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sairam0424/toolwarrant/internal/gate"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

func TestViews_ToolsVersionsAndOrdering(t *testing.T) {
	t.Parallel()
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
	if b.State != lifecycle.ChangedPendingReapproval || !b.Drifted || b.Versions != 2 || b.Approved == b.Pending || b.ID <= 0 || b.Unusable {
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
	for _, v := range vs {
		if v.DigestProfile != gate.DigestProfile || len(v.Proposers) != 1 || v.Proposers[0] != "crawler" || v.ProposedBy != "crawler" {
			t.Errorf("version %d = profile %q proposers %v by %q", v.No, v.DigestProfile, v.Proposers, v.ProposedBy)
		}
	}
}

func TestSnapshotAndApproved_AcrossServers(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	if _, err := s.Snapshot(bg, "ghost"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Snapshot(ghost) = %v", err)
	}
	mustAddServer(t, s, "beta")
	mustAddServer(t, s, "alpha")
	snap, err := s.Snapshot(bg, "alpha")
	if err != nil || snap.Tools == nil || len(snap.Tools) != 0 || snap.Server != "alpha" || !snap.CrawledAt.IsZero() {
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
	betaSnap := mustSnapshot(t, s, "beta")
	if len(betaSnap.Tools) != 3 || betaSnap.Tools["off"].State != lifecycle.Disabled {
		t.Errorf("beta snapshot = %+v", betaSnap.Tools)
	}
	if betaSnap.Generation != mustGeneration(t, s) {
		t.Errorf("snapshot generation %d != %d", betaSnap.Generation, mustGeneration(t, s))
	}
	if betaSnap.CrawledAt.IsZero() || betaSnap.CrawledAt.Location() != time.UTC ||
		betaSnap.CrawledAt.After(time.Now().Add(time.Second)) {
		t.Errorf("CrawledAt = %v", betaSnap.CrawledAt)
	}
}
