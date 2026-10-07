package catalog

import (
	"errors"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// D7 regression (reviewers' "system actors may approve"): every decision needs
// a person; the crawler identity is refused before anything is read.
func TestDecisions_RequireAHumanActor(t *testing.T) {
	s, path := newStoreAt(t, defaultPolicyForTests())
	mustAddServer(t, s, "alpha")
	if _, err := s.RecordCrawl(bg, crawlOf(tool("echo", "v1")), alice); err != nil {
		t.Fatal(err)
	}
	d := digestOf(t, "echo", "v1")
	bot := Actor{Name: "approval-bot", Type: ActorSystem}
	before := takeTrace(t, s)
	for name, err := range map[string]error{
		"approve by a bot":           s.Approve(bg, "alpha", "echo", d, bot),
		"approve by the crawler":     s.Approve(bg, "alpha", "echo", d, crawler),
		"reject by the crawler":      s.Reject(bg, "alpha", "echo", d, crawler),
		"rollback by the crawler":    s.Rollback(bg, "alpha", "echo", d, crawler),
		"disable by the crawler":     s.Disable(bg, "alpha", "echo", crawler),
		"enable by the crawler":      s.Enable(bg, "alpha", "echo", crawler),
		"pause by the crawler":       s.PauseServer(bg, "alpha", crawler),
		"resume by the crawler":      s.ResumeServer(bg, "alpha", crawler),
		"pause of an unknown server": s.PauseServer(bg, "ghost", crawler),
	} {
		if !errors.Is(err, ErrHumanRequired) {
			t.Errorf("%s: %v, want ErrHumanRequired", name, err)
		}
	}
	before.mustEqual(t, s, "refused decisions")
	if stateOf(t, s, "alpha", "echo") != lifecycle.PendingReview {
		t.Error("a system actor changed the state")
	}
	mustApprove(t, s, "alpha", "echo", d) // a person still can
	if n := mustCount(t, rawDB(t, path), `SELECT COUNT(*) FROM approvals WHERE actor_type = 'system'`); n != 0 {
		t.Errorf("%d system decisions recorded", n)
	}
}

// Reviewers' "Alice approves alice's crawl": names are normalised, so case and
// compatibility variants are one identity, and that identity is what is stored.
func TestActors_AreNormalisedBeforeStorageAndComparison(t *testing.T) {
	s := newStore(t)
	mustAddServer(t, s, "alpha")
	if _, err := s.RecordCrawl(bg, crawlOf(tool("echo", "v1")), Actor{Name: "Alice", Type: ActorHuman}); err != nil {
		t.Fatal(err)
	}
	d := digestOf(t, "echo", "v1")
	for _, twin := range []Actor{
		{Name: "alice", Type: ActorHuman}, {Name: "ALICE", Type: ActorHuman}, {Name: cp(0xFF21, 0xFF2C, 0xFF29, 0xFF23, 0xFF25), Type: ActorHuman},
	} {
		if err := s.Approve(bg, "alpha", "echo", d, twin); !errors.Is(err, lifecycle.ErrSelfApproval) {
			t.Errorf("Approve by %q of a proposal by \"Alice\": %v, want ErrSelfApproval", twin.Name, err)
		}
	}
	vs, _ := s.Versions(bg, "alpha", "echo")
	if vs[0].ProposedBy != "alice" || strings.Join(vs[0].Proposers, ",") != "alice" {
		t.Errorf("stored proposer = %q %v, want the normalised name", vs[0].ProposedBy, vs[0].Proposers)
	}
	if e := entryOf(t, s, "version.proposed"); e.Actor != "alice" {
		t.Errorf("audit actor = %q", e.Actor)
	}
	if err := s.Approve(bg, "alpha", "echo", d, Actor{Name: "Bob", Type: ActorHuman}); err != nil {
		t.Fatal(err)
	}
	list, _ := s.Approved(bg)
	if len(list) != 1 || list[0].ApprovedBy != "bob" || entryOf(t, s, "version.approved").Actor != "bob" {
		t.Errorf("approver stored as %q / %q, want bob", list[0].ApprovedBy, entryOf(t, s, "version.approved").Actor)
	}
	// The crawler's name is normalised too, and a crawl row records it so.
	if _, err := s.RecordCrawl(bg, crawlOf(tool("echo", "v1")), Actor{Name: "Crawler", Type: ActorSystem}); err != nil {
		t.Fatal(err)
	}
	if e := entryOf(t, s, "crawl.completed"); e.Actor != "crawler" || e.ActorType != "system" {
		t.Errorf("crawl entry actor = %q %q", e.Actor, e.ActorType)
	}
}

// Reviewers' "proposed_by overwritten by a re-proposal": the whole proposer
// history is stored, survives a reopen, and every proposer is refused.
func TestProposers_ArePersistedAndEveryOneIsRefused(t *testing.T) {
	s, path := newStoreAt(t, defaultPolicyForTests())
	mustAddServer(t, s, "alpha")
	dA := digestOf(t, "echo", "A")
	for _, step := range []struct {
		by      Actor
		variant string
	}{{alice, "A"}, {bob, "B"}, {bob, "A"}} {
		if _, err := s.RecordCrawl(bg, crawlOf(tool("echo", step.variant)), step.by); err != nil {
			t.Fatal(err)
		}
	}
	_ = s.Close()
	s = openStore(t, path, defaultPolicyForTests())

	vs, err := s.Versions(bg, "alpha", "echo")
	if err != nil || len(vs) != 2 {
		t.Fatalf("Versions = %+v, %v", vs, err)
	}
	if vs[0].Digest != dA || vs[0].ProposedBy != "alice" || strings.Join(vs[0].Proposers, ",") != "alice,bob" || vs[0].Status != lifecycle.VersionPending {
		t.Errorf("version A = %+v", vs[0])
	}
	if strings.Join(vs[1].Proposers, ",") != "bob" || vs[1].Status != lifecycle.VersionSuperseded {
		t.Errorf("version B = %+v", vs[1])
	}
	for _, proposer := range []Actor{alice, bob} {
		if err := s.Approve(bg, "alpha", "echo", dA, proposer); !errors.Is(err, lifecycle.ErrSelfApproval) {
			t.Errorf("Approve by proposer %s: %v, want ErrSelfApproval", proposer.Name, err)
		}
	}
	if err := s.Approve(bg, "alpha", "echo", dA, carol); err != nil {
		t.Fatalf("Approve by a third person: %v", err)
	}
	db := rawDB(t, path)
	rows, err := db.QueryContext(bg, `SELECT p.position, p.actor FROM tool_version_proposers p JOIN tool_versions v ON v.id = p.version_id
		WHERE v.digest = ? ORDER BY p.position`, dA)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var stored []string
	for rows.Next() {
		var pos int
		var actor string
		if err := rows.Scan(&pos, &actor); err != nil {
			t.Fatal(err)
		}
		stored = append(stored, itoa(int64(pos))+":"+actor)
	}
	if strings.Join(stored, " ") != "0:alice 1:bob" {
		t.Errorf("proposer rows = %v", stored)
	}
	// Proposers are also loaded into the lifecycle for crawls: carol's crawl
	// of B re-proposes it and appends her.
	if _, err := s.RecordCrawl(bg, crawlOf(tool("echo", "B")), carol); err != nil {
		t.Fatal(err)
	}
	vs, _ = s.Versions(bg, "alpha", "echo")
	if strings.Join(vs[1].Proposers, ",") != "bob,carol" {
		t.Errorf("B after carol's re-proposal = %v", vs[1].Proposers)
	}
}

// D9: pausing a server stops crawls and serving while decisions keep working.
func TestPauseAndResumeServer(t *testing.T) {
	s := newStore(t)
	mustAddServer(t, s, "alpha")
	mustAddServer(t, s, "beta")
	dA := digestOf(t, "echo", "A")
	mustCrawl(t, s, "alpha", tool("echo", "A"), tool("other", "x"))
	mustApprove(t, s, "alpha", "echo", dA)
	mustCrawl(t, s, "beta", tool("b", "x"))
	crawledAt := mustSnapshot(t, s, "alpha").CrawledAt

	if err := s.PauseServer(bg, "alpha", alice); err != nil {
		t.Fatal(err)
	}
	srv, err := s.Server(bg, "alpha")
	if err != nil || !srv.Paused {
		t.Fatalf("Server = %+v, %v", srv, err)
	}
	snap := mustSnapshot(t, s, "alpha")
	if len(snap.Tools) != 0 || snap.Serves("echo", dA) || !snap.CrawledAt.Equal(crawledAt) {
		t.Errorf("paused snapshot = %+v; nothing may be served", snap)
	}
	if len(mustSnapshot(t, s, "beta").Tools) != 1 {
		t.Error("pausing alpha touched beta")
	}
	before := takeTrace(t, s)
	if _, err := s.RecordCrawl(bg, crawlOf(tool("echo", "B")), crawler); !errors.Is(err, ErrPaused) {
		t.Errorf("RecordCrawl of a paused server: %v, want ErrPaused", err)
	}
	if _, err := s.RecordCrawl(bg, CrawlInput{Server: "alpha", Error: "down"}, crawler); !errors.Is(err, ErrPaused) {
		t.Errorf("failed crawl of a paused server: %v, want ErrPaused", err)
	}
	before.mustEqual(t, s, "crawl of a paused server")
	if err := s.PauseServer(bg, "alpha", alice); !errors.Is(err, ErrInvalid) {
		t.Errorf("second pause: %v, want ErrInvalid", err)
	}
	if err := s.ResumeServer(bg, "beta", alice); !errors.Is(err, ErrInvalid) {
		t.Errorf("resume of a running server: %v, want ErrInvalid", err)
	}
	if err := s.PauseServer(bg, "ghost", alice); !errors.Is(err, ErrNotFound) {
		t.Errorf("pause of an unknown server: %v, want ErrNotFound", err)
	}
	// Decisions and views keep working.
	if err := s.Disable(bg, "alpha", "other", alice); err != nil {
		t.Errorf("Disable while paused: %v", err)
	}
	if list, _ := s.Tools(bg, "alpha"); len(list) != 2 {
		t.Errorf("Tools while paused = %+v", list)
	}
	if list, _ := s.Approved(bg); len(list) != 1 || list[0].Name != "echo" {
		t.Errorf("Approved while paused = %+v; the export describes approvals, not serving", list)
	}
	e := entryOf(t, s, "server.paused")
	if e.Subject != "alpha" || e.Actor != "alice" || e.Detail != "paused=true" {
		t.Errorf("server.paused entry = %+v", e)
	}

	if err := s.ResumeServer(bg, "alpha", bob); err != nil {
		t.Fatal(err)
	}
	if snap := mustSnapshot(t, s, "alpha"); !snap.Serves("echo", dA) || len(snap.Tools) != 2 {
		t.Errorf("snapshot after resume = %+v", snap)
	}
	if srv, _ := s.Server(bg, "alpha"); srv.Paused {
		t.Error("still paused after resume")
	}
	if e := entryOf(t, s, "server.resumed"); e.Subject != "alpha" || e.Actor != "bob" || e.Detail != "paused=false" {
		t.Errorf("server.resumed entry = %+v", e)
	}
	mustCrawl(t, s, "alpha", tool("echo", "A"), tool("other", "x"))
	if _, err := s.VerifyAudit(bg); err != nil {
		t.Fatal(err)
	}
}
