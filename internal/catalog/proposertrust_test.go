package catalog

import (
	"errors"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// The fifth review's probe 2 (D15 b): alice's crawl proposed echo, so her
// approval is ErrSelfApproval; the forger rewrites the proposers table and
// proposed_by to the crawler under re-created guards and rewrites every entry
// alice wrote about the tool in place, each re-sealed from its real
// predecessor, so Integrity's reconstruction from the log agreed with the
// table and alice approved her own bytes. Now the decision reads the
// version.proposed entries through the chain the Store verified: the rewritten
// entries hash to other values than the walk recorded, so Approve is
// ErrCorrupt, Versions shows no laundered history, Integrity reports the link
// the rewrite broke, and a fresh Store refuses the file at open.
func TestApprove_ProposerLaunderedByInPlaceRewriteIsCorrupt(t *testing.T) {
	t.Parallel()
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	mustAddServer(t, s, "alpha")
	if _, err := s.RecordCrawl(bg, crawlFor("alpha", tool("echo", "v1")), alice); err != nil {
		t.Fatal(err)
	}
	d1 := digestOf(t, "echo", "v1")
	if err := s.Approve(bg, "alpha", "echo", d1, alice); !errors.Is(err, lifecycle.ErrSelfApproval) {
		t.Fatalf("Approve by the proposer before the forgery = %v, want ErrSelfApproval", err)
	}
	mustCrawl(t, s, "alpha", tool("echo", "v1"), tool("sum", "v1")) // the proposal entries sit below the head
	if _, err := s.Versions(bg, "alpha", "echo"); err != nil {
		t.Fatal(err)
	}
	mustBeClean(t, s, "before the forgery")
	recorded, err := s.VerifyAudit(bg)
	if err != nil {
		t.Fatal(err)
	}

	db := rawDB(t, path)
	entries := rawEntries(t, db)
	guards := []string{"proposers_no_update", "audit_log_no_update", "tool_versions_immutable"}
	ddl := map[string]string{}
	for _, name := range guards {
		ddl[name] = triggerDDL(t, db, name)
		mustExec(t, db, `DROP TRIGGER `+name)
	}
	mustExec(t, db, `UPDATE tool_version_proposers SET actor = 'crawler' WHERE actor = 'alice'`)
	mustExec(t, db, `UPDATE tool_versions SET proposed_by = 'crawler' WHERE proposed_by = 'alice'`)
	rewritten := 0
	for i, e := range entries {
		if e.Actor != "alice" || !strings.HasPrefix(e.Subject, "alpha/") {
			continue
		}
		prev := audit.Entry{}
		if i > 0 {
			prev = entries[i-1]
		}
		forged := e
		forged.Actor, forged.ActorType = "crawler", string(ActorSystem)
		if forged, err = audit.Seal(prev, forged); err != nil {
			t.Fatal(err)
		}
		entries[i] = forged
		mustExec(t, db, `UPDATE audit_log SET actor = ?, actor_type = ?, prev_hash = ?, hash = ? WHERE seq = ?`,
			forged.Actor, forged.ActorType, forged.PrevHash, forged.Hash, forged.Seq)
		rewritten++
	}
	if rewritten == 0 {
		t.Fatal("test setup: no entry by alice about the tool was rewritten")
	}
	for _, name := range guards {
		mustExec(t, db, ddl[name])
	}
	mustExec(t, db, `UPDATE meta SET value = value + 1 WHERE key = 'generation'`)
	if after := rawEntries(t, db); audit.Head(after) != recorded.Head {
		t.Fatal("test setup: the head must be unchanged")
	}

	err = s.Approve(bg, "alpha", "echo", d1, alice)
	if !errors.Is(err, ErrCorrupt) && !errors.Is(err, lifecycle.ErrSelfApproval) {
		t.Fatalf("Approve by alice after the laundering = %v, want ErrCorrupt or ErrSelfApproval", err)
	}
	if !strings.Contains(err.Error(), "is not the entry this store verified") {
		t.Errorf("Approve = %v, want the rewritten proposal entry named", err)
	}
	// The serving path reads the newest entry about the tool for its state
	// (D17 c, extended), so the laundered entry is refused there too instead
	// of the tool being quietly left unserved.
	if _, err := s.Snapshot(bg, "alpha"); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "is not the entry this store verified") {
		t.Errorf("Snapshot after the laundering = %v, want ErrCorrupt naming the rewritten entry", err)
	}
	if _, err := s.Versions(bg, "alpha", "echo"); !errors.Is(err, ErrCorrupt) {
		t.Errorf("Versions after the laundering = %v, want ErrCorrupt rather than the laundered history", err)
	}
	rep := mustIntegrity(t, s)
	if rep.ChainBreaks == 0 {
		t.Errorf("Integrity after the laundering = %+v, want the broken link reported", rep)
	}
	problemMentioning(t, rep, "does not continue the chain from entry")
	for name, opts := range map[string]OpenOptions{"read-only": {ReadOnly: true}, "read-write": {Policy: lifecycle.DefaultPolicy()}} {
		s2, err := OpenWith(path, opts)
		if s2 != nil {
			_ = s2.Close()
		}
		if !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s Open after the laundering = %v, want ErrCorrupt: the chain the walk verifies is broken", name, err)
		}
	}
}

// The chain memory is shared by nothing: a decision on one handle trusts the
// entries another handle appended, because every write transaction first
// extends its own memory to the head of the file. No Store-written history is
// refused.
func TestDecisions_TrustEntriesAnotherHandleAppended(t *testing.T) {
	t.Parallel()
	path := dbPath(t)
	a := openStore(t, path, lifecycle.DefaultPolicy())
	b := openStore(t, path, lifecycle.DefaultPolicy())
	mustAddServer(t, a, "alpha")
	if _, err := a.RecordCrawl(bg, crawlFor("alpha", tool("echo", "v1")), alice); err != nil {
		t.Fatal(err)
	}
	d1 := digestOf(t, "echo", "v1")
	if err := b.Approve(bg, "alpha", "echo", d1, alice); !errors.Is(err, lifecycle.ErrSelfApproval) {
		t.Errorf("Approve by the proposer on the other handle = %v, want ErrSelfApproval from the verified proposer list", err)
	}
	mustApprove(t, a, "alpha", "echo", d1)
	if err := b.Disable(bg, "alpha", "echo", carol); err != nil {
		t.Fatalf("Disable on the other handle = %v", err)
	}
	if err := a.Enable(bg, "alpha", "echo", carol); err != nil {
		t.Fatalf("Enable after the other handle's disable = %v", err)
	}
	mustCrawl(t, b, "alpha", tool("echo", "v2"))
	if err := a.Approve(bg, "alpha", "echo", digestOf(t, "echo", "v2"), bob); err != nil {
		t.Fatalf("Approve of a version the other handle proposed = %v", err)
	}
	if err := b.Rollback(bg, "alpha", "echo", d1, carol); err != nil {
		t.Fatalf("Rollback on the other handle = %v", err)
	}
	for _, st := range []*Store{a, b} {
		for name, err := range allPaths(st, "alpha", "echo") {
			if err != nil {
				t.Errorf("%s = %v", name, err)
			}
		}
		mustBeClean(t, st, "after decisions on two handles")
	}
}
