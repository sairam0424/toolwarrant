package catalog

import (
	"errors"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// The fourth hostile review's launderings of the proposer rule (D14 c): a
// deleted tool row, a rewritten proposer history, a rejected version put back
// to pending. The tools table now refuses deletes, and Integrity reconstructs
// every version's status and proposers from the log and reports every row the
// history describes that is gone.

// A plain DELETE on tools is refused by the new guard, foreign keys on or off.
// With the guard dropped and re-created around the delete, the orphaned
// versions and the subject without a row are reported, and the crawl that
// discovers the name afresh leaves a second tool.discovered that is reported
// too; alice's approval of her own bytes then goes through the serving path,
// which is the limit D14 states, with Integrity naming the laundering.
func TestIntegrity_DeletedToolRowIsRefusedAndReported(t *testing.T) {
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	mustAddServer(t, s, "alpha")
	if _, err := s.RecordCrawl(bg, crawlOf(tool("echo", "v1"), tool("zeta", "v1")), alice); err != nil {
		t.Fatal(err)
	}
	d1 := digestOf(t, "echo", "v1")
	if err := s.Approve(bg, "alpha", "echo", d1, alice); !errors.Is(err, lifecycle.ErrSelfApproval) {
		t.Fatalf("precondition: Approve by the proposer = %v, want ErrSelfApproval", err)
	}
	mustBeClean(t, s, "before the deletion")
	for name, exec := range map[string]func() error{
		"foreign keys on": func() error {
			_, err := rawDB(t, path).ExecContext(bg, `DELETE FROM tools WHERE name = 'echo'`)
			return err
		},
		"foreign keys off": func() error {
			_, err := rawDBNoFK(t, path).ExecContext(bg, `DELETE FROM tools WHERE name = 'echo'`)
			return err
		},
	} {
		if err := exec(); err == nil || !strings.Contains(err.Error(), "tools are never deleted") {
			t.Fatalf("DELETE FROM tools with %s = %v, want the guard's refusal", name, err)
		}
	}

	db := rawDBNoFK(t, path)
	guard := triggerDDL(t, db, "tools_no_delete")
	mustExec(t, db, `DROP TRIGGER tools_no_delete`)
	mustExec(t, db, `DELETE FROM tools WHERE name = 'echo'`)
	mustExec(t, db, guard)
	rep := mustIntegrity(t, s)
	if rep.RowsMissing != 3 {
		t.Errorf("Integrity after the deletion = %+v, want the subject without a row, the proposed version without a row and the orphaned version row counted", rep)
	}
	problemMentioning(t, rep, `"alpha/echo"`, "no tools row exists")
	problemMentioning(t, rep, `"alpha/echo"`, "proposed digest "+d1, "no tool_versions row exists")
	problemMentioning(t, rep, "belongs to tool row", "which does not exist")

	rep2 := mustCrawl(t, s, "alpha", tool("echo", "v1"), tool("zeta", "v1"))
	if kindsOf(rep2)["echo"] != ChangeNew {
		t.Fatalf("crawl after the deletion = %+v, want echo discovered afresh", rep2.Changes)
	}
	// The fresh row's version carries the crawler alone while the verified
	// version.proposed entries about the digest name alice first, so the
	// decision path refuses the laundered list (D15 b) and Integrity names it.
	if err := s.Approve(bg, "alpha", "echo", d1, alice); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "proposer history was rewritten") {
		t.Fatalf("Approve after the laundering = %v, want ErrCorrupt naming the proposers", err)
	}
	rep = mustIntegrity(t, s)
	if rep.DiscoveryMismatches != 1 || rep.RowsMissing != 1 || rep.ProposerMismatches != 1 {
		t.Errorf("Integrity after the re-discovery = %+v, want the second tool.discovered, the orphaned version row and the proposer mismatch", rep)
	}
	problemMentioning(t, rep, "discovers tool", `"alpha/echo"`, "a second time")
	problemMentioning(t, rep, `proposers are ["crawler"]`, `name ["alice" "crawler"]`)
}

// The proposer history rewritten under re-created guards (proposers_no_update
// and tool_versions_immutable dropped, actor and proposed_by set to the
// crawler, both triggers re-created byte for byte): Integrity compares the
// proposer list with the actors of the version.proposed entries and names the
// rewrite, before and after alice approves her own bytes.
func TestIntegrity_ProposerHistoryRewrittenUnderRecreatedGuardsIsReported(t *testing.T) {
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	mustAddServer(t, s, "alpha")
	if _, err := s.RecordCrawl(bg, crawlOf(tool("echo", "v1")), alice); err != nil {
		t.Fatal(err)
	}
	d1 := digestOf(t, "echo", "v1")
	if err := s.Approve(bg, "alpha", "echo", d1, alice); !errors.Is(err, lifecycle.ErrSelfApproval) {
		t.Fatalf("precondition: Approve by the proposer = %v, want ErrSelfApproval", err)
	}
	db := rawDB(t, path)
	proposersGuard, versionsGuard := triggerDDL(t, db, "proposers_no_update"), triggerDDL(t, db, "tool_versions_immutable")
	mustExec(t, db, `DROP TRIGGER proposers_no_update`)
	mustExec(t, db, `DROP TRIGGER tool_versions_immutable`)
	mustExec(t, db, `UPDATE tool_version_proposers SET actor = 'crawler' WHERE actor = 'alice'`)
	mustExec(t, db, `UPDATE tool_versions SET proposed_by = 'crawler' WHERE proposed_by = 'alice'`)
	mustExec(t, db, proposersGuard)
	mustExec(t, db, versionsGuard)

	rep := mustIntegrity(t, s)
	if rep.ProposerMismatches != 1 {
		t.Errorf("Integrity after the rewrite = %+v, want the proposer mismatch", rep)
	}
	problemMentioning(t, rep, `"alpha/echo"`, `proposers are ["crawler"]`, `name ["alice"]`)
	// D15 (b): the decision reads the proposers from the verified chain, so the
	// rewritten table is refused rather than laundering alice's approval.
	if err := s.Approve(bg, "alpha", "echo", d1, alice); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "proposer history was rewritten") {
		t.Fatalf("Approve after the rewrite = %v, want ErrCorrupt naming the proposers", err)
	}
	if rep := mustIntegrity(t, s); rep.ProposerMismatches != 1 {
		t.Errorf("Integrity after the refused approval = %+v, want the proposer mismatch still reported", rep)
	}
}

// A rejected version put back to pending by one UPDATE: the status differs
// from what the log leaves behind, and the decision path refuses the flipped
// column instead of approving the resurrected version (D17 a; until the
// seventh round a second person could approve it, the D14 residual). The
// impossible edge, version.rejected then version.approved with no proposal
// between, is still reported when a forger with write access appends the
// approval entry to the log itself.
func TestIntegrity_RejectedVersionFlippedToPendingIsReported(t *testing.T) {
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("echo", "v1"))
	d1 := digestOf(t, "echo", "v1")
	if err := s.Reject(bg, "alpha", "echo", d1, bob); err != nil {
		t.Fatal(err)
	}
	mustBeClean(t, s, "after the reject")
	db := rawDB(t, path)
	mustExec(t, db, `UPDATE tool_versions SET status = 'pending' WHERE digest = ?`, d1)
	rep := mustIntegrity(t, s)
	if rep.VersionStatusMismatches != 1 {
		t.Errorf("Integrity after the flip = %+v, want the status mismatch", rep)
	}
	problemMentioning(t, rep, `"alpha/echo"`, `status is "pending"`, "leaves it rejected")

	err := s.Approve(bg, "alpha", "echo", d1, bob)
	if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "leave it rejected") {
		t.Fatalf("Approve of the resurrected version = %v, want ErrCorrupt naming the status the verified entries leave", err)
	}
	appendSealed(t, db, audit.Entry{TS: forgedTS, Actor: "mallory", ActorType: string(ActorHuman), Event: string(lifecycle.EvApproved),
		Subject: "alpha/echo", AfterHash: d1, Detail: "digest=" + d1 + " state=pending_review->enabled last_seen=" + d1 + " proposals=1->0"})
	rep = mustIntegrity(t, s)
	problemMentioning(t, rep, "version.approved of digest "+d1, "from status rejected", "the lifecycle never does")
	// Superseded instead of pending lets the next sighting re-propose the
	// rejected digest; the same pass reports it.
	mustExec(t, db, `UPDATE tool_versions SET status = 'superseded' WHERE digest = ?`, d1)
	problemMentioning(t, mustIntegrity(t, s), `status is "superseded"`)
}

// Integrity accepts every proposer history the Store writes: a crawl by a
// person, a re-proposal by another crawler, an Enable that re-proposes without
// adding anybody, and a reappearance.
func TestIntegrity_ProposerAndStatusReconstructionAcceptsStoreWrittenHistory(t *testing.T) {
	p := lifecycle.DefaultPolicy()
	s, _ := newStoreAt(t, p)
	mustAddServer(t, s, "alpha")
	if _, err := s.RecordCrawl(bg, crawlOf(tool("echo", "v1")), alice); err != nil {
		t.Fatal(err)
	}
	mustCrawl(t, s, "alpha", tool("echo", "v2"))
	mustCrawl(t, s, "alpha", tool("echo", "v1")) // v1 proposed again, by the crawler
	d1 := digestOf(t, "echo", "v1")
	mustApprove(t, s, "alpha", "echo", d1)
	if err := s.Disable(bg, "alpha", "echo", alice); err != nil {
		t.Fatal(err)
	}
	if err := s.Enable(bg, "alpha", "echo", carol); err != nil { // re-proposes v1, carol joins nobody
		t.Fatal(err)
	}
	vs, err := s.Versions(bg, "alpha", "echo")
	if err != nil || len(vs) != 2 || strings.Join(vs[0].Proposers, ",") != "alice,crawler" || vs[0].Status != lifecycle.VersionPending {
		t.Fatalf("Versions = %+v, %v", vs, err)
	}
	for i := 0; i < p.DeprecateAfter; i++ {
		mustCrawl(t, s, "alpha")
	}
	if _, err := s.RecordCrawl(bg, crawlOf(tool("echo", "v1")), bob); err != nil { // reappears on v1, bob joins
		t.Fatal(err)
	}
	mustBeClean(t, s, "after the whole history")
	if vs, err := s.Versions(bg, "alpha", "echo"); err != nil || strings.Join(vs[0].Proposers, ",") != "alice,crawler,bob" {
		t.Fatalf("Versions after the reappearance = %+v, %v", vs, err)
	}
}

// A version row the log never proposed, and a version the log proposed whose
// row is gone, are both reported.
func TestIntegrity_RowsTheLogDoesNotDescribeAreReported(t *testing.T) {
	t.Run("planted version", func(t *testing.T) {
		s, path := newStoreAt(t, lifecycle.DefaultPolicy())
		d1 := approvedEcho(t, s)
		db := rawDB(t, path)
		mustExec(t, db, `INSERT INTO tool_versions (tool_id, version_no, digest, digest_profile, canonical, raw, status, proposed_by, ever_approved, first_seen_at, crawl_id)
			SELECT tool_id, 2, ?, digest_profile, canonical, raw, 'superseded', 'mallory', 0, first_seen_at, crawl_id FROM tool_versions WHERE digest = ?`,
			strings.Repeat("ab", 32), d1)
		mustExec(t, db, `INSERT INTO tool_version_proposers (version_id, position, actor) SELECT id, 0, 'mallory' FROM tool_versions WHERE version_no = 2`)
		rep := mustIntegrity(t, s)
		if rep.VersionStatusMismatches != 1 || rep.ProposerMismatches != 0 || rep.RowsMissing != 0 {
			t.Errorf("Integrity with a planted version = %+v", rep)
		}
		problemMentioning(t, rep, "version 2 of tool", "never proposed digest "+strings.Repeat("ab", 32))
	})
	t.Run("version rows gone", func(t *testing.T) {
		s, path := newStoreAt(t, lifecycle.DefaultPolicy())
		mustAddServer(t, s, "alpha")
		mustCrawl(t, s, "alpha", tool("echo", "v1"))
		d1 := digestOf(t, "echo", "v1")
		db := rawDBNoFK(t, path)
		mustExec(t, db, `DROP TRIGGER tool_versions_no_delete`)
		mustExec(t, db, `DROP TRIGGER proposers_no_delete`)
		mustExec(t, db, `DELETE FROM tool_version_proposers`)
		mustExec(t, db, `DELETE FROM tool_versions`)
		restoreGuard(t, db, "tool_versions_no_delete")
		restoreGuard(t, db, "proposers_no_delete")
		rep := mustIntegrity(t, s)
		if rep.RowsMissing != 1 {
			t.Errorf("Integrity with the version rows gone = %+v, want the proposed version without a row", rep)
		}
		problemMentioning(t, rep, `"alpha/echo"`, "proposed digest "+d1, "no tool_versions row exists")
	})
}
