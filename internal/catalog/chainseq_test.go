package catalog

import (
	"database/sql"
	"errors"
	"math"
	"slices"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// The seventh hostile review's probes against the walks (D17 d) and the
// statement of the pin's limit (D17 k). Every walk started at seq > 0, so an
// entry stored at seq 0 or below was read by nothing that verified or listed
// the log while the decision path read it and refused every decision on the
// tool for good, with audit verify reporting integrity ok. Every walk now
// starts below the smallest seq SQLite can store.

// plantEntryBelowOne stores a version.proposed entry about alpha/echo at a seq
// the catalog never writes, as a forger who drops and re-creates
// audit_log_sequential does; the entry is sealed from the genesis, so only its
// sequence number betrays it.
func plantEntryBelowOne(t *testing.T, db *sql.DB, seq int64, digest string) {
	t.Helper()
	ddl := triggerDDL(t, db, "audit_log_sequential")
	mustExec(t, db, `DROP TRIGGER audit_log_sequential`)
	e := audit.Entry{Seq: seq, TS: forgedTS, Actor: "mallory", ActorType: string(ActorHuman), Event: string(lifecycle.EvProposed),
		Subject: "alpha/echo", Detail: "digest=" + digest + " state=discovered->pending_review last_seen=" + digest + " proposals=0->1", PrevHash: audit.Genesis}
	h, err := audit.HashOf(e)
	if err != nil {
		// HashOf refuses a seq the chain can never hold; a forger writes any
		// 64 hex characters, and so does this helper.
		h = strings.Repeat("ab", 32)
	}
	e.Hash = h
	mustExec(t, db, insertAudit, e.Seq, e.TS, e.Actor, e.ActorType, e.Event, e.Subject, e.BeforeHash, e.AfterHash, e.Detail, e.PrevHash, e.Hash)
	mustExec(t, db, ddl)
	mustExec(t, db, `UPDATE meta SET value = value + 1 WHERE key = 'generation'`)
}

// wantBreakAt requires a VerifyAudit error to be the chain break at seq with
// the reason a row below the first can only have.
func wantBreakAt(t *testing.T, what string, err error, seq int64) {
	t.Helper()
	var broken *audit.BrokenError
	if !errors.As(err, &broken) || broken.Seq != seq || !strings.Contains(broken.Reason, "expected seq 1") {
		t.Errorf("%s = %v, want the chain broken at seq %d (expected seq 1)", what, err, seq)
	}
}

// A row at seq 0 or below is a chain break on every walk: VerifyAudit reports
// it, Integrity reports it and counts the rows, the listing shows it, every
// read and decision refuses the file naming it, a fresh open refuses the file,
// and a forensic open can still inspect it. Removing the row restores the log.
func TestAudit_RowBelowSeqOneIsAChainBreakOnEveryWalk(t *testing.T) {
	for _, seq := range []int64{0, -7, math.MinInt64} {
		t.Run("seq "+itoa(seq), func(t *testing.T) {
			s, path := newStoreAt(t, lifecycle.DefaultPolicy())
			d1 := approvedEcho(t, s)
			recorded, err := s.VerifyAudit(bg)
			if err != nil {
				t.Fatal(err)
			}
			db := rawDB(t, path)
			plantEntryBelowOne(t, db, seq, d1)

			_, err = s.VerifyAudit(bg)
			wantBreakAt(t, "VerifyAudit", err, seq)
			rep := mustIntegrity(t, s)
			if rep.ChainBreaks != 1 {
				t.Errorf("Integrity.ChainBreaks = %d, want 1; %q", rep.ChainBreaks, rep.Problems)
			}
			problemMentioning(t, rep, "audit entry "+itoa(seq), "sequence number below 1")
			listed, err := s.AuditEntries(bg, 0, 0)
			if err != nil || len(listed) != recorded.Entries+1 || listed[0].Seq != seq {
				t.Errorf("AuditEntries(0, 0) = %d entries, first seq %d, %v; want %d entries starting at %d", len(listed), listed[0].Seq, err, recorded.Entries+1, seq)
			}
			const cause = "audit_log holds a row whose seq is below 1"
			for name, err := range allPaths(s, "alpha", "echo") {
				if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), cause) {
					t.Errorf("%s = %v, want ErrCorrupt naming the row below seq 1", name, err)
				}
			}
			if err := s.Disable(bg, "alpha", "echo", alice); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), cause) {
				t.Errorf("Disable = %v, want ErrCorrupt naming the row below seq 1", err)
			}
			for label, opts := range map[string]OpenOptions{"read-only": {ReadOnly: true}, "read-write": {Policy: lifecycle.DefaultPolicy()}} {
				fresh, err := OpenWith(path, opts)
				if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "does not form one chain from its first entry") {
					t.Errorf("%s Open = %v, want ErrCorrupt naming the broken chain", label, err)
				}
				if err == nil {
					_ = fresh.Close()
				}
			}
			forensicShowsTheRow(t, path, seq, recorded.Entries+1)

			mustExec(t, db, `DROP TRIGGER audit_log_no_delete`)
			mustExec(t, db, `DELETE FROM audit_log WHERE seq = ?`, seq)
			restoreGuard(t, db, "audit_log_no_delete")
			if after, err := s.VerifyAudit(bg); err != nil || after != recorded {
				t.Errorf("VerifyAudit after the repair = %+v, %v; want %+v", after, err, recorded)
			}
			if err := s.Disable(bg, "alpha", "echo", alice); err != nil {
				t.Errorf("Disable after the repair = %v", err)
			}
			mustBeClean(t, s, "after the repair")
		})
	}
}

// forensicShowsTheRow requires a forensic open to list the row below seq 1,
// to report the break and to count it.
func forensicShowsTheRow(t *testing.T, path string, seq int64, rows int) {
	t.Helper()
	f, err := OpenWith(path, OpenOptions{Forensic: true})
	if err != nil {
		t.Fatalf("forensic Open = %v", err)
	}
	defer func() { _ = f.Close() }()
	_, err = f.VerifyAudit(bg)
	wantBreakAt(t, "forensic VerifyAudit", err, seq)
	listed, err := f.AuditEntries(bg, 0, 0)
	if err != nil || len(listed) != rows || !slices.ContainsFunc(listed, func(e audit.Entry) bool { return e.Seq == seq }) {
		t.Errorf("forensic AuditEntries(0, 0) = %d entries, %v; want %d with seq %d among them", len(listed), err, rows, seq)
	}
	if rep := mustIntegrity(t, f); rep.ChainBreaks != 1 {
		t.Errorf("forensic Integrity.ChainBreaks = %d, want 1; %q", rep.ChainBreaks, rep.Problems)
	}
}

// The limit of the pin, as the code has it (D17 k): with no Store open (the
// CLI between commands, the processors during the ErrCorrupt procedure) a
// forger rewrites one approval and every entry about the tool that names the
// benign digest, re-chains from the first of them and leaves everything before
// it byte for byte as it was. A fresh read-only and a fresh read-write Store
// serve the poison, VerifyAudit is clean with the same count and Integrity
// reports nothing; only the recorded head differs. Nothing in the file catches
// a rewrite made while no Store holds a pin, so the documents must not say
// that only a chain rewritten completely is caught by the recorded head alone.
func TestOpen_SuffixRewrittenWhileNoStoreHeldAPinIsCaughtByTheRecordedHeadAlone(t *testing.T) {
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	mustAddServer(t, s, "beta") // another server's whole history comes first in the log
	mustCrawl(t, s, "beta", tool("sum", "v1"))
	mustApprove(t, s, "beta", "sum", digestOf(t, "sum", "v1"))
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("echo", "benign"))
	benign := digestOf(t, "echo", "benign")
	mustApprove(t, s, "alpha", "echo", benign)
	mustCrawl(t, s, "alpha", tool("echo", "benign"), tool("other", "v1"))
	mustBeClean(t, s, "before the forgery")
	recorded, err := s.VerifyAudit(bg)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close() // nothing holds a pin

	db := rawDB(t, path)
	entries := rawEntries(t, db)
	p := poisonedEcho(t)
	approval := newestApprovalEntry(t, entries, "alpha/echo")
	rewriteApprovalInPlace(t, db, entries, approval, benign, p, true)
	first := approval.Seq
	mustExec(t, db, `DROP TRIGGER audit_log_no_update`)
	for _, e := range entries {
		if e.Subject != "alpha/echo" || e.Seq == approval.Seq || !strings.Contains(e.Detail, benign) {
			continue
		}
		mustExec(t, db, `UPDATE audit_log SET detail = ? WHERE seq = ?`, strings.ReplaceAll(e.Detail, benign, p.digest), e.Seq)
		first = min(first, e.Seq)
	}
	restoreGuard(t, db, "audit_log_no_update")
	rechainFrom(t, db, first)
	untouched := 0
	for i, e := range rawEntries(t, db) {
		if e == entries[i] {
			untouched++
		}
	}
	if untouched != int(first)-1 || untouched < 4 {
		t.Fatalf("test setup: expected exactly the %d entries before seq %d to be untouched, got %d", first-1, first, untouched)
	}

	for name, opts := range map[string]OpenOptions{"read-only (a restarted processor)": {ReadOnly: true}, "read-write (the CLI)": {Policy: lifecycle.DefaultPolicy()}} {
		s2, err := OpenWith(path, opts)
		if err != nil {
			t.Fatalf("%s Open = %v", name, err)
		}
		if snap, err := s2.Snapshot(bg, "alpha"); err != nil || !snap.Serves("echo", p.digest) {
			t.Errorf("%s Snapshot = %+v, %v; the limit: a suffix re-chained before the open serves", name, snap.Tools["echo"], err)
		}
		sum, err := s2.VerifyAudit(bg)
		if err != nil || sum.Entries != recorded.Entries || sum.Head == recorded.Head {
			t.Errorf("%s VerifyAudit = %+v, %v; want a clean walk of %d entries whose head differs from the recorded one", name, sum, err, recorded.Entries)
		}
		if rep := mustIntegrity(t, s2); len(rep.Problems) != 0 {
			t.Errorf("%s Integrity problems: %q; the limit: nothing inside the file sees the rewrite", name, rep.Problems)
		}
		_ = s2.Close()
	}
}
