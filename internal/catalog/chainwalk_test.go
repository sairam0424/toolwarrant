package catalog

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// The walk a Store makes when it opens (D15 a): the whole chain, in pages, with
// the hash of every decision entry and the head kept; a broken chain refuses
// the open, except for a forensic one, which refuses only the views.

// rawHandle is rawDB for tests and benchmarks alike.
func rawHandle(tb testing.TB, path string) *sql.DB {
	tb.Helper()
	db, err := sql.Open(driverName, dsnFor(path, connWriter, DefaultBusyTimeout))
	if err != nil {
		tb.Fatalf("raw open: %v", err)
	}
	db.SetMaxOpenConns(1)
	tb.Cleanup(func() { _ = db.Close() })
	return db
}

// appendRawEntries appends n correctly sealed entries through a raw handle in
// one transaction, alternating a decision event (tool.budget_reset) with a
// plain one (crawl.completed), so that a test can grow the log past a page in
// well under a second. It returns the new head.
func appendRawEntries(tb testing.TB, db *sql.DB, n int) audit.Entry {
	tb.Helper()
	var prev audit.Entry
	err := db.QueryRowContext(bg, `SELECT `+auditCols+` FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(
		&prev.Seq, &prev.TS, &prev.Actor, &prev.ActorType, &prev.Event, &prev.Subject,
		&prev.BeforeHash, &prev.AfterHash, &prev.Detail, &prev.PrevHash, &prev.Hash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		tb.Fatal(err)
	}
	tx, err := db.BeginTx(bg, nil)
	if err != nil {
		tb.Fatal(err)
	}
	stmt, err := tx.PrepareContext(bg, insertAudit)
	if err != nil {
		tb.Fatal(err)
	}
	for i := 0; i < n; i++ {
		event, detail := evCrawlCompleted, "crawl=1 tools=1 changes=0 rejected=0"
		if i%2 == 0 {
			event, detail = evBudgetReset, "digest=- state=enabled->enabled last_seen=- proposals=3->0"
		}
		e, err := audit.Seal(prev, audit.Entry{Seq: prev.Seq + 1, TS: "2026-10-12T00:00:00.000000000Z", Actor: "alice",
			ActorType: string(ActorHuman), Event: event, Subject: "alpha/bulk", Detail: detail})
		if err != nil {
			tb.Fatal(err)
		}
		if _, err := stmt.ExecContext(bg, e.Seq, e.TS, e.Actor, e.ActorType, e.Event, e.Subject, e.BeforeHash, e.AfterHash,
			e.Detail, e.PrevHash, e.Hash); err != nil {
			tb.Fatal(err)
		}
		prev = e
	}
	if err := tx.Commit(); err != nil {
		tb.Fatal(err)
	}
	return prev
}

// A log longer than one page is walked whole at open: the head is pinned,
// every decision entry is remembered, VerifyAudit agrees, and an entry edited
// in place deep in a later page refuses a fresh read-only and read-write open
// while a forensic open still verifies, lists and inspects.
func TestOpen_VerifiesTheWholeChainAndPagesThroughIt(t *testing.T) {
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	approvedEcho(t, s)
	_ = s.Close()
	db := rawHandle(t, path)
	head := appendRawEntries(t, db, auditPage+700)
	entries := rawEntries(t, db)
	decisions := 0
	for _, e := range entries {
		if isChainRecordedEvent(e.Event) {
			decisions++
		}
	}

	ro, err := OpenWith(path, OpenOptions{ReadOnly: true})
	if err != nil {
		t.Fatalf("Open on a long log = %v", err)
	}
	defer func() { _ = ro.Close() }()
	if pin := ro.loadPin(); pin != (chainPin{seq: head.Seq, hash: head.Hash}) {
		t.Errorf("pin after open = %+v, want the head (seq %d)", pin, head.Seq)
	}
	if got := ro.chain.decisions(); got != decisions {
		t.Errorf("memory holds %d decision entries, the log has %d", got, decisions)
	}
	if sum, err := ro.VerifyAudit(bg); err != nil || sum.Entries != len(entries) || sum.Head != head.Hash {
		t.Errorf("VerifyAudit = %+v, %v; want %d entries and head %s", sum, err, len(entries), head.Hash[:12])
	}
	mustSnapshot(t, ro, "alpha")

	edited := int64(auditPage + 100)
	mustExec(t, db, `DROP TRIGGER audit_log_no_update`)
	mustExec(t, db, `UPDATE audit_log SET actor = 'mallory' WHERE seq = ?`, edited)
	restoreGuard(t, db, "audit_log_no_update")
	for name, opts := range map[string]OpenOptions{"read-only": {ReadOnly: true}, "read-write": {Policy: lifecycle.DefaultPolicy()}} {
		s2, err := OpenWith(path, opts)
		if s2 != nil {
			_ = s2.Close()
		}
		var broken *audit.BrokenError
		if !errors.Is(err, ErrCorrupt) || !errors.As(err, &broken) || broken.Seq != edited || !strings.Contains(err.Error(), "does not form one chain from its first entry") {
			t.Errorf("%s Open after the edit = %v, want ErrCorrupt wrapping the break at %d", name, err, edited)
		}
	}
	f, err := OpenWith(path, OpenOptions{Forensic: true})
	if err != nil {
		t.Fatalf("forensic Open after the edit = %v", err)
	}
	defer func() { _ = f.Close() }()
	var broken *audit.BrokenError
	if _, err := f.VerifyAudit(bg); !errors.As(err, &broken) || broken.Seq != edited {
		t.Errorf("forensic VerifyAudit = %v, want the break at %d", err, edited)
	}
	if got, err := f.AuditEntries(bg, 0, 0); err != nil || len(got) != len(entries) {
		t.Errorf("forensic AuditEntries = %d, %v", len(got), err)
	}
	if _, err := f.Tools(bg, ""); !errors.Is(err, ErrCorrupt) {
		t.Errorf("forensic Tools on a broken chain = %v, want ErrCorrupt: the views trust only a chain that verifies", err)
	}
	if rep := mustIntegrity(t, f); rep.ChainBreaks != 1 {
		t.Errorf("forensic Integrity.ChainBreaks = %d, want 1; %q", rep.ChainBreaks, rep.Problems)
	}
}

// A write transaction first extends the Store's memory to the head of the
// file, so a writer whose chain was edited behind its back appends nothing to
// it, and the entries it does append chain from the verified head.
func TestInTx_RefusesToAppendAfterTheChainWasEdited(t *testing.T) {
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("echo", "v1"))
	db := rawDB(t, path)
	entries := rawEntries(t, db)
	before := len(entries)
	mustExec(t, db, `DROP TRIGGER audit_log_no_update`)
	mustExec(t, db, `UPDATE audit_log SET actor = 'mallory' WHERE seq = 2`)
	restoreGuard(t, db, "audit_log_no_update")

	_, err := s.AddServer(bg, ServerSpec{Name: "beta", URL: "https://b.example.com/mcp"}, alice)
	if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "do not continue its chain") {
		t.Errorf("AddServer after the edit = %v, want ErrCorrupt naming the broken suffix", err)
	}
	if _, err := s.RecordCrawl(bg, crawlOf(tool("echo", "v1")), crawler); !errors.Is(err, ErrCorrupt) {
		t.Errorf("RecordCrawl after the edit = %v, want ErrCorrupt", err)
	}
	if n := len(rawEntries(t, db)); n != before {
		t.Errorf("the refused writes appended %d entries", n-before)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM servers`); n != 1 {
		t.Errorf("servers = %d, want the one from before", n)
	}
	// Restoring the entry makes the file whole again and the same Store writes.
	mustExec(t, db, `DROP TRIGGER audit_log_no_update`)
	mustExec(t, db, `UPDATE audit_log SET actor = ? WHERE seq = 2`, entries[1].Actor)
	restoreGuard(t, db, "audit_log_no_update")
	mustAddServer(t, s, "beta")
	if _, err := s.VerifyAudit(bg); err != nil {
		t.Errorf("VerifyAudit after the restored entry and a new write = %v", err)
	}
}

// Integrity verifies every entry as it streams the log and reports each break
// on its own line, where VerifyAudit stops at the first: a seal broken by an
// in-place edit with the hash column kept, a link broken by an entry re-sealed
// in place, and a gap left by a deleted entry.
func TestIntegrity_ReportsEveryChainBreak(t *testing.T) {
	t.Run("seal and link", func(t *testing.T) {
		s, path := seededStore(t)
		db := rawDB(t, path)
		entries := rawEntries(t, db)
		if len(entries) < 7 {
			t.Fatalf("test setup: %d entries, want at least 7", len(entries))
		}
		mustExec(t, db, `DROP TRIGGER audit_log_no_update`)
		mustExec(t, db, `UPDATE audit_log SET after_hash = 'x' WHERE seq = 3`) // seal break at 3
		resealed := entries[4]                                                 // seq 5, re-sealed from its real predecessor
		resealed.Actor = "mallory"
		resealed, err := audit.Seal(entries[3], resealed)
		if err != nil {
			t.Fatal(err)
		}
		mustExec(t, db, `UPDATE audit_log SET actor = ?, prev_hash = ?, hash = ? WHERE seq = 5`, resealed.Actor, resealed.PrevHash, resealed.Hash)
		restoreGuard(t, db, "audit_log_no_update")

		rep := mustIntegrity(t, s)
		if rep.ChainBreaks != 2 {
			t.Errorf("ChainBreaks = %d, want 2; %q", rep.ChainBreaks, rep.Problems)
		}
		problemMentioning(t, rep, "audit entry 3 does not re-seal: its hash is not the hash of its fields; the entry was rewritten in place",
			"audit entry 6 does not continue the chain from entry 5: its prev_hash is not that entry's hash")
		if b := brokenAt(t, verifyErr(s)); b.Seq != 3 {
			t.Errorf("VerifyAudit stops at %d, want the first break at 3", b.Seq)
		}
	})
	t.Run("gap", func(t *testing.T) {
		s, path := seededStore(t)
		db := rawDB(t, path)
		mustExec(t, db, `DROP TRIGGER audit_log_no_delete`)
		mustExec(t, db, `DELETE FROM audit_log WHERE seq = 4`)
		restoreGuard(t, db, "audit_log_no_delete")
		rep := mustIntegrity(t, s)
		if rep.ChainBreaks != 2 {
			t.Errorf("ChainBreaks = %d, want the gap and the link; %q", rep.ChainBreaks, rep.Problems)
		}
		problemMentioning(t, rep, "audit entry 5 follows entry 3: the sequence has a gap, entries were deleted",
			"audit entry 5 does not continue the chain from entry 3")
	})
	t.Run("intact", func(t *testing.T) {
		s, _ := seededStore(t)
		if rep := mustIntegrity(t, s); rep.ChainBreaks != 0 {
			t.Errorf("ChainBreaks on an intact log = %d; %q", rep.ChainBreaks, rep.Problems)
		}
	})
}

// BenchmarkOpen_WalksAChainOf100000Entries measures the open-time walk (D15 a)
// on a log of one hundred thousand entries: one read-only open, which verifies
// every entry and keeps the hash of every decision entry.
func BenchmarkOpen_WalksAChainOf100000Entries(b *testing.B) {
	const entries = 100000
	path := filepath.Join(b.TempDir(), "catalog.db")
	s, err := Open(path, lifecycle.DefaultPolicy())
	if err != nil {
		b.Fatal(err)
	}
	if _, err := s.AddServer(bg, ServerSpec{Name: "alpha", URL: "https://alpha.example.com/mcp"}, alice); err != nil {
		b.Fatal(err)
	}
	_ = s.Close()
	appendRawEntries(b, rawHandle(b, path), entries-1)
	b.ResetTimer()
	for b.Loop() {
		ro, err := OpenWith(path, OpenOptions{ReadOnly: true})
		if err != nil {
			b.Fatal(err)
		}
		if pin := ro.loadPin(); pin.seq != entries {
			b.Fatalf("pin seq = %d, want %d", pin.seq, entries)
		}
		_ = ro.Close()
	}
}
