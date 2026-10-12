package catalog

import (
	"testing"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// The state column anchored to the chain (D17 c, extended after the round).
// Disable keeps the approved pointer of a tool that is not deprecated, and
// lifecycle.Serves decides from the state, so one UPDATE tools SET state =
// 'enabled' served a disabled tool again while every approval anchor held and
// only Integrity saw the edit (the eighth review). The newest state-bearing
// entry about the tool must now have left the state the row holds, on the
// serving path, in the views, in the export, in the decisions and in the
// crawl, on the long-lived Store and on a fresh one.
func TestSnapshot_DisabledToolReEnabledByAColumnFlipIsCorrupt(t *testing.T) {
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	d1 := approvedEcho(t, s)
	if err := s.Disable(bg, "alpha", "echo", bob); err != nil {
		t.Fatal(err)
	}
	if snap := mustSnapshot(t, s, "alpha"); snap.Serves("echo", d1) {
		t.Fatalf("a disabled tool is served: %+v", snap.Tools["echo"])
	}
	recorded, err := s.VerifyAudit(bg)
	if err != nil {
		t.Fatal(err)
	}
	db := rawDB(t, path)
	mustExec(t, db, `UPDATE tools SET state = 'enabled' WHERE name = 'echo'`)
	mustExec(t, db, `UPDATE meta SET value = value + 1 WHERE key = 'generation'`)

	want := []string{"state of tool", `"alpha/echo"`, `is "enabled"`, "tool.disabled", `left it "disabled"`, "state column was edited"}
	_, err = s.Snapshot(bg, "alpha")
	requireCorruptMentioning(t, "Snapshot", err, want)
	_, err = s.Tools(bg, "alpha")
	requireCorruptMentioning(t, "Tools", err, want)
	_, err = s.Tool(bg, "alpha", "echo")
	requireCorruptMentioning(t, "Tool", err, want)
	_, err = s.Approved(bg)
	requireCorruptMentioning(t, "Approved", err, want)
	requireCorruptMentioning(t, "Enable", s.Enable(bg, "alpha", "echo", bob), want)
	requireCorruptMentioning(t, "Disable", s.Disable(bg, "alpha", "echo", bob), want)
	in := CrawlInput{Server: "alpha", Complete: true}
	in.Tools = append(in.Tools, tool("echo", "v1"))
	_, err = s.RecordCrawl(bg, in, crawler)
	requireCorruptMentioning(t, "RecordCrawl", err, want)
	for label, opts := range map[string]OpenOptions{"read-only": {ReadOnly: true}, "read-write": {Policy: lifecycle.DefaultPolicy()}} {
		fresh, err := OpenWith(path, opts)
		if err != nil {
			t.Fatalf("%s Open = %v", label, err)
		}
		_, err = fresh.Snapshot(bg, "alpha")
		requireCorruptMentioning(t, label+" fresh Snapshot", err, want)
		_ = fresh.Close()
	}
	if after, err := s.VerifyAudit(bg); err != nil || after.Head != recorded.Head {
		t.Errorf("VerifyAudit = %+v, %v; the log was not touched", after, err)
	}
	if rep := mustIntegrity(t, s); len(rep.Problems) == 0 {
		t.Errorf("Integrity reports nothing about the flipped state")
	}

	mustExec(t, db, `UPDATE tools SET state = 'disabled' WHERE name = 'echo'`)
	if snap := mustSnapshot(t, s, "alpha"); snap.Serves("echo", d1) {
		t.Errorf("Snapshot once the column is restored serves the disabled tool: %+v", snap.Tools["echo"])
	}
	if err := s.Enable(bg, "alpha", "echo", bob); err != nil {
		t.Fatalf("Enable once the column is restored = %v", err)
	}
	mustBeClean(t, s, "after the enable")
}

// A tool the log never created cannot exist by a planted row alone: without a
// state-bearing entry about it, every path refuses the file.
func TestSnapshot_PlantedToolRowWithoutAnEntryIsCorrupt(t *testing.T) {
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	approvedEcho(t, s)
	db := rawDB(t, path)
	// pending_review needs no approved pointer, so the row passes the table's
	// own CHECK and only the chain can tell it was never created.
	mustExec(t, db, `INSERT INTO tools (server_id, name, state, last_seen_digest, missing_crawls, proposals_since_decision)
		SELECT server_id, 'ghost', 'pending_review', last_seen_digest, 0, 0 FROM tools WHERE name = 'echo'`)
	mustExec(t, db, `UPDATE meta SET value = value + 1 WHERE key = 'generation'`)
	want := []string{`"alpha/ghost"`, "no audit entry about its state"}
	_, err := s.Snapshot(bg, "alpha")
	requireCorruptMentioning(t, "Snapshot", err, want)
	_, err = s.Tools(bg, "alpha")
	requireCorruptMentioning(t, "Tools", err, want)
}
