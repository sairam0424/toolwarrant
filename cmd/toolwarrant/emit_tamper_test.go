package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The v0.1.0 verification drove the released binary against a catalog whose
// state column had been edited by hand (echo, approved, set to disabled):
// list and audit verify refused with ErrCorrupt, and emit wrote gateway.yaml
// with one allow rule fewer, exit 0, no change line. The catalog's Approved
// view anchored only the rows it exported, so a tool hidden by the edit was
// never checked. emit now fails like list does, writes nothing and appends
// nothing; a file emit wrote before stays as it was.
func TestEmitRefusesACatalogWhoseToolStateColumnWasEdited(t *testing.T) {
	c, _ := fixture(t)
	c.approve("alice", "s1", "echo", c.tool("s1", "echo").Pending)
	out := filepath.Join(t.TempDir(), "gateway.yaml")
	c.ok("emit", "--out", out)
	written := readFile(t, out)
	execSQL(t, c.db, `UPDATE tools SET state = 'disabled' WHERE name = 'echo'`)

	r := c.fail(exitFailure, "emit", "--out", out)
	wantContains(t, "stderr", r.stderr, adviceCorrupt, "state column was edited", "s1/echo")
	wantNotContains(t, "stdout", r.stdout, "wrote ", "APPROVED")
	if got := readFile(t, out); got != written {
		t.Errorf("the refused emit replaced the file:\n%s", got)
	}
	fresh := filepath.Join(t.TempDir(), "fresh.yaml")
	c.fail(exitFailure, "emit", "--out", fresh)
	if _, err := os.Stat(fresh); !os.IsNotExist(err) {
		t.Errorf("the refused emit wrote a file: %v", err)
	}
	if entries := c.processorSetEntries(); len(entries) != 1 {
		t.Errorf("the refused emit changed the audit log: %+v", entries)
	}
}
