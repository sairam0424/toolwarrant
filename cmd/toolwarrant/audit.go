package main

import (
	"fmt"
	"strconv"
	"strings"
)

// headReminder is printed after every successful verify. The chain proves
// that no row was altered, deleted or inserted since the first entry, but not
// that the whole log was not replaced; only a head recorded elsewhere does.
const headReminder = "record this head outside the database (a ticket, a notebook): the chain alone cannot show that the whole log was rewritten"

// auditCommands is the table behind "audit".
func auditCommands() []*command {
	return []*command{
		{name: "verify", synopsis: "audit verify [--expect-head HASH]", summary: "check the hash chain of the audit log and print its head", run: runAuditVerify},
		{name: "list", synopsis: "audit list [--after N] [--limit N] [--json]", summary: "print audit entries", run: runAuditList},
	}
}

// runAuditVerify checks the whole chain and, when asked, that the head is the
// one the operator recorded.
func runAuditVerify(a *app, c *command, args []string) error {
	fs := newFlagSet(c.name)
	expect := fs.String("expect-head", "", "fail unless the head equals this hash you recorded earlier")
	pos, err := a.parseArgs(c, fs, args)
	if err != nil {
		return err
	}
	if err := wantArgs(c, pos); err != nil {
		return err
	}
	store, err := a.openStore(false)
	if err != nil {
		return err
	}
	defer store.Close()
	summary, err := store.VerifyAudit(a.ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "audit log ok: %d entries, head %s\n", summary.Entries, summary.Head)
	if *expect != "" && !strings.EqualFold(*expect, summary.Head) {
		return fmt.Errorf("audit head mismatch: expected %s, found %s; either the log grew since you recorded the head or it was rewritten", *expect, summary.Head)
	}
	fmt.Fprintln(a.stdout, headReminder)
	return nil
}

// runAuditList prints entries in sequence order. Every field comes from the
// database and is rendered through cell, because subjects carry tool names.
func runAuditList(a *app, c *command, args []string) error {
	fs := newFlagSet(c.name)
	after := fs.Int64("after", 0, "only entries with a sequence number above this")
	limit := fs.Int("limit", 0, "at most this many entries (0 means all)")
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := a.parseArgs(c, fs, args)
	if err != nil {
		return err
	}
	if err := wantArgs(c, pos); err != nil {
		return err
	}
	if *after < 0 || *limit < 0 {
		return &usageError{msg: "--after and --limit must not be negative", cmd: c}
	}
	store, err := a.openStore(false)
	if err != nil {
		return err
	}
	defer store.Close()
	entries, err := store.AuditEntries(a.ctx, *after, *limit)
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(a.stdout, entries)
	}
	t := newTable(a.stdout)
	t.row("SEQ", "TIME", "ACTOR", "TYPE", "EVENT", "SUBJECT", "DETAIL")
	for _, e := range entries {
		t.row(strconv.FormatInt(e.Seq, 10), cell(e.TS), cell(e.Actor), cell(e.ActorType), cell(e.Event), cell(e.Subject), cell(e.Detail))
	}
	return t.flush()
}
