package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	"github.com/sairam0424/toolwarrant/internal/textdiff"
)

// headReminder is printed after every successful verify. The chain proves
// that no row was altered, deleted or inserted since the first entry, but not
// that the whole log was not replaced; only a head recorded elsewhere does.
const headReminder = "record this head outside the database (a ticket, a notebook): the chain alone cannot show that the whole log was rewritten"

// auditCommands is the table behind "audit". Both commands open the database
// in forensic mode: read-only, and tolerant of the dropped guard objects that
// make a normal open refuse the file as corrupt, because naming the broken
// entry after tampering is exactly what they are for.
func auditCommands() []*command {
	return []*command{
		{name: "verify", synopsis: "audit verify [--expect-head HASH]", summary: "check the hash chain of the audit log, print its head, then cross-check the registry against the approvals table and the log (opens the database read-only, tampered or not)", run: runAuditVerify},
		{name: "list", synopsis: "audit list [--after N] [--limit N] [--json]", summary: "print audit entries (opens the database read-only, tampered or not)", run: runAuditList},
	}
}

// runAuditVerify checks the whole chain and, when asked, that the head is the
// one the operator recorded.
func runAuditVerify(a *app, c *command, args []string) (err error) {
	fs := newFlagSet(c.name)
	expect := fs.String("expect-head", "", "fail unless the head equals this hash you recorded earlier")
	pos, err := a.parseArgs(c, fs, args)
	if err != nil {
		return err
	}
	if err := wantArgs(c, pos); err != nil {
		return err
	}
	store, err := a.openStore(openForensic)
	if err != nil {
		return err
	}
	defer closeStore(store, &err)
	summary, err := store.VerifyAudit(a.ctx)
	if err != nil {
		return err
	}
	a.stdout.printf("audit log ok: %d entries, head %s\n", summary.Entries, summary.Head)
	if *expect != "" && !strings.EqualFold(*expect, summary.Head) {
		return fmt.Errorf("audit head mismatch: expected %s, found %s; either the log grew since you recorded the head or it was rewritten", textdiff.Escape(*expect), summary.Head)
	}
	if err := a.reportIntegrity(store); err != nil {
		return err
	}
	a.stdout.printf("%s\n", headReminder)
	return a.stdout.broken()
}

// reportIntegrity runs the catalog's cross-check of the registry against its
// history and the guard objects against the schema, and fails the command when
// anything disagrees. The chain alone proves that the log was not edited; a
// forensic open tolerates dropped guards and a forged approval leaves the
// chain intact, so "audit log ok" on its own said nothing about the file
// (second review). Every problem line is the catalog's own fixed wording with
// quoted names and is escaped once more here.
func (a *app) reportIntegrity(store *catalog.Store) error {
	rep, err := store.Integrity(a.ctx)
	if err != nil {
		return fmt.Errorf("integrity check: %w", err)
	}
	if len(rep.Problems) == 0 {
		a.stdout.printf("integrity ok: guard objects intact, every approval recorded in the log\n")
		return nil
	}
	for _, p := range rep.Problems {
		a.stdout.printf("integrity problem: %s\n", cell(p))
	}
	return fmt.Errorf("%w: %d problem(s) listed above; the file was edited outside toolwarrant or a bug wrote it, do not serve from it", catalog.ErrCorrupt, len(rep.Problems))
}

// runAuditList prints entries in sequence order. Every field comes from the
// database and is rendered through cell, because subjects carry tool names.
func runAuditList(a *app, c *command, args []string) (err error) {
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
	store, err := a.openStore(openForensic)
	if err != nil {
		return err
	}
	defer closeStore(store, &err)
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
