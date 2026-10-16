package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/catalog"
	"github.com/sairam0424/toolwarrant/internal/signing"
)

// eventBudgetReset is the audit event the catalog writes for a reset; the
// entry is read back and printed so the person sees what the log now says.
const eventBudgetReset = "tool.budget_reset"

// budgetCommands is the table behind "budget". Its one subcommand is the
// decision that is always available (decision D6, limit L6): approve, reject
// and rollback each need a version in the right status, and a tool whose
// upstream exhausted the proposal budget and then went back to the approved
// definition has none, so without this command it could never take a new
// definition again.
func budgetCommands() []*command {
	return []*command{
		{name: "reset", synopsis: "budget reset SERVER TOOL [--by NAME] [--expect-head HEX]", summary: "forget the proposals a tool gained since its last decision so the next crawl may store a new digest (a human decision, one audit entry)", run: runBudgetReset},
	}
}

// runBudgetReset resets the proposal budget of one tool. The person deciding
// is named with --by, or else resolved like every other decision (the global
// --as, TOOLWARRANT_ACTOR, the OS user). The system actor is refused either
// way as a usage error: a reset is a decision (D7), and it is what lets the
// upstream's next twenty digests into the file, so a person must have looked.
// The audit entry the catalog wrote is printed back, so the person sees what
// the log records about their decision.
func runBudgetReset(a *app, c *command, args []string) (err error) {
	fs := newFlagSet(c.name)
	by := fs.String("by", "", "the person deciding (default: the global --as, "+envActor+" or the OS user; with a trust list in force, the operator the key belongs to); the system actor \""+systemActorName+"\" is refused")
	expect := fs.String(flagExpect, "", expectHelp)
	pos, err := a.parseArgs(c, fs, args)
	if err != nil {
		return err
	}
	if err := wantArgs(c, pos, "SERVER", "TOOL"); err != nil {
		return err
	}
	label, err := a.budgetActor(c, *by)
	if err != nil {
		return err
	}
	f, err := a.beginSigned(c, *expect, label, *by != "" || a.labelGiven())
	if err != nil {
		return err
	}
	defer f.close(&err)
	r, err := f.decide(a, signing.KindBudgetReset, pos[0], pos[1], "")
	if err != nil {
		return err
	}
	entry, err := lastBudgetReset(a.ctx, f.store, pos[0]+"/"+pos[1])
	if err != nil {
		return err
	}
	a.stdout.printf("reset the proposal budget of %s/%s by %s; the next crawl may store a new digest\n", cell(pos[0]), cell(pos[1]), cell(f.actor.Name))
	a.stdout.printf("audit entry %d: %s %s by %s (%s) at %s, detail %s, hash %s\n",
		entry.Seq, cell(entry.Event), cell(entry.Subject), cell(entry.Actor), cell(entry.ActorType), cell(entry.TS), cell(entry.Detail), cell(entry.Hash))
	f.report(a, r)
	return a.stdout.broken()
}

// lastBudgetReset returns the newest tool.budget_reset entry about subject.
// The catalog exposes the log only in ascending pages, so the whole log is
// read; a reset is a rare human decision and the log is small next to the
// versions table. The newest entry about the subject is the one this command
// wrote, unless another process reset the same tool in between, which the
// printed actor would show. No such entry is an error: the catalog wrote one
// in the same transaction, so its absence means the log cannot be read back.
func lastBudgetReset(ctx context.Context, store *catalog.Store, subject string) (audit.Entry, error) {
	entries, err := store.AuditEntries(ctx, 0, 0)
	if err != nil {
		return audit.Entry{}, fmt.Errorf("read the audit entry back: %w", err)
	}
	for i := len(entries) - 1; i >= 0; i-- {
		if entries[i].Event == eventBudgetReset && entries[i].Subject == subject {
			return entries[i], nil
		}
	}
	return audit.Entry{}, errors.New("the reset was recorded but its audit entry cannot be read back; run audit verify")
}

// budgetActor resolves --by when it was given and the deciding actor
// otherwise. --by goes through the same normalisation as --as, so case and
// look-alike variants of one name collapse to one identity, and the reserved
// name of the system actor is refused with the fix in the message.
func (a *app) budgetActor(c *command, by string) (catalog.Actor, error) {
	if by == "" {
		return a.decidingActor(c)
	}
	name, err := normalizeActorName(by)
	if err != nil {
		return catalog.Actor{}, err
	}
	if name == systemActorName {
		return catalog.Actor{}, &usageError{msg: "the system actor cannot reset a proposal budget; pass --by with your own name", cmd: c}
	}
	return catalog.Actor{Name: name, Type: catalog.ActorHuman}, nil
}
