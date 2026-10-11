package catalog

import (
	"context"
	"fmt"
	"sort"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// RecordCrawl applies one crawl in a single transaction: it creates tools and
// versions for the usable definitions, drives the lifecycle for every tool
// that was listed or is live (a live tool absent from a complete crawl is
// missing), and writes one audit entry per event. A crawl never approves
// anything and never edits an existing version.
//
// Every crawl of a registered server is recorded: a crawls row plus a
// crawl.completed or crawl.failed entry. If in.Complete is false, or the
// listing as a whole breaks a cap (MaxToolsPerCrawl, MaxCrawlBytes), or it
// would push the server over MaxToolsPerServer or MaxServerBytes, or it would
// reject more than MaxRejectedPerCrawl entries, only the failure is recorded,
// under a class, and no tool changes: a crawl failure is not a removal. One
// bad tool never fails a crawl (D3): a listed tool whose name breaks the
// shared rule, whose definition cannot be used, or whose name is listed more
// than once is quarantined on its own. If it is a known tool it is observed
// as unusable (lifecycle.UnusableDigest: hidden, nothing stored); otherwise it
// is reported in CrawlReport.Rejected with a tool.rejected audit entry, and no
// tool row is created for it. The caps bound rows and bytes; the log grows
// with every observed change, bounded by the crawl cadence and the cap on
// rejected entries (D14).
//
// Proposal budget (D6): once a tool has gained MaxProposalsPerDecision
// versions without a decision, a crawl that brings yet another new digest
// observes the tool as unusable instead of storing the definition; a known
// digest is still observed normally. Approve, reject and rollback reset the
// budget.
//
// A deprecated tool is neither loaded nor reported unless the listing names
// it or it still carries the unusable marker from an earlier sighting, so the
// cost of a crawl follows the live set and not the server's history (D13); a
// sighting of a deprecated name loads that tool and it reappears, and the
// first crawl that does not list a marked deprecated tool clears the marker
// (one missing line) and then leaves it alone.
//
// All digesting and validation happen before the transaction begins; inside
// it there are only inserts and updates, so the write lock is held briefly.
// The only inputs that leave no record are an invalid actor (the audit entry
// needs a principal), an unregistered server (ErrNotFound) and a paused one
// (ErrPaused).
func (s *Store) RecordCrawl(ctx context.Context, in CrawlInput, by Actor) (CrawlReport, error) {
	actor, err := normalizeActor(by)
	if err != nil {
		return CrawlReport{}, err
	}
	var ls listing
	if in.Complete {
		ls = prepareListing(in)
	} else {
		ls.count = len(in.Tools) + len(in.Unusable)
	}
	var report CrawlReport
	err = s.inTx(ctx, func(t *txn) error {
		var err error
		report, err = s.crawlTx(ctx, t, in, &ls, actor)
		return err
	})
	if err != nil {
		return CrawlReport{}, err
	}
	return report, nil
}

func (s *Store) crawlTx(ctx context.Context, t *txn, in CrawlInput, ls *listing, by Actor) (CrawlReport, error) {
	srv, err := loadServerRow(ctx, t, in.Server)
	if err != nil {
		return CrawlReport{}, err
	}
	if srv.Paused {
		return CrawlReport{}, fmt.Errorf("%w: server %s", ErrPaused, quote(srv.Name))
	}
	if !in.Complete || ls.failure != "" {
		return t.recordFailedCrawl(ctx, srv, in.Error, ls, by)
	}
	known, err := loadCrawlTools(ctx, t, srv.ID, ls.names())
	if err != nil {
		return CrawlReport{}, err
	}
	if ls.rejectedCount(known) > MaxRejectedPerCrawl {
		ls.failure = failureRejectedCap
		return t.recordFailedCrawl(ctx, srv, in.Error, ls, by)
	}
	class, err := s.caps.check(ctx, t, srv.ID, known, ls)
	if err != nil {
		return CrawlReport{}, err
	}
	if class != "" {
		ls.failure = class
		return t.recordFailedCrawl(ctx, srv, in.Error, ls, by)
	}
	crawlID, err := t.insertCrawl(ctx, srv, true, "", ls.count, by)
	if err != nil {
		return CrawlReport{}, err
	}
	changes, rejected, err := s.observeAll(ctx, t, srv, known, ls, crawlID, by)
	if err != nil {
		return CrawlReport{}, err
	}
	detail := fmt.Sprintf("crawl=%d tools=%d changes=%d rejected=%d", crawlID, ls.count, countChanged(changes), len(rejected))
	if err := t.appendAudit(ctx, by, evCrawlCompleted, srv.Name, "", "", detail); err != nil {
		return CrawlReport{}, err
	}
	return CrawlReport{CrawlID: crawlID, Complete: true, Changes: changes, Rejected: rejected}, nil
}

// insertCrawl writes the crawls row and returns its id.
func (t *txn) insertCrawl(ctx context.Context, srv Server, complete bool, errorRecord string, count int, by Actor) (int64, error) {
	crawlID, err := t.insert(ctx,
		`INSERT INTO crawls (server_id, started_at, complete, error, tool_count, actor) VALUES (?, ?, ?, ?, ?, ?)`,
		srv.ID, t.ts, boolInt(complete), errorRecord, count, by.Name)
	if err != nil {
		return 0, fmt.Errorf("catalog: record crawl: %w", err)
	}
	return crawlID, nil
}

// recordFailedCrawl records a crawl that observes no tool: the caller's
// incomplete one, or a listing the catalog refused under ls.failure. The
// caller's text is kept in the crawls table only, quoted: it can echo the
// request URL, and the audit log can never be scrubbed.
func (t *txn) recordFailedCrawl(ctx context.Context, srv Server, text string, ls *listing, by Actor) (CrawlReport, error) {
	crawlID, err := t.insertCrawl(ctx, srv, false, crawlErrorRecord(text, ls.failure), ls.count, by)
	if err != nil {
		return CrawlReport{}, err
	}
	class := ls.failure
	if class == "" {
		class = errorClass(text)
	}
	detail := fmt.Sprintf("crawl=%d tools=%d complete=false reason=%s", crawlID, ls.count, auditClass(class))
	return CrawlReport{CrawlID: crawlID, Error: class}, t.appendAudit(ctx, by, evCrawlFailed, srv.Name, "", "", detail)
}

// observation is what one crawl said about one tool, in the catalog's terms.
type observation struct {
	present  bool
	digest   string // set when present and usable
	unusable bool
	reason   string // class, when unusable
	budget   bool   // the unusable verdict comes from the proposal budget
}

// observeAll reports the crawl to the lifecycle for every tool that was listed
// or was loaded as live, in name order, and records the entries that no tool
// row describes.
func (s *Store) observeAll(ctx context.Context, t *txn, srv Server, known map[string]*toolRec,
	ls *listing, crawlID int64, by Actor) ([]ToolChange, []RejectedTool, error) {
	names := ls.names()
	for name := range known {
		if ls.usableByName(name) == nil {
			if _, listed := ls.unusable[name]; !listed {
				names = append(names, name)
			}
		}
	}
	sort.Strings(names)
	changes := make([]ToolChange, 0, len(names))
	var rejected []RejectedTool
	for _, name := range names {
		rec := known[name]
		if rj, listedUnusable := ls.unusable[name]; listedUnusable && rec == nil {
			if err := t.rejectEntry(ctx, by, srv.Name, crawlID, rj); err != nil {
				return nil, nil, err
			}
			rejected = append(rejected, rj.rejected())
			continue
		}
		p := ls.usableByName(name)
		if rec == nil {
			var err error
			if rec, err = insertTool(ctx, t, srv.ID, name); err != nil {
				return nil, nil, err
			}
		}
		ch, err := s.observeOne(ctx, t, srv, rec, p, ls.unusable[name], crawlID, by)
		if err != nil {
			return nil, nil, err
		}
		changes = append(changes, ch)
	}
	for _, rj := range ls.nameless {
		if err := t.rejectEntry(ctx, by, srv.Name, crawlID, rj); err != nil {
			return nil, nil, err
		}
		rejected = append(rejected, rj.rejected())
	}
	return changes, rejected, nil
}

// decide turns what the crawl listed under a known tool into an observation,
// applying the proposal budget to a digest the tool does not know yet.
func decide(rec *toolRec, p *preparedTool, rj rejection) observation {
	switch {
	case p != nil && !rec.knowsDigest(p.digest) && rec.budget >= MaxProposalsPerDecision:
		return observation{present: true, unusable: true, reason: reasonBudget, budget: true}
	case p != nil:
		return observation{present: true, digest: p.digest}
	case rj.reason != "":
		return observation{present: true, unusable: true, reason: rj.reason}
	}
	return observation{}
}

func (s *Store) observeOne(ctx context.Context, t *txn, srv Server, rec *toolRec, p *preparedTool, rj rejection,
	crawlID int64, by Actor) (ToolChange, error) {
	ob := decide(rec, p, rj)
	cmd := lifecycle.ObserveCrawl{Present: ob.present, Digest: ob.digest, Unusable: ob.unusable, Actor: by.Name}
	res, err := lifecycle.Apply(rec.tool, cmd, s.policy)
	if err != nil {
		return ToolChange{}, fmt.Errorf("catalog: crawl %s/%s: %w", quote(srv.Name), quote(rec.name), err)
	}
	if err := crawlMustNotDecide(res.Events); err != nil {
		return ToolChange{}, err
	}
	before := rec.state()
	if err := rec.save(ctx, t, res.Tool, p, crawlID); err != nil {
		return ToolChange{}, err
	}
	note := ""
	if ob.unusable {
		note = " reason=" + auditClass(ob.reason)
		if ob.budget {
			note += fmt.Sprintf(" budget=%d", MaxProposalsPerDecision)
		}
	}
	if err := t.auditTool(ctx, by, srv.Name, rec.name, before, rec.state(), res.Events, note); err != nil {
		return ToolChange{}, err
	}
	return ToolChange{Tool: rec.name, Kind: classify(res.Events), Digest: ob.digest, State: res.Tool.State, Reason: ob.reason}, nil
}

// rejectEntry records a listed entry that no tool row describes. The detail
// carries the reason class and the quoted name, or a fixed marker when the
// name itself was refused; the subject names the tool only when it is safe.
func (t *txn) rejectEntry(ctx context.Context, by Actor, server string, crawlID int64, rj rejection) error {
	subject := server
	if rj.name != "" {
		subject += "/" + rj.name
	}
	detail := fmt.Sprintf("crawl=%d reason=%s name=%s", crawlID, auditClass(rj.reason), rj.auditName())
	return t.appendAudit(ctx, by, evToolRejected, subject, "", "", detail)
}

// crawlMustNotDecide is the catalog's own check of the rule the whole product
// rests on: observing an upstream never approves, rejects or rolls back.
func crawlMustNotDecide(events []lifecycle.Event) error {
	for _, ev := range events {
		switch ev.Kind {
		case lifecycle.EvApproved, lifecycle.EvRejected, lifecycle.EvRolledBack:
			return internalf("a crawl produced the decision event %s", ev.Kind)
		}
	}
	return nil
}

// classify names what a crawl did to one tool. When several events apply the
// one an operator must act on first wins, in this order: discovered (new),
// reappeared, proposed (changed: a new proposal to review), deprecated,
// missing, unusable, returned, reverted, drifted (changed), else unchanged.
//
// Drift without a proposal, to an already known pending or rejected digest, is
// still reported as changed: what the upstream serves changed and is not the
// approved definition, which is what the operator needs to see. A tool that
// comes back after missed crawls on its approved digest is "returned" rather
// than "reverted": the miss is the rarer fact, and the digest column shows
// that it equals the approval. The audit log carries every event regardless.
func classify(events []lifecycle.Event) ChangeKind {
	has := map[lifecycle.EventKind]bool{}
	for _, ev := range events {
		has[ev.Kind] = true
	}
	switch {
	case has[lifecycle.EvDiscovered]:
		return ChangeNew
	case has[lifecycle.EvReappeared]:
		return ChangeReappeared
	case has[lifecycle.EvProposed]:
		return ChangeChanged
	case has[lifecycle.EvDeprecated]:
		return ChangeDeprecated
	case has[lifecycle.EvMissing]:
		return ChangeMissing
	case has[lifecycle.EvUnusable]:
		return ChangeUnusable
	case has[lifecycle.EvReturned]:
		return ChangeReturned
	case has[lifecycle.EvReverted]:
		return ChangeReverted
	case has[lifecycle.EvDrifted]:
		return ChangeChanged
	}
	return ChangeUnchanged
}

func countChanged(changes []ToolChange) int {
	n := 0
	for _, c := range changes {
		if c.Kind != ChangeUnchanged {
			n++
		}
	}
	return n
}
