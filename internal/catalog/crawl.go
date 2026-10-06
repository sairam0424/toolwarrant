package catalog

import (
	"context"
	"fmt"
	"sort"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// RecordCrawl applies one crawl in a single transaction: it computes each
// tool's digest, creates tools and versions, drives the lifecycle for every
// known tool (tools absent from a complete crawl are reported as missing), and
// writes one audit entry per event. A crawl never approves anything and never
// edits an existing version. If in.Complete is false only the failure is
// recorded. Duplicate tool names in one crawl, or a tool name containing
// control or invisible Unicode characters, fail the whole call with
// ErrInvalid and change nothing.
//
// The tools of an incomplete crawl are validated like any others and then
// ignored: a crawl that stopped half way says nothing about what is missing.
func (s *Store) RecordCrawl(ctx context.Context, in CrawlInput, by Actor) (CrawlReport, error) {
	if err := validateActor(by); err != nil {
		return CrawlReport{}, err
	}
	tools, err := prepareCrawlTools(in.Tools)
	if err != nil {
		return CrawlReport{}, err
	}
	var report CrawlReport
	err = s.inTx(ctx, func(t *txn) error {
		var err error
		report, err = s.crawlTx(ctx, t, in, tools, by)
		return err
	})
	if err != nil {
		return CrawlReport{}, err
	}
	return report, nil
}

func (s *Store) crawlTx(ctx context.Context, t *txn, in CrawlInput, tools []preparedTool, by Actor) (CrawlReport, error) {
	srv, err := loadServerRow(ctx, t, in.Server)
	if err != nil {
		return CrawlReport{}, err
	}
	crawlID, err := t.insert(ctx,
		`INSERT INTO crawls (server_id, started_at, complete, error, tool_count, actor) VALUES (?, ?, ?, ?, ?, ?)`,
		srv.ID, t.ts, boolInt(in.Complete), sanitizeText(in.Error, maxCrawlErrorBytes), len(tools), by.Name)
	if err != nil {
		return CrawlReport{}, fmt.Errorf("catalog: record crawl: %w", err)
	}
	if !in.Complete {
		// The error text is kept in the crawls table only: it can echo the
		// request URL, and the audit log can never be scrubbed.
		detail := fmt.Sprintf("crawl=%d tools=%d complete=false", crawlID, len(tools))
		return CrawlReport{CrawlID: crawlID}, t.appendAudit(ctx, by, evCrawlFailed, srv.Name, "", "", detail)
	}
	known, err := loadServerTools(ctx, t, srv.ID)
	if err != nil {
		return CrawlReport{}, err
	}
	changes, err := s.observeAll(ctx, t, srv, known, tools, crawlID, by)
	if err != nil {
		return CrawlReport{}, err
	}
	detail := fmt.Sprintf("crawl=%d tools=%d changes=%d", crawlID, len(tools), countChanged(changes))
	if err := t.appendAudit(ctx, by, evCrawlCompleted, srv.Name, "", "", detail); err != nil {
		return CrawlReport{}, err
	}
	return CrawlReport{CrawlID: crawlID, Complete: true, Changes: changes}, nil
}

// observeAll reports the crawl to the lifecycle for every tool that was listed
// or was already known, in name order.
func (s *Store) observeAll(ctx context.Context, t *txn, srv Server, known map[string]*toolRec,
	tools []preparedTool, crawlID int64, by Actor) ([]ToolChange, error) {
	listed := make(map[string]*preparedTool, len(tools))
	names := make([]string, 0, len(tools)+len(known))
	for i := range tools {
		listed[tools[i].name] = &tools[i]
		names = append(names, tools[i].name)
	}
	for name := range known {
		if _, ok := listed[name]; !ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	changes := make([]ToolChange, 0, len(names))
	for _, name := range names {
		rec := known[name]
		if rec == nil {
			var err error
			if rec, err = insertTool(ctx, t, srv.ID, name); err != nil {
				return nil, err
			}
		}
		ch, err := s.observeOne(ctx, t, srv, rec, listed[name], crawlID, by)
		if err != nil {
			return nil, err
		}
		changes = append(changes, ch)
	}
	return changes, nil
}

func (s *Store) observeOne(ctx context.Context, t *txn, srv Server, rec *toolRec, listed *preparedTool,
	crawlID int64, by Actor) (ToolChange, error) {
	cmd := lifecycle.ObserveCrawl{Present: listed != nil, Actor: by.Name}
	live := ""
	if listed != nil {
		cmd.Digest, live = listed.digest, listed.digest
	}
	res, err := lifecycle.Apply(rec.tool, cmd, s.policy)
	if err != nil {
		return ToolChange{}, fmt.Errorf("catalog: crawl %s/%s: %w", quote(srv.Name), quote(rec.name), err)
	}
	if err := crawlMustNotDecide(res.Events); err != nil {
		return ToolChange{}, err
	}
	before := rec.tool
	if err := rec.save(ctx, t, res.Tool, listed, crawlID); err != nil {
		return ToolChange{}, err
	}
	if err := t.auditTool(ctx, by, srv.Name, rec.name, before, res.Tool, res.Events); err != nil {
		return ToolChange{}, err
	}
	return ToolChange{Tool: rec.name, Kind: classify(res.Events), Digest: live, State: res.Tool.State}, nil
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
// most significant wins: a tool that came back from deprecation also gets a
// fresh proposal, and that is a reappearance, not an ordinary change.
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
	case has[lifecycle.EvDeprecated]:
		return ChangeDeprecated
	case has[lifecycle.EvMissing]:
		return ChangeMissing
	case has[lifecycle.EvReverted]:
		return ChangeReverted
	case has[lifecycle.EvProposed]:
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
