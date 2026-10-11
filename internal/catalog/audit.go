package catalog

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// Audit events the catalog adds to the lifecycle's own.
const (
	evServerAdded    = "server.added"
	evServerPaused   = "server.paused"
	evServerResumed  = "server.resumed"
	evCrawlCompleted = "crawl.completed"
	evCrawlFailed    = "crawl.failed"
	// evToolRejected records a listed entry that no tool row describes: an
	// unknown name whose definition or name broke a rule. Its detail carries
	// the reason class and the quoted name, or a marker when the name itself
	// was refused.
	evToolRejected = "tool.rejected"
	// evBudgetReset records ResetProposalBudget: a person forgot the proposals a
	// tool gained since its last decision. Its detail is a tool detail whose
	// note says how many were forgotten.
	evBudgetReset = "tool.budget_reset"

	noDigest    = "-" // the digest field of an event that concerns no version
	noLimit     = -1  // SQLite: a negative LIMIT means no limit
	auditPage   = 5000
	auditCols   = `seq, ts, actor, actor_type, event, subject, before_hash, after_hash, detail, prev_hash, hash`
	insertAudit = `INSERT INTO audit_log (` + auditCols + `) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
)

func scanAudit(sc rowScanner) (audit.Entry, error) {
	var e audit.Entry
	err := sc.Scan(&e.Seq, &e.TS, &e.Actor, &e.ActorType, &e.Event, &e.Subject,
		&e.BeforeHash, &e.AfterHash, &e.Detail, &e.PrevHash, &e.Hash)
	return e, err
}

// lastEntry reads the newest audit entry inside this transaction. The write
// lock is already held, so no other writer can append until we commit.
func (t *txn) lastEntry(ctx context.Context) (audit.Entry, error) {
	if t.hasLast {
		return t.last, nil
	}
	e, err := scanAudit(t.QueryRowContext(ctx, `SELECT `+auditCols+` FROM audit_log ORDER BY seq DESC LIMIT 1`))
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return audit.Entry{}, fmt.Errorf("catalog: read audit head: %w", err)
	}
	t.last, t.hasLast = e, true
	return e, nil
}

// appendAudit seals and stores one entry chained to the previous one.
func (t *txn) appendAudit(ctx context.Context, by Actor, event, subject, before, after, detail string) error {
	prev, err := t.lastEntry(ctx)
	if err != nil {
		return err
	}
	sealed, err := audit.Seal(prev, audit.Entry{
		Seq: prev.Seq + 1, TS: t.ts, Actor: by.Name, ActorType: string(by.Type),
		Event: event, Subject: subject, BeforeHash: before, AfterHash: after, Detail: detail,
	})
	if err != nil {
		return fmt.Errorf("catalog: seal audit entry: %w", err)
	}
	if _, err := t.exec(ctx, insertAudit, sealed.Seq, sealed.TS, sealed.Actor, sealed.ActorType,
		sealed.Event, sealed.Subject, sealed.BeforeHash, sealed.AfterHash, sealed.Detail,
		sealed.PrevHash, sealed.Hash); err != nil {
		return fmt.Errorf("catalog: append audit entry: %w", err)
	}
	t.last = sealed
	return nil
}

// auditTool writes one entry per lifecycle event. before_hash and after_hash
// are the approved digest before and after the whole operation; the detail is
// a tool detail (toolDetail) followed by note (the reason class of an unusable
// observation), never tool text.
func (t *txn) auditTool(ctx context.Context, by Actor, server, tool string, before, after lifecycle.Tool,
	events []lifecycle.Event, note string) error {
	for _, ev := range events {
		detail := toolDetail(ev.Digest, before, after, note)
		if err := t.appendAudit(ctx, by, string(ev.Kind), server+"/"+tool, before.Approved, after.Approved, detail); err != nil {
			return err
		}
	}
	return nil
}

// The fields of a tool detail. Every entry about a tool (auditTool and the
// budget reset) starts with these three, in this order, as key=value tokens
// whose values never contain a space: digest is the version the event concerns
// (noDigest when none), state the transition, last_seen what the upstream was
// last seen serving once the operation was done (a digest,
// lifecycle.UnusableDigest, or noDigest when the tool was absent). The last
// field exists so that Integrity can read the state an operation left behind
// and compare it with the mutable tools row: tool.missing and tool.unusable
// both concern no version, so the digest field alone would not say what
// last_seen became. A note of further key=value tokens may follow.
const (
	fieldDigest   = "digest"
	fieldState    = "state"
	fieldLastSeen = "last_seen"
)

// toolDetail renders the detail of one entry about a tool; see the field
// constants for the format Integrity relies on.
func toolDetail(digest string, before, after lifecycle.Tool, note string) string {
	return fmt.Sprintf("%s=%s %s=%s->%s %s=%s%s", fieldDigest, orNoDigest(digest),
		fieldState, before.State, after.State, fieldLastSeen, orNoDigest(after.LastSeen), note)
}

// orNoDigest renders an empty digest or last-seen value as noDigest, so that
// every field of a detail has a value.
func orNoDigest(s string) string {
	if s == "" {
		return noDigest
	}
	return s
}

// isToolDetail reports whether a detail was written by toolDetail: it starts
// with the digest field. Entries about a server, a crawl or a rejected entry
// do not.
func isToolDetail(detail string) bool { return strings.HasPrefix(detail, fieldDigest+"=") }

// detailField returns the value of key in a tool detail: the token that starts
// with "key=". Values carry no space, and no token of a tool detail other than
// its fields contains '=' (a class token cannot, see isClassToken), so a split
// on spaces reads the field exactly.
func detailField(detail, key string) (string, bool) {
	for _, tok := range strings.Fields(detail) {
		if v, ok := strings.CutPrefix(tok, key+"="); ok {
			return v, true
		}
	}
	return "", false
}

func queryAudit(ctx context.Context, q queryer, after int64, limit int) ([]audit.Entry, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT `+auditCols+` FROM audit_log WHERE seq > ? ORDER BY seq LIMIT ?`, after, limit)
	if err != nil {
		return nil, fmt.Errorf("catalog: read audit log: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []audit.Entry{}
	for rows.Next() {
		e, err := scanAudit(rows)
		if err != nil {
			return nil, fmt.Errorf("catalog: read audit log: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AuditEntries returns up to limit entries with Seq greater than after, in
// order. A limit of zero or less means no limit.
func (s *Store) AuditEntries(ctx context.Context, after int64, limit int) ([]audit.Entry, error) {
	if limit <= 0 {
		limit = noLimit
	}
	var out []audit.Entry
	err := s.inRead(ctx, func(q queryer) error {
		var err error
		out, err = queryAudit(ctx, q, after, limit)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// VerifyAudit reads the whole log and checks the hash chain. A broken chain
// yields *audit.BrokenError, returned as is so callers can errors.As it.
//
// Memory: the log is read in pages but held whole for audit.Verify, so the
// cost is one Entry (a few hundred bytes; details are short and never carry
// tool text) per event ever recorded. A catalog of ten thousand tools crawled
// daily for a year is on the order of a hundred megabytes; an operator
// verifying a log that large should expect that.
func (s *Store) VerifyAudit(ctx context.Context) (AuditSummary, error) {
	var entries []audit.Entry
	err := s.inRead(ctx, func(q queryer) error {
		for after := int64(0); ; {
			page, err := queryAudit(ctx, q, after, auditPage)
			if err != nil {
				return err
			}
			entries = append(entries, page...)
			if len(page) < auditPage {
				return nil
			}
			after = page[len(page)-1].Seq
		}
	})
	if err != nil {
		return AuditSummary{}, err
	}
	if err := audit.Verify(entries); err != nil {
		return AuditSummary{}, err
	}
	return AuditSummary{Entries: len(entries), Head: audit.Head(entries)}, nil
}
