package catalog

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// Audit events the catalog adds to the lifecycle's own.
const (
	evServerAdded    = "server.added"
	evCrawlCompleted = "crawl.completed"
	evCrawlFailed    = "crawl.failed"

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
// are the approved digest before and after the whole operation; the detail
// names the digest the event concerns and the state change, never tool text.
func (t *txn) auditTool(ctx context.Context, by Actor, server, tool string, before, after lifecycle.Tool, events []lifecycle.Event) error {
	for _, ev := range events {
		digest := ev.Digest
		if digest == "" {
			digest = noDigest
		}
		detail := fmt.Sprintf("digest=%s state=%s->%s", digest, before.State, after.State)
		if err := t.appendAudit(ctx, by, string(ev.Kind), server+"/"+tool, before.Approved, after.Approved, detail); err != nil {
			return err
		}
	}
	return nil
}

func queryAudit(ctx context.Context, q queryer, after int64, limit int) ([]audit.Entry, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT `+auditCols+` FROM audit_log WHERE seq > ? ORDER BY seq LIMIT ?`, after, limit)
	if err != nil {
		return nil, fmt.Errorf("catalog: read audit log: %w", err)
	}
	defer rows.Close()
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
