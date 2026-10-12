package catalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// Audit events the catalog adds to the lifecycle's own.
const (
	evServerAdded   = "server.added"
	evServerPaused  = "server.paused"
	evServerResumed = "server.resumed"
	// evServerProcessorSet records SetProcessorAddr: the processor address
	// emit assigned to the server. Its detail carries the address, so that
	// Integrity can compare servers.processor_addr with the log (D14).
	evServerProcessorSet = "server.processor_set"
	evCrawlCompleted     = "crawl.completed"
	evCrawlFailed        = "crawl.failed"
	// evToolRejected records a listed entry that no tool row describes: an
	// unknown name whose definition or name broke a rule. Its detail carries
	// the reason class and the quoted name, or a marker when the name itself
	// was refused.
	evToolRejected = "tool.rejected"
	// evBudgetReset records ResetProposalBudget: a person forgot the proposals a
	// tool gained since its last decision. Its detail is a plain tool detail;
	// the proposals field says how many were forgotten.
	evBudgetReset = "tool.budget_reset"

	noDigest    = "-" // the digest field of an event that concerns no version
	noLimit     = -1  // SQLite: a negative LIMIT means no limit
	auditPage   = 5000
	auditCols   = `seq, ts, actor, actor_type, event, subject, before_hash, after_hash, detail, prev_hash, hash`
	insertAudit = `INSERT INTO audit_log (` + auditCols + `) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	// firstPossibleSeq is where every read of the log from its start begins,
	// bound included: the smallest value the seq column can hold, so that a
	// row at seq 0 or below, which the catalog never writes (the chain starts
	// at seq 1), is read by the chain walks, by Integrity and by the listing
	// instead of being skipped by a bound of seq > 0, and is refused as a break
	// (D17 d; the seventh review placed a version.proposed entry at seq 0 that
	// no walk read while the decision path read it and refused every decision
	// on the tool; the eighth review planted one at this very value, which an
	// exclusive bound could not reach).
	firstPossibleSeq = math.MinInt64
)

func scanAudit(sc rowScanner) (audit.Entry, error) {
	var e audit.Entry
	err := sc.Scan(&e.Seq, &e.TS, &e.Actor, &e.ActorType, &e.Event, &e.Subject,
		&e.BeforeHash, &e.AfterHash, &e.Detail, &e.PrevHash, &e.Hash)
	return e, err
}

// appendAudit seals and stores one entry chained to the previous one: the
// verified head of the chain at the start of the transaction, or the entry
// appended before it.
func (t *txn) appendAudit(ctx context.Context, by Actor, event, subject, before, after, detail string) error {
	prev := t.last
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

// toolState is the part of a tool row that a tool detail records: the
// lifecycle state and the proposal budget (tools.proposals_since_decision).
// Two of them, before and after an operation, make one detail.
type toolState struct {
	tool   lifecycle.Tool
	budget int
}

// state returns what the record holds now, for a detail's before or after half.
func (r *toolRec) state() toolState { return toolState{tool: r.tool, budget: r.budget} }

// auditTool writes one entry per lifecycle event. before_hash and after_hash
// are the approved digest before and after the whole operation; the detail is
// a tool detail (toolDetail) followed by note (the reason class of an unusable
// observation), never tool text.
func (t *txn) auditTool(ctx context.Context, by Actor, server, tool string, before, after toolState,
	events []lifecycle.Event, note string) error {
	for _, ev := range events {
		detail := toolDetail(ev.Digest, before, after, note)
		if err := t.appendAudit(ctx, by, string(ev.Kind), server+"/"+tool, before.tool.Approved, after.tool.Approved, detail); err != nil {
			return err
		}
	}
	return nil
}

// The fields of a tool detail. Every entry about a tool (auditTool and the
// budget reset) starts with these four, in this order, as key=value tokens
// whose values never contain a space: digest is the version the event concerns
// (noDigest when none), state the transition A->B, last_seen what the upstream
// was last seen serving once the operation was done (a digest,
// lifecycle.UnusableDigest, or noDigest when the tool was absent), and
// proposals the transition A->B of the proposal budget
// (tools.proposals_since_decision). The last two exist so that Integrity can
// read the row an operation left behind and compare it with the mutable tools
// table: tool.missing and tool.unusable both concern no version, so the digest
// field alone would not say what last_seen became, and the budget is the one
// column no event names. A note of further key=value tokens may follow.
const (
	fieldDigest    = "digest"
	fieldState     = "state"
	fieldLastSeen  = "last_seen"
	fieldProposals = "proposals"
	// transitionArrow separates the before and after halves of the state and
	// proposals fields; Integrity compares the registry with the after half.
	transitionArrow = "->"
)

// The fields of a server detail: server.added carries the policy flag and a
// SHA-256 of the URL (never the URL, which can hold a credential in its query
// string), server.paused and server.resumed carry the paused flag, and
// server.processor_set carries the processor address (a host:port with no
// space in it, so it is one token). Integrity compares the servers row with
// them.
const (
	fieldAllowPrivate  = "allow_private"
	fieldURLSHA256     = "url_sha256"
	fieldPaused        = "paused"
	fieldProcessorAddr = "processor_addr"
)

// toolDetail renders the detail of one entry about a tool; see the field
// constants for the format Integrity relies on.
func toolDetail(digest string, before, after toolState, note string) string {
	return fmt.Sprintf("%s=%s %s=%s %s=%s %s=%s%s", fieldDigest, orNoDigest(digest),
		fieldState, transition(string(before.tool.State), string(after.tool.State)),
		fieldLastSeen, orNoDigest(after.tool.LastSeen),
		fieldProposals, transition(strconv.Itoa(before.budget), strconv.Itoa(after.budget)), note)
}

// transition renders a before and after value as one field value.
func transition(before, after string) string { return before + transitionArrow + after }

// transitionAfter returns the after half of a transition value, or false when
// the value is not one.
func transitionAfter(v string) (string, bool) {
	_, after, ok := strings.Cut(v, transitionArrow)
	return after, ok
}

// serverAddedDetail renders the detail of a server.added entry.
func serverAddedDetail(spec ServerSpec) string {
	return fmt.Sprintf("%s=%t %s=%s", fieldAllowPrivate, spec.AllowPrivate, fieldURLSHA256, urlSHA256(spec.URL))
}

// pausedDetail renders the detail of a server.paused or server.resumed entry.
func pausedDetail(paused bool) string { return fmt.Sprintf("%s=%t", fieldPaused, paused) }

// processorDetail renders the detail of a server.processor_set entry.
func processorDetail(addr string) string { return fmt.Sprintf("%s=%s", fieldProcessorAddr, addr) }

// urlSHA256 is how the log records a server URL: a hash that a rewritten URL
// no longer matches, which never discloses a credential the URL may carry.
func urlSHA256(url string) string {
	sum := sha256.Sum256([]byte(url))
	return hex.EncodeToString(sum[:])
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

// detailField returns the value of key in a detail: the token that starts
// with "key=". Values carry no space, and no token of a detail other than its
// fields contains '=' (a class token cannot, see isClassToken), so a split on
// spaces reads the field exactly.
func detailField(detail, key string) (string, bool) {
	for _, tok := range strings.Fields(detail) {
		if v, ok := strings.CutPrefix(tok, key+"="); ok {
			return v, true
		}
	}
	return "", false
}

// queryAudit reads up to limit entries whose seq is from or above, in order.
// The bound is inclusive so that a read from firstPossibleSeq, the smallest
// value the column can hold, misses no row: with an exclusive bound that one
// value was unreachable (eighth review).
func queryAudit(ctx context.Context, q queryer, from int64, limit int) ([]audit.Entry, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT `+auditCols+` FROM audit_log WHERE seq >= ? ORDER BY seq LIMIT ?`, from, limit)
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
// order. A limit of zero or less means no limit. An after of zero lists the
// table from its start, a row at seq 0 or below included: the catalog never
// writes one, so a forensic listing must show it (D17 d) rather than hide it
// behind a bound of seq > 0.
func (s *Store) AuditEntries(ctx context.Context, after int64, limit int) ([]audit.Entry, error) {
	if limit <= 0 {
		limit = noLimit
	}
	from := after + 1
	if after == 0 {
		from = firstPossibleSeq
	}
	var out []audit.Entry
	err := s.inRead(ctx, func(q queryer) error {
		var err error
		out, err = queryAudit(ctx, q, from, limit)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// VerifyAudit reads the whole log and checks the hash chain. A broken chain
// yields *audit.BrokenError, returned as is so callers can errors.As it. The
// log is streamed in pages and verified page by page (walkChain, the same walk
// a Store makes when it opens), so the cost in memory is one page, whatever
// the size of the log. The Store's own memory of the chain is not consulted:
// this is the operator's check of the file as it is.
func (s *Store) VerifyAudit(ctx context.Context) (AuditSummary, error) {
	var (
		head   chainPin
		walked int
	)
	err := s.inRead(ctx, func(q queryer) error {
		var err error
		head, walked, err = walkChain(ctx, q, chainPin{}, nil)
		return err
	})
	if err != nil {
		return AuditSummary{}, err
	}
	hash := head.hash
	if head.seq == 0 {
		hash = audit.Genesis
	}
	return AuditSummary{Entries: walked, Head: hash}, nil
}
