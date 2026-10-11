package catalog

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/sairam0424/toolwarrant/internal/audit"
)

// txn is one write transaction. Every row written in it carries the same
// timestamp, and audit entries are chained from the head of the chain the
// Store verified at the start of the transaction (chainFrom), which holds the
// write lock, so no other writer can slip an entry in between and no hash is
// read back from the file to chain from.
type txn struct {
	*sql.Tx
	stamp time.Time
	ts    string
	stmts map[string]*sql.Stmt
	// last is the entry the next appended entry chains from: the verified
	// head at first, then each entry appended here.
	last audit.Entry
}

func newTxn(tx *sql.Tx, now time.Time) *txn {
	ts := formatTime(now)
	// Round-trip the instant so values returned to callers equal the stored text.
	stamp, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		stamp = now.UTC()
	}
	return &txn{Tx: tx, stamp: stamp, ts: ts, stmts: make(map[string]*sql.Stmt)}
}

// chainFrom sets the entry the first appended audit entry chains from: the
// head of the verified chain (the zero pin for an empty log, which Seal reads
// as the genesis).
func (t *txn) chainFrom(head chainPin) {
	t.last = audit.Entry{Seq: head.seq, Hash: head.hash}
}

// exec runs a statement, preparing it once per transaction: a crawl of many
// tools repeats the same few statements thousands of times.
func (t *txn) exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	st, ok := t.stmts[query]
	if !ok {
		var err error
		if st, err = t.PrepareContext(ctx, query); err != nil {
			return nil, err
		}
		t.stmts[query] = st
	}
	return st.ExecContext(ctx, args...)
}

// insert runs an INSERT and returns the new row id.
func (t *txn) insert(ctx context.Context, query string, args ...any) (int64, error) {
	res, err := t.exec(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("catalog: read new row id: %w", err)
	}
	return id, nil
}

// bumpGeneration makes every committed write visible to pollers.
func (t *txn) bumpGeneration(ctx context.Context) error {
	res, err := t.exec(ctx, `UPDATE meta SET value = value + 1 WHERE key = 'generation'`)
	if err != nil {
		return fmt.Errorf("catalog: bump generation: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return fmt.Errorf("%w: generation counter is missing", ErrCorrupt)
	}
	return nil
}
