package catalog

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	sqlite "modernc.org/sqlite" // the pure-Go SQLite driver, registered as "sqlite"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

const (
	driverName        = "sqlite"
	busyTimeoutMillis = 5000
	maxReadConns      = 8
	dbFileMode        = 0o600
	memoryPath        = ":memory:"
	walMode           = "wal"
	walRetryDelay     = 20 * time.Millisecond

	// Primary SQLite result codes that mean "someone else holds the lock".
	sqliteBusy   = 5
	sqliteLocked = 6

	// timeLayout is RFC 3339 in UTC with a fixed nine-digit fraction, so stored
	// timestamps sort lexically and round-trip exactly.
	timeLayout = "2006-01-02T15:04:05.000000000Z"
)

// ErrCorrupt means the database contradicts itself: a stored digest does not
// hash its canonical form, a pointer dangles, or a status disagrees with the
// tool row. Someone edited the file outside this package, or a bug wrote it.
// Callers must not serve from a corrupt catalog.
var ErrCorrupt = errors.New("catalog: database integrity check failed")

// Store is the catalog. Create one with Open and release it with Close.
//
// Writes go through a single connection so writers in one process queue up in
// the pool instead of fighting over the file lock; writers in other processes
// are handled by SQLite's busy timeout. Reads use separate read-only
// connections, so a slow reader never delays a writer (WAL).
type Store struct {
	wdb    *sql.DB
	rdb    *sql.DB
	policy lifecycle.Policy
	now    func() time.Time
}

// Open opens or creates the database at path. It enables WAL, foreign keys and
// a busy timeout, creates the schema, and refuses a database written by a newer
// schema version (ErrSchema). policy controls the lifecycle rules.
//
// A new file is created readable by its owner only: it holds the approval
// state and the audit log.
func Open(path string, policy lifecycle.Policy) (*Store, error) {
	if path == "" || path == memoryPath {
		return nil, fmt.Errorf("%w: a database file path is required", ErrInvalid)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("catalog: resolve database path: %w", err)
	}
	if err := createPrivateFile(abs); err != nil {
		return nil, fmt.Errorf("catalog: create database file: %w", err)
	}
	wdb, err := openPool(abs, true, 1)
	if err != nil {
		return nil, err
	}
	if err := prepareFile(context.Background(), wdb); err != nil {
		_ = wdb.Close()
		return nil, err
	}
	rdb, err := openPool(abs, false, maxReadConns)
	if err != nil {
		_ = wdb.Close()
		return nil, err
	}
	return &Store{wdb: wdb, rdb: rdb, policy: policy, now: time.Now}, nil
}

// Close releases the database.
func (s *Store) Close() error {
	return errors.Join(s.rdb.Close(), s.wdb.Close())
}

// Generation returns a counter that increases by at least one with every
// committed write, from any process. Readers poll it to know when to reload.
func (s *Store) Generation(ctx context.Context) (int64, error) {
	var gen int64
	err := s.inRead(ctx, func(q queryer) error {
		var err error
		gen, err = readGeneration(ctx, q)
		return err
	})
	return gen, err
}

func readGeneration(ctx context.Context, q queryer) (int64, error) {
	var gen int64
	err := q.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = 'generation'`).Scan(&gen)
	if err != nil {
		return 0, fmt.Errorf("%w: read generation: %v", ErrCorrupt, err)
	}
	return gen, nil
}

// queryer is the read half shared by *sql.Tx and txn, so one loader serves both
// read transactions and write transactions.
type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// inTx runs fn in one BEGIN IMMEDIATE transaction. Whatever fn did is committed
// together with exactly one generation bump, or rolled back if fn (or the bump)
// fails or panics.
func (s *Store) inTx(ctx context.Context, fn func(t *txn) error) error {
	sqlTx, err := s.wdb.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("catalog: begin write transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = sqlTx.Rollback() // the original error is what the caller needs
		}
	}()
	t := newTxn(sqlTx, s.now())
	if err := fn(t); err != nil {
		return err
	}
	if err := t.bumpGeneration(ctx); err != nil {
		return err
	}
	if err := sqlTx.Commit(); err != nil {
		return fmt.Errorf("catalog: commit: %w", err)
	}
	committed = true
	return nil
}

// inRead runs fn against one consistent snapshot of the database.
func (s *Store) inRead(ctx context.Context, fn func(q queryer) error) error {
	tx, err := s.rdb.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("catalog: begin read transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // a read transaction has nothing to commit
	return fn(tx)
}

func openPool(absPath string, writer bool, maxConns int) (*sql.DB, error) {
	db, err := sql.Open(driverName, dsnFor(absPath, writer))
	if err != nil {
		return nil, fmt.Errorf("catalog: open database: %w", err)
	}
	db.SetMaxOpenConns(maxConns)
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("catalog: open database: %w", err)
	}
	return db, nil
}

// dsnFor builds the connection string. The writer pool starts every
// transaction with BEGIN IMMEDIATE so that two processes cannot both read and
// then fail to upgrade to a write lock; the reader pool cannot write at all.
func dsnFor(absPath string, writer bool) string {
	q := url.Values{}
	q.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", busyTimeoutMillis))
	q.Add("_pragma", "foreign_keys(1)")
	if writer {
		q.Set("_txlock", "immediate")
	} else {
		q.Add("_pragma", "query_only(1)")
	}
	u := url.URL{Scheme: "file", Path: absPath, RawQuery: q.Encode()}
	return u.String()
}

// prepareFile refuses a newer database before touching it, switches the file
// to WAL and creates or checks the schema.
func prepareFile(ctx context.Context, db *sql.DB) error {
	var version int
	if err := db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("catalog: read schema version: %w", err)
	}
	if version < 0 || version > schemaVersion {
		return fmt.Errorf("%w: database is version %d, this build supports %d", ErrSchema, version, schemaVersion)
	}
	if err := enableWAL(ctx, db); err != nil {
		return err
	}
	return migrate(ctx, db)
}

// enableWAL switches the file to WAL. Converting a new file needs an exclusive
// lock, and SQLite reports SQLITE_BUSY at once instead of running the busy
// handler when several processes start on the same new file, so the losers
// retry until the winner has finished.
func enableWAL(ctx context.Context, db *sql.DB) error {
	deadline := time.Now().Add(busyTimeoutMillis * time.Millisecond)
	for {
		var mode string
		err := db.QueryRowContext(ctx, `PRAGMA journal_mode = WAL`).Scan(&mode)
		if err == nil {
			if !strings.EqualFold(mode, walMode) {
				return fmt.Errorf("catalog: the database must run in WAL mode to be shared, got %q", mode)
			}
			return nil
		}
		if !isBusy(err) || time.Now().After(deadline) {
			return fmt.Errorf("catalog: enable WAL: %w", err)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("catalog: enable WAL: %w", ctx.Err())
		case <-time.After(walRetryDelay):
		}
	}
}

func isBusy(err error) bool {
	var se *sqlite.Error
	if !errors.As(err, &se) {
		return false
	}
	code := se.Code() & 0xff // strip the extended result code
	return code == sqliteBusy || code == sqliteLocked
}

func createPrivateFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, dbFileMode)
	if err != nil {
		return err
	}
	return f.Close()
}

func formatTime(t time.Time) string { return t.UTC().Format(timeLayout) }

func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: bad timestamp %q", ErrCorrupt, s)
	}
	return t, nil
}
