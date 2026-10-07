package catalog

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	sqlite "modernc.org/sqlite" // the pure-Go SQLite driver, registered as "sqlite"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

const (
	driverName = "sqlite"
	// DefaultBusyTimeout is how long a write waits for another process's lock.
	// A crawl of many changed tools can hold the lock for seconds; an
	// operator's approve in another process must wait for it, not fail.
	DefaultBusyTimeout = 30 * time.Second
	maxReadConns       = 8
	dbFileMode         = 0o600
	memoryPath         = ":memory:"
	walMode            = "wal"
	walRetryDelay      = 20 * time.Millisecond

	// Primary SQLite result codes that mean "someone else holds the lock".
	sqliteBusy   = 5
	sqliteLocked = 6

	// timeLayout is RFC 3339 in UTC with a fixed nine-digit fraction, so stored
	// timestamps sort lexically and round-trip exactly.
	timeLayout = "2006-01-02T15:04:05.000000000Z"
)

// OpenOptions configures OpenWith.
type OpenOptions struct {
	// Policy controls the lifecycle rules.
	Policy lifecycle.Policy
	// ReadOnly opens the file with SQLite's mode=ro and makes every mutating
	// method return ErrReadOnly. The database must exist and be in WAL mode
	// (every Open leaves it so). SQLite still needs the -shm file: it must
	// exist and be writable, or the directory must allow creating it; a
	// directory the reader cannot write to needs an existing -shm file.
	ReadOnly bool
	// MustExist makes a missing file ErrNotFound instead of creating it, so a
	// mistyped path cannot quietly become an empty catalog.
	MustExist bool
	// BusyTimeout is how long a write waits for another process's lock; zero
	// means DefaultBusyTimeout.
	BusyTimeout time.Duration
	// AllowSharedFile accepts an existing file that is readable by its group
	// or by others. Off by default: the file holds the approval state and the
	// audit log, and the WAL and SHM files inherit its mode.
	AllowSharedFile bool
	// Forensic opens a database of ours even when its guard triggers or
	// indexes are missing, which Open otherwise reports as ErrCorrupt. It is
	// for inspection after tampering: VerifyAudit can then name the broken
	// entry and the views can show the rows. It implies ReadOnly; nothing is
	// ever served or written from such an open.
	Forensic bool
}

// Store is the catalog. Create one with Open or OpenWith and release it with
// Close.
//
// Writes go through a single connection so writers in one process queue up in
// the pool instead of fighting over the file lock; writers in other processes
// are handled by SQLite's busy timeout. Reads use separate read-only
// connections, so a slow reader never delays a writer (WAL).
type Store struct {
	wdb      *sql.DB // nil when the store is read-only
	rdb      *sql.DB
	policy   lifecycle.Policy
	now      func() time.Time
	readOnly bool
	// verified remembers, for RecheckTTL, the version rows whose bytes a read
	// path re-checked; see verifier. Close drops it.
	verified *verifier
}

// Open opens or creates the database at path with the default options: read
// and write, create a missing file, DefaultBusyTimeout. It enables WAL,
// foreign keys and the busy timeout, creates the schema, and refuses a
// database written by another schema version (ErrSchema) or by another
// application. See OpenWith for the rules on the file itself.
func Open(path string, policy lifecycle.Policy) (*Store, error) {
	return OpenWith(path, OpenOptions{Policy: policy})
}

// OpenWith opens the database at path per opts. The file is checked before
// SQLite touches it: a symbolic link, a non-regular file, or a file readable by
// group or others (unless AllowSharedFile) is ErrInvalid; a missing file is
// created owner-only unless MustExist or ReadOnly (ErrNotFound). The schema
// version is checked before the journal mode is switched, so a foreign
// database is refused untouched.
func OpenWith(path string, opts OpenOptions) (*Store, error) {
	if path == "" || path == memoryPath {
		return nil, fmt.Errorf("%w: a database file path is required", ErrInvalid)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("catalog: resolve database path: %w", err)
	}
	if err := prepareDatabaseFile(abs, opts); err != nil {
		return nil, err
	}
	timeout := opts.BusyTimeout
	if timeout <= 0 {
		timeout = DefaultBusyTimeout
	}
	if opts.ReadOnly || opts.Forensic {
		return openReadOnly(abs, opts, timeout)
	}
	wdb, err := openPool(dsnFor(abs, connWriter, timeout), 1)
	if err != nil {
		return nil, err
	}
	if err := prepareFile(context.Background(), wdb, timeout); err != nil {
		_ = wdb.Close()
		return nil, err
	}
	rdb, err := openPool(dsnFor(abs, connReader, timeout), maxReadConns)
	if err != nil {
		_ = wdb.Close()
		return nil, err
	}
	return wireStore(wdb, rdb, opts), nil
}

// openReadOnly opens an existing WAL database through mode=ro connections only.
func openReadOnly(abs string, opts OpenOptions, timeout time.Duration) (*Store, error) {
	rdb, err := openPool(dsnFor(abs, connReadOnlyFile, timeout), maxReadConns)
	if err != nil {
		return nil, err
	}
	if err := checkReadOnlyFile(context.Background(), rdb, !opts.Forensic); err != nil {
		_ = rdb.Close()
		return nil, err
	}
	return wireStore(nil, rdb, opts), nil
}

// Close releases the database and drops the re-check memory.
func (s *Store) Close() error {
	s.verified.drop()
	var errs []error
	if s.rdb != nil {
		errs = append(errs, s.rdb.Close())
	}
	if s.wdb != nil {
		errs = append(errs, s.wdb.Close())
	}
	return errors.Join(errs...)
}

// ReadOnly reports whether the store was opened with OpenOptions.ReadOnly.
func (s *Store) ReadOnly() bool { return s.readOnly }

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

// queryer is the read half shared by *sql.Tx, *sql.DB and txn, so one loader
// serves read transactions, write transactions and the open-time checks.
type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// inTx runs fn in one BEGIN IMMEDIATE transaction. Whatever fn did is committed
// together with exactly one generation bump, or rolled back if fn (or the bump)
// fails or panics. A read-only store refuses before touching the database.
func (s *Store) inTx(ctx context.Context, fn func(t *txn) error) error {
	if s.readOnly || s.wdb == nil {
		return ErrReadOnly
	}
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

func openPool(dsn string, maxConns int) (*sql.DB, error) {
	db, err := sql.Open(driverName, dsn)
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

// connKind selects the connection string for one pool.
type connKind int

const (
	// connWriter starts every transaction with BEGIN IMMEDIATE so that two
	// processes cannot both read and then fail to upgrade to a write lock.
	connWriter connKind = iota
	// connReader cannot write (query_only) but shares the writable file handle
	// mode, so it can create the -shm file.
	connReader
	// connReadOnlyFile opens the file itself read-only (mode=ro) and is also
	// query_only; it never switches the journal mode or runs the migration.
	connReadOnlyFile
)

// dsnFor builds the connection string for one kind of connection.
func dsnFor(absPath string, kind connKind, timeout time.Duration) string {
	q := url.Values{}
	q.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", timeout.Milliseconds()))
	q.Add("_pragma", "foreign_keys(1)")
	switch kind {
	case connWriter:
		q.Set("_txlock", "immediate")
	case connReader:
		q.Add("_pragma", "query_only(1)")
	case connReadOnlyFile:
		q.Add("_pragma", "query_only(1)")
		q.Set("mode", "ro")
	}
	u := url.URL{Scheme: "file", Path: absPath, RawQuery: q.Encode()}
	return u.String()
}

// prepareFile decides whether the file is ours before changing anything about
// it: a foreign database, an empty file carrying other tables, or another
// schema version is refused with its journal mode untouched. Only then is the
// file switched to WAL and the schema created or checked.
func prepareFile(ctx context.Context, db *sql.DB, timeout time.Duration) error {
	version, err := readUserVersion(ctx, db)
	if err != nil {
		return err
	}
	switch version {
	case 0:
		objects, err := countObjects(ctx, db)
		if err != nil {
			return err
		}
		if objects > 0 {
			return fmt.Errorf("%w: the file holds another application's tables", ErrSchema)
		}
	case schemaVersion:
		if err := checkOurs(ctx, db, true); err != nil {
			return err
		}
	default:
		return schemaError(version)
	}
	if err := enableWAL(ctx, db, timeout); err != nil {
		return err
	}
	return migrate(ctx, db)
}

// checkReadOnlyFile verifies that a read-only open found a complete, WAL-mode
// database of ours. Nothing can be created or converted on this path. A
// forensic open skips the guard check (requireGuards false).
func checkReadOnlyFile(ctx context.Context, db *sql.DB, requireGuards bool) error {
	version, err := readUserVersion(ctx, db)
	if err != nil {
		return err
	}
	switch version {
	case 0:
		return fmt.Errorf("%w: the database is empty; initialise it with a read-write open first", ErrSchema)
	case schemaVersion:
		if err := checkOurs(ctx, db, requireGuards); err != nil {
			return err
		}
	default:
		return schemaError(version)
	}
	var mode string
	if err := db.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&mode); err != nil {
		return fmt.Errorf("catalog: read journal mode: %w", err)
	}
	if !strings.EqualFold(mode, walMode) {
		return fmt.Errorf("catalog: a read-only open needs a WAL-mode database, got %q; open it read-write once", mode)
	}
	return nil
}

// enableWAL switches the file to WAL. Converting a new file needs an exclusive
// lock, and SQLite reports SQLITE_BUSY at once instead of running the busy
// handler when several processes start on the same new file, so the losers
// retry until the winner has finished.
func enableWAL(ctx context.Context, db *sql.DB, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
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

func formatTime(t time.Time) string { return t.UTC().Format(timeLayout) }

func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: bad timestamp %q", ErrCorrupt, s)
	}
	return t, nil
}
