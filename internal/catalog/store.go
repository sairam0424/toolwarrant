package catalog

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
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

	// Primary SQLite result codes that mean "someone else holds the lock", and
	// the one that means a constraint or a guard trigger refused a write.
	sqliteBusy       = 5
	sqliteLocked     = 6
	sqliteConstraint = 19
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
	// indexes are missing, which Open otherwise reports as ErrCorrupt, and
	// even when its journal mode is no longer WAL (then with immutable=1, so
	// SQLite needs neither a lock nor a journal). It is for inspection after
	// tampering: VerifyAudit can then name the broken entry, Integrity can
	// list every disagreement, AuditEntries can show the log, and the views
	// read past the guard check too, while still refusing a row whose
	// approval evidence fails. It implies ReadOnly and MustExist (a missing
	// file is ErrNotFound, never created); nothing is ever served or written
	// from such an open.
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
	// forensic is set by OpenOptions.Forensic: the reads skip the guard check
	// that Open skipped.
	forensic bool
	// chain is what this Store knows about the audit chain it verified: the
	// head it pinned and the hash of every decision entry it walked (chain.go,
	// D15). Every serving-path read and every write transaction extends it to
	// the current head and trusts an audit entry only through it. Close drops
	// it.
	chain *chainMemory
	// caps are the per-server growth limits RecordCrawl enforces: the
	// constants MaxToolsPerServer and MaxServerBytes, except in tests.
	caps serverCaps
	// path, identity and file say which catalog this Store opened: the
	// absolute path, the identity meta value read at open and the device and
	// inode of the file. Generation compares them with the path (identity.go).
	path     string
	identity string
	file     fileID
}

// Open opens or creates the database at path with the default options: read
// and write, create a missing file, DefaultBusyTimeout. It enables WAL, and on
// every connection synchronous FULL, foreign keys and the busy timeout
// (dsnFor), creates the schema, and refuses a database written by another
// schema version (ErrSchema) or by another application. See OpenWith for the
// rules on the file itself.
func Open(path string, policy lifecycle.Policy) (*Store, error) {
	return OpenWith(path, OpenOptions{Policy: policy})
}

// OpenWith opens the database at path per opts. The file is checked before
// SQLite touches it: a symbolic link, a non-regular file, or a file readable by
// group or others (unless AllowSharedFile) is ErrInvalid; a missing file is
// created owner-only unless MustExist, ReadOnly or Forensic (ErrNotFound). The schema
// version is checked before the journal mode is switched, so a foreign
// database is refused untouched. The Store records the catalog identity and
// the file it opened, so that Generation can tell when the path names another
// file (ErrReplaced), and then verifies the whole audit chain once and pins
// its head (D15 a): a broken chain is ErrCorrupt at open, except on a forensic
// open, which exists to inspect such a file and verifies lazily on the views.
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
	s, err := openPools(abs, opts, timeout)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	if err := s.adoptIdentity(ctx, opts.Forensic); err != nil {
		_ = s.Close()
		return nil, err
	}
	if !opts.Forensic {
		if err := s.inRead(ctx, func(q queryer) error { return s.verifyChain(ctx, q) }); err != nil {
			_ = s.Close()
			return nil, err
		}
	}
	return s, nil
}

// openPools opens the connection pools for the requested mode and wires the Store.
func openPools(abs string, opts OpenOptions, timeout time.Duration) (*Store, error) {
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
	return wireStore(wdb, rdb, abs, opts), nil
}

// Close releases the database and drops the memory of the chain.
func (s *Store) Close() error {
	s.chain.drop()
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
// Before the counter is read, the file at the Store's path must still be the
// file it opened and carry the identity it read at open: a reader whose file
// was deleted and re-initialised, or replaced by another catalog, would
// otherwise keep serving the old file's approvals from its open descriptor
// (ErrReplaced, D14).
func (s *Store) Generation(ctx context.Context) (int64, error) {
	if err := s.checkFileIdentity(); err != nil {
		return 0, err
	}
	var gen int64
	err := s.inRead(ctx, func(q queryer) error {
		if err := s.checkStoredIdentity(ctx, q); err != nil {
			return err
		}
		var err error
		gen, err = readGeneration(ctx, q)
		return err
	})
	return gen, err
}

func readGeneration(ctx context.Context, q queryer) (int64, error) {
	var gen int64
	err := q.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, metaGeneration).Scan(&gen)
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
//
// The history tables must hold no row below id 1 (checkGhostRows, D17 b) and
// the audit chain is verified first (verifyChain, D15): the suffix appended
// since this Store last looked must continue the chain it verified, the memory
// is extended to the head, and the entries fn appends are chained from that
// verified head rather than from a hash column read back from the file. The
// guard objects are verified before the commit (verifyGuards): a crawl
// scheduled every minute must not keep writing crawls, tool state and audit
// entries into a file whose immutability triggers were dropped after it
// opened, and a trigger of someone else's making must not get to rewrite the
// policy inside the catalog's own transaction. The write lock is held from
// the first statement, so what the checks see is what the file held
// throughout, and nothing commits into a file a check refuses. A constraint
// failure inside fn is ErrCorrupt: the Store validates everything before it
// writes, so a constraint that still fires is one the schema does not have (a
// unique index someone added, a table re-created with another constraint) or
// a guard refusing a row, never a condition a retry or a later crawl could
// meet (D14); the error names the table and constraint SQLite reports.
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
	if err := checkGhostRows(ctx, t); err != nil {
		return err
	}
	if err := s.verifyChain(ctx, t); err != nil {
		return err
	}
	t.chainFrom(s.chain.pin())
	if err := fn(t); err != nil {
		return corruptIfConstraint(err)
	}
	if err := verifyGuards(ctx, t); err != nil {
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

// sqliteCode returns the primary result code of a SQLite error, or -1 when err
// is not one.
func sqliteCode(err error) int {
	var se *sqlite.Error
	if !errors.As(err, &se) {
		return -1
	}
	return se.Code() & 0xff // strip the extended result code
}

func isBusy(err error) bool {
	code := sqliteCode(err)
	return code == sqliteBusy || code == sqliteLocked
}

// corruptIfConstraint turns a constraint failure into ErrCorrupt (see inTx);
// every other error, and an error that already is ErrCorrupt, passes through.
func corruptIfConstraint(err error) error {
	if errors.Is(err, ErrCorrupt) || sqliteCode(err) != sqliteConstraint {
		return err
	}
	return fmt.Errorf("%w: %s; the file was edited outside toolwarrant", ErrCorrupt, describeConstraint(err))
}

func formatTime(t time.Time) string { return t.UTC().Format(timeLayout) }

func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: bad timestamp %q", ErrCorrupt, s)
	}
	return t, nil
}
