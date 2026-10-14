package catalog

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// The connection strings and the open-time checks of the three ways a file is
// opened: read-write (the CLI), read-only (the processor) and forensic (audit
// verify and audit list on a file someone edited).

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
	// connImmutableFile is connReadOnlyFile with immutable=1: SQLite takes no
	// lock and reads no journal, so a database whose journal mode was switched
	// away from WAL by whoever tampered with it can still be inspected
	// (forensic opens only, D14). Nothing written by another process while
	// such a connection is open is guaranteed to be seen.
	connImmutableFile
)

// synchronousFull is the synchronous level every connection runs at, spelled
// as the DSN carries it. FULL is SQLite's compile-time default and is pinned
// here on purpose (owner decision O-3 of the 2026-10-14 plan): in WAL mode it
// syncs the WAL file after every commit, which is what makes a decision whose
// command returned durable across a power loss and not only across a crash of
// the process; NORMAL syncs only around checkpoints and may lose the newest
// commits with the power. It changes only after a measured benchmark on the
// target file system.
const synchronousFull = "FULL"

// dsnFor builds the connection string for one kind of connection. The pragmas
// travel in the DSN because the driver runs them on every connection the pool
// opens; a PRAGMA run through Exec would reach the one pooled connection that
// ran it and leave the others as they were. synchronous and foreign_keys are
// set for every kind alike: they are harmless on a query_only or immutable
// connection, which never commits, and that uniformity is what
// TestOpen_EveryPooledConnectionIsSynchronousFullWithForeignKeysInWAL reads
// back from every connection of every pool.
func dsnFor(absPath string, kind connKind, timeout time.Duration) string {
	q := url.Values{}
	q.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", timeout.Milliseconds()))
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "synchronous("+synchronousFull+")")
	switch kind {
	case connWriter:
		q.Set("_txlock", "immediate")
	case connReader:
		q.Add("_pragma", "query_only(1)")
	case connReadOnlyFile:
		q.Add("_pragma", "query_only(1)")
		q.Set("mode", "ro")
	case connImmutableFile:
		q.Add("_pragma", "query_only(1)")
		q.Set("mode", "ro")
		q.Set("immutable", "1")
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
		if err := checkEmptyFile(ctx, db); err != nil {
			return err
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

// checkEmptyFile accepts a file at version 0 only when it holds no object at
// all. Several processes may open one new file together, and another opener
// can commit the schema between the two reads, so a file that gained objects
// is re-read: at our version it is ours and checked as such, at any other it
// holds another application's tables.
func checkEmptyFile(ctx context.Context, db *sql.DB) error {
	objects, err := countObjects(ctx, db)
	if err != nil || objects == 0 {
		return err
	}
	version, err := readUserVersion(ctx, db)
	if err != nil {
		return err
	}
	if version != schemaVersion {
		return fmt.Errorf("%w: the file holds another application's tables", ErrSchema)
	}
	return checkOurs(ctx, db, true)
}

// openReadOnly opens an existing database through mode=ro connections only. A
// read-only open needs a WAL-mode file; a forensic open of a file in another
// journal mode is reopened with immutable=1 instead of being refused, because
// the one who tampered with the file could otherwise lock the inspection out
// with a single PRAGMA (D14).
func openReadOnly(abs string, opts OpenOptions, timeout time.Duration) (*Store, error) {
	rdb, err := openPool(dsnFor(abs, connReadOnlyFile, timeout), maxReadConns)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	mode, err := checkReadOnlyFile(ctx, rdb, !opts.Forensic)
	if err != nil {
		_ = rdb.Close()
		return nil, err
	}
	switch {
	case strings.EqualFold(mode, walMode):
	case !opts.Forensic:
		_ = rdb.Close()
		return nil, fmt.Errorf("catalog: a read-only open needs a WAL-mode database, got %q; open it read-write once", mode)
	default:
		_ = rdb.Close()
		if rdb, err = openPool(dsnFor(abs, connImmutableFile, timeout), maxReadConns); err != nil {
			return nil, err
		}
	}
	return wireStore(nil, rdb, abs, opts), nil
}

// checkReadOnlyFile verifies that a read-only open found a complete database
// of ours and returns its journal mode. Nothing can be created or converted on
// this path. A forensic open skips the guard check (requireGuards false).
func checkReadOnlyFile(ctx context.Context, db *sql.DB, requireGuards bool) (string, error) {
	version, err := readUserVersion(ctx, db)
	if err != nil {
		return "", err
	}
	switch version {
	case 0:
		return "", fmt.Errorf("%w: the database is empty; initialise it with a read-write open first", ErrSchema)
	case schemaVersion:
		if err := checkOurs(ctx, db, requireGuards); err != nil {
			return "", err
		}
	default:
		return "", schemaError(version)
	}
	var mode string
	if err := db.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&mode); err != nil {
		return "", fmt.Errorf("catalog: read journal mode: %w", err)
	}
	return mode, nil
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
