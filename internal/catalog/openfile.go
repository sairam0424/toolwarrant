package catalog

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"runtime"
)

// The database file holds the approval state and the audit log. These checks
// run before SQLite opens it, so that a planted symbolic link cannot redirect
// where the private file is created, and a file that other users can read is
// refused instead of being written to (its WAL and SHM files would inherit the
// mode, exposing even entries written later).

// sharedBits are the permission bits that give group or others any access.
const sharedBits = 0o077

// prepareDatabaseFile checks an existing file or creates a private one. Only
// an init-style open (neither MustExist, ReadOnly nor Forensic) may create: a
// reader, and above all an inspection of a tampered catalog, must never leave
// a new file behind at a path it was pointed at.
func prepareDatabaseFile(abs string, opts OpenOptions) error {
	fi, err := os.Lstat(abs)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if opts.MustExist || opts.ReadOnly || opts.Forensic {
			return fmt.Errorf("%w: database file %s does not exist", ErrNotFound, abs)
		}
		return createPrivateFile(abs, opts)
	case err != nil:
		return fmt.Errorf("catalog: inspect database file: %w", err)
	}
	return checkExistingFile(abs, fi, opts)
}

// checkExistingFile refuses anything but a regular file with a private mode.
func checkExistingFile(abs string, fi fs.FileInfo, opts OpenOptions) error {
	if fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%w: database path %s is a symbolic link; name the file itself", ErrInvalid, abs)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: database path %s is not a regular file", ErrInvalid, abs)
	}
	return checkFileMode(abs, fi.Mode(), opts)
}

// checkFileMode refuses a file that group or others can reach. Windows has no
// POSIX permission bits to check.
func checkFileMode(abs string, mode fs.FileMode, opts OpenOptions) error {
	if opts.AllowSharedFile || runtime.GOOS == "windows" {
		return nil
	}
	if perm := mode.Perm(); perm&sharedBits != 0 {
		return fmt.Errorf("%w: database file %s is readable by other users (mode %04o); it holds the approval state and the audit log, so chmod 600 it or open it with AllowSharedFile", ErrInvalid, abs, perm)
	}
	return nil
}

// createPrivateFile creates the file owner-only without following a symbolic
// link, then re-checks what it opened: a file that appeared in between with a
// wider mode is refused the same way as a pre-existing one.
func createPrivateFile(abs string, opts OpenOptions) error {
	f, err := os.OpenFile(abs, os.O_RDWR|os.O_CREATE|openNoFollow, dbFileMode)
	if err != nil {
		return fmt.Errorf("catalog: create database file: %w", err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("catalog: inspect database file: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: database path %s is not a regular file", ErrInvalid, abs)
	}
	return checkFileMode(abs, fi.Mode(), opts)
}
