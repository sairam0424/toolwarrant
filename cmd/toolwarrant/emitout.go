package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/sairam0424/toolwarrant/internal/emit"
	"github.com/sairam0424/toolwarrant/internal/textdiff"
)

// What emit refuses to replace at --out (D17 j). Until the seventh review any
// regular file passed the --out check, the catalog database included: "emit
// --out <the --db path>" opened the catalog, staged the YAML next to it and
// renamed it over the database while the store still held the old inode,
// recorded the processor address into the unlinked inode and exited 0; every
// later command then refused the file and the only recovery was a backup
// (canary-5). The same went for the -wal and -shm siblings, for the gateway
// binary and for any other file the operator named by mistake.
const (
	// emitHeaderProbeBytes is how much of an existing --out is read to see
	// whether its first lines are the ones emit writes: the three comment
	// lines and the hash line are well under it.
	emitHeaderProbeBytes = 1024
	// SQLite keeps the write-ahead log and the shared-memory index of a
	// database next to it under these suffixes.
	walSuffix = "-wal"
	shmSuffix = "-shm"
)

// protectedFile is one file emit must never replace, with the words the
// refusal uses for it.
type protectedFile struct {
	path string
	what string
}

// protectedFiles lists the files emit must never replace: the catalog and its
// SQLite siblings, and the gateway binary when one is given.
func protectedFiles(dbPath, gatewayBinary string) []protectedFile {
	files := []protectedFile{
		{dbPath, "the catalog database (--db)"},
		{dbPath + walSuffix, "the catalog's write-ahead log"},
		{dbPath + shmSuffix, "the catalog's shared-memory index"},
	}
	if gatewayBinary != "" {
		files = append(files, protectedFile{gatewayBinary, "the gateway binary (--gateway-binary)"})
	}
	return files
}

// checkOut refuses an --out that must not be replaced, as a usage error naming
// the fix, before anything is read or written: a path that is the catalog
// database, one of its SQLite siblings or the gateway binary, compared by
// canonical path and, when the file exists, by identity (os.SameFile), so a
// relative spelling or a hard link is refused too, and so is a sibling that
// does not exist at that moment (SQLite removes the -wal and -shm files on a
// clean close; a configuration written into that slot is deleted by the next
// open, and the eighth review's live run saw emit exit 0 and the file vanish);
// and a regular file whose first lines are not the ones emit writes, because
// emit replaces only its own files. A file the gateway rewrote
// after a document was posted to its admin API keeps those lines and stays
// replaceable, so the documented re-emit after a CONFIG-EDITED still works. A
// missing --out is fine; refuseIrregularFile has already refused anything
// that is not a regular file.
func (o *emitOptions) checkOut(c *command, dbPath string) error {
	protected := protectedFiles(dbPath, o.gatewayBinary)
	for _, p := range protected {
		if samePath(o.out, p.path) {
			return o.protectedOutError(c, p)
		}
	}
	fi, err := os.Lstat(o.out)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("--out %s: %w", textdiff.Escape(o.out), err)
	}
	for _, p := range protected {
		pfi, err := os.Stat(p.path)
		if err == nil && os.SameFile(fi, pfi) {
			return o.protectedOutError(c, p)
		}
	}
	return refuseForeignOut(c, o.out)
}

// protectedOutError is the usage error for an --out that names a protected file.
func (o *emitOptions) protectedOutError(c *command, p protectedFile) error {
	return &usageError{msg: fmt.Sprintf("--out %s is %s; emit would replace it with the gateway configuration, so name another file", textdiff.Escape(o.out), p.what), cmd: c}
}

// samePath reports whether two spellings name the same path once each is made
// absolute and cleaned, with its directory resolved through symlinks when the
// directory exists. It needs no file at either path, which is what catches a
// SQLite sibling that is absent at the moment of the check.
func samePath(a, b string) bool {
	ca, okA := canonicalPath(a)
	cb, okB := canonicalPath(b)
	return okA && okB && ca == cb
}

// canonicalPath is the absolute, cleaned spelling of a path with its parent
// directory resolved through symlinks when that directory exists; false when
// the working directory cannot be determined.
func canonicalPath(p string) (string, bool) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", false
	}
	dir, base := filepath.Split(abs)
	if resolved, err := filepath.EvalSymlinks(filepath.Clean(dir)); err == nil {
		dir = resolved
	}
	return filepath.Join(dir, base), true
}

// refuseForeignOut refuses an existing regular file at --out whose first lines
// are not the generated-file header and hash line emit writes. The file is
// opened without following a link and without blocking, like every file the
// CLI reads by operator-given path, and only its head is read.
func refuseForeignOut(c *command, out string) error {
	head, err := readFileHead(out, emitHeaderProbeBytes)
	if err != nil {
		return fmt.Errorf("--out %s: %w", textdiff.Escape(out), err)
	}
	if hash, _ := emit.Verify(head); hash == "" {
		return &usageError{msg: fmt.Sprintf("--out %s exists and its first lines are not the header emit writes, so it is not a file emit wrote; emit replaces only its own files (a file the gateway rewrote keeps the header and is replaced), so move it away or name another file", textdiff.Escape(out)), cmd: c}
	}
	return nil
}

// readFileHead reads at most n bytes from the start of a regular file.
func readFileHead(path string, n int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("is %s, %w; name a regular file", describeFileType(fi.Mode()), errNotRegular)
	}
	head, err := io.ReadAll(io.LimitReader(f, n))
	if err != nil {
		return nil, err
	}
	return head, nil
}
