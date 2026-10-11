package catalog

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// Which file a Store is reading (D14). A Store holds the database by its open
// descriptor, so after the operator deletes the file and runs init again, or
// restores another catalog at the same path, a long-lived reader (the
// processor) would keep serving the approvals of the file that no longer
// exists at the path, its generation never moving. Two facts recorded at open
// catch that: the device and inode of the file (the path names another file
// once they differ, or no file at all) and the catalog identity, a random
// value init writes into meta once (the file at the path was initialised by
// another init once it differs, even when it was copied over the same inode).
// Generation compares both on every call and returns ErrReplaced, which wraps
// ErrCorrupt, so the processor denies everything and logs the error.

// Keys of the meta table.
const (
	metaGeneration = "generation"
	metaIdentity   = "identity"
	// identityBytes is the length of the random identity: 128 bits, written
	// as 32 hex characters.
	identityBytes = 16
)

// newIdentity draws the catalog identity for a fresh schema.
func newIdentity() (string, error) {
	var buf [identityBytes]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("catalog: draw catalog identity: %w", err)
	}
	return hex.EncodeToString(buf[:]), nil
}

// fileID identifies a file by device and inode. known is false where the
// platform does not expose them (store_other.go); only the identity is
// compared then.
type fileID struct {
	dev, ino uint64
	known    bool
}

// readIdentity reads the catalog identity from meta. A database of this
// schema version always has one, written with the schema; a missing or
// malformed row means the file was edited.
func readIdentity(ctx context.Context, q queryer) (string, error) {
	var identity string
	err := q.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, metaIdentity).Scan(&identity)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", fmt.Errorf("%w: the catalog identity is missing from meta", ErrCorrupt)
	case err != nil:
		return "", fmt.Errorf("%w: read catalog identity: %v", ErrCorrupt, err)
	}
	if len(identity) != 2*identityBytes || !isHex(identity) {
		return "", fmt.Errorf("%w: the catalog identity is not %d hex characters", ErrCorrupt, 2*identityBytes)
	}
	return identity, nil
}

// adoptIdentity records what the Store opened: the identity in meta and the
// device and inode of the file at its path. A forensic open tolerates a
// missing or malformed identity, since the file under inspection may have
// been edited there too; Generation then compares the file alone.
func (s *Store) adoptIdentity(ctx context.Context, forensic bool) error {
	err := s.inRead(ctx, func(q queryer) error {
		identity, err := readIdentity(ctx, q)
		if err != nil {
			return err
		}
		s.identity = identity
		return nil
	})
	if err != nil && !forensic {
		return err
	}
	id, err := statFile(s.path)
	if err != nil {
		return err
	}
	s.file = id
	return nil
}

// statFile returns the device and inode of the file at path.
func statFile(path string) (fileID, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return fileID{}, fmt.Errorf("catalog: inspect database file: %w", err)
	}
	return fileIDOf(fi), nil
}

// checkFileIdentity requires the file at the Store's path to be the one it
// opened. The path is checked by name on purpose: the open descriptor always
// finds its own file, which is exactly what a replaced file hides.
func (s *Store) checkFileIdentity() error {
	fi, err := os.Stat(s.path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("%w: %s no longer exists; this store still holds the deleted file", ErrReplaced, s.path)
	case err != nil:
		return fmt.Errorf("catalog: inspect database file: %w", err)
	}
	if now := fileIDOf(fi); now.known && s.file.known && now != s.file {
		return fmt.Errorf("%w: %s is another file than the one this store opened; restart on the new file", ErrReplaced, s.path)
	}
	return nil
}

// checkStoredIdentity requires the identity in meta to be the one read at
// open, within the caller's read transaction. A forensic open that found none
// has nothing to compare.
func (s *Store) checkStoredIdentity(ctx context.Context, q queryer) error {
	if s.identity == "" {
		return nil
	}
	identity, err := readIdentity(ctx, q)
	if err != nil {
		return err
	}
	if identity != s.identity {
		return fmt.Errorf("%w: %s carries another catalog identity than the one this store opened; restart on the new file", ErrReplaced, s.path)
	}
	return nil
}
