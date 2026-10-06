package export

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const (
	dirMode  os.FileMode = 0o755
	fileMode os.FileMode = 0o644

	// tmpPrefix starts with a dot, which no encoded name can, so a temporary
	// file never collides with an exported one and a leftover one can be
	// recognised and swept.
	tmpPrefix = ".tmp-"

	tmpRandomBytes = 8
)

// openExportRoot creates dir if needed, refuses it if it is a symlink or not a
// directory, and opens it as an os.Root. Every later operation goes through
// the Root, which the OS-level traversal rules confine to this directory even
// if an attacker swaps a path component for a symlink between a check and its
// use.
func openExportRoot(dir string) (*os.Root, error) {
	if dir == "" {
		return nil, errors.New("export: directory is empty")
	}
	clean := filepath.Clean(dir)
	if err := os.MkdirAll(clean, dirMode); err != nil {
		return nil, fmt.Errorf("export: create directory: %w", err)
	}
	fi, err := os.Lstat(clean)
	if err != nil {
		return nil, fmt.Errorf("export: stat directory: %w", err)
	}
	if fi.Mode()&fs.ModeSymlink != 0 || !fi.IsDir() {
		return nil, errors.New("export: directory is a symlink or not a directory")
	}
	root, err := os.OpenRoot(clean)
	if err != nil {
		return nil, fmt.Errorf("export: open directory: %w", err)
	}
	return root, nil
}

// checkDirShape refuses a server path that exists but is a symlink or not a
// directory; a missing one is fine. It is the check half of ensureDir, run
// before anything is written.
func checkDirShape(root *os.Root, name string) error {
	fi, err := root.Lstat(name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("export: stat server directory: %w", err)
	case fi.Mode()&fs.ModeSymlink != 0 || !fi.IsDir():
		return errors.New("export: server path is a symlink or not a directory")
	}
	return nil
}

// ensureDir makes sure name is a real directory directly inside root. A
// symlink or regular file in its place is refused, never followed or replaced.
func ensureDir(root *os.Root, name string) error {
	if err := checkDirShape(root, name); err != nil {
		return err
	}
	if _, err := root.Lstat(name); err == nil {
		return nil
	}
	if err := root.Mkdir(name, dirMode); err != nil {
		return fmt.Errorf("export: create server directory: %w", err)
	}
	// Mkdir is subject to the umask; chmod makes the mode predictable.
	if err := root.Chmod(name, dirMode); err != nil {
		return fmt.Errorf("export: set server directory mode: %w", err)
	}
	return nil
}

// sameContent reports whether rel already holds exactly want. A symlink or
// non-regular file at rel is an error, never something to overwrite through.
func sameContent(root *os.Root, rel string, want []byte) (exists, same bool, err error) {
	fi, err := root.Lstat(rel)
	if errors.Is(err, fs.ErrNotExist) {
		return false, false, nil
	}
	if err != nil {
		return false, false, fmt.Errorf("export: stat target: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return true, false, errors.New("export: target exists and is not a regular file")
	}
	if fi.Size() != int64(len(want)) {
		return true, false, nil
	}
	have, err := root.ReadFile(rel)
	if err != nil {
		return true, false, fmt.Errorf("export: read target: %w", err)
	}
	return true, bytes.Equal(have, want), nil
}

// randomSuffix returns unguessable hex for temporary file names.
func randomSuffix() (string, error) {
	buf := make([]byte, tmpRandomBytes)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", fmt.Errorf("export: random name: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// writeAtomic replaces rel with data so that a reader sees either the old file
// or the complete new one. The temporary file lives in the same directory so
// the rename cannot cross a file system; it is removed on every failure path,
// and one left behind by a crash is swept by the next Write. Directory
// metadata is not fsynced: the export is reproducible from the catalog, so a
// lost rename after power loss costs a re-run, not data.
func writeAtomic(root *os.Root, rel string, data []byte) (err error) {
	suffix, err := randomSuffix()
	if err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(filepath.FromSlash(rel)), tmpPrefix+suffix)
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
	if err != nil {
		return fmt.Errorf("export: create temp file: %w", err)
	}
	defer func() {
		if err != nil {
			// Best effort: the original error is the one worth reporting.
			_ = root.Remove(tmp)
		}
	}()
	if err = fillTemp(f, data); err != nil {
		return err
	}
	if err = root.Rename(tmp, filepath.FromSlash(rel)); err != nil {
		return fmt.Errorf("export: rename into place: %w", err)
	}
	return nil
}

// fillTemp writes, sets the mode, fsyncs and closes f. The mode is set
// explicitly because OpenFile's permission bits are masked by the umask.
func fillTemp(f *os.File, data []byte) error {
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("export: write temp file: %w", err)
	}
	if err := f.Chmod(fileMode); err != nil {
		_ = f.Close()
		return fmt.Errorf("export: chmod temp file: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("export: fsync temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("export: close temp file: %w", err)
	}
	return nil
}

// isStaleFile reports whether rel is a regular file inside a real directory,
// which is the only shape removeStale will delete.
func isStaleFile(root *os.Root, rel string) bool {
	dirName, _, _ := strings.Cut(rel, "/")
	dfi, err := root.Lstat(dirName)
	if err != nil || dfi.Mode()&fs.ModeSymlink != 0 || !dfi.IsDir() {
		return false
	}
	ffi, err := root.Lstat(filepath.FromSlash(rel))
	return err == nil && ffi.Mode().IsRegular()
}

// removeStale deletes the regular file at rel if its server directory is a
// real directory, then removes that directory if it is now empty. It reports
// whether a file was deleted; anything unexpected is skipped, not followed.
func removeStale(root *os.Root, rel string) (bool, error) {
	if !isStaleFile(root, rel) {
		return false, nil
	}
	if err := root.Remove(filepath.FromSlash(rel)); err != nil {
		return false, fmt.Errorf("export: remove stale file: %w", err)
	}
	dirName, _, _ := strings.Cut(rel, "/")
	if err := removeIfEmpty(root, dirName); err != nil {
		return true, err
	}
	return true, nil
}

// removeIfEmpty removes the directory name only when it holds no entries.
func removeIfEmpty(root *os.Root, name string) error {
	d, err := root.Open(name)
	if err != nil {
		return fmt.Errorf("export: open server directory: %w", err)
	}
	_, readErr := d.Readdirnames(1)
	closeErr := d.Close()
	if !errors.Is(readErr, io.EOF) {
		if readErr != nil {
			return fmt.Errorf("export: list server directory: %w", readErr)
		}
		return closeErr // not empty: keep it
	}
	if closeErr != nil {
		return fmt.Errorf("export: close server directory: %w", closeErr)
	}
	if err := root.Remove(name); err != nil {
		return fmt.Errorf("export: remove empty server directory: %w", err)
	}
	return nil
}

// listTemp returns the leftover temporary files directly inside dir, as
// slash-separated paths. Only regular files with the temp prefix count: a
// directory or symlink wearing the name is left alone. A missing dir, or one
// that is not a real directory, has no temp files.
func listTemp(root *os.Root, dir string) ([]string, error) {
	fi, err := root.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("export: stat directory: %w", err)
	}
	if fi.Mode()&fs.ModeSymlink != 0 || !fi.IsDir() {
		return nil, nil
	}
	d, err := root.Open(dir)
	if err != nil {
		return nil, fmt.Errorf("export: open directory: %w", err)
	}
	entries, readErr := d.ReadDir(-1)
	closeErr := d.Close()
	if readErr != nil {
		return nil, fmt.Errorf("export: list directory: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("export: close directory: %w", closeErr)
	}
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), tmpPrefix) && e.Type().IsRegular() {
			out = append(out, path.Join(dir, e.Name()))
		}
	}
	return out, nil
}

// sweepTemp deletes the listed leftover temporary files. One that vanished in
// the meantime is not an error.
func sweepTemp(root *os.Root, temps []string) error {
	for _, p := range temps {
		if err := root.Remove(filepath.FromSlash(p)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("export: remove leftover temp file: %w", err)
		}
	}
	return nil
}
