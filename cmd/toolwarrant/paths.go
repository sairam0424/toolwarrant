package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Rules for the files the CLI opens by operator-given path. A path is hostile
// until its final component has been looked at: whoever can write the
// directory of a file can plant a named pipe where the file was (open then
// blocks until a writer appears and the command prints nothing, exits nothing
// and ignores the signals it handles, fourth review cli-docs-2), a device, a
// socket, or a symbolic link that redirects the read or the write elsewhere.
// Every refusal below embeds the path as the operator gave it: the sentence is
// escaped once where it is printed (describe for an error on stderr, readConfig
// for the canary's verdict), so a control character in a path shows as one
// \u{HEX} and never as a doubled backslash.
const (
	// maxEmittedFileBytes bounds the emitted configuration file the canary
	// reads. The emitter's own output for the per-server caps stays far below
	// it; the bound exists so that a replaced file cannot make the canary
	// read without limit.
	maxEmittedFileBytes = 64 << 20
	// The kinds of file readRegularFile names in its size refusal.
	emittedFileNoun  = "emitted file"
	pemFileNoun      = "PEM file"
	pemPublicKeyNoun = "PEM public key file"
	// rootUID owns the symbolic links an operating system installs in its own
	// directories (on macOS /var and /tmp are links into /private). A link
	// nobody but root could have made is not one planted in a shared working
	// directory.
	rootUID = 0
)

// errNotRegular is why a path was refused: the directory entry is not a
// regular file. Callers wrap it with the path and what to do.
var errNotRegular = errors.New("not a regular file")

// describeFileType names what a directory entry is, for a refusal.
func describeFileType(mode fs.FileMode) string {
	switch {
	case mode&fs.ModeSymlink != 0:
		return "a symbolic link"
	case mode.IsDir():
		return "a directory"
	case mode&fs.ModeNamedPipe != 0:
		return "a named pipe"
	case mode&fs.ModeSocket != 0:
		return "a socket"
	case mode&fs.ModeDevice != 0 || mode&fs.ModeCharDevice != 0:
		return "a device"
	case mode.IsRegular():
		return "a regular file"
	}
	return "not a regular file"
}

// refuseIrregularFile refuses a path that exists and is anything but a regular
// file, by Lstat and before any open: a named pipe blocks the open, a device
// or a socket is never what the operator meant, and a symbolic link would make
// the command read or replace a file at another path. A missing file is fine;
// the caller decides what that means.
func refuseIrregularFile(path, flagName string) error {
	fi, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("%s %s: %w", flagName, path, err)
	case fi.Mode().IsRegular():
		return nil
	}
	return fmt.Errorf("%s %s is %s, %w; name a regular file", flagName, path, describeFileType(fi.Mode()), errNotRegular)
}

// readRegularFile reads a file that must be a regular one, at most maxBytes
// long; what names the kind of file the caller expects ("emitted file", "PEM
// public key file"), so the size refusal says what no such file is. The Lstat
// refusal comes first so the message names what was found; the open itself
// never follows a link and never blocks (O_NOFOLLOW, O_NONBLOCK), and the open
// file is checked again, so a pipe planted between the two calls is refused
// instead of waited on.
func readRegularFile(path, flagName, what string, maxBytes int64) ([]byte, error) {
	if err := refuseIrregularFile(path, flagName); err != nil {
		return nil, err
	}
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
		return nil, fmt.Errorf("%s %s is %s, %w; name a regular file", flagName, path, describeFileType(fi.Mode()), errNotRegular)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%s %s is larger than %d bytes, which no %s is", flagName, path, maxBytes, what)
	}
	return data, nil
}

// refuseLinkedDirectory refuses a database path whose directory goes through a
// symbolic link that root does not own. The final component is checked by
// refuseSymlink and ensurePrivateFile; this walk covers every component above
// it, because a link planted one level up (state -> elsewhere) in a shared
// working directory would otherwise make init create the owner-only file in
// the directory the link points to and print the link's path (fourth review
// cli-docs-8). Links the operating system installs in its own directories are
// owned by root and nobody else could have made them, so they are tolerated;
// a component that does not exist yet ends the walk, and the create reports
// it with its own message.
func refuseLinkedDirectory(path string) error {
	dir, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("resolve database directory: %w", err)
	}
	parts := strings.Split(filepath.Clean(dir), string(filepath.Separator))
	prefix := string(filepath.Separator)
	for _, part := range parts {
		if part == "" {
			continue
		}
		prefix = filepath.Join(prefix, part)
		fi, err := os.Lstat(prefix)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return nil
		case err != nil:
			return fmt.Errorf("inspect database directory %s: %w", prefix, err)
		case fi.Mode()&fs.ModeSymlink == 0 || ownedByRoot(fi):
			continue
		}
		resolved, rerr := filepath.EvalSymlinks(prefix)
		if rerr != nil {
			resolved = "(unresolvable)"
		}
		return fmt.Errorf("database directory %s goes through the symbolic link %s, which resolves to %s; a link planted in a shared directory would redirect where the owner-only file is created, so name the resolved directory", dir, prefix, resolved)
	}
	return nil
}

// ownedByRoot reports whether a directory entry belongs to root. Without the
// owner information (a platform whose Stat does not carry it) the answer is
// no, so the check fails closed.
func ownedByRoot(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Uid == rootUID
}
