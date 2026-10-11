//go:build unix

package catalog

import (
	"os"
	"syscall"
)

// openNoFollow makes the create path refuse a symbolic link at the database
// path, closing the window between the Lstat check and the open.
const openNoFollow = syscall.O_NOFOLLOW

// fileIDOf reads the device and inode behind a stat result, which is how a
// reader tells the file it opened from another file created at the same path.
func fileIDOf(fi os.FileInfo) fileID {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{}
	}
	// Dev and Ino differ in width and sign across unix platforms, hence the
	// conversions.
	return fileID{dev: uint64(st.Dev), ino: uint64(st.Ino), known: true}
}
