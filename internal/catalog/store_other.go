//go:build !unix

package catalog

import "os"

// openNoFollow is unavailable on this platform; the Lstat check in
// prepareDatabaseFile is the only symbolic-link defence here.
const openNoFollow = 0

// fileIDOf has no device and inode to read on this platform, so Generation
// compares the catalog identity alone.
func fileIDOf(os.FileInfo) fileID { return fileID{} }
