//go:build unix

package catalog

import "syscall"

// openNoFollow makes the create path refuse a symbolic link at the database
// path, closing the window between the Lstat check and the open.
const openNoFollow = syscall.O_NOFOLLOW
