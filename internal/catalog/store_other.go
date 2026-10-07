//go:build !unix

package catalog

// openNoFollow is unavailable on this platform; the Lstat check in
// prepareDatabaseFile is the only symbolic-link defence here.
const openNoFollow = 0
