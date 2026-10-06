//go:build tools

// Package deps keeps dependencies that are not imported yet in go.mod and
// go.sum while packages are being written in parallel. Delete this file and run
// go mod tidy once every package imports what it needs.
package deps

import (
	_ "modernc.org/sqlite"
	_ "pgregory.net/rapid"
)
