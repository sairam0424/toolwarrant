// Package export writes the approved tool snapshots to a directory so the
// approvals can be reviewed and versioned in git.
//
// The export is write-only: nothing in toolwarrant reads it back to make a
// decision. That is deliberate. The catalog is the source of truth; this is a
// human-facing mirror, so its failure modes are kept narrow. Every name that
// reaches the file system is hostile input (it came from an upstream server),
// nothing is deleted except files the previous MANIFEST.json says this package
// created, and symlinks are never followed.
package export

import (
	"fmt"
	"os"
	"path/filepath"
)

// Report counts what one Write did to the tool files (the manifest is not
// counted). Unchanged files are left untouched so that file times and git
// status only move when an approval really changed.
type Report struct {
	Written   int
	Removed   int
	Unchanged int
}

// Write lays the tools out as <dir>/<server>/<tool>.json plus
// <dir>/MANIFEST.json and removes files a previous Write created that are no
// longer wanted.
//
// It validates the whole batch (digests, JSON, names, collisions) before it
// touches the disk, so a bad input changes nothing. Running it twice with the
// same tools leaves the directory byte-identical.
func Write(dir string, tools []Tool) (Report, error) {
	planned, err := planAll(tools)
	if err != nil {
		return Report{}, err
	}
	manifest, err := renderManifest(planned)
	if err != nil {
		return Report{}, err
	}
	root, err := openExportRoot(dir)
	if err != nil {
		return Report{}, err
	}
	defer root.Close()

	prev, err := readPrevManifest(root)
	if err != nil {
		return Report{}, err
	}
	var rep Report
	if err := writeTools(root, planned, &rep); err != nil {
		return rep, err
	}
	if err := removeUnwanted(root, prev, planned, &rep); err != nil {
		return rep, err
	}
	// The manifest goes last: until it is replaced, a retry still sees the old
	// list of created files and can finish the clean-up.
	if err := writeIfChanged(root, manifestName, manifest); err != nil {
		return rep, err
	}
	return rep, nil
}

// writeTools writes every planned tool file, counting into rep.
func writeTools(root *os.Root, planned []plannedTool, rep *Report) error {
	for _, p := range sortPlanned(planned) {
		if err := ensureDir(root, p.dirName); err != nil {
			return err
		}
		changed, err := writeFileIfChanged(root, p.rel, p.data)
		if err != nil {
			return err
		}
		if changed {
			rep.Written++
		} else {
			rep.Unchanged++
		}
	}
	return nil
}

// writeFileIfChanged writes data to the slash-separated rel unless the file
// already holds exactly those bytes. It reports whether it wrote.
func writeFileIfChanged(root *os.Root, rel string, data []byte) (bool, error) {
	_, same, err := sameContent(root, filepath.FromSlash(rel), data)
	if err != nil {
		return false, err
	}
	if same {
		return false, nil
	}
	if err := writeAtomic(root, rel, data); err != nil {
		return false, err
	}
	return true, nil
}

// writeIfChanged is writeFileIfChanged for callers that ignore the flag.
func writeIfChanged(root *os.Root, rel string, data []byte) error {
	_, err := writeFileIfChanged(root, rel, data)
	return err
}

// removeUnwanted deletes files listed by the previous manifest that are not in
// the new plan. Files are compared lower-cased: on a case-insensitive file
// system "Tool.json" and "tool.json" are one file, and the fresh copy must not
// be deleted as if it were the stale one.
func removeUnwanted(root *os.Root, prev []string, planned []plannedTool, rep *Report) error {
	keep := make(map[string]struct{}, len(planned))
	for _, p := range planned {
		keep[lowerASCII(p.rel)] = struct{}{}
	}
	for _, rel := range prev {
		if _, ok := keep[lowerASCII(rel)]; ok {
			continue
		}
		removed, err := removeStale(root, rel)
		if removed {
			rep.Removed++
		}
		if err != nil {
			return fmt.Errorf("%w (%d removed before the failure)", err, rep.Removed)
		}
	}
	return nil
}

// lowerASCII lower-cases an encoded path. Encoded paths are pure ASCII.
func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
