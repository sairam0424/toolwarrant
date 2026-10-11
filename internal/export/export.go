// Package export writes the approved tool snapshots to a directory so the
// approvals can be reviewed and versioned in git.
//
// The export is write-only: nothing in toolwarrant reads it back to make a
// decision. That is deliberate. The catalog is the source of truth; this is a
// human-facing mirror, so its failure modes are kept narrow. Every name that
// reaches the file system is hostile input (it came from an upstream server);
// nothing is deleted except files MANIFEST.json says this package created and
// this package's own leftover temporary files (".tmp-" followed by exactly
// sixteen lower-case hex digits, looked for only in the export root and the
// server directories the manifest or the plan names); and symlinks are never
// followed.
//
// MANIFEST.json is written twice by a Write that changes anything: first
// marked pending, listing every file that may exist while the work is in
// progress (the previous files plus the new plan), then marked complete with
// the final list. A Write that dies in between leaves the pending record, and
// the next Write uses it to finish the clean-up, so no snapshot is ever
// orphaned on disk and later committed as if it were still approved. A Write
// that changes nothing touches nothing.
//
// Two Writes must not run on one directory at the same time; the catalog
// serialises them.
package export

import (
	"fmt"
	"os"
)

// Report counts what one Write did to the tool files (the manifest is not
// counted). Unchanged files are left untouched so that file times and git
// status only move when an approval really changed.
type Report struct {
	Written   int
	Removed   int
	Unchanged int
	// Skipped lists approved tools that were left out, sorted by server then
	// name. The caller should surface them to an operator; their names are
	// raw upstream text and must be escaped before they are printed.
	Skipped []Skipped
}

// Write lays the tools out as <dir>/<server>/<tool>.json plus
// <dir>/MANIFEST.json and removes files a previous Write created that are no
// longer wanted.
//
// It validates the whole batch (digests, JSON, names, collisions) before it
// touches the disk, so a bad input changes nothing. Running it twice with the
// same tools leaves the directory byte-identical and untouched.
func Write(dir string, tools []Tool) (Report, error) {
	planned, skipped, err := planAll(tools)
	if err != nil {
		return Report{}, err
	}
	final, err := renderManifest(planEntries(planned), statusComplete)
	if err != nil {
		return Report{}, err
	}
	root, err := openExportRoot(dir)
	if err != nil {
		return Report{}, err
	}
	defer func() { _ = root.Close() }()

	prev, err := readPrevManifest(root)
	if err != nil {
		return Report{}, err
	}
	act, err := planActions(root, prev, planned)
	if err != nil {
		return Report{}, err
	}
	rep := Report{Skipped: skipped}
	if act.empty() {
		// Only the manifest may differ (metadata, or a pending one whose work
		// is already done); replacing it is one atomic step.
		rep.Unchanged = len(planned)
		return rep, writeIfChanged(root, manifestName, final)
	}
	pending, err := renderManifest(unionEntries(prev.Tools, planned), statusPending)
	if err != nil {
		return rep, err
	}
	return rep, apply(root, planned, act, pending, final, &rep)
}

// apply performs the actions in the order that keeps MANIFEST.json a complete
// record at every instant a crash could happen: the pending manifest first,
// then the file changes, then the complete manifest.
func apply(root *os.Root, planned []plannedTool, act actions, pending, final []byte, rep *Report) error {
	if err := writeAtomic(root, manifestName, pending); err != nil {
		return err
	}
	if err := sweepTemp(root, act.sweep); err != nil {
		return err
	}
	if err := writeTools(root, planned, act.write, rep); err != nil {
		return err
	}
	if err := removeUnwanted(root, act.remove, rep); err != nil {
		return err
	}
	return writeAtomic(root, manifestName, final)
}

// writeTools writes the planned files that planActions found changed or
// missing, counting into rep, and creates the server directories as needed.
func writeTools(root *os.Root, planned []plannedTool, write map[string]struct{}, rep *Report) error {
	for _, p := range sortPlanned(planned) {
		if err := ensureDir(root, p.dirName); err != nil {
			return err
		}
		if _, ok := write[p.rel]; !ok {
			rep.Unchanged++
			continue
		}
		if err := writeAtomic(root, p.rel, p.data); err != nil {
			return err
		}
		rep.Written++
	}
	return nil
}

// writeIfChanged writes data to the slash-separated rel unless the file
// already holds exactly those bytes.
func writeIfChanged(root *os.Root, rel string, data []byte) error {
	_, same, err := sameContent(root, rel, data)
	if err != nil || same {
		return err
	}
	return writeAtomic(root, rel, data)
}

// removeUnwanted deletes the stale files planActions found, counting into rep.
// A failure reports how far it got, because the pending manifest still lists
// the rest and the next Write will finish.
func removeUnwanted(root *os.Root, stale []string, rep *Report) error {
	for _, rel := range stale {
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
