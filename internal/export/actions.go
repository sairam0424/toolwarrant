package export

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// actions is what one Write has to do to the disk, decided before anything is
// touched. Deciding first serves two ends: a Write with nothing to do leaves
// the directory alone, so not even the manifest's time stamp moves, and a
// Write with work puts the pending manifest down before the first change, so
// every file it may create is on record from the start.
type actions struct {
	write  map[string]struct{} // planned files whose bytes differ or are missing
	remove []string            // previously created files that exist and are no longer wanted
	sweep  []string            // temporary files an interrupted Write left behind
}

// empty reports whether the directory already matches the plan.
func (a actions) empty() bool {
	return len(a.write) == 0 && len(a.remove) == 0 && len(a.sweep) == 0
}

// planActions compares the plan with the directory. It refuses, before any
// change, a server path or tool path that is a symlink or of the wrong type,
// so a hostile layout changes nothing.
func planActions(root *os.Root, prev manifestDoc, planned []plannedTool) (actions, error) {
	act := actions{write: make(map[string]struct{})}
	dirs := map[string]struct{}{".": {}}
	for _, p := range planned {
		dirs[p.dirName] = struct{}{}
		if err := checkDirShape(root, p.dirName); err != nil {
			return actions{}, err
		}
		_, same, err := sameContent(root, filepath.FromSlash(p.rel), p.data)
		if err != nil {
			return actions{}, err
		}
		if !same {
			act.write[p.rel] = struct{}{}
		}
	}
	for _, rel := range staleCandidates(prev, planned) {
		dirName, _, _ := strings.Cut(rel, "/")
		dirs[dirName] = struct{}{}
		if isStaleFile(root, rel) {
			act.remove = append(act.remove, rel)
		}
	}
	for _, dir := range sortedNames(dirs) {
		temps, err := listTemp(root, dir)
		if err != nil {
			return actions{}, err
		}
		act.sweep = append(act.sweep, temps...)
	}
	return act, nil
}

// staleCandidates lists the files the previous manifest created that the plan
// no longer wants. Files are compared lower-cased: on a case-insensitive file
// system "Tool.json" and "tool.json" are one file, and the fresh copy must not
// be deleted as if it were the stale one.
func staleCandidates(prev manifestDoc, planned []plannedTool) []string {
	keep := make(map[string]struct{}, len(planned))
	for _, p := range planned {
		keep[lowerASCII(p.rel)] = struct{}{}
	}
	var out []string
	for _, rel := range prev.files() {
		if _, ok := keep[lowerASCII(rel)]; !ok {
			out = append(out, rel)
		}
	}
	return out
}

// sortedNames returns the keys of set in order, for deterministic work.
func sortedNames(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
