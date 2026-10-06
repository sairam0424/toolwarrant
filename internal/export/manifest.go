package export

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"time"

	"github.com/sairam0424/toolwarrant/internal/textdiff"
)

const (
	// manifestName is the index file at the top of the export directory. It is
	// also the only record of which files this package created, which is what
	// limits what a later Write may delete.
	manifestName = "MANIFEST.json"

	// manifestVersion is bumped on any incompatible change to the layout. A
	// manifest with another version is ignored rather than trusted, which
	// means its files are left alone and never deleted. Version 2 stores the
	// percent-encoded server and tool names (version 1 stored the raw upstream
	// names) and carries a status.
	manifestVersion = 2

	// maxManifestBytes bounds how much of a previous manifest is parsed; the
	// file lives in a directory other people can edit.
	maxManifestBytes = 32 << 20

	manifestIndent = "  "

	// statusComplete marks a manifest that lists exactly the files on disk.
	statusComplete = "complete"
	// statusPending marks the manifest Write puts down before it touches any
	// tool file. It lists the union of the previous files and the new plan, so
	// a Write that dies half way leaves a record that still covers every file
	// this package may have created, and the next Write finishes the clean-up.
	statusPending = "pending"
)

// manifestEntry is one approved tool as listed in MANIFEST.json. Server and
// Tool hold the encoded names: the manifest is read in terminals and web
// views, so it must never carry a raw upstream name with a control character
// or an invisible code point in it.
type manifestEntry struct {
	Server     string `json:"server"`
	Tool       string `json:"tool"`
	File       string `json:"file"`
	Digest     string `json:"digest"`
	ApprovedBy string `json:"approved_by"`
	ApprovedAt string `json:"approved_at"`
	VersionNo  int    `json:"version_no"`
}

// manifestDoc is the whole MANIFEST.json document.
type manifestDoc struct {
	Version int             `json:"version"`
	Status  string          `json:"status"`
	Tools   []manifestEntry `json:"tools"`
}

// files returns the relative paths the manifest lists.
func (d manifestDoc) files() []string {
	out := make([]string, 0, len(d.Tools))
	for _, e := range d.Tools {
		out = append(out, e.File)
	}
	return out
}

// entryOf builds the manifest entry of a planned tool. The names are the
// encoded ones, which are plain ASCII, and the approver's name goes through
// textdiff.Escape, so nothing in the manifest can act on a terminal or hide
// from a reader. The file field is the exact identity of the snapshot.
func entryOf(p plannedTool) manifestEntry {
	return manifestEntry{
		Server:     p.dirName,
		Tool:       p.encTool,
		File:       p.rel,
		Digest:     p.tool.Digest,
		ApprovedBy: textdiff.Escape(p.tool.ApprovedBy),
		ApprovedAt: p.tool.ApprovedAt.UTC().Format(time.RFC3339Nano),
		VersionNo:  p.tool.VersionNo,
	}
}

// planEntries returns the manifest entries of a plan.
func planEntries(planned []plannedTool) []manifestEntry {
	out := make([]manifestEntry, 0, len(planned))
	for _, p := range planned {
		out = append(out, entryOf(p))
	}
	return out
}

// unionEntries returns the plan's entries plus every previous entry whose file
// the plan does not claim: exactly the set of files that may exist on disk
// while a Write is in progress.
func unionEntries(prev []manifestEntry, planned []plannedTool) []manifestEntry {
	out := planEntries(planned)
	claimed := make(map[string]struct{}, len(planned))
	for _, p := range planned {
		claimed[p.rel] = struct{}{}
	}
	for _, e := range prev {
		if _, ok := claimed[e.File]; !ok {
			out = append(out, e)
		}
	}
	return out
}

// renderManifest returns the deterministic, pretty-printed manifest bytes for
// the entries, sorted by file and ending in a newline. HTML escaping is off so
// the digests and dates stay readable in a git diff; the names are encoded,
// so there is nothing hostile left for the JSON encoder to escape.
func renderManifest(entries []manifestEntry, status string) ([]byte, error) {
	sorted := make([]manifestEntry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].File < sorted[j].File })
	doc := manifestDoc{Version: manifestVersion, Status: status, Tools: sorted}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", manifestIndent)
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("export: encode manifest: %w", err)
	}
	return buf.Bytes(), nil
}

// parseManifest reads an untrusted manifest. It returns ok=false unless the
// version matches, the status is one this package writes, and every entry
// names exactly the file this package derives from its own encoded server and
// tool fields, with no file listed twice. One bad entry invalidates the whole
// manifest, because the alternative is deleting files on the word of a
// document we only half trust.
func parseManifest(raw []byte) (manifestDoc, bool) {
	var doc manifestDoc
	if err := json.Unmarshal(raw, &doc); err != nil || doc.Version != manifestVersion {
		return manifestDoc{}, false
	}
	if doc.Status != statusComplete && doc.Status != statusPending {
		return manifestDoc{}, false
	}
	seen := make(map[string]struct{}, len(doc.Tools))
	for _, e := range doc.Tools {
		if !isEncodedName("server", e.Server) || !isEncodedName("tool", e.Tool) || e.File != relPath(e.Server, e.Tool) {
			return manifestDoc{}, false
		}
		if _, dup := seen[e.File]; dup {
			return manifestDoc{}, false
		}
		seen[e.File] = struct{}{}
	}
	return doc, true
}

// readPrevManifest returns the previous manifest, pending or complete, as the
// record of the files this package created. A missing, oversized, unreadable
// or invalid manifest yields an empty one, which means nothing will be
// deleted. Only a symlink or directory at the manifest path is an error,
// because writing the new manifest there would follow it or fail.
func readPrevManifest(root *os.Root) (manifestDoc, error) {
	fi, err := root.Lstat(manifestName)
	if errors.Is(err, fs.ErrNotExist) {
		return manifestDoc{}, nil
	}
	if err != nil {
		return manifestDoc{}, fmt.Errorf("export: stat manifest: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return manifestDoc{}, errors.New("export: manifest path is a symlink or not a regular file")
	}
	if fi.Size() > maxManifestBytes {
		return manifestDoc{}, nil
	}
	raw, err := root.ReadFile(manifestName)
	if err != nil {
		return manifestDoc{}, nil //nolint:nilerr // unreadable manifest is treated as invalid: delete nothing
	}
	doc, ok := parseManifest(raw)
	if !ok {
		return manifestDoc{}, nil
	}
	return doc, nil
}
