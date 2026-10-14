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

	// manifestVersion is the version Write writes. It is bumped on any
	// incompatible change to the layout, and a manifest with a version this
	// package does not read is ignored rather than trusted, which means its
	// files are left alone and never deleted. Version 2 stores the
	// percent-encoded server and tool names (version 1 stored the raw upstream
	// names) and carries a status; version 3 adds the head of the audit chain
	// the catalog had verified when the approvals were read and the digest
	// profile every digest was computed under (D21 e). parseManifest still
	// reads version 2, so an export written before the bump is cleaned up
	// rather than left behind.
	manifestVersion = 3
	// manifestVersionNoHead is the last version without the two catalog
	// fields; it is read, never written.
	manifestVersionNoHead = 2

	// digestHexLen is the length of a lower-case hex SHA-256, the shape of a
	// digest and of the audit head.
	digestHexLen = 64
	// maxProfileBytes bounds the digest profile name a manifest may carry.
	maxProfileBytes = 64

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

// manifestDoc is the whole MANIFEST.json document. AuditHead and
// DigestProfile are version 3 fields: the head is the hash of the newest audit
// entry the catalog had verified when the approvals were read, so a signed
// manifest names the exact log it mirrors, and the profile is the rule under
// which every digest in the file was computed. Both are absent from a version
// 2 document.
type manifestDoc struct {
	Version       int             `json:"version"`
	Status        string          `json:"status"`
	AuditHead     string          `json:"audit_head,omitempty"`
	DigestProfile string          `json:"digest_profile,omitempty"`
	Tools         []manifestEntry `json:"tools"`
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
// the entries, sorted by file and ending in a newline, with the catalog fields
// of opts. HTML escaping is off so the digests and dates stay readable in a
// git diff; the names are encoded, so there is nothing hostile left for the
// JSON encoder to escape.
func renderManifest(entries []manifestEntry, status string, opts Options) ([]byte, error) {
	sorted := make([]manifestEntry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].File < sorted[j].File })
	doc := manifestDoc{Version: manifestVersion, Status: status, AuditHead: opts.AuditHead, DigestProfile: opts.DigestProfile, Tools: sorted}
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
// version is one this package reads (3, or 2 from before the catalog fields),
// the catalog fields have the shape of that version (a version 3 document
// carries a hex audit head and a profile name, a version 2 document neither),
// the status is one this package writes, and every entry names exactly the
// file this package derives from its own encoded server and tool fields, with
// no file listed twice. One bad entry invalidates the whole manifest, because
// the alternative is deleting files on the word of a document we only half
// trust.
func parseManifest(raw []byte) (manifestDoc, bool) {
	var doc manifestDoc
	if err := json.Unmarshal(raw, &doc); err != nil || !catalogFieldsFit(doc) {
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

// catalogFieldsFit reports whether the version and the two catalog fields of
// an untrusted document agree: version 3 with a well-formed head and profile,
// or version 2 with neither. Any other version is not read.
func catalogFieldsFit(doc manifestDoc) bool {
	switch doc.Version {
	case manifestVersion:
		return isHexDigest(doc.AuditHead) && isProfileName(doc.DigestProfile)
	case manifestVersionNoHead:
		return doc.AuditHead == "" && doc.DigestProfile == ""
	}
	return false
}

// isHexDigest reports whether s is exactly 64 lower-case hex digits, the shape
// of a SHA-256 digest and of the audit head (the genesis, 64 zeros, included).
func isHexDigest(s string) bool {
	if len(s) != digestHexLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// isProfileName reports whether s has the shape of a digest profile name as
// the gate names them: one to maxProfileBytes of lower-case letters, digits
// and hyphens.
func isProfileName(s string) bool {
	if s == "" || len(s) > maxProfileBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
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
