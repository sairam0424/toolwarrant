package export

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

const (
	// manifestName is the index file at the top of the export directory. It is
	// also the only record of which files this package created, which is what
	// limits what a later Write may delete.
	manifestName = "MANIFEST.json"

	// manifestVersion is bumped on any incompatible change to the layout. A
	// manifest with another version is ignored rather than trusted.
	manifestVersion = 1

	// maxManifestBytes bounds how much of a previous manifest is parsed; the
	// file lives in a directory other people can edit.
	maxManifestBytes = 32 << 20

	manifestIndent = "  "
)

// manifestEntry is one approved tool as listed in MANIFEST.json.
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
	Tools   []manifestEntry `json:"tools"`
}

// sortPlanned orders tools by raw server then raw tool name, so the manifest
// does not depend on the order the caller passed them in.
func sortPlanned(in []plannedTool) []plannedTool {
	out := make([]plannedTool, len(in))
	copy(out, in)
	sort.Slice(out, func(i, j int) bool {
		if out[i].tool.Server != out[j].tool.Server {
			return out[i].tool.Server < out[j].tool.Server
		}
		return out[i].tool.Name < out[j].tool.Name
	})
	return out
}

// renderManifest returns the deterministic, pretty-printed manifest bytes for
// a validated plan, ending in a newline. HTML escaping is off so names stay
// readable in a git diff.
func renderManifest(planned []plannedTool) ([]byte, error) {
	sorted := sortPlanned(planned)
	doc := manifestDoc{Version: manifestVersion, Tools: make([]manifestEntry, 0, len(sorted))}
	for _, p := range sorted {
		doc.Tools = append(doc.Tools, manifestEntry{
			Server:     p.tool.Server,
			Tool:       p.tool.Name,
			File:       p.rel,
			Digest:     p.tool.Digest,
			ApprovedBy: p.tool.ApprovedBy,
			ApprovedAt: p.tool.ApprovedAt.UTC().Format(time.RFC3339Nano),
			VersionNo:  p.tool.VersionNo,
		})
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", manifestIndent)
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("export: encode manifest: %w", err)
	}
	return buf.Bytes(), nil
}

// parseManifestFiles reads the file list out of a previous manifest. The input
// is untrusted: it returns ok=false unless the version matches and every entry
// names exactly the path this package would derive from its own server and
// tool fields. One bad entry invalidates the whole manifest, because the
// alternative is deleting files on the word of a document we only half trust.
func parseManifestFiles(raw []byte) (files []string, ok bool) {
	var doc manifestDoc
	if err := json.Unmarshal(raw, &doc); err != nil || doc.Version != manifestVersion {
		return nil, false
	}
	seen := make(map[string]struct{}, len(doc.Tools))
	for _, e := range doc.Tools {
		encServer, errS := encodeName("server", e.Server)
		encTool, errT := encodeName("tool", e.Tool)
		if errS != nil || errT != nil || e.File != relPath(encServer, encTool) {
			return nil, false
		}
		if _, dup := seen[e.File]; dup {
			return nil, false
		}
		seen[e.File] = struct{}{}
		files = append(files, e.File)
	}
	return files, true
}
