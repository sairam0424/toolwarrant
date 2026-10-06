package export

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"
	"unicode/utf8"
)

const (
	// maxToolBytes bounds one canonical tool definition. Real definitions are
	// a few kilobytes; the cap keeps a hostile upstream from filling the disk
	// of whoever reviews the export.
	maxToolBytes = 1 << 20

	// maxApproverBytes caps the approver's name. It matches the catalog's cap
	// on actor names, so a name the catalog accepted is never refused here.
	maxApproverBytes = 256
)

// ReasonCaseCollision is the Skipped reason for tools of one server whose
// encoded file names differ only in ASCII letter case. On a case-insensitive
// file system the two would be one file, and there is no fair way to pick a
// winner, so neither is written. It is a constant so callers and tests can
// match on it without parsing prose.
const ReasonCaseCollision = "tool file name differs from another tool of the same server only in letter case, which a case-insensitive file system cannot tell apart"

// Skipped records an approved tool that Write left out of the export, with the
// reason. Server and Name are the raw names and therefore hostile input: a
// caller that prints them must escape them first.
type Skipped struct {
	Server string
	Name   string
	Reason string
}

// Tool is one approved tool definition to export. Canonical must be the RFC
// 8785 canonical JSON whose SHA-256 is Digest; Write re-checks that so a
// snapshot in git can never disagree with the digest a person approved.
type Tool struct {
	Server     string
	Name       string
	Digest     string
	Canonical  []byte
	ApprovedBy string
	ApprovedAt time.Time
	VersionNo  int
}

// plannedTool is a validated Tool with its on-disk names and content.
type plannedTool struct {
	tool    Tool
	dirName string // the encoded server name
	encTool string // the encoded tool name
	rel     string // dirName/encTool.json, slash-separated
	data    []byte
}

// validateContent checks the digest and the JSON validity of one tool before
// anything is written. Digest comparison is on lower-case hex only, so a
// differently cased digest is refused rather than silently normalised. The
// canonical text must be valid UTF-8: the catalog guarantees it, and this is
// the boundary where the guarantee is checked rather than assumed.
func validateContent(t Tool) error {
	if len(t.Canonical) == 0 {
		return fmt.Errorf("export: tool has no canonical definition")
	}
	if len(t.Canonical) > maxToolBytes {
		return fmt.Errorf("export: canonical definition exceeds %d bytes", maxToolBytes)
	}
	if !utf8.Valid(t.Canonical) {
		return fmt.Errorf("export: canonical definition is not valid UTF-8")
	}
	if t.VersionNo < 0 {
		return fmt.Errorf("export: negative version number %d", t.VersionNo)
	}
	if len(t.ApprovedBy) > maxApproverBytes || !utf8.ValidString(t.ApprovedBy) {
		return fmt.Errorf("export: approver name is longer than %d bytes or not valid UTF-8", maxApproverBytes)
	}
	sum := sha256.Sum256(t.Canonical)
	if hex.EncodeToString(sum[:]) != t.Digest {
		return fmt.Errorf("export: digest does not match canonical definition (want sha256 %s)", hex.EncodeToString(sum[:]))
	}
	if !json.Valid(t.Canonical) {
		return fmt.Errorf("export: canonical definition is not valid JSON")
	}
	return nil
}

// planTool validates one tool and derives its paths and file content.
func planTool(t Tool) (plannedTool, error) {
	encServer, err := encodeName("server", t.Server)
	if err != nil {
		return plannedTool{}, err
	}
	encTool, err := encodeName("tool", t.Name)
	if err != nil {
		return plannedTool{}, err
	}
	if err := validateContent(t); err != nil {
		return plannedTool{}, err
	}
	data := make([]byte, 0, len(t.Canonical)+1)
	data = append(data, t.Canonical...)
	data = append(data, '\n')
	return plannedTool{tool: t, dirName: encServer, encTool: encTool, rel: relPath(encServer, encTool), data: data}, nil
}

// planAll validates every tool before any byte is written, so a bad batch
// leaves the directory exactly as it was. Bad input, an exact duplicate and
// two server directories that collide on a case-insensitive file system are
// errors: the caller controls those. Tools of one server whose file names
// collide only in letter case come from the upstream, so they are not an
// error: the colliding group is left out and reported in Skipped, and the
// export of every other tool goes ahead.
func planAll(tools []Tool) ([]plannedTool, []Skipped, error) {
	all := make([]plannedTool, 0, len(tools))
	seen := make(map[[2]string]struct{}, len(tools))
	dirs := make(map[string]string)
	for i, t := range tools {
		p, err := planTool(t)
		if err != nil {
			return nil, nil, fmt.Errorf("tool %d: %w", i, err)
		}
		id := [2]string{t.Server, t.Name}
		if _, dup := seen[id]; dup {
			return nil, nil, fmt.Errorf("export: tool %d: duplicate of an earlier tool", i)
		}
		seen[id] = struct{}{}
		dirKey := lowerASCII(p.dirName)
		if prev, ok := dirs[dirKey]; ok && prev != p.dirName {
			return nil, nil, fmt.Errorf("export: tool %d: server directory collides with another server on a case-insensitive file system", i)
		}
		dirs[dirKey] = p.dirName
		all = append(all, p)
	}
	planned, skipped := splitCaseCollisions(all)
	return planned, skipped, nil
}

// splitCaseCollisions separates the tools whose file names are equal once
// lower-cased. Every member of such a group is skipped: writing one of them
// would silently drop the others on a case-insensitive file system, and
// writing all of them would make the last one overwrite the rest.
func splitCaseCollisions(all []plannedTool) ([]plannedTool, []Skipped) {
	count := make(map[string]int, len(all))
	for _, p := range all {
		count[lowerASCII(p.rel)]++
	}
	kept := make([]plannedTool, 0, len(all))
	var skipped []Skipped
	for _, p := range all {
		if count[lowerASCII(p.rel)] > 1 {
			skipped = append(skipped, Skipped{Server: p.tool.Server, Name: p.tool.Name, Reason: ReasonCaseCollision})
			continue
		}
		kept = append(kept, p)
	}
	sort.Slice(skipped, func(i, j int) bool {
		if skipped[i].Server != skipped[j].Server {
			return skipped[i].Server < skipped[j].Server
		}
		return skipped[i].Name < skipped[j].Name
	})
	return kept, skipped
}

// sortPlanned orders tools by their encoded path, so the write order and the
// manifest do not depend on the order the caller passed them in.
func sortPlanned(in []plannedTool) []plannedTool {
	out := make([]plannedTool, len(in))
	copy(out, in)
	sort.Slice(out, func(i, j int) bool { return out[i].rel < out[j].rel })
	return out
}
