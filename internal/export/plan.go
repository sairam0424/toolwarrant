package export

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// maxToolBytes bounds one canonical tool definition. Real definitions are a
// few kilobytes; the cap keeps a hostile upstream from filling the disk of
// whoever reviews the export.
const maxToolBytes = 1 << 20

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
	dirName string
	rel     string
	data    []byte
}

// validateContent checks the digest and the JSON validity of one tool before
// anything is written. Digest comparison is on lower-case hex only, so a
// differently cased digest is refused rather than silently normalised.
func validateContent(t Tool) error {
	if len(t.Canonical) == 0 {
		return fmt.Errorf("export: tool has no canonical definition")
	}
	if len(t.Canonical) > maxToolBytes {
		return fmt.Errorf("export: canonical definition exceeds %d bytes", maxToolBytes)
	}
	if t.VersionNo < 0 {
		return fmt.Errorf("export: negative version number %d", t.VersionNo)
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
	return plannedTool{tool: t, dirName: encServer, rel: relPath(encServer, encTool), data: data}, nil
}

// planAll validates every tool and rejects collisions before any byte is
// written, so a bad batch leaves the directory exactly as it was. Collisions
// are compared lower-cased because the target may be a case-insensitive file
// system, where "A.json" and "a.json" are the same file.
func planAll(tools []Tool) ([]plannedTool, error) {
	planned := make([]plannedTool, 0, len(tools))
	dirs := make(map[string]string)
	files := make(map[string]struct{})
	for i, t := range tools {
		p, err := planTool(t)
		if err != nil {
			return nil, fmt.Errorf("tool %d: %w", i, err)
		}
		dirKey := strings.ToLower(p.dirName)
		if prev, ok := dirs[dirKey]; ok && prev != p.dirName {
			return nil, fmt.Errorf("export: tool %d: server directory collides with another server on a case-insensitive file system", i)
		}
		dirs[dirKey] = p.dirName
		fileKey := strings.ToLower(p.rel)
		if _, dup := files[fileKey]; dup {
			return nil, fmt.Errorf("export: tool %d: duplicate or case-colliding file name", i)
		}
		files[fileKey] = struct{}{}
		planned = append(planned, p)
	}
	return planned, nil
}
