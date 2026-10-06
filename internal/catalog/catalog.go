// Package catalog is the SQLite-backed registry of servers, tools and tool
// versions. It is the only writer of lifecycle state and of the audit log, and
// it writes both in the same transaction, so a state change without an audit
// entry (or the reverse) cannot be committed.
//
// Several processes may open the same database file: the CLI writes, the
// ExtMCP processor reads. Every committed write bumps a generation counter
// that readers poll to know when to reload.
package catalog

import (
	"context"
	"errors"
	"time"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// Errors returned by Store methods. Lifecycle errors (lifecycle.ErrSelfApproval
// and friends) are wrapped with %w and so stay matchable with errors.Is.
var (
	ErrNotFound  = errors.New("catalog: not found")
	ErrExists    = errors.New("catalog: already exists")
	ErrAmbiguous = errors.New("catalog: digest prefix matches more than one version")
	ErrInvalid   = errors.New("catalog: invalid input")
	// ErrSchema means the database was written by a newer, incompatible version.
	ErrSchema = errors.New("catalog: unsupported schema version")
)

// ActorType says whether a principal is a person or an automated process.
type ActorType string

const (
	ActorHuman  ActorType = "human"
	ActorSystem ActorType = "system"
)

// Actor is the principal behind an operation. Name must be non-empty.
type Actor struct {
	Name string
	Type ActorType
}

// ServerSpec describes an upstream MCP server to register.
type ServerSpec struct {
	// Name is unique and matches ^[a-z0-9][a-z0-9_-]{0,62}$.
	Name string
	// URL is the remote Streamable HTTP endpoint (http or https). Stdio
	// commands are never executed.
	URL string
	// OwnerGroup is a label only in this version.
	OwnerGroup string
	// AllowPrivate lets the crawler reach loopback and private addresses. Off
	// by default; meant for a lab or demo.
	AllowPrivate bool
}

// Server is a registered upstream.
type Server struct {
	ID int64
	ServerSpec
	CreatedAt time.Time
}

// CrawledTool is one tool exactly as the upstream sent it.
type CrawledTool struct {
	Name string // the tool's "name" field
	Raw  []byte // the complete tool JSON object, byte for byte
}

// CrawlInput is the result of one crawl of one server.
type CrawlInput struct {
	Server string
	// Complete is true only if every page of tools/list was fetched. An
	// incomplete crawl records a failure and changes no tool: a crawl failure is
	// not a removal.
	Complete bool
	// Error describes why the crawl was incomplete.
	Error string
	Tools []CrawledTool
}

// ChangeKind classifies what a crawl did to one tool.
type ChangeKind string

const (
	ChangeNew        ChangeKind = "new"        // first time this tool was seen
	ChangeChanged    ChangeKind = "changed"    // a new digest was proposed
	ChangeUnchanged  ChangeKind = "unchanged"  // nothing to record
	ChangeReverted   ChangeKind = "reverted"   // upstream is back on the approved digest
	ChangeMissing    ChangeKind = "missing"    // absent from a successful crawl
	ChangeDeprecated ChangeKind = "deprecated" // absent for too many crawls
	ChangeReappeared ChangeKind = "reappeared" // returned after deprecation
)

// ToolChange is one line of a CrawlReport.
type ToolChange struct {
	Tool   string
	Kind   ChangeKind
	Digest string // the live digest, or "" if absent
	State  lifecycle.State
}

// CrawlReport summarises one RecordCrawl call. Changes is sorted by tool name.
type CrawlReport struct {
	CrawlID  int64
	Complete bool
	Changes  []ToolChange
}

// ToolView is a tool as shown to an operator.
type ToolView struct {
	ID            int64
	Server        string
	Name          string
	State         lifecycle.State
	Approved      string // digest, or ""
	Pending       string // digest of the current proposal, or ""
	LastSeen      string // digest the upstream served in the latest crawl, or ""
	Drifted       bool   // LastSeen differs from Approved
	Versions      int
	MissingCrawls int
}

// VersionView is one immutable version of a tool.
type VersionView struct {
	No           int // 1-based, in first-seen order
	Digest       string
	Status       lifecycle.VersionStatus
	ProposedBy   string
	EverApproved bool
	FirstSeen    time.Time
	// Canonical is the RFC 8785 form that Digest hashes, volatile keys removed.
	Canonical []byte
}

// ToolPolicy is what the processor needs to know about one tool.
type ToolPolicy struct {
	State    lifecycle.State
	Approved string // digest, or ""
	// LastSeen is the digest the upstream served in the latest crawl, or "" if
	// the tool was absent. The tools/call hook carries no tool definition, so
	// this is how the control plane can veto a call for a client that has not
	// re-listed since the upstream changed.
	LastSeen string
}

// Snapshot is the serving policy of one server at one generation. Keys are
// upstream tool names. A name that is not in Tools is not served (a catalog
// miss fails closed).
type Snapshot struct {
	Server     string
	Generation int64
	Tools      map[string]ToolPolicy
}

// Serves reports whether the named tool may be served when the upstream
// currently serves the definition with the live digest.
func (s Snapshot) Serves(name, live string) bool {
	p, ok := s.Tools[name]
	if !ok {
		return false
	}
	return lifecycle.Serves(p.State, p.Approved, live)
}

// ApprovedTool is the approved version of one enabled tool, for export.
type ApprovedTool struct {
	Server     string
	Name       string
	Digest     string
	Canonical  []byte
	VersionNo  int
	ApprovedBy string
	ApprovedAt time.Time
}

// AuditSummary is the result of VerifyAudit.
type AuditSummary struct {
	Entries int
	Head    string // hash of the last entry, or audit.Genesis if empty
}

// AuditReader is the read side of the log, for callers that only verify.
type AuditReader interface {
	AuditEntries(ctx context.Context, after int64, limit int) ([]audit.Entry, error)
}
