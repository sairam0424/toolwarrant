package catalog

import (
	"context"
	"errors"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

var errNotImplemented = errors.New("catalog: not implemented")

// Store is the catalog. Create one with Open and release it with Close.
type Store struct{}

// Open opens or creates the database at path. It enables WAL, foreign keys and
// a busy timeout, creates the schema, and refuses a database written by a newer
// schema version (ErrSchema). policy controls the lifecycle rules.
func Open(path string, policy lifecycle.Policy) (*Store, error) { return nil, errNotImplemented }

// Close releases the database.
func (s *Store) Close() error { return errNotImplemented }

// AddServer registers an upstream. ErrExists if the name is taken, ErrInvalid
// for a bad name or URL.
func (s *Store) AddServer(ctx context.Context, spec ServerSpec, by Actor) (Server, error) {
	return Server{}, errNotImplemented
}

// Servers lists registered upstreams ordered by name.
func (s *Store) Servers(ctx context.Context) ([]Server, error) { return nil, errNotImplemented }

// Server returns one upstream by name, or ErrNotFound.
func (s *Store) Server(ctx context.Context, name string) (Server, error) {
	return Server{}, errNotImplemented
}

// RecordCrawl applies one crawl in a single transaction: it computes each
// tool's digest, creates tools and versions, drives the lifecycle for every
// known tool (tools absent from a complete crawl are reported as missing), and
// writes one audit entry per event. A crawl never approves anything and never
// edits an existing version. If in.Complete is false only the failure is
// recorded. Duplicate tool names in one crawl, or a tool name containing
// control or invisible Unicode characters, fail the whole call with
// ErrInvalid and change nothing.
func (s *Store) RecordCrawl(ctx context.Context, in CrawlInput, by Actor) (CrawlReport, error) {
	return CrawlReport{}, errNotImplemented
}

// Tools lists tools ordered by server then name. An empty server means all.
func (s *Store) Tools(ctx context.Context, server string) ([]ToolView, error) {
	return nil, errNotImplemented
}

// Tool returns one tool, or ErrNotFound.
func (s *Store) Tool(ctx context.Context, server, tool string) (ToolView, error) {
	return ToolView{}, errNotImplemented
}

// Versions lists a tool's versions oldest first.
func (s *Store) Versions(ctx context.Context, server, tool string) ([]VersionView, error) {
	return nil, errNotImplemented
}

// ResolveDigest expands a hex prefix of at least 8 characters to the full
// digest of exactly one version of the tool. ErrNotFound, ErrAmbiguous or
// ErrInvalid otherwise.
func (s *Store) ResolveDigest(ctx context.Context, server, tool, prefix string) (string, error) {
	return "", errNotImplemented
}

// Approve approves the pending version with this full digest. The digest is
// the hash the approver viewed: if the pending proposal has changed since,
// the call fails with lifecycle.ErrStaleVersion.
func (s *Store) Approve(ctx context.Context, server, tool, digest string, by Actor) error {
	return errNotImplemented
}

// Reject rejects the pending version with this full digest.
func (s *Store) Reject(ctx context.Context, server, tool, digest string, by Actor) error {
	return errNotImplemented
}

// Disable switches a tool off.
func (s *Store) Disable(ctx context.Context, server, tool string, by Actor) error {
	return errNotImplemented
}

// Enable brings a disabled tool back under the store's lifecycle.Policy.
func (s *Store) Enable(ctx context.Context, server, tool string, by Actor) error {
	return errNotImplemented
}

// Rollback re-approves a version that was approved before.
func (s *Store) Rollback(ctx context.Context, server, tool, toDigest string, by Actor) error {
	return errNotImplemented
}

// Generation returns a counter that increases by at least one with every
// committed write, from any process. Readers poll it to know when to reload.
func (s *Store) Generation(ctx context.Context) (int64, error) { return 0, errNotImplemented }

// Snapshot returns the serving policy of one server, or ErrNotFound if the
// server is not registered.
func (s *Store) Snapshot(ctx context.Context, server string) (Snapshot, error) {
	return Snapshot{}, errNotImplemented
}

// Approved returns the approved version of every tool that is enabled or
// changed_pending_reapproval, ordered by server then tool name.
func (s *Store) Approved(ctx context.Context) ([]ApprovedTool, error) {
	return nil, errNotImplemented
}

// AuditEntries returns up to limit entries with Seq greater than after, in
// order. A limit of zero or less means no limit.
func (s *Store) AuditEntries(ctx context.Context, after int64, limit int) ([]audit.Entry, error) {
	return nil, errNotImplemented
}

// VerifyAudit reads the whole log and checks the hash chain. A broken chain
// yields *audit.BrokenError.
func (s *Store) VerifyAudit(ctx context.Context) (AuditSummary, error) {
	return AuditSummary{}, errNotImplemented
}
