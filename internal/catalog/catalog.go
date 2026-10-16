// Package catalog is the SQLite-backed registry of servers, tools and tool
// versions. It is the only writer of lifecycle state and of the audit log, and
// it writes both in the same transaction, so a state change without an audit
// entry (or the reverse) cannot be committed.
//
// Several processes may open the same database file: the CLI writes through
// Open, the ExtMCP processor reads through OpenWith with OpenOptions.ReadOnly.
// Every committed write bumps a generation counter that readers poll to know
// when to reload.
//
// Everything an upstream sends is hostile. A crawl of a registered server is
// always recorded, whatever it carried: a tool that breaks a rule is
// quarantined on its own (RecordCrawl), a definition that cannot be used marks
// its tool unusable instead of becoming a version, and a tool whose upstream
// proposes new definitions faster than people decide stops gaining versions
// (MaxProposalsPerDecision), and a server whose upstream keeps listing fresh
// names stops gaining rows and bytes (MaxToolsPerServer, MaxServerBytes).
// Nothing is served until a person approves it. The serving path (Snapshot,
// and the Tools and Tool views) hands out digests, each anchored to a verified
// audit entry, and reads no canonical bytes; every path that hands out bytes
// (Approved, Versions, a decision through loadTool) hashes them against the
// digest on every call, with no memory between calls (D21 d; before, every
// read path re-hashed the bytes behind the digests it handed out and
// remembered each verified row for ten minutes, a window in which a rewrite of
// the bytes went unreported). An approval is served only when the tool's
// newest approve or rollback record names that exact version and digest and
// the newest version.approved or version.rolled_back audit entry about the
// tool recorded that digest and is part of the chain the Store verified (D15:
// a Store verifies the whole chain once at open and the suffix on every
// reload, keeps the hash of every decision entry it walked, and trusts an
// entry only when its fields hash to that value; a forger must rewrite every
// entry from the forged one to the head, which the head a running Store
// pinned betrays while that Store runs, and which only the head the operator
// records outside the file betrays once no Store holds a pin, the CLI's state
// between commands, D17 k). A rewrite of an approved version's bytes with the
// digest column intact is therefore invisible to the snapshot and the list,
// cannot change what the gateway serves (the processor compares the live
// definition's digest with the anchored one) and is refused at once by the
// export, emit, show, diff and every decision, and named by Integrity. Decisions
// always load their tool afresh and require every version's status,
// ever-approved flag and proposer list to be what the verified version.*
// entries about the tool leave behind (D17 a). A Store also remembers the
// catalog identity and the file it opened, so every read reports ErrReplaced
// once the file at the path is another one.
//
// The servers and tools tables are the current policy and have no update
// guard: their columns must change with every crawl and decision; nothing is
// ever deleted from them. What binds them to the append-only history
// (versions, approvals, the audit log) is Integrity, which cross-checks every
// mutable column the log describes against the latest entry about its
// subject, reconstructs every version's status and proposers from the log, and
// names every row that disagrees, is missing or was never recorded; audit
// verify prints its report. The columns emit and the crawler act on are bound
// on the read path too: Server and Servers anchor processor_addr, url,
// allow_private and paused to the verified server.processor_set,
// server.added and newest server.paused or server.resumed entries, and
// Snapshot, RecordCrawl, PauseServer and ResumeServer anchor the paused flag
// they act on (D17 c). Open, every Snapshot, Approved and view load and every write
// transaction refuse a file whose guard objects are missing or redefined, that
// holds a trigger, view or unique index the schema did not create, or that
// holds a history row below id 1 (D17 b).
package catalog

import (
	"context"
	"errors"
	"fmt"
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
	// ErrSchema means the database was not written by this schema version: a
	// newer build, an older unreleased one, or another application. There is
	// no migration code; re-initialise the database.
	ErrSchema = errors.New("catalog: unsupported schema version")
	// ErrCorrupt means the database contradicts itself: a stored digest does
	// not hash its canonical form, a pointer dangles, a status disagrees with
	// the tool row, an approved version is not the one the tool's newest
	// decision names or the one its newest approval entry recorded, an audit
	// entry is not the one this Store verified in the chain, the chain does
	// not verify at open, an entry this Store had verified is gone or
	// rewritten, a proposer list is not what the log names, a write failed a
	// constraint the schema does not have, a guard object or table is missing
	// or redefined, a table, trigger, view, unique index or automatic index
	// exists that the schema did not create, or a signed record fails a rule
	// of the walk (trustwalk.go: replaced, unverifiable, for another catalog
	// or head, a trust list the rotation rule refuses, a signer the list does
	// not name). Someone edited the file outside this package, or a bug wrote
	// it. Callers must not serve from a corrupt catalog.
	ErrCorrupt = errors.New("catalog: database integrity check failed")
	// ErrReplaced is returned by Generation when the file at the path the Store
	// opened is no longer the file it opened (another device and inode, or
	// gone) or no longer carries the catalog identity it read at open: the
	// operator deleted and re-initialised the catalog, or restored another
	// one, under a running reader. It wraps ErrCorrupt, so a caller that denies
	// on ErrCorrupt denies on this too; the processor turns it into a source
	// error and serves nothing until it is restarted on the new file.
	ErrReplaced = fmt.Errorf("%w: the database file was replaced or removed", ErrCorrupt)
	// ErrReadOnly is returned by every mutating method of a Store opened with
	// OpenOptions.ReadOnly: the processor reads policy and must never be able
	// to change it.
	ErrReadOnly = errors.New("catalog: the store is read-only")
	// ErrPaused is returned by RecordCrawl for a paused server: an operator
	// stopped crawling it, so an observation of it must not be recorded.
	ErrPaused = errors.New("catalog: server is paused")
	// ErrHumanRequired is returned when a decision (approve, reject, roll
	// back, disable, enable, pause, resume) is attempted by a system actor.
	// Only a named person decides; the crawler identity may only observe.
	ErrHumanRequired = errors.New("catalog: a decision requires a human actor")
	// ErrSignatureRequired is returned by a decision made without a signed
	// record while a trust list is in force: from the bootstrap on, every
	// human decision (approve, reject, rollback, disable, enable, pause,
	// resume, budget reset) must be signed by a listed key and made through
	// Decide (D22 b, O-16). Nothing is written.
	ErrSignatureRequired = errors.New("catalog: this decision must be signed: a trust list is in force")
	// ErrNotASigner is returned when a signed record was made with a key the
	// rule in force does not admit: a rotation not signed by a key of both
	// lists, a bootstrap not signed by its own list, or a decision signed by
	// a key the list does not name. A valid signature from such a key is not
	// authorisation (research finding 6).
	ErrNotASigner = errors.New("catalog: the key is not in the trust list")
	// ErrHeadMoved is returned by a signed write whose payload names another
	// audit head than the one the chain has: the log grew between the signing
	// and the transaction, so the signature must be made again over the new
	// head (the compare-and-set of finding 12). Nothing is written.
	ErrHeadMoved = errors.New("catalog: audit head mismatch")
	// ErrNoTrustList is returned when an operation needs the trust list and
	// the catalog was never bootstrapped; OpenWith wraps it in ErrCorrupt when
	// a trust root was pinned.
	ErrNoTrustList = errors.New("catalog: the catalog has no trust list")
)

// ActorType says whether a principal is a person or an automated process.
type ActorType string

const (
	ActorHuman  ActorType = "human"
	ActorSystem ActorType = "system"
)

// Actor is the principal behind an operation. Name is normalised by every
// Store method before it is stored or compared: NFKC, lower-cased, and it must
// then match ^[a-z0-9][a-z0-9._@-]{0,63}$, so that "Alice", "alice" and a
// full-width spelling are one identity and the two-person rule cannot be
// side-stepped with a look-alike.
type Actor struct {
	Name string
	Type ActorType
}

// ServerSpec describes an upstream MCP server to register.
type ServerSpec struct {
	// Name is unique and matches ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ in at most 63
	// bytes: the rule agentgateway v1.6.0 applies to the MCP target name the
	// emitted configuration derives from it. No underscore (the gateway
	// reserves it), no trailing hyphen, and no dot by choice; see
	// validateServerName.
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
	// Paused is set by PauseServer: crawls are refused and the snapshot is
	// empty until ResumeServer, while decisions keep working.
	Paused bool
	// ProcessorAddr is the host:port the server's processor listens on, as
	// emit last wrote it (SetProcessorAddr), or "" before the first emit. It
	// lives here, in the catalog, so that a re-emit never takes the address
	// from a file at --out that someone else may have written (D14).
	ProcessorAddr string
	CreatedAt     time.Time
}

// CrawledTool is one tool exactly as the upstream sent it.
type CrawledTool struct {
	Name string // the tool's "name" field
	Raw  []byte // the complete tool JSON object, byte for byte
}

// UnusableTool is a listed tool whose definition the crawler could not use:
// invalid, over a cap, or a name listed more than once. The catalog marks a
// known tool of that name unusable (it is never served while the marker
// stands) and records an unknown name as rejected.
type UnusableTool struct {
	// Name may be empty when the crawler could not read one, or when the name
	// itself broke the shared rule and must not be shown.
	Name string
	// Reason is a short class string such as "not-canonical".
	Reason string
	// Detail says how in fixed words; it never contains raw upstream text.
	Detail string
}

// CrawlInput is the result of one crawl of one server.
type CrawlInput struct {
	Server string
	// Complete is true only if every page of tools/list was fetched. An
	// incomplete crawl records a failure and changes no tool: a crawl failure is
	// not a removal.
	Complete bool
	// Error describes why the crawl was incomplete. Only its class is kept
	// outside the crawls table.
	Error    string
	Tools    []CrawledTool
	Unusable []UnusableTool
}

// ChangeKind classifies what a crawl did to one tool.
type ChangeKind string

const (
	ChangeNew        ChangeKind = "new"        // first time this tool was seen
	ChangeChanged    ChangeKind = "changed"    // the upstream serves a digest that is not the approved one
	ChangeUnchanged  ChangeKind = "unchanged"  // nothing to record
	ChangeReverted   ChangeKind = "reverted"   // upstream is back on the approved digest
	ChangeMissing    ChangeKind = "missing"    // absent from a successful crawl
	ChangeDeprecated ChangeKind = "deprecated" // absent for too many crawls
	ChangeReappeared ChangeKind = "reappeared" // returned after deprecation
	ChangeUnusable   ChangeKind = "unusable"   // listed with a definition that cannot be used
	ChangeReturned   ChangeKind = "returned"   // listed again after one or more missed crawls
)

// ToolChange is one line of a CrawlReport.
type ToolChange struct {
	Tool   string
	Kind   ChangeKind
	Digest string // the live digest, or "" if absent or unusable
	State  lifecycle.State
	// Reason is the class of an unusable observation, "" otherwise.
	Reason string
}

// RejectedTool is a listed entry that no tool row records: its name is not a
// known tool of the server and its definition or name broke a rule. Name is
// "" when the name itself was refused, so that a look-alike is never shown.
type RejectedTool struct {
	Name   string
	Reason string
	Detail string
}

// CrawlReport summarises one RecordCrawl call. Changes is sorted by tool name.
type CrawlReport struct {
	CrawlID  int64
	Complete bool
	// Error is the class recorded for a crawl that is not complete: the
	// caller's class, or the catalog's own reason for refusing the listing.
	Error    string
	Changes  []ToolChange
	Rejected []RejectedTool
}

// ToolView is a tool as shown to an operator.
type ToolView struct {
	ID            int64
	Server        string
	Name          string
	State         lifecycle.State
	Approved      string // digest, or ""
	Pending       string // digest of the current proposal, or ""
	LastSeen      string // digest the upstream served in the latest crawl, lifecycle.UnusableDigest, or ""
	Drifted       bool   // LastSeen differs from Approved
	Unusable      bool   // the upstream lists a definition that cannot be used
	Versions      int
	MissingCrawls int
	// ApprovedBy, ApprovedSeq and SignedSeq come from the verified approval
	// entry that anchors Approved (the newest version.approved or
	// version.rolled_back entry about the tool): the person who approved,
	// the entry's seq, and the seq of the decision.signed entry its signed=
	// token names, 0 for an approval made before the trust bootstrap or on a
	// catalog without a trust list. They let show say who approved and
	// whether the approval is signed (D22 (h)) without a second log read;
	// all three are zero while nothing is approved.
	ApprovedBy  string
	ApprovedSeq int64
	SignedSeq   int64
}

// VersionView is one immutable version of a tool.
type VersionView struct {
	No            int // 1-based, in first-seen order
	Digest        string
	DigestProfile string // the rule Digest was computed under, gate.DigestProfile
	Status        lifecycle.VersionStatus
	ProposedBy    string
	// Proposers is every principal whose crawl proposed this version, oldest
	// first; the first one is ProposedBy. None of them may approve it.
	Proposers    []string
	EverApproved bool
	FirstSeen    time.Time
	// Canonical is the RFC 8785 form of the whole definition that Digest hashes.
	Canonical []byte
}

// ToolPolicy is what the processor needs to know about one tool.
type ToolPolicy struct {
	State    lifecycle.State
	Approved string // digest, or ""
	// LastSeen is the digest the upstream served in the latest crawl,
	// lifecycle.UnusableDigest if it served a definition that cannot be used,
	// or "" if the tool was absent. The tools/call hook carries no tool
	// definition, so this is how the control plane can veto a call for a
	// client that has not re-listed since the upstream changed.
	LastSeen string
}

// Snapshot is the serving policy of one server at one generation. Keys are
// upstream tool names. A name that is not in Tools is not served (a catalog
// miss fails closed); a paused server has no tools at all.
type Snapshot struct {
	Server     string
	Generation int64
	// CrawledAt is the UTC time of the latest complete crawl of the server,
	// zero if there was none.
	CrawledAt time.Time
	Tools     map[string]ToolPolicy
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
