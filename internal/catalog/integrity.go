package catalog

import (
	"context"
	"fmt"

	"github.com/sairam0424/toolwarrant/internal/audit"
)

// IntegrityReport is the result of Integrity: the mutable registry (the
// servers and tools tables and the status columns of tool_versions) checked
// against the append-only history (approvals and the audit log), and the
// objects in the file against the schema. The counters summarise the
// cross-checks by kind; Problems lists every finding, one line each, with
// names quoted and no upstream text. An empty Problems means the registry is
// what its history says it should be; a non-empty one means the file was
// edited outside toolwarrant, or a bug wrote it, and nothing should be served
// from it.
type IntegrityReport struct {
	// GuardsMissing and GuardsRedefined label the schema's objects ("trigger
	// X", "index X", "table X") that are absent, or present under a definition
	// that differs from the schema's. A missing or redefined guard leaves
	// history tables editable; a redefined table carries a constraint the
	// schema does not have (D15 e).
	GuardsMissing, GuardsRedefined []string
	// ForeignObjects labels the tables, triggers, views, unique indexes and
	// automatic indexes ("table X", "trigger X", "view X", "index X") that the
	// schema did not create. A trigger on the tools table can undo every
	// decision inside the catalog's own transaction while the log records the
	// decision, and a unique or automatic index makes every write that repeats
	// its value fail; nothing of someone else's making may exist.
	ForeignObjects []string
	// ChainBreaks counts the audit entries that do not re-seal (the hash of
	// their fields is not their stored hash: rewritten in place), do not link
	// to their predecessor (prev_hash is not its hash: re-chained, or the
	// predecessor rewritten), or do not follow it in sequence (deleted
	// entries), the rows at seq 0 or below, which the catalog never writes and
	// no chain contains (D17 d), and a row count that differs from the entries
	// the walk read. Integrity verifies every entry as it streams the log (D15
	// c), so its cross-checks against the log stand on their own; VerifyAudit
	// stops at the first break, this counts every one.
	ChainBreaks int
	// GhostRows counts approvals and tool_versions rows whose id is below 1
	// and signed_records rows whose seq is below 1. The catalog assigns ids
	// from 1, and SQLite evaluates an unsupplied id as -1 inside a BEFORE
	// INSERT trigger, so such a row was never the newest decision, satisfied
	// the per-version approval evidence, and made the no-replace guards
	// refuse every later insert (D17 b, g), and a signed record below seq 1
	// belongs to no audit entry (D22 g); every read and write refuses a file
	// that holds one, and the positive-id guards refuse the insert.
	GhostRows int
	// ApprovalsWithoutRecord counts versions in status approved, or marked
	// ever approved, with no approve or rollback row in the approvals table:
	// the status columns are mutable, the approvals table is not.
	ApprovalsWithoutRecord int
	// ApprovalsWithoutAuditEntry counts approvals rows with no audit entry of
	// the same event, tool, digest, actor and time; a row appended by hand.
	ApprovalsWithoutAuditEntry int
	// AuditEntriesWithoutApproval counts version.approved, version.rejected
	// and version.rolled_back entries with no approvals row to match.
	AuditEntriesWithoutApproval int
	// ApprovedDigestMismatches counts tools whose approved digest, or lack of
	// one, is not what the audit log last recorded: the newest
	// version.approved or version.rolled_back entry about the tool must name
	// it as after_hash, and so must the newest entry about the tool of any
	// kind, because every operation that changes the approval writes one.
	ApprovedDigestMismatches int
	// StaleLastSeen counts tools whose last_seen_digest is not the last_seen
	// value the newest audit entry about the tool recorded, and tools the log
	// never mentions at all.
	StaleLastSeen int
	// StateMismatches counts tools whose state is not the one the newest audit
	// entry about the tool left behind (the after half of its state field): a
	// disabled, deprecated or never-approved tool switched on by hand.
	StateMismatches int
	// BudgetMismatches counts tools whose proposals_since_decision is not what
	// the newest audit entry about the tool recorded (the after half of its
	// proposals field): a budget granted back without a tool.budget_reset entry.
	BudgetMismatches int
	// ServersMismatched counts servers whose row disagrees with the log: the
	// paused flag against the newest server.paused or server.resumed entry (or
	// server.added, which registers a running server), allow_private and the
	// SHA-256 of the URL against the server.added detail, the processor
	// address against the newest server.processor_set entry, a row the log
	// never registered, and a registration whose row is gone.
	ServersMismatched int
	// RowsMissing counts what the history describes but the registry has lost:
	// a tool the log mentions with no tools row, a version the log proposed
	// with no tool_versions row, and a tool_versions row whose tool row is
	// gone. The catalog never deletes a row, so each is an edit of history
	// (D14): deleting a tool row lets the next crawl discover the name afresh
	// with a fresh proposer history, which launders the two-person rule.
	RowsMissing int
	// DiscoveryMismatches counts tools rows with no tool.discovered entry and
	// tool.discovered entries about a subject an earlier entry already
	// discovered; the catalog writes exactly one per tool it ever creates.
	DiscoveryMismatches int
	// VersionStatusMismatches counts versions whose status or ever_approved
	// column differs from what the log's version.proposed, version.superseded,
	// version.rejected, version.approved and version.rolled_back entries leave
	// behind, and versions the log never proposed: a rejected definition put
	// back to pending by hand becomes approvable again.
	VersionStatusMismatches int
	// ProposerMismatches counts versions whose proposer list is not the
	// sequence of actors of the version.proposed entries about them (an
	// Enable re-proposes without adding anybody): a proposer rewritten out of
	// the history under a re-created guard may then approve their own bytes.
	ProposerMismatches int
	// SignedRecordsInvalid counts the signed entries (trust.bootstrap,
	// trust.rotated, decision.signed) whose record fails the binding rule of
	// the walk (trustwalk.go, rule 1: no row at the seq, a sigref or signer
	// token the row does not match, a signature that does not verify, a
	// payload that is not canonical, of another type, for another catalog or
	// another head, or by a system actor) and the decision records whose
	// signer the list in force does not authorise (rule 4).
	SignedRecordsInvalid int
	// SignedRecordsOrphaned counts signed_records rows at the seq of an entry
	// that carries no record, or of no entry; the catalog writes a row only
	// with a signed entry, so such a row was inserted by hand.
	SignedRecordsOrphaned int
	// UnsignedDecisionsAfterBootstrap counts the entries after the trust
	// bootstrap that a human decision alone writes (version.approved,
	// version.rejected, version.rolled_back, tool.disabled, tool.enabled,
	// tool.budget_reset, server.paused, server.resumed) and that name no
	// verified decision.signed entry of their own transaction (rule 5 of the
	// walk, decisionwalk.go): no signed= token, a token naming no verified
	// record, one of another subject, actor, time or transaction, or one
	// whose kind writes no such entry; and every other entry whose signed=
	// token fails the same binding. Each was appended outside toolwarrant.
	UnsignedDecisionsAfterBootstrap int
	// CrawlTransitionsForged counts the entries after the trust bootstrap
	// that no decision signed and that move a tool's state along a
	// transition no crawl observation can make (rule 6, lifecycle.CrawlMayMove):
	// a tool.reverted with state=disabled->enabled appended by hand.
	CrawlTransitionsForged int
	// LegacyApprovalsInService lists, sorted, the tools whose approval in
	// force was made before the trust bootstrap (O-12): served by chain
	// anchoring alone, as in v0.3, until re-approved with a signed decision.
	// It is information, not a problem, and adds no line to Problems; nil
	// when the catalog has no trust list.
	LegacyApprovalsInService []string
	// TrustListsInvalid counts the trust entries whose list the rotation rule
	// refuses (rule 3: a second bootstrap, a rotation before one, a version
	// that is not exactly one above the list in force, a signer not in both
	// lists, a bootstrap not signed by its own list or by the pinned root, an
	// invalid list, an actor the new list names another key for) and, with a
	// trust root pinned, a log that holds no trust entry at all, which every
	// walk refuses as a catalog that was never bootstrapped. The list in
	// force stays what it was, so later records are judged against it.
	TrustListsInvalid int
	// Problems lists every finding in one line each, in table order.
	Problems []string
}

// Integrity checks the database against itself and reports every
// disagreement; see IntegrityReport. VerifyAudit proves that the log was not
// edited and stops at the first break; Integrity verifies every entry's seal
// and link as it streams the log and reports each break, then proves that the
// current policy is what the log says it should be, which the chain alone
// cannot: the servers and tools tables and
// the status columns of tool_versions are mutable by design, so a forged
// approval, a tool switched back on, a server un-paused, a rewritten
// last_seen_digest or a replaced guard trigger leaves the chain intact and the
// processor's read path has no way to tell. Integrity also re-hashes the
// canonical bytes of every approved version, whatever the Store remembers, so
// the one report says whether the file can be trusted.
//
// Everything is read in one read transaction, so the report describes one
// consistent state. The log is streamed in pages and reduced to one small
// record per tool, one per server, one per version ever proposed and one per
// decision ever made, so memory grows with the catalog and the decisions, not
// with the crawl history. The error is non-nil only when the check itself
// could not run; otherwise the report is complete and Problems is the verdict.
func (s *Store) Integrity(ctx context.Context) (IntegrityReport, error) {
	var rep IntegrityReport
	err := s.inRead(ctx, func(q queryer) error {
		c := newIntegrityCheck(ctx, q, &rep, s.trustRoot)
		return c.run()
	})
	if err != nil {
		return IntegrityReport{}, err
	}
	return rep, nil
}

// integrityCheck is the state of one Integrity run: what the audit log says
// about every tool, every server, every version and every decision, gathered
// in one pass over the log, and the report being filled.
type integrityCheck struct {
	ctx context.Context
	q   queryer
	rep *IntegrityReport
	// latest is, per tool subject, what the newest entry about the tool left
	// behind; latestApproval the newest version.approved or version.rolled_back
	// entry; discovered the seq of the tool.discovered entry per subject;
	// versions what the log says about each version, by subject and digest;
	// servers what the log says about each server; decisions the multiset of
	// decision entries, by key, with their sequence numbers, which
	// checkApprovals consumes; seen the tool subjects that have a row, which
	// checkTools fills for checkLogSubjects; signedEntries the entries that
	// carry a signed record, in seq order, which checkSignedRecords verifies
	// against the rows with the pinned trustRoot (integrity_signed.go),
	// leaving in trustFold the list in force after them and in outcomes the
	// decision records it accepted, which checkDecisionEntries holds every
	// other entry to (integrity_decisions.go).
	latest         map[string]toolTrace
	latestApproval map[string]decisionTrace
	discovered     map[string]int64
	versions       map[versionKey]*versionTrace
	servers        map[string]*serverTrace
	decisions      map[decisionKey][]int64
	seen           map[string]bool
	signedEntries  []audit.Entry
	trustRoot      string
	trustFold      trustMemory
	outcomes       map[int64]signedOutcome
}

func newIntegrityCheck(ctx context.Context, q queryer, rep *IntegrityReport, trustRoot string) *integrityCheck {
	return &integrityCheck{
		ctx: ctx, q: q, rep: rep,
		latest:         map[string]toolTrace{},
		latestApproval: map[string]decisionTrace{},
		discovered:     map[string]int64{},
		versions:       map[versionKey]*versionTrace{},
		servers:        map[string]*serverTrace{},
		decisions:      map[decisionKey][]int64{},
		seen:           map[string]bool{},
		trustRoot:      trustRoot,
		outcomes:       map[int64]signedOutcome{},
	}
}

// run performs the passes in dependency order: the log first, because the
// tool, server, version and approval passes compare against what it recorded.
func (c *integrityCheck) run() error {
	steps := []func() error{
		c.checkGuardObjects, c.readLog, c.checkServers, c.checkTools, c.checkLogSubjects,
		c.checkVersions, c.checkVersionHistory, c.checkOrphanVersions, c.checkApprovedBytes, c.checkApprovals,
		c.checkSignedRecords, c.checkDecisionEntries,
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return err
		}
	}
	return nil
}

func (c *integrityCheck) problem(format string, args ...any) {
	c.rep.Problems = append(c.rep.Problems, fmt.Sprintf(format, args...))
}

func (c *integrityCheck) checkGuardObjects() error {
	g, err := checkGuards(c.ctx, c.q)
	if err != nil {
		return err
	}
	c.rep.GuardsMissing, c.rep.GuardsRedefined, c.rep.ForeignObjects = g.missing, g.redefined, g.foreign
	for _, line := range g.describe(": the schema did not create it") {
		c.problem("%s", line)
	}
	return nil
}
