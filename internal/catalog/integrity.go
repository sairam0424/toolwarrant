package catalog

import (
	"context"
	"database/sql"
	"fmt"
	"maps"
	"slices"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
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
	// GuardsMissing and GuardsRedefined label the guard objects ("trigger X",
	// "index X") that are absent, or present under a definition that differs
	// from the schema's. Either leaves history tables editable.
	GuardsMissing, GuardsRedefined []string
	// ForeignObjects labels the triggers, views and unique indexes ("trigger
	// X", "view X", "index X") that the schema did not create. A trigger on
	// the tools table can undo every decision inside the catalog's own
	// transaction while the log records the decision, and a unique index makes
	// every write that repeats its value fail; nothing of someone else's making
	// may exist.
	ForeignObjects []string
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
	// Problems lists every finding in one line each, in table order.
	Problems []string
}

// Integrity checks the database against itself and reports every
// disagreement; see IntegrityReport. VerifyAudit proves that the log was not
// edited; Integrity proves that the current policy is what the log says it
// should be, which the chain alone cannot: the servers and tools tables and
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
		c := newIntegrityCheck(ctx, q, &rep)
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
	// checkTools fills for checkLogSubjects.
	latest         map[string]toolTrace
	latestApproval map[string]decisionTrace
	discovered     map[string]int64
	versions       map[versionKey]*versionTrace
	servers        map[string]*serverTrace
	decisions      map[decisionKey][]int64
	seen           map[string]bool
}

func newIntegrityCheck(ctx context.Context, q queryer, rep *IntegrityReport) *integrityCheck {
	return &integrityCheck{
		ctx: ctx, q: q, rep: rep,
		latest:         map[string]toolTrace{},
		latestApproval: map[string]decisionTrace{},
		discovered:     map[string]int64{},
		versions:       map[versionKey]*versionTrace{},
		servers:        map[string]*serverTrace{},
		decisions:      map[decisionKey][]int64{},
		seen:           map[string]bool{},
	}
}

// run performs the passes in dependency order: the log first, because the
// tool, server, version and approval passes compare against what it recorded.
func (c *integrityCheck) run() error {
	steps := []func() error{
		c.checkGuardObjects, c.readLog, c.checkServers, c.checkTools, c.checkLogSubjects,
		c.checkVersions, c.checkVersionHistory, c.checkOrphanVersions, c.checkApprovedBytes, c.checkApprovals,
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
	for _, label := range g.missing {
		c.problem("guard %s is missing", label)
	}
	for _, label := range g.redefined {
		c.problem("guard %s was redefined", label)
	}
	for _, label := range g.foreign {
		c.problem("unexpected %s: the schema did not create it", label)
	}
	return nil
}

// integrityToolsQuery reads every tool with what the registry claims about
// its approval. The joins are outer so that a row pointing nowhere is
// reported rather than dropped.
const integrityToolsQuery = `SELECT s.name, t.id, t.name, t.state, t.last_seen_digest, t.proposals_since_decision,
		t.approved_version_id, av.id, av.tool_id, COALESCE(av.digest, ''), COALESCE(av.status, '')
	FROM tools t LEFT JOIN servers s ON s.id = t.server_id
	LEFT JOIN tool_versions av ON av.id = t.approved_version_id
	ORDER BY s.name, t.name`

// integrityTool is one row of integrityToolsQuery.
type integrityTool struct {
	server                      sql.NullString
	id                          int64
	name, state, lastSeen       string
	budget                      int
	pointer, joined, joinedTool sql.NullInt64
	digest, status              string
}

func (c *integrityCheck) checkTools() error {
	rows, err := c.q.QueryContext(c.ctx, integrityToolsQuery)
	if err != nil {
		return fmt.Errorf("catalog: read tools: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var r integrityTool
		if err := rows.Scan(&r.server, &r.id, &r.name, &r.state, &r.lastSeen, &r.budget, &r.pointer, &r.joined, &r.joinedTool,
			&r.digest, &r.status); err != nil {
			return fmt.Errorf("catalog: read tools: %w", err)
		}
		c.checkTool(r)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("catalog: read tools: %w", err)
	}
	return nil
}

// checkTool compares one tools row with what the log recorded about it. A
// tool counts once under ApprovedDigestMismatches however many ways its
// approval disagrees with the log, and once under each of StaleLastSeen,
// StateMismatches, BudgetMismatches and DiscoveryMismatches.
func (c *integrityCheck) checkTool(r integrityTool) {
	subject := r.server.String + "/" + r.name
	shown := quote(subject)
	c.seen[subject] = true
	if !r.server.Valid {
		c.problem("tool %s belongs to a server that does not exist", shown)
	}
	if _, ok := c.discovered[subject]; !ok {
		c.problem("tool %s: the audit log has no tool.discovered entry about it", shown)
		c.rep.DiscoveryMismatches++
	}
	approved, sound := c.registryApproval(r, shown)
	mismatch := !sound
	trace, known := c.latest[subject]
	switch {
	case !known:
		c.problem("tool %s: the audit log has no entry about it", shown)
		c.rep.StaleLastSeen++
		mismatch = mismatch || approved != ""
	default:
		if trace.approved != approved {
			c.problem("tool %s: approved digest is %s but the latest audit entry (seq %d) left it as %s",
				shown, shownDigest(approved), trace.seq, shownDigest(trace.approved))
			mismatch = true
		}
		c.compareMutableColumns(r, trace, shown)
	}
	if approved != "" && !c.approvalEntryNames(subject, approved, shown) {
		mismatch = true
	}
	if mismatch {
		c.rep.ApprovedDigestMismatches++
	}
}

// compareMutableColumns checks the columns of a tools row that no other pass
// covers against the newest entry about the tool: last_seen_digest, state and
// proposals_since_decision.
func (c *integrityCheck) compareMutableColumns(r integrityTool, trace toolTrace, shown string) {
	if trace.lastSeen != r.lastSeen {
		c.problem("tool %s: last_seen_digest is %s but the latest audit entry (seq %d) recorded %s",
			shown, shownDigest(r.lastSeen), trace.seq, shownDigest(trace.lastSeen))
		c.rep.StaleLastSeen++
	}
	if trace.state != r.state {
		c.problem("tool %s: state is %s but the latest audit entry (seq %d) left it as %s",
			shown, quote(r.state), trace.seq, quote(trace.state))
		c.rep.StateMismatches++
	}
	if trace.budget != r.budget {
		c.problem("tool %s: proposals_since_decision is %d but the latest audit entry (seq %d) left it as %d",
			shown, r.budget, trace.seq, trace.budget)
		c.rep.BudgetMismatches++
	}
}

// registryApproval returns the digest the tools row claims is approved ("" when
// none) and whether the pointer behind the claim is sound: it must resolve to
// a version of this tool whose status is approved.
func (c *integrityCheck) registryApproval(r integrityTool, shown string) (string, bool) {
	if !r.pointer.Valid {
		return "", true
	}
	switch {
	case !r.joined.Valid:
		c.problem("tool %s points at a version that does not exist", shown)
		return "", false
	case r.joinedTool.Int64 != r.id:
		c.problem("tool %s points at a version that is not its own", shown)
	case r.status != string(lifecycle.VersionApproved):
		c.problem("tool %s points at a version whose status is %s, not approved", shown, quote(r.status))
	default:
		return r.digest, true
	}
	return r.digest, false
}

// approvalEntryNames requires the newest version.approved or
// version.rolled_back entry about the tool to have approved exactly digest.
func (c *integrityCheck) approvalEntryNames(subject, digest, shown string) bool {
	d, ok := c.latestApproval[subject]
	switch {
	case !ok:
		c.problem("tool %s: approved digest %s has no version.approved or version.rolled_back entry", shown, digest)
	case d.digest != digest:
		c.problem("tool %s: approved digest is %s but the latest approval entry (seq %d) approved %s",
			shown, digest, d.seq, shownDigest(d.digest))
	default:
		return true
	}
	return false
}

// checkLogSubjects reports every tool the log describes whose row is gone.
// The catalog never deletes a tools row, and the next crawl would discover the
// name afresh with a fresh proposer history (D14).
func (c *integrityCheck) checkLogSubjects() error {
	for _, subject := range slices.Sorted(maps.Keys(c.latest)) {
		if !c.seen[subject] {
			c.problem("tool %s: the audit log describes it (latest entry seq %d) but no tools row exists", quote(subject), c.latest[subject].seq)
			c.rep.RowsMissing++
		}
	}
	return nil
}

// shownDigest renders a digest column for a report line: "none" for an empty
// value, the marker and a well-formed digest as they are, anything else
// quoted, because a column someone edited by hand may hold anything.
func shownDigest(s string) string {
	switch {
	case s == "":
		return "none"
	case s == lifecycle.UnusableDigest, lifecycle.IsDigest(s):
		return s
	}
	return quote(s)
}
