package catalog

import (
	"database/sql"
	"fmt"
	"maps"
	"slices"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// The tools side of Integrity: every tools row compared with what the newest
// audit entry about the tool left behind, and every tool the log describes
// whose row is gone.

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
