package catalog

import (
	"database/sql"
	"fmt"
	"slices"
	"strconv"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// The audit side of Integrity: one streaming pass over the log reduces it to
// what the registry must agree with, and the approvals table is then matched
// against the decision entries as a multiset.

// toolTrace is what the newest audit entry about a tool left behind: the
// approved digest (after_hash) and, from its detail, the state and proposals
// transitions' after halves and the last_seen field.
type toolTrace struct {
	seq      int64
	approved string
	state    string
	lastSeen string
	budget   int
}

// decisionTrace is the newest version.approved or version.rolled_back entry
// about a tool and the digest it approved.
type decisionTrace struct {
	seq    int64
	digest string
}

// decisionKey identifies a decision as both the approvals table and the audit
// log record it. The catalog writes both sides in one transaction with one
// timestamp, so every field must agree; a row or an entry that matches on
// nothing less was not written by a decision.
type decisionKey struct {
	event, subject, digest, actor, actorType, ts string
}

// decisionEvent maps an approvals.decision value to the audit event the same
// transaction writes.
func decisionEvent(decision string) string {
	switch decision {
	case decisionApprove:
		return string(lifecycle.EvApproved)
	case decisionReject:
		return string(lifecycle.EvRejected)
	case decisionRollback:
		return string(lifecycle.EvRolledBack)
	}
	return ""
}

func isDecisionEvent(event string) bool {
	return event == string(lifecycle.EvApproved) || event == string(lifecycle.EvRejected) || event == string(lifecycle.EvRolledBack)
}

// readLog streams the whole log in pages, oldest first, and notes every entry.
func (c *integrityCheck) readLog() error {
	for after := int64(0); ; {
		page, err := queryAudit(c.ctx, c.q, after, auditPage)
		if err != nil {
			return err
		}
		for _, e := range page {
			c.noteEntry(e)
		}
		if len(page) < auditPage {
			return nil
		}
		after = page[len(page)-1].Seq
	}
}

// noteEntry records what one entry says. Entries arrive in sequence order, so
// the last one written about a subject is the one that stands.
func (c *integrityCheck) noteEntry(e audit.Entry) {
	if isDecisionEvent(e.Event) {
		digest, _ := detailField(e.Detail, fieldDigest)
		k := decisionKey{event: e.Event, subject: e.Subject, digest: digest, actor: e.Actor, actorType: e.ActorType, ts: e.TS}
		c.decisions[k] = append(c.decisions[k], e.Seq)
		if e.Event != string(lifecycle.EvRejected) {
			c.latestApproval[e.Subject] = decisionTrace{seq: e.Seq, digest: e.AfterHash}
		}
	}
	switch e.Event {
	case evServerAdded, evServerPaused, evServerResumed, evServerProcessorSet:
		c.noteServerEntry(e)
		return
	}
	if !isToolDetail(e.Detail) {
		return // about a crawl or a rejected entry: no tool row to compare
	}
	trace, missing := parseToolTrace(e)
	if missing != "" {
		c.problem("audit entry %d about %s has no %s field", e.Seq, quote(e.Subject), missing)
		return
	}
	c.latest[e.Subject] = trace
	if e.Event == string(lifecycle.EvDiscovered) {
		c.noteDiscovered(e)
	}
	if isVersionEvent(e.Event) {
		c.noteVersionEvent(e)
	}
}

// noteDiscovered records the one tool.discovered entry a subject may have. The
// catalog writes it when it creates the row and never deletes a row, so a
// second one means the row was deleted and the name discovered afresh (D14).
func (c *integrityCheck) noteDiscovered(e audit.Entry) {
	if first, ok := c.discovered[e.Subject]; ok {
		c.problem("audit entry %d discovers tool %s a second time (entry %d discovered it first); its row was deleted and re-created", e.Seq, quote(e.Subject), first)
		c.rep.DiscoveryMismatches++
		return
	}
	c.discovered[e.Subject] = e.Seq
}

// parseToolTrace reads the fields of a tool detail Integrity compares with the
// tools row. It returns the name of the first field that is absent or not of
// the shape toolDetail writes; an entry with such a detail is reported and
// does not replace what an earlier entry said.
func parseToolTrace(e audit.Entry) (toolTrace, string) {
	trace := toolTrace{seq: e.Seq, approved: e.AfterHash}
	lastSeen, ok := detailField(e.Detail, fieldLastSeen)
	if !ok {
		return toolTrace{}, fieldLastSeen
	}
	trace.lastSeen = fromNoDigest(lastSeen)
	state, ok := detailField(e.Detail, fieldState)
	if trace.state, ok = transitionAfterIf(state, ok); !ok {
		return toolTrace{}, fieldState
	}
	proposals, ok := detailField(e.Detail, fieldProposals)
	after, ok := transitionAfterIf(proposals, ok)
	if !ok {
		return toolTrace{}, fieldProposals
	}
	budget, err := strconv.Atoi(after)
	if err != nil || budget < 0 {
		return toolTrace{}, fieldProposals
	}
	trace.budget = budget
	return trace, ""
}

// transitionAfterIf is transitionAfter guarded by whether the field was found.
func transitionAfterIf(v string, found bool) (string, bool) {
	if !found {
		return "", false
	}
	return transitionAfter(v)
}

// fromNoDigest undoes orNoDigest.
func fromNoDigest(s string) string {
	if s == noDigest {
		return ""
	}
	return s
}

// integrityApprovalsQuery reads every approvals row with the tool it concerns.
// The joins are outer so that a row pointing nowhere is reported, not dropped.
const integrityApprovalsQuery = `SELECT a.id, a.decision, a.approver, a.actor_type, a.hash_seen, a.at,
		v.digest, s.name, t.name
	FROM approvals a LEFT JOIN tool_versions v ON v.id = a.version_id
	LEFT JOIN tools t ON t.id = v.tool_id LEFT JOIN servers s ON s.id = t.server_id
	ORDER BY a.id`

// approvalRow is one row of integrityApprovalsQuery.
type approvalRow struct {
	id                                      int64
	decision, approver, actorType, seen, at string
	digest, server, tool                    sql.NullString
}

// checkApprovals matches every approvals row with a decision entry and then
// reports the entries no row matched.
func (c *integrityCheck) checkApprovals() error {
	rows, err := c.q.QueryContext(c.ctx, integrityApprovalsQuery)
	if err != nil {
		return fmt.Errorf("catalog: read approvals: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var a approvalRow
		if err := rows.Scan(&a.id, &a.decision, &a.approver, &a.actorType, &a.seen, &a.at, &a.digest, &a.server, &a.tool); err != nil {
			return fmt.Errorf("catalog: read approvals: %w", err)
		}
		c.matchApproval(a)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("catalog: read approvals: %w", err)
	}
	c.reportUnmatchedDecisions()
	return nil
}

// matchApproval consumes the decision entry that recorded this row, or reports
// the row. The approver, timestamp and hash_seen columns are quoted when shown:
// a row appended by hand may hold anything.
func (c *integrityCheck) matchApproval(a approvalRow) {
	if !a.digest.Valid || !a.server.Valid || !a.tool.Valid {
		c.rep.ApprovalsWithoutAuditEntry++
		c.problem("approvals row %d points at a version, tool or server that does not exist", a.id)
		return
	}
	if a.seen != a.digest.String {
		c.problem("approvals row %d: hash_seen %s is not the digest of its version (%s)", a.id, quote(a.seen), a.digest.String)
	}
	subject := a.server.String + "/" + a.tool.String
	k := decisionKey{event: decisionEvent(a.decision), subject: subject, digest: a.digest.String,
		actor: a.approver, actorType: a.actorType, ts: a.at}
	if seqs := c.decisions[k]; len(seqs) > 0 {
		c.decisions[k] = seqs[1:]
		return
	}
	c.rep.ApprovalsWithoutAuditEntry++
	c.problem("approvals row %d (%s of %s on tool %s by %s at %s) has no matching audit entry",
		a.id, a.decision, a.digest.String, quote(subject), quote(a.approver), quote(a.at))
}

// reportUnmatchedDecisions lists, in sequence order, every decision entry that
// no approvals row accounted for.
func (c *integrityCheck) reportUnmatchedDecisions() {
	type leftover struct {
		seq int64
		key decisionKey
	}
	var left []leftover
	for k, seqs := range c.decisions {
		for _, seq := range seqs {
			left = append(left, leftover{seq: seq, key: k})
		}
	}
	slices.SortFunc(left, func(a, b leftover) int { return int(a.seq - b.seq) })
	for _, l := range left {
		c.rep.AuditEntriesWithoutApproval++
		c.problem("audit entry %d (%s of %s on tool %s by %s) has no matching approvals row",
			l.seq, l.key.event, shownDigest(l.key.digest), quote(l.key.subject), l.key.actor)
	}
}
