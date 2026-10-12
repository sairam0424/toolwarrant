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

// readLog streams the whole log in pages, oldest first, from the smallest
// seq SQLite can store, bound included (D17 d), verifies every entry's seal and its
// link to the entry before it (checkLink, D15 c) and notes what every entry
// says. A row at seq 0 or below is outside the chain: it is reported as a
// break and neither linked nor noted, so a forged row placed there cannot
// stand in for history. The row count is then compared with the entries read.
func (c *integrityCheck) readLog() error {
	var prev audit.Entry
	walked := 0
	for next := int64(firstPossibleSeq); ; {
		page, err := queryAudit(c.ctx, c.q, next, auditPage)
		if err != nil {
			return err
		}
		for _, e := range page {
			walked++
			if e.Seq < 1 {
				c.problem("audit entry %d has a sequence number below 1, which the catalog never writes (the chain starts at seq 1); the row was inserted by hand and is not part of the chain", e.Seq)
				c.rep.ChainBreaks++
				continue
			}
			c.checkLink(prev, e)
			prev = e
			c.noteEntry(e)
		}
		if len(page) < auditPage {
			break
		}
		next = page[len(page)-1].Seq + 1
	}
	return c.checkLogCount(walked)
}

// checkLogCount compares the number of rows audit_log holds with the number
// the walk read; the two are read in one transaction, so a difference means
// the table answers the two questions differently.
func (c *integrityCheck) checkLogCount(walked int) error {
	var n int
	if err := c.q.QueryRowContext(c.ctx, `SELECT COUNT(*) FROM audit_log`).Scan(&n); err != nil {
		return fmt.Errorf("catalog: count audit entries: %w", err)
	}
	if n != walked {
		c.problem("audit_log holds %d rows but the walk from the first sequence number read %d", n, walked)
		c.rep.ChainBreaks++
	}
	return nil
}

// checkLink verifies one entry against the entry before it (the zero Entry
// before the first) and reports each break on its own line: a seq that does
// not follow means deleted entries; a prev_hash that is not the predecessor's
// hash means the entry was re-chained or its predecessor rewritten; a hash
// that is not the hash of the entry's fields means the entry was rewritten in
// place. Integrity does not stop at a break, as VerifyAudit does, so one
// report names every one; the cross-checks that follow then rest on entries
// this pass has verified.
func (c *integrityCheck) checkLink(prev, e audit.Entry) {
	if e.Seq != prev.Seq+1 {
		c.problem("audit entry %d follows entry %d: the sequence has a gap, entries were deleted", e.Seq, prev.Seq)
		c.rep.ChainBreaks++
	}
	want := prev.Hash
	if prev.Seq == 0 {
		want = audit.Genesis
	}
	if e.PrevHash != want {
		c.problem("audit entry %d does not continue the chain from entry %d: its prev_hash is not that entry's hash", e.Seq, prev.Seq)
		c.rep.ChainBreaks++
	}
	if h, err := audit.HashOf(e); err != nil || h != e.Hash {
		c.problem("audit entry %d does not re-seal: its hash is not the hash of its fields; the entry was rewritten in place", e.Seq)
		c.rep.ChainBreaks++
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
// the row. A row below id 1 is reported and matched against nothing: the
// catalog never assigns such an id, and a row placed there must not consume
// the entry of a decision the Store did write (D17 b). The approver, timestamp
// and hash_seen columns are quoted when shown: a row appended by hand may hold
// anything.
func (c *integrityCheck) matchApproval(a approvalRow) {
	if a.id < 1 {
		c.rep.GhostRows++
		c.problem("approvals row %d has an id below 1, which the catalog never assigns; the row was inserted by hand and is not a decision", a.id)
		return
	}
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
