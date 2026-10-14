package catalog

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// Approved returns the approved version of every tool that is enabled or
// changed_pending_reapproval, ordered by server then tool name. The tool's
// newest approve or rollback row must name the approved version and carry its
// digest as hash_seen, and the newest version.approved or version.rolled_back
// audit entry about the tool must have recorded the digest and be part of the
// verified chain (anchorApproved). The approver and time come from that
// verified entry, and the row must agree with it (D17 e: the export used to
// take them from the row, which one UPDATE under a re-created guard rewrote
// while the chain, the recorded head and every serving-path check stayed
// clean, so the git export named the wrong approver). A version whose
// canonical form no longer hashes to its digest, whose digest profile is not
// the current one, whose pointer dangles or names another tool's version, or
// that the newest decision or the newest approval entry does not name, is
// reported as ErrCorrupt rather than exported. The export carries the bytes,
// so they are read on every call; only the hash is skipped, for a row this
// Store verified within RecheckTTL. Tools of a paused server are included: the
// export describes approvals, not serving. The guard objects and the pinned
// chain are verified first, as on every Snapshot load. The state column of
// every tool row, exported or not, is anchored to the newest state-bearing
// entry about the tool (readToolStates, anchorStates): the export used to
// anchor only the rows it returned, so an approved tool whose state had been
// edited to disabled by hand simply vanished from it, and emit wrote a smaller
// allow list from a catalog that list and audit verify refused (found by the
// v0.1.0 verification). Such a row is ErrCorrupt here as everywhere else.
func (s *Store) Approved(ctx context.Context) ([]ApprovedTool, error) {
	tools, _, err := s.ApprovedWithHead(ctx)
	return tools, err
}

// ApprovedWithHead is Approved together with the head of the audit chain as
// this read verified it (AuditHead), both from one read transaction: the
// file check fixes the snapshot and walks the chain to the head under the
// walk lock, the pin is taken under that same hold, and the approvals and
// every anchor are read from the same snapshot. A commit by another process
// or handle while the export runs (the scheduled crawl appends every minute
// and can deprecate a tool, another operator can approve or revoke) therefore
// lands in both the head and the list or in neither; read as two calls, a
// commit between them made MANIFEST.json name a head whose approval set was
// not the one the files mirrored (D21 e). The head is audit.Genesis for an
// empty log.
func (s *Store) ApprovedWithHead(ctx context.Context) ([]ApprovedTool, string, error) {
	out := []ApprovedTool{}
	head := audit.Genesis
	err := s.inRead(ctx, func(q queryer) error {
		pin, err := s.checkFilePinned(ctx, q)
		if err != nil {
			return err
		}
		head = headOf(pin)
		return s.readApprovedAnchored(ctx, q, &out)
	})
	if err != nil {
		return nil, "", err
	}
	return out, head, nil
}

// readApprovedAnchored is the body of Approved after the file check: the
// exported tools, their approval entries verified against the chain, every
// tool row's state anchored, and the approvers adopted from the verified
// entries.
func (s *Store) readApprovedAnchored(ctx context.Context, q queryer, out *[]ApprovedTool) error {
	refs, err := s.readApproved(ctx, q, out)
	if err != nil {
		return err
	}
	entries, err := verifyAnchors(ctx, q, s.chain, refs)
	if err != nil {
		return err
	}
	states, err := readToolStates(ctx, q)
	if err != nil {
		return err
	}
	if err := anchorStates(ctx, q, s.chain, states); err != nil {
		return err
	}
	return adoptApprovers(*out, refs, entries)
}

// adoptApprovers fills in the approver and time of every exported tool from
// its verified approval entry; refs runs parallel to tools.
func adoptApprovers(tools []ApprovedTool, refs []approvedRef, entries map[int64]audit.Entry) error {
	for i, r := range refs {
		e := entries[r.entry.Int64]
		when, err := parseTime(e.TS)
		if err != nil {
			return err
		}
		tools[i].ApprovedBy, tools[i].ApprovedAt = e.Actor, when
	}
	return nil
}

// readApproved runs approvedQuery, appends every exported tool to out and
// returns the references the anchor check needs. The rows are closed before
// it returns, so the anchor's own queries never interleave with them.
func (s *Store) readApproved(ctx context.Context, q queryer, out *[]ApprovedTool) ([]approvedRef, error) {
	rows, err := q.QueryContext(ctx, approvedQuery)
	if err != nil {
		return nil, fmt.Errorf("catalog: list approved tools: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var refs []approvedRef
	for rows.Next() {
		a, ref, err := scanApproved(rows, s.verified)
		if err != nil {
			return nil, err
		}
		*out = append(*out, a)
		refs = append(refs, ref)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("catalog: list approved tools: %w", err)
	}
	return refs, nil
}

// toolStatesQuery reads the state column of every tool with the seq of the
// newest state-bearing entry about it, so that Approved anchors tools the
// export leaves out as well as the ones it returns.
const toolStatesQuery = `SELECT s.name || '/' || t.name, t.state, ` + stateEntryOfServerTool + `
	FROM tools t JOIN servers s ON s.id = t.server_id
	ORDER BY s.name, t.name`

// readToolStates returns one stateRef per tool row, exported or not.
func readToolStates(ctx context.Context, q queryer) ([]stateRef, error) {
	rows, err := q.QueryContext(ctx, toolStatesQuery)
	if err != nil {
		return nil, fmt.Errorf("catalog: read tool states: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var states []stateRef
	for rows.Next() {
		var (
			r     stateRef
			state string
		)
		if err := rows.Scan(&r.tool, &state, &r.entry); err != nil {
			return nil, fmt.Errorf("catalog: read tool states: %w", err)
		}
		r.state = lifecycle.State(state)
		states = append(states, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("catalog: read tool states: %w", err)
	}
	return states, nil
}

// approvedQuery joins each exported tool with its newest approve or rollback
// row across all of its versions (the row form of newestDecisionNames), so
// that scanApproved can check which version it names and take the approver
// and time from it, and with the seq of the newest approval entry about it.
const approvedQuery = `SELECT s.name, t.id, t.name, v.id, v.tool_id, COALESCE(v.digest, ''), COALESCE(v.digest_profile, ''),
		v.canonical, COALESCE(v.version_no, 0), a.version_id, a.hash_seen, a.approver, a.at,
		` + decisionEntryOfServerTool + `
	FROM tools t
	JOIN servers s ON s.id = t.server_id
	LEFT JOIN tool_versions v ON v.id = t.approved_version_id
	LEFT JOIN approvals a ON a.id = (
		SELECT MAX(a2.id) FROM approvals a2 JOIN tool_versions o ON o.id = a2.version_id
		WHERE o.tool_id = t.id AND a2.decision IN ('approve', 'rollback'))
	WHERE t.state IN ('enabled', 'changed_pending_reapproval')
	ORDER BY s.name, t.name`

// scanApproved reads one approved tool and re-checks what it can without the
// log: the pointer must resolve to the tool's own version, the profile must be
// the current one, the bytes must hash to the digest unless the verifier
// remembers the row, and the tool's newest decision must name the version. The
// returned reference carries what verifyAnchors checks afterwards, the row's
// approver and time included; the tool's own ApprovedBy and ApprovedAt are
// filled in from the verified entry (adoptApprovers).
func scanApproved(sc rowScanner, v *verifier) (ApprovedTool, approvedRef, error) {
	var (
		a                  ApprovedTool
		toolID             int64
		joined, joinedTool sql.NullInt64
		profile            string
		decided, entry     sql.NullInt64
		seen, approver, at sql.NullString
	)
	if err := sc.Scan(&a.Server, &toolID, &a.Name, &joined, &joinedTool, &a.Digest, &profile, &a.Canonical, &a.VersionNo,
		&decided, &seen, &approver, &at, &entry); err != nil {
		return ApprovedTool{}, approvedRef{}, fmt.Errorf("catalog: list approved tools: %w", err)
	}
	name := a.Server + "/" + a.Name
	if err := checkPointer(name, toolID, joined, joinedTool); err != nil {
		return ApprovedTool{}, approvedRef{}, err
	}
	if err := checkApprovedProfile(name, profile); err != nil {
		return ApprovedTool{}, approvedRef{}, err
	}
	if !v.verify(joined.Int64, a.Digest, a.Canonical) {
		return ApprovedTool{}, approvedRef{}, fmt.Errorf("%w: approved version of %s does not hash to its digest", ErrCorrupt, quote(name))
	}
	if !decided.Valid || !approver.Valid || !at.Valid {
		return ApprovedTool{}, approvedRef{}, errNoApprovalRecord(name)
	}
	if decided.Int64 != joined.Int64 || seen.String != a.Digest {
		return ApprovedTool{}, approvedRef{}, errNotNewestDecision(name)
	}
	ref := approvedRef{id: joined.Int64, tool: name, digest: a.Digest, entry: entry, approver: approver.String, at: at.String, showsApprover: true}
	return a, ref, nil
}
