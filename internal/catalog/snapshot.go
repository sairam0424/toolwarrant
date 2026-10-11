package catalog

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// Snapshot returns the serving policy of one server, or ErrNotFound if the
// server is not registered. The generation is read in the same read
// transaction as the tools, so the pair is consistent: a reader that sees
// generation N holds exactly the policy of generation N. A paused server has
// an empty Tools map, so nothing of it is served (fail closed).
//
// Every approved digest is re-checked against the stored canonical bytes on
// the way out, the digest profile against the current one, and the approval
// itself against the append-only approvals table: the tool's newest approve or
// rollback row must name the approved version and carry its digest as
// hash_seen (newestDecisionNames, joined in the same query). This is the
// processor's read path, so a tampered row must fail it (ErrCorrupt) rather
// than be served. The guard objects are verified on every load too, so a
// trigger replaced or added after the file was opened is caught at the next
// reload (verifyGuards). The first reload reads and hashes every approved
// tool; the Store then remembers each verified row for RecheckTTL, and a
// reload within that time neither reads nor hashes its bytes again, which is
// what keeps a crawl of a large server from costing a full re-read. RecheckTTL
// states the window this opens.
func (s *Store) Snapshot(ctx context.Context, server string) (Snapshot, error) {
	var snap Snapshot
	err := s.inRead(ctx, func(q queryer) error {
		if err := verifyGuards(ctx, q); err != nil {
			return err
		}
		srv, err := loadServerRow(ctx, q, server)
		if err != nil {
			return err
		}
		gen, err := readGeneration(ctx, q)
		if err != nil {
			return err
		}
		crawledAt, err := latestCompleteCrawl(ctx, q, srv.ID)
		if err != nil {
			return err
		}
		tools := map[string]ToolPolicy{}
		if !srv.Paused {
			if tools, err = s.snapshotTools(ctx, q, srv.ID); err != nil {
				return err
			}
		}
		snap = Snapshot{Server: srv.Name, Generation: gen, CrawledAt: crawledAt, Tools: tools}
		return nil
	})
	if err != nil {
		return Snapshot{}, err
	}
	return snap, nil
}

// latestCompleteCrawl returns when the newest complete crawl of the server
// started, or the zero time when there was none.
func latestCompleteCrawl(ctx context.Context, q queryer, serverID int64) (time.Time, error) {
	var started string
	err := q.QueryRowContext(ctx,
		`SELECT started_at FROM crawls WHERE server_id = ? AND complete = 1 ORDER BY id DESC LIMIT 1`, serverID).Scan(&started)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return time.Time{}, nil
	case err != nil:
		return time.Time{}, fmt.Errorf("catalog: read latest crawl: %w", err)
	}
	return parseTime(started)
}

// snapshotQuery reads the policy rows without the canonical bytes: those are
// fetched by recheckApproved, and only for rows the verifier does not
// remember. The approved version is aliased v so that the shared evidence
// expression applies; its tool id comes along so that a pointer at another
// tool's version is caught here, and so does whether the tool's newest
// decision names it, in the same query rather than one per tool.
const snapshotQuery = `SELECT t.id, t.name, t.state, t.approved_version_id, v.id, v.tool_id,
		COALESCE(v.digest, ''), COALESCE(v.digest_profile, ''), t.last_seen_digest,
		` + newestDecisionNames + `
	FROM tools t LEFT JOIN tool_versions v ON v.id = t.approved_version_id
	WHERE t.server_id = ? AND t.state <> ?`

// snapshotTools maps every non-deprecated tool of a server to its policy and
// re-checks the approved versions. A deprecated tool is left out on purpose: a
// name missing from the snapshot is not served either.
func (s *Store) snapshotTools(ctx context.Context, q queryer, serverID int64) (map[string]ToolPolicy, error) {
	tools, refs, err := readPolicyRows(ctx, q, serverID)
	if err != nil {
		return nil, err
	}
	if err := s.recheckApproved(ctx, q, refs); err != nil {
		return nil, err
	}
	return tools, nil
}

// readPolicyRows reads the policy of every non-deprecated tool and collects
// the approved versions to re-check. Its rows are closed before it returns, so
// the re-check's own queries never interleave with them.
func readPolicyRows(ctx context.Context, q queryer, serverID int64) (map[string]ToolPolicy, []approvedRef, error) {
	rows, err := q.QueryContext(ctx, snapshotQuery, serverID, string(lifecycle.Deprecated))
	if err != nil {
		return nil, nil, fmt.Errorf("catalog: read snapshot: %w", err)
	}
	defer func() { _ = rows.Close() }()
	tools := make(map[string]ToolPolicy)
	var refs []approvedRef
	for rows.Next() {
		r, err := scanPolicy(rows)
		if err != nil {
			return nil, nil, err
		}
		tools[r.name] = r.policy
		if r.approved.id != 0 {
			refs = append(refs, r.approved)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("catalog: read snapshot: %w", err)
	}
	return tools, refs, nil
}

// policyRow is one row of snapshotQuery: a tool's policy and, when it has an
// approved version, the reference the re-check needs.
type policyRow struct {
	name     string
	policy   ToolPolicy
	approved approvedRef // id is 0 when the tool has no approved version
}

// scanPolicy reads one tool's policy and checks what needs no bytes: the
// approved pointer must resolve to a version of this tool, the digest
// profile must be the current one, and the tool's newest approve or rollback
// row must name the version. The bytes themselves are left to recheckApproved.
func scanPolicy(sc rowScanner) (policyRow, error) {
	var (
		r                           policyRow
		toolID                      int64
		state, profile              string
		pointer, joined, joinedTool sql.NullInt64
		newest                      int
	)
	if err := sc.Scan(&toolID, &r.name, &state, &pointer, &joined, &joinedTool, &r.policy.Approved, &profile, &r.policy.LastSeen, &newest); err != nil {
		return policyRow{}, fmt.Errorf("catalog: read snapshot: %w", err)
	}
	r.policy.State = lifecycle.State(state)
	if !pointer.Valid {
		return r, nil
	}
	if err := checkPointer(r.name, toolID, joined, joinedTool); err != nil {
		return policyRow{}, err
	}
	if err := checkApprovedProfile(r.name, profile); err != nil {
		return policyRow{}, err
	}
	if newest == 0 {
		return policyRow{}, errNotNewestDecision(r.name)
	}
	r.approved = approvedRef{id: joined.Int64, tool: r.name, digest: r.policy.Approved}
	return r, nil
}

// checkPointer requires a tool's approved pointer to resolve, and to a version
// of that tool: another tool's version hashes to its own digest and would pass
// the re-check while meaning a different definition.
func checkPointer(name string, toolID int64, joined, joinedTool sql.NullInt64) error {
	if !joined.Valid {
		return fmt.Errorf("%w: tool %s points at a version that does not exist", ErrCorrupt, quote(name))
	}
	if !joinedTool.Valid || joinedTool.Int64 != toolID {
		return fmt.Errorf("%w: tool %s points at a version that is not its own", ErrCorrupt, quote(name))
	}
	return nil
}

// errNoApprovalRecord is the ErrCorrupt for a version in status approved that no
// approve or rollback row ever recorded: someone wrote the status by hand.
func errNoApprovalRecord(name string) error {
	return fmt.Errorf("%w: approved version of %s has no approval record", ErrCorrupt, quote(name))
}

// Approved returns the approved version of every tool that is enabled or
// changed_pending_reapproval, ordered by server then tool name. The approver
// and time come from the tool's newest approve or rollback row, which must
// name the approved version and carry its digest as hash_seen. A version
// whose canonical form no longer hashes to its digest, whose digest profile is
// not the current one, whose pointer dangles or names another tool's version,
// or that the newest decision does not name, is reported as ErrCorrupt rather
// than exported. The export carries the bytes, so they are read on every call;
// only the hash is skipped, for a row this Store verified within RecheckTTL.
// Tools of a paused server are included: the export describes approvals, not
// serving. The guard objects are verified first, as on every Snapshot load.
func (s *Store) Approved(ctx context.Context) ([]ApprovedTool, error) {
	out := []ApprovedTool{}
	err := s.inRead(ctx, func(q queryer) error {
		if err := verifyGuards(ctx, q); err != nil {
			return err
		}
		rows, err := q.QueryContext(ctx, approvedQuery)
		if err != nil {
			return fmt.Errorf("catalog: list approved tools: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			a, err := scanApproved(rows, s.verified)
			if err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// approvedQuery joins each exported tool with its newest approve or rollback
// row across all of its versions (the row form of newestDecisionNames), so
// that scanApproved can check which version it names and take the approver
// and time from it.
const approvedQuery = `SELECT s.name, t.id, t.name, v.id, v.tool_id, COALESCE(v.digest, ''), COALESCE(v.digest_profile, ''),
		v.canonical, COALESCE(v.version_no, 0), a.version_id, a.hash_seen, a.approver, a.at
	FROM tools t
	JOIN servers s ON s.id = t.server_id
	LEFT JOIN tool_versions v ON v.id = t.approved_version_id
	LEFT JOIN approvals a ON a.id = (
		SELECT MAX(a2.id) FROM approvals a2 JOIN tool_versions o ON o.id = a2.version_id
		WHERE o.tool_id = t.id AND a2.decision IN ('approve', 'rollback'))
	WHERE t.state IN ('enabled', 'changed_pending_reapproval')
	ORDER BY s.name, t.name`

// scanApproved reads one approved tool and re-checks it: the pointer must
// resolve to the tool's own version, the profile must be the current one, the
// bytes must hash to the digest unless the verifier remembers the row, and the
// tool's newest decision must name the version.
func scanApproved(sc rowScanner, v *verifier) (ApprovedTool, error) {
	var (
		a                  ApprovedTool
		toolID             int64
		joined, joinedTool sql.NullInt64
		profile            string
		decided            sql.NullInt64
		seen, approver, at sql.NullString
	)
	if err := sc.Scan(&a.Server, &toolID, &a.Name, &joined, &joinedTool, &a.Digest, &profile, &a.Canonical, &a.VersionNo,
		&decided, &seen, &approver, &at); err != nil {
		return ApprovedTool{}, fmt.Errorf("catalog: list approved tools: %w", err)
	}
	name := a.Server + "/" + a.Name
	if err := checkPointer(name, toolID, joined, joinedTool); err != nil {
		return ApprovedTool{}, err
	}
	if err := checkApprovedProfile(name, profile); err != nil {
		return ApprovedTool{}, err
	}
	if !v.verify(joined.Int64, a.Digest, a.Canonical) {
		return ApprovedTool{}, fmt.Errorf("%w: approved version of %s does not hash to its digest", ErrCorrupt, quote(name))
	}
	if !decided.Valid || !approver.Valid || !at.Valid {
		return ApprovedTool{}, errNoApprovalRecord(name)
	}
	if decided.Int64 != joined.Int64 || seen.String != a.Digest {
		return ApprovedTool{}, errNotNewestDecision(name)
	}
	when, err := parseTime(at.String)
	if err != nil {
		return ApprovedTool{}, err
	}
	a.ApprovedBy, a.ApprovedAt = approver.String, when
	return a, nil
}
