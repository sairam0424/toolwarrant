package catalog

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/sairam0424/toolwarrant/internal/gate"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// Snapshot returns the serving policy of one server, or ErrNotFound if the
// server is not registered. The generation is read in the same read
// transaction as the tools, so the pair is consistent: a reader that sees
// generation N holds exactly the policy of generation N.
func (s *Store) Snapshot(ctx context.Context, server string) (Snapshot, error) {
	var snap Snapshot
	err := s.inRead(ctx, func(q queryer) error {
		srv, err := loadServerRow(ctx, q, server)
		if err != nil {
			return err
		}
		gen, err := readGeneration(ctx, q)
		if err != nil {
			return err
		}
		tools, err := snapshotTools(ctx, q, srv.ID)
		if err != nil {
			return err
		}
		snap = Snapshot{Server: srv.Name, Generation: gen, Tools: tools}
		return nil
	})
	if err != nil {
		return Snapshot{}, err
	}
	return snap, nil
}

// snapshotTools maps every non-deprecated tool of a server to its policy. A
// deprecated tool is left out on purpose: a name missing from the snapshot is
// not served either.
func snapshotTools(ctx context.Context, q queryer, serverID int64) (map[string]ToolPolicy, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT t.name, t.state, COALESCE(av.digest, ''), t.last_seen_digest
		 FROM tools t LEFT JOIN tool_versions av ON av.id = t.approved_version_id
		 WHERE t.server_id = ? AND t.state <> ?`, serverID, string(lifecycle.Deprecated))
	if err != nil {
		return nil, fmt.Errorf("catalog: read snapshot: %w", err)
	}
	defer rows.Close()
	tools := make(map[string]ToolPolicy)
	for rows.Next() {
		var (
			name, state string
			p           ToolPolicy
		)
		if err := rows.Scan(&name, &state, &p.Approved, &p.LastSeen); err != nil {
			return nil, fmt.Errorf("catalog: read snapshot: %w", err)
		}
		p.State = lifecycle.State(state)
		tools[name] = p
	}
	return tools, rows.Err()
}

// Approved returns the approved version of every tool that is enabled or
// changed_pending_reapproval, ordered by server then tool name. The approver
// and time come from the latest approve or rollback row of that version. A
// version whose canonical form no longer hashes to its digest, or that has no
// approval row, is reported as ErrCorrupt rather than exported.
func (s *Store) Approved(ctx context.Context) ([]ApprovedTool, error) {
	out := []ApprovedTool{}
	err := s.inRead(ctx, func(q queryer) error {
		rows, err := q.QueryContext(ctx, approvedQuery)
		if err != nil {
			return fmt.Errorf("catalog: list approved tools: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			a, err := scanApproved(rows)
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

const approvedQuery = `SELECT s.name, t.name, v.digest, v.canonical, v.version_no, a.approver, a.at
	FROM tools t
	JOIN servers s ON s.id = t.server_id
	JOIN tool_versions v ON v.id = t.approved_version_id
	LEFT JOIN approvals a ON a.id = (
		SELECT MAX(id) FROM approvals WHERE version_id = v.id AND decision IN ('approve', 'rollback'))
	WHERE t.state IN ('enabled', 'changed_pending_reapproval')
	ORDER BY s.name, t.name`

func scanApproved(sc rowScanner) (ApprovedTool, error) {
	var (
		a        ApprovedTool
		approver sql.NullString
		at       sql.NullString
	)
	if err := sc.Scan(&a.Server, &a.Name, &a.Digest, &a.Canonical, &a.VersionNo, &approver, &at); err != nil {
		return ApprovedTool{}, fmt.Errorf("catalog: list approved tools: %w", err)
	}
	if gate.DigestOfCanonical(a.Canonical) != a.Digest {
		return ApprovedTool{}, fmt.Errorf("%w: approved version of %s/%s does not hash to its digest", ErrCorrupt, quote(a.Server), quote(a.Name))
	}
	if !approver.Valid || !at.Valid {
		return ApprovedTool{}, fmt.Errorf("%w: approved version of %s/%s has no approval record", ErrCorrupt, quote(a.Server), quote(a.Name))
	}
	when, err := parseTime(at.String)
	if err != nil {
		return ApprovedTool{}, err
	}
	a.ApprovedBy, a.ApprovedAt = approver.String, when
	return a, nil
}
