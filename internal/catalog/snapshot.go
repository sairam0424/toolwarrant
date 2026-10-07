package catalog

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/sairam0424/toolwarrant/internal/gate"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// Snapshot returns the serving policy of one server, or ErrNotFound if the
// server is not registered. The generation is read in the same read
// transaction as the tools, so the pair is consistent: a reader that sees
// generation N holds exactly the policy of generation N. A paused server has
// an empty Tools map, so nothing of it is served (fail closed).
//
// Every approved digest is re-checked against the stored canonical bytes on
// the way out, and the digest profile against the current one: this is the
// processor's read path, so a tampered row must fail it (ErrCorrupt) rather
// than be served. The cost is one SHA-256 per approved tool per reload, which
// the processor only does when the generation moved.
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
		crawledAt, err := latestCompleteCrawl(ctx, q, srv.ID)
		if err != nil {
			return err
		}
		tools := map[string]ToolPolicy{}
		if !srv.Paused {
			if tools, err = snapshotTools(ctx, q, srv.ID); err != nil {
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

const snapshotQuery = `SELECT t.name, t.state, t.approved_version_id, av.id, COALESCE(av.digest, ''),
		COALESCE(av.digest_profile, ''), av.canonical, t.last_seen_digest
	FROM tools t LEFT JOIN tool_versions av ON av.id = t.approved_version_id
	WHERE t.server_id = ? AND t.state <> ?`

// snapshotTools maps every non-deprecated tool of a server to its policy. A
// deprecated tool is left out on purpose: a name missing from the snapshot is
// not served either.
func snapshotTools(ctx context.Context, q queryer, serverID int64) (map[string]ToolPolicy, error) {
	rows, err := q.QueryContext(ctx, snapshotQuery, serverID, string(lifecycle.Deprecated))
	if err != nil {
		return nil, fmt.Errorf("catalog: read snapshot: %w", err)
	}
	defer func() { _ = rows.Close() }()
	tools := make(map[string]ToolPolicy)
	for rows.Next() {
		name, p, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		tools[name] = p
	}
	return tools, rows.Err()
}

// scanPolicy reads one tool's policy and verifies its approved version: the
// pointer must resolve, and the canonical bytes must hash to the digest under
// the current profile.
func scanPolicy(sc rowScanner) (string, ToolPolicy, error) {
	var (
		name, state, profile string
		pointer, joined      sql.NullInt64
		canonical            []byte
		p                    ToolPolicy
	)
	if err := sc.Scan(&name, &state, &pointer, &joined, &p.Approved, &profile, &canonical, &p.LastSeen); err != nil {
		return "", ToolPolicy{}, fmt.Errorf("catalog: read snapshot: %w", err)
	}
	p.State = lifecycle.State(state)
	if pointer.Valid && !joined.Valid {
		return "", ToolPolicy{}, fmt.Errorf("%w: tool %s points at a version that does not exist", ErrCorrupt, quote(name))
	}
	if joined.Valid {
		if err := verifyApproved(name, p.Approved, profile, canonical); err != nil {
			return "", ToolPolicy{}, err
		}
	}
	return name, p, nil
}

// verifyApproved re-checks one approved version as read from a joined row.
func verifyApproved(name, digest, profile string, canonical []byte) error {
	if profile != gate.DigestProfile {
		return fmt.Errorf("%w: approved version of %s was digested under profile %s, this build uses %s",
			ErrCorrupt, quote(name), quote(profile), gate.DigestProfile)
	}
	if gate.DigestOfCanonical(canonical) != digest {
		return fmt.Errorf("%w: approved version of %s does not hash to its digest", ErrCorrupt, quote(name))
	}
	return nil
}

// Approved returns the approved version of every tool that is enabled or
// changed_pending_reapproval, ordered by server then tool name. The approver
// and time come from the latest approve or rollback row of that version. A
// version whose canonical form no longer hashes to its digest, whose digest
// profile is not the current one, whose pointer dangles, or that has no
// approval row, is reported as ErrCorrupt rather than exported. Tools of a
// paused server are included: the export describes approvals, not serving.
func (s *Store) Approved(ctx context.Context) ([]ApprovedTool, error) {
	out := []ApprovedTool{}
	err := s.inRead(ctx, func(q queryer) error {
		rows, err := q.QueryContext(ctx, approvedQuery)
		if err != nil {
			return fmt.Errorf("catalog: list approved tools: %w", err)
		}
		defer func() { _ = rows.Close() }()
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

const approvedQuery = `SELECT s.name, t.name, v.id, COALESCE(v.digest, ''), COALESCE(v.digest_profile, ''), v.canonical,
		COALESCE(v.version_no, 0), a.approver, a.at
	FROM tools t
	JOIN servers s ON s.id = t.server_id
	LEFT JOIN tool_versions v ON v.id = t.approved_version_id
	LEFT JOIN approvals a ON a.id = (
		SELECT MAX(id) FROM approvals WHERE version_id = v.id AND decision IN ('approve', 'rollback'))
	WHERE t.state IN ('enabled', 'changed_pending_reapproval')
	ORDER BY s.name, t.name`

func scanApproved(sc rowScanner) (ApprovedTool, error) {
	var (
		a        ApprovedTool
		joined   sql.NullInt64
		profile  string
		approver sql.NullString
		at       sql.NullString
	)
	if err := sc.Scan(&a.Server, &a.Name, &joined, &a.Digest, &profile, &a.Canonical, &a.VersionNo, &approver, &at); err != nil {
		return ApprovedTool{}, fmt.Errorf("catalog: list approved tools: %w", err)
	}
	if !joined.Valid {
		return ApprovedTool{}, fmt.Errorf("%w: approved version of %s/%s does not exist", ErrCorrupt, quote(a.Server), quote(a.Name))
	}
	if err := verifyApproved(a.Server+"/"+a.Name, a.Digest, profile, a.Canonical); err != nil {
		return ApprovedTool{}, err
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
