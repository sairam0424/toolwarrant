package catalog

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/sairam0424/toolwarrant/internal/gate"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

const toolViewSelect = `SELECT s.name, t.id, t.name, t.state,
		COALESCE(av.digest, ''), COALESCE(pv.digest, ''), t.last_seen_digest, t.missing_crawls,
		(SELECT COUNT(*) FROM tool_versions c WHERE c.tool_id = t.id)
	FROM tools t
	JOIN servers s ON s.id = t.server_id
	LEFT JOIN tool_versions av ON av.id = t.approved_version_id
	LEFT JOIN tool_versions pv ON pv.tool_id = t.id AND pv.status = 'pending'`

func scanToolView(sc rowScanner) (ToolView, error) {
	var (
		v     ToolView
		state string
	)
	err := sc.Scan(&v.Server, &v.ID, &v.Name, &state, &v.Approved, &v.Pending, &v.LastSeen, &v.MissingCrawls, &v.Versions)
	if err != nil {
		return ToolView{}, err
	}
	v.State = lifecycle.State(state)
	v.Drifted = lifecycle.Tool{Approved: v.Approved, LastSeen: v.LastSeen}.Drifted()
	v.Unusable = v.LastSeen == lifecycle.UnusableDigest
	return v, nil
}

// Tools lists tools ordered by server then name. An empty server means all. A
// server that does not exist has no tools.
func (s *Store) Tools(ctx context.Context, server string) ([]ToolView, error) {
	out := []ToolView{}
	err := s.inRead(ctx, func(q queryer) error {
		rows, err := q.QueryContext(ctx, toolViewSelect+` WHERE (? = '' OR s.name = ?) ORDER BY s.name, t.name`, server, server)
		if err != nil {
			return fmt.Errorf("catalog: list tools: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			v, err := scanToolView(rows)
			if err != nil {
				return fmt.Errorf("catalog: list tools: %w", err)
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Tool returns one tool, or ErrNotFound.
func (s *Store) Tool(ctx context.Context, server, tool string) (ToolView, error) {
	var v ToolView
	err := s.inRead(ctx, func(q queryer) error {
		var err error
		v, err = scanToolView(q.QueryRowContext(ctx, toolViewSelect+` WHERE s.name = ? AND t.name = ?`, server, tool))
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return fmt.Errorf("%w: tool %s/%s", ErrNotFound, quote(server), quote(tool))
		case err != nil:
			return fmt.Errorf("catalog: load tool: %w", err)
		}
		return nil
	})
	if err != nil {
		return ToolView{}, err
	}
	return v, nil
}

func toolID(ctx context.Context, q queryer, server, tool string) (int64, error) {
	var id int64
	err := q.QueryRowContext(ctx,
		`SELECT t.id FROM tools t JOIN servers s ON s.id = t.server_id WHERE s.name = ? AND t.name = ?`,
		server, tool).Scan(&id)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return 0, fmt.Errorf("%w: tool %s/%s", ErrNotFound, quote(server), quote(tool))
	case err != nil:
		return 0, fmt.Errorf("catalog: find tool: %w", err)
	}
	return id, nil
}

// Versions lists a tool's versions oldest first, each with its full proposer
// history. Each canonical form is re-hashed on the way out and its digest
// profile checked, so a tampered row is reported, not displayed.
func (s *Store) Versions(ctx context.Context, server, tool string) ([]VersionView, error) {
	out := []VersionView{}
	err := s.inRead(ctx, func(q queryer) error {
		id, err := toolID(ctx, q, server, tool)
		if err != nil {
			return err
		}
		proposers, err := loadProposers(ctx, q, proposersOfTool, id)
		if err != nil {
			return err
		}
		rows, err := q.QueryContext(ctx,
			`SELECT id, version_no, digest, digest_profile, status, proposed_by, ever_approved, first_seen_at, canonical
			 FROM tool_versions WHERE tool_id = ? ORDER BY version_no`, id)
		if err != nil {
			return fmt.Errorf("catalog: list versions: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			v, err := scanVersionView(rows, proposers)
			if err != nil {
				return err
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func scanVersionView(sc rowScanner, proposers map[int64][]string) (VersionView, error) {
	var (
		v      VersionView
		id     int64
		status string
		ever   int
		seen   string
	)
	if err := sc.Scan(&id, &v.No, &v.Digest, &v.DigestProfile, &status, &v.ProposedBy, &ever, &seen, &v.Canonical); err != nil {
		return VersionView{}, fmt.Errorf("catalog: list versions: %w", err)
	}
	if v.DigestProfile != gate.DigestProfile {
		return VersionView{}, fmt.Errorf("%w: version %d was digested under profile %s, this build uses %s",
			ErrCorrupt, v.No, quote(v.DigestProfile), gate.DigestProfile)
	}
	if gate.DigestOfCanonical(v.Canonical) != v.Digest {
		return VersionView{}, fmt.Errorf("%w: version %d does not hash to its stored digest", ErrCorrupt, v.No)
	}
	names := proposers[id]
	if len(names) == 0 || names[0] != v.ProposedBy {
		return VersionView{}, fmt.Errorf("%w: version %d has no proposer list, or its first proposer is not proposed_by", ErrCorrupt, v.No)
	}
	at, err := parseTime(seen)
	if err != nil {
		return VersionView{}, err
	}
	v.Status, v.EverApproved, v.FirstSeen = lifecycle.VersionStatus(status), ever == 1, at
	v.Proposers = append([]string(nil), names...)
	return v, nil
}

// ResolveDigest expands a hex prefix of at least 8 characters to the full
// digest of exactly one version of the tool. ErrNotFound, ErrAmbiguous or
// ErrInvalid otherwise.
func (s *Store) ResolveDigest(ctx context.Context, server, tool, prefix string) (string, error) {
	p, err := normalizePrefix(prefix)
	if err != nil {
		return "", err
	}
	var digests []string
	err = s.inRead(ctx, func(q queryer) error {
		id, err := toolID(ctx, q, server, tool)
		if err != nil {
			return err
		}
		rows, err := q.QueryContext(ctx,
			`SELECT digest FROM tool_versions WHERE tool_id = ? AND substr(digest, 1, ?) = ? LIMIT 2`,
			id, len(p), p)
		if err != nil {
			return fmt.Errorf("catalog: resolve digest: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var d string
			if err := rows.Scan(&d); err != nil {
				return fmt.Errorf("catalog: resolve digest: %w", err)
			}
			digests = append(digests, d)
		}
		return rows.Err()
	})
	if err != nil {
		return "", err
	}
	switch len(digests) {
	case 0:
		return "", fmt.Errorf("%w: no version of %s/%s starts with %s", ErrNotFound, quote(server), quote(tool), quote(p))
	case 1:
		return digests[0], nil
	}
	return "", fmt.Errorf("%w: %s", ErrAmbiguous, quote(p))
}
