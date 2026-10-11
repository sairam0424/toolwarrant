package catalog

import (
	"context"
	"fmt"
)

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
