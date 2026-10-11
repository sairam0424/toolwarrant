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
// the way out, the digest profile against the current one, the approval
// against the append-only approvals table (the tool's newest approve or
// rollback row must name the approved version and carry its digest as
// hash_seen, newestDecisionNames, joined in the same query) and against the
// audit chain (the newest version.approved or version.rolled_back entry about
// the tool must have recorded the digest and must be the entry the Store
// verified in the chain, anchorApproved, D15). This is the processor's read
// path, so a tampered row must fail it (ErrCorrupt) rather than be served. The
// file is checked on every load too (checkFile): the identity and the guard
// objects, so a trigger or table replaced after the file was opened is caught
// at the next reload, and the pinned audit entry and the chain appended since.
// The first reload reads and hashes every approved tool; the Store then
// remembers each verified row for RecheckTTL, and a reload within that time
// neither reads nor hashes the bytes again, which is what keeps a crawl of a
// large server from costing a full re-read (RecheckTTL states the window this
// opens). The approval entries are hashed on every load: one hash of a few
// hundred bytes per approved tool, with no memory standing in for it.
func (s *Store) Snapshot(ctx context.Context, server string) (Snapshot, error) {
	var snap Snapshot
	err := s.inRead(ctx, func(q queryer) error {
		if err := s.checkFile(ctx, q); err != nil {
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
			if tools, err = s.snapshotTools(ctx, q, srv); err != nil {
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
// tool's version is caught here, and so do whether the tool's newest decision
// names it and the seq of the newest approval entry about the tool (looked up
// only for tools with an approval), in the same query rather than one per
// tool. The parameters are the server name, its id and the deprecated state.
const snapshotQuery = `SELECT t.id, t.name, t.state, t.approved_version_id, v.id, v.tool_id,
		COALESCE(v.digest, ''), COALESCE(v.digest_profile, ''), t.last_seen_digest,
		` + newestDecisionNames + `,
		CASE WHEN t.approved_version_id IS NULL THEN NULL ELSE ` + decisionEntryOfTool + ` END
	FROM tools t LEFT JOIN tool_versions v ON v.id = t.approved_version_id
	WHERE t.server_id = ? AND t.state <> ?`

// snapshotTools maps every non-deprecated tool of a server to its policy and
// re-checks the approved versions. A deprecated tool is left out on purpose: a
// name missing from the snapshot is not served either.
func (s *Store) snapshotTools(ctx context.Context, q queryer, srv Server) (map[string]ToolPolicy, error) {
	tools, refs, err := readPolicyRows(ctx, q, srv)
	if err != nil {
		return nil, err
	}
	if err := s.recheckApproved(ctx, q, refs); err != nil {
		return nil, err
	}
	if err := anchorApproved(ctx, q, s.chain, refs); err != nil {
		return nil, err
	}
	return tools, nil
}

// readPolicyRows reads the policy of every non-deprecated tool and collects
// the approved versions to re-check. Its rows are closed before it returns, so
// the re-check's own queries never interleave with them.
func readPolicyRows(ctx context.Context, q queryer, srv Server) (map[string]ToolPolicy, []approvedRef, error) {
	rows, err := q.QueryContext(ctx, snapshotQuery, srv.Name, srv.ID, string(lifecycle.Deprecated))
	if err != nil {
		return nil, nil, fmt.Errorf("catalog: read snapshot: %w", err)
	}
	defer func() { _ = rows.Close() }()
	tools := make(map[string]ToolPolicy)
	var refs []approvedRef
	for rows.Next() {
		r, err := scanPolicy(rows, srv.Name)
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
// row must name the version. The bytes and the chain are left to
// recheckApproved and anchorApproved.
func scanPolicy(sc rowScanner, server string) (policyRow, error) {
	var (
		r                           policyRow
		toolID                      int64
		state, profile              string
		pointer, joined, joinedTool sql.NullInt64
		newest                      int
		entry                       sql.NullInt64
	)
	if err := sc.Scan(&toolID, &r.name, &state, &pointer, &joined, &joinedTool, &r.policy.Approved, &profile, &r.policy.LastSeen,
		&newest, &entry); err != nil {
		return policyRow{}, fmt.Errorf("catalog: read snapshot: %w", err)
	}
	r.policy.State = lifecycle.State(state)
	if !pointer.Valid {
		return r, nil
	}
	subject := server + "/" + r.name
	if err := checkPointer(subject, toolID, joined, joinedTool); err != nil {
		return policyRow{}, err
	}
	if err := checkApprovedProfile(subject, profile); err != nil {
		return policyRow{}, err
	}
	if newest == 0 {
		return policyRow{}, errNotNewestDecision(subject)
	}
	r.approved = approvedRef{id: joined.Int64, tool: subject, digest: r.policy.Approved, entry: entry}
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
