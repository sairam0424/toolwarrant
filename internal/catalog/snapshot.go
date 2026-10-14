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
// The snapshot hands out digests, never bytes: the processor compares the
// digest of the live definition with ToolPolicy.Approved. Every approved
// digest is checked on the way out against the append-only approvals table
// (the tool's newest approve or rollback row must name the approved version
// and carry its digest as hash_seen, newestDecisionNames, joined in the same
// query), its digest profile against the current one, and the digest against
// the audit chain (the newest version.approved or version.rolled_back entry
// about the tool must have recorded the digest and must be the entry the Store
// verified in the chain, anchorApproved, D15); the state column of every tool
// row is anchored the same way (anchorStates, D17 c). This is the processor's
// read path, so a tampered digest must fail it (ErrCorrupt) rather than be
// served. The file is checked on every load too (checkFile): the identity and
// the guard objects, so a trigger or table replaced after the file was opened
// is caught at the next reload, and the pinned audit entry and the chain
// appended since. The canonical bytes are not read: a reload costs one policy
// row per tool and the entry hashes of anchorTools, with no memory standing in
// for any of it, and does not grow with the size of the definitions (D21 d;
// before, every reload re-hashed every approved definition, remembered the
// result for ten minutes, and the memory was the only thing that kept a crawl
// of a large server from costing a full re-read). What this means for a
// bytes-only rewrite of an approved version (the digest column intact): the
// snapshot does not see it and keeps serving the anchored digest, which the
// rewrite cannot change, so the gateway still serves only a live definition
// that hashes to the approved digest; the rewritten bytes are refused at once
// by every path that hands them out (Approved, Versions, a decision through
// loadTool) and named by Integrity.
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
		if err := anchorPaused(ctx, q, s.chain, srv); err != nil {
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

// snapshotQuery reads the policy rows and nothing of the canonical bytes: no
// column of the statement names them (TestSnapshot_ReadsNoCanonicalBytesAndStillServesTheAnchoredDigest).
// The approved version is aliased v so that the shared evidence
// expression applies; its tool id comes along so that a pointer at another
// tool's version is caught here, and so do whether the tool's newest decision
// names it and the seq of the newest approval entry about the tool (looked up
// only for tools with an approval), in the same query rather than one per
// tool), and the seq of the newest state-bearing entry about the tool, which
// anchors the state column (D17 c). The parameters are the server name twice
// and its id. Every row of the server comes back, deprecated ones included:
// readPolicyRows anchors the state of each and only then leaves a deprecated
// row out of the policy, so a tool flipped to deprecated by hand is ErrCorrupt
// rather than a tool quietly gone (the review of the v0.1.0 fix named this as
// the sibling of the export's gap).
const snapshotQuery = `SELECT t.id, t.name, t.state, t.approved_version_id, v.id, v.tool_id,
		COALESCE(v.digest, ''), COALESCE(v.digest_profile, ''), t.last_seen_digest,
		` + newestDecisionNames + `,
		CASE WHEN t.approved_version_id IS NULL THEN NULL ELSE ` + decisionEntryOfTool + ` END,
		` + stateEntryOfTool + `
	FROM tools t LEFT JOIN tool_versions v ON v.id = t.approved_version_id
	WHERE t.server_id = ?`

// snapshotTools maps every non-deprecated tool of a server to its policy and
// anchors the approved versions and the state columns to the verified chain in
// one pass. A deprecated tool is left out on purpose: a name missing from the
// snapshot is not served either. Its state column is anchored all the same,
// before it is left out.
func (s *Store) snapshotTools(ctx context.Context, q queryer, srv Server) (map[string]ToolPolicy, error) {
	tools, refs, states, err := readPolicyRows(ctx, q, srv)
	if err != nil {
		return nil, err
	}
	if _, err := anchorTools(ctx, q, s.chain, refs, states); err != nil {
		return nil, err
	}
	return tools, nil
}

// readPolicyRows reads every tool of the server, anchors nothing itself but
// collects the state of every row, and keeps the policy and the approved
// version to anchor of the non-deprecated ones. Its rows are closed before it
// returns, so the anchor's own queries never interleave with them.
func readPolicyRows(ctx context.Context, q queryer, srv Server) (map[string]ToolPolicy, []approvedRef, []stateRef, error) {
	rows, err := q.QueryContext(ctx, snapshotQuery, srv.Name, srv.Name, srv.ID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("catalog: read snapshot: %w", err)
	}
	defer func() { _ = rows.Close() }()
	tools := make(map[string]ToolPolicy)
	var (
		refs   []approvedRef
		states []stateRef
	)
	for rows.Next() {
		r, err := scanPolicy(rows, srv.Name)
		if err != nil {
			return nil, nil, nil, err
		}
		states = append(states, r.state)
		if r.policy.State == lifecycle.Deprecated {
			continue
		}
		tools[r.name] = r.policy
		if r.approved.id != 0 {
			refs = append(refs, r.approved)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, nil, fmt.Errorf("catalog: read snapshot: %w", err)
	}
	return tools, refs, states, nil
}

// policyRow is one row of snapshotQuery: a tool's policy and, when it has an
// approved version, the reference the anchor needs.
type policyRow struct {
	name     string
	policy   ToolPolicy
	approved approvedRef // id is 0 when the tool has no approved version
	state    stateRef    // the state column against the newest entry about the tool
}

// scanPolicy reads one tool's policy and checks what needs no log: the
// approved pointer must resolve to a version of this tool, the digest
// profile must be the current one, and the tool's newest approve or rollback
// row must name the version. The chain is left to anchorTools.
func scanPolicy(sc rowScanner, server string) (policyRow, error) {
	var (
		r                           policyRow
		toolID                      int64
		state, profile              string
		pointer, joined, joinedTool sql.NullInt64
		newest                      int
		entry, stateEntry           sql.NullInt64
	)
	if err := sc.Scan(&toolID, &r.name, &state, &pointer, &joined, &joinedTool, &r.policy.Approved, &profile, &r.policy.LastSeen,
		&newest, &entry, &stateEntry); err != nil {
		return policyRow{}, fmt.Errorf("catalog: read snapshot: %w", err)
	}
	r.policy.State = lifecycle.State(state)
	subject := server + "/" + r.name
	r.state = stateRef{tool: subject, state: r.policy.State, entry: stateEntry}
	if !pointer.Valid {
		return r, nil
	}
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
// of that tool: another tool's version carries its own digest and would pass
// every check of the digest while meaning a different definition.
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
