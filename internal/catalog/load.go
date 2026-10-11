package catalog

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/sairam0424/toolwarrant/internal/gate"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// toolRec is a tool row and its versions, loaded into the pure lifecycle types.
// versionIDs runs parallel to tool.Versions.
type toolRec struct {
	id         int64
	serverID   int64
	name       string
	tool       lifecycle.Tool
	versionIDs []int64
	maxNo      int
	// budget counts the versions added since the last decision on the tool
	// (tools.proposals_since_decision); see MaxProposalsPerDecision.
	// storedBudget is the value the row holds, so updateTool knows when to write.
	budget       int
	storedBudget int
}

type toolRow struct {
	id       int64
	serverID int64
	name     string
	state    string
	lastSeen string
	missing  int
	approved sql.NullInt64
	budget   int
}

type versionRow struct {
	id         int64
	toolID     int64
	no         int
	digest     string
	profile    string
	canonical  []byte
	status     string
	proposedBy string
	ever       int
	// recorded is 1 when an approve or rollback row exists for the version;
	// a version in status approved, or ever approved, without one is corrupt.
	recorded int
	// newest is 1 when the tool's newest approve or rollback row names this
	// version (newestDecisionNames); the version in status approved must be it.
	newest int
}

// The approvals table is append-only and every decision writes one row in the
// transaction that moves the status, so it is the evidence the serving path
// trusts; the status columns alone are mutable and prove nothing.
//
// Evidence per version (approvalRecorded) says that someone once approved the
// version. Evidence per tool (newestDecisionNames) says that the newest
// decision about the tool, approve or rollback, is the approval the tools row
// claims: its version_id is the approved version and its hash_seen (the digest
// the approver viewed, in the append-only table) is that version's digest
// (D13). The second rule is what a Snapshot, an export, a listing of versions
// and a decision require of the approved version, because the first one is
// satisfied by any superseded version that was approved once (a pointer flip
// to a retired digest) and by a version whose digest and bytes were rewritten
// together under a dropped and re-created guard (hash_seen still names the
// digest that was approved).
const (
	decisionFilter   = `a.decision IN ('approve', 'rollback')`
	approvalRecorded = `EXISTS (SELECT 1 FROM approvals a WHERE a.version_id = v.id AND ` + decisionFilter + `)`
	// newestDecisionNames is 1 when the newest approve or rollback row about
	// any version of the tool that owns the version aliased v names v, 0
	// otherwise (also when the tool has no decision, or v is NULL).
	newestDecisionNames = `COALESCE((SELECT a.version_id = v.id AND a.hash_seen = v.digest
		FROM approvals a JOIN tool_versions o ON o.id = a.version_id
		WHERE o.tool_id = v.tool_id AND ` + decisionFilter + ` ORDER BY a.id DESC LIMIT 1), 0)`
)

const (
	toolCols = `t.id, t.server_id, t.name, t.state, t.last_seen_digest, t.missing_crawls, t.approved_version_id,
		t.proposals_since_decision`

	// The first argument switches the canonical bytes on: bulk loads do not
	// need them, single-tool loads re-check them against the digest. The last
	// two columns are the approval evidence; see approvalRecorded.
	versionCols = `v.id, v.tool_id, v.version_no, v.digest, v.digest_profile, CASE WHEN ? THEN v.canonical ELSE NULL END,
		v.status, v.proposed_by, v.ever_approved, ` + approvalRecorded + `, ` + newestDecisionNames

	versionsOfTool = `SELECT ` + versionCols + ` FROM tool_versions v WHERE v.tool_id = ? ORDER BY v.version_no`

	proposerCols    = `p.version_id, p.position, p.actor`
	proposersOfTool = `SELECT ` + proposerCols + ` FROM tool_version_proposers p JOIN tool_versions v ON v.id = p.version_id
		WHERE v.tool_id = ? ORDER BY p.version_id, p.position`

	insertVersion = `INSERT INTO tool_versions
		(tool_id, version_no, digest, digest_profile, canonical, raw, status, proposed_by, ever_approved, first_seen_at, crawl_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	insertProposer = `INSERT INTO tool_version_proposers (version_id, position, actor) VALUES (?, ?, ?)`
)

func scanToolRow(sc rowScanner) (toolRow, error) {
	var r toolRow
	err := sc.Scan(&r.id, &r.serverID, &r.name, &r.state, &r.lastSeen, &r.missing, &r.approved, &r.budget)
	return r, err
}

// queryVersionRows runs a query that selects versionCols; args follow the
// canonical switch, which is the query's first parameter.
func queryVersionRows(ctx context.Context, q queryer, query string, withCanonical bool, args ...any) ([]versionRow, error) {
	rows, err := q.QueryContext(ctx, query, append([]any{boolInt(withCanonical)}, args...)...)
	if err != nil {
		return nil, fmt.Errorf("catalog: load versions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []versionRow
	for rows.Next() {
		var v versionRow
		if err := rows.Scan(&v.id, &v.toolID, &v.no, &v.digest, &v.profile, &v.canonical, &v.status, &v.proposedBy,
			&v.ever, &v.recorded, &v.newest); err != nil {
			return nil, fmt.Errorf("catalog: load versions: %w", err)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// loadProposers returns every version's proposers in position order, keyed by
// version id, adding to out when it is not nil. Positions must run 0, 1, 2...
// per version; a gap is corruption.
func loadProposers(ctx context.Context, q queryer, out map[int64][]string, query string, args ...any) (map[int64][]string, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("catalog: load proposers: %w", err)
	}
	defer func() { _ = rows.Close() }()
	if out == nil {
		out = map[int64][]string{}
	}
	for rows.Next() {
		var (
			versionID int64
			position  int
			actor     string
		)
		if err := rows.Scan(&versionID, &position, &actor); err != nil {
			return nil, fmt.Errorf("catalog: load proposers: %w", err)
		}
		if position != len(out[versionID]) {
			return nil, fmt.Errorf("%w: proposers of version %d are not in sequence", ErrCorrupt, versionID)
		}
		out[versionID] = append(out[versionID], actor)
	}
	return out, rows.Err()
}

// loadTool loads one tool and re-checks every stored digest against its
// canonical form, and its approval against the audit chain (anchorOne, with
// sealed as the Store's memory of verified entries), before any decision is
// based on it.
func loadTool(ctx context.Context, q queryer, sealed *verifier, server, tool string) (*toolRec, error) {
	row, err := scanToolRow(q.QueryRowContext(ctx,
		`SELECT `+toolCols+` FROM tools t JOIN servers s ON s.id = t.server_id WHERE s.name = ? AND t.name = ?`,
		server, tool))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, fmt.Errorf("%w: tool %s/%s", ErrNotFound, quote(server), quote(tool))
	case err != nil:
		return nil, fmt.Errorf("catalog: load tool: %w", err)
	}
	vrs, err := queryVersionRows(ctx, q, versionsOfTool, true, row.id)
	if err != nil {
		return nil, err
	}
	for _, v := range vrs {
		if err := checkCanonical(v); err != nil {
			return nil, err
		}
	}
	proposers, err := loadProposers(ctx, q, nil, proposersOfTool, row.id)
	if err != nil {
		return nil, err
	}
	rec, err := newToolRec(row, vrs, proposers)
	if err != nil {
		return nil, err
	}
	if rec.tool.Approved == "" {
		return rec, nil
	}
	versionID, err := rec.versionID(rec.tool.Approved)
	if err != nil {
		return nil, err
	}
	if err := anchorOne(ctx, q, sealed, server+"/"+tool, versionID, rec.tool.Approved); err != nil {
		return nil, err
	}
	return rec, nil
}

// checkCanonical re-hashes the stored canonical bytes: they must hash to the
// stored digest under the current digest profile, or the row is corrupt.
func checkCanonical(v versionRow) error {
	if err := checkProfile(v); err != nil {
		return err
	}
	if gate.DigestOfCanonical(v.canonical) != v.digest {
		return fmt.Errorf("%w: version %d of tool %d does not hash to its stored digest", ErrCorrupt, v.no, v.toolID)
	}
	return nil
}

// checkProfile requires the digest to have been computed under the profile
// this build uses: an approval made under another rule means another thing.
func checkProfile(v versionRow) error {
	if v.profile != gate.DigestProfile {
		return fmt.Errorf("%w: version %d of tool %d was digested under profile %s, this build uses %s",
			ErrCorrupt, v.no, v.toolID, quote(v.profile), gate.DigestProfile)
	}
	return nil
}

// newToolRec converts rows into lifecycle types and checks that the approved
// pointer, the version statuses, the approval records and the proposer lists
// agree, because lifecycle.Apply relies on them.
func newToolRec(row toolRow, vrs []versionRow, proposers map[int64][]string) (*toolRec, error) {
	rec := &toolRec{id: row.id, serverID: row.serverID, name: row.name, budget: row.budget, storedBudget: row.budget}
	rec.tool = lifecycle.Tool{
		State:         lifecycle.State(row.state),
		LastSeen:      row.lastSeen,
		MissingCrawls: row.missing,
	}
	approvedSeen := false
	for _, v := range vrs {
		if err := checkProfile(v); err != nil {
			return nil, err
		}
		names := proposers[v.id]
		if len(names) == 0 || names[0] != v.proposedBy {
			return nil, fmt.Errorf("%w: version %d of tool %q has no proposer list, or its first proposer is not proposed_by", ErrCorrupt, v.no, row.name)
		}
		rec.tool.Versions = append(rec.tool.Versions, lifecycle.Version{
			Digest:       v.digest,
			Status:       lifecycle.VersionStatus(v.status),
			ProposedBy:   v.proposedBy,
			Proposers:    lifecycle.ProposersOf(names...),
			EverApproved: v.ever == 1,
		})
		rec.versionIDs = append(rec.versionIDs, v.id)
		rec.maxNo = v.no
		isPointer := row.approved.Valid && row.approved.Int64 == v.id
		if isPointer {
			rec.tool.Approved = v.digest
			approvedSeen = true
		}
		if err := checkVersionEvidence(row.name, v, isPointer); err != nil {
			return nil, err
		}
	}
	if row.approved.Valid && !approvedSeen {
		return nil, fmt.Errorf("%w: tool %q points at a version that is not its own", ErrCorrupt, row.name)
	}
	return rec, nil
}

// checkVersionEvidence requires the status columns of one version to agree
// with the approved pointer and with the approvals table: the approved version
// is the pointer and the tool's newest decision names it, and a version that
// was ever approved has an approval record.
func checkVersionEvidence(name string, v versionRow, isPointer bool) error {
	if isPointer != (v.status == string(lifecycle.VersionApproved)) {
		return fmt.Errorf("%w: tool %q approved pointer and version status disagree", ErrCorrupt, name)
	}
	if (isPointer || v.ever == 1) && v.recorded == 0 {
		return fmt.Errorf("%w: version %d of tool %q is marked approved but has no approval record", ErrCorrupt, v.no, name)
	}
	if isPointer && v.newest == 0 {
		return errNotNewestDecision(name)
	}
	return nil
}

// errNotNewestDecision is the ErrCorrupt for an approved version that the tool's
// newest approve or rollback row does not name: a retired digest put back by
// hand, or a version whose digest was rewritten under a dropped guard.
func errNotNewestDecision(name string) error {
	return fmt.Errorf("%w: approved version of %s is not the tool's newest approval decision", ErrCorrupt, quote(name))
}

// insertTool creates the row for a tool seen for the first time, in the
// Discovered state that lifecycle.ObserveCrawl moves on from.
func insertTool(ctx context.Context, t *txn, serverID int64, name string) (*toolRec, error) {
	id, err := t.insert(ctx,
		`INSERT INTO tools (server_id, name, state, approved_version_id, last_seen_digest, missing_crawls, proposals_since_decision)
		 VALUES (?, ?, ?, NULL, '', 0, 0)`, serverID, name, string(lifecycle.Discovered))
	if err != nil {
		return nil, fmt.Errorf("catalog: insert tool: %w", err)
	}
	return &toolRec{id: id, serverID: serverID, name: name, tool: lifecycle.Tool{State: lifecycle.Discovered}}, nil
}

func internalf(format string, args ...any) error {
	return fmt.Errorf("catalog: internal error: "+format, args...)
}

func isLive(s lifecycle.VersionStatus) bool {
	return s == lifecycle.VersionPending || s == lifecycle.VersionApproved
}

func indexOfDigest(vs []lifecycle.Version, digest string) int {
	for i, v := range vs {
		if v.Digest == digest {
			return i
		}
	}
	return -1
}

// knowsDigest reports whether the tool already has a version with this digest.
func (r *toolRec) knowsDigest(digest string) bool { return indexOfDigest(r.tool.Versions, digest) >= 0 }

// versionID returns the row id of the version with this digest.
func (r *toolRec) versionID(digest string) (int64, error) {
	i := indexOfDigest(r.tool.Versions, digest)
	if i < 0 || i >= len(r.versionIDs) {
		return 0, internalf("tool %q has no version %s", r.name, digest)
	}
	return r.versionIDs[i], nil
}
