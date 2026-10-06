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
}

type toolRow struct {
	id       int64
	serverID int64
	name     string
	state    string
	lastSeen string
	missing  int
	approved sql.NullInt64
}

type versionRow struct {
	id         int64
	toolID     int64
	no         int
	digest     string
	canonical  []byte
	status     string
	proposedBy string
	ever       int
}

const (
	toolCols = `t.id, t.server_id, t.name, t.state, t.last_seen_digest, t.missing_crawls, t.approved_version_id`

	// The first argument switches the canonical bytes on: bulk loads do not
	// need them, single-tool loads re-check them against the digest.
	versionCols = `v.id, v.tool_id, v.version_no, v.digest, CASE WHEN ? THEN v.canonical ELSE NULL END,
		v.status, v.proposed_by, v.ever_approved`

	versionsOfTool   = `SELECT ` + versionCols + ` FROM tool_versions v WHERE v.tool_id = ? ORDER BY v.version_no`
	versionsOfServer = `SELECT ` + versionCols + ` FROM tool_versions v JOIN tools t ON t.id = v.tool_id
		WHERE t.server_id = ? ORDER BY v.tool_id, v.version_no`

	insertVersion = `INSERT INTO tool_versions
		(tool_id, version_no, digest, canonical, raw, status, proposed_by, ever_approved, first_seen_at, crawl_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
)

func scanToolRow(sc rowScanner) (toolRow, error) {
	var r toolRow
	err := sc.Scan(&r.id, &r.serverID, &r.name, &r.state, &r.lastSeen, &r.missing, &r.approved)
	return r, err
}

func queryVersionRows(ctx context.Context, q queryer, query string, withCanonical bool, id int64) ([]versionRow, error) {
	rows, err := q.QueryContext(ctx, query, boolInt(withCanonical), id)
	if err != nil {
		return nil, fmt.Errorf("catalog: load versions: %w", err)
	}
	defer rows.Close()
	var out []versionRow
	for rows.Next() {
		var v versionRow
		if err := rows.Scan(&v.id, &v.toolID, &v.no, &v.digest, &v.canonical, &v.status, &v.proposedBy, &v.ever); err != nil {
			return nil, fmt.Errorf("catalog: load versions: %w", err)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// loadTool loads one tool and re-checks every stored digest against its
// canonical form before any decision is based on it.
func loadTool(ctx context.Context, q queryer, server, tool string) (*toolRec, error) {
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
	return newToolRec(row, vrs)
}

// loadServerTools loads every tool of one server, keyed by name.
func loadServerTools(ctx context.Context, q queryer, serverID int64) (map[string]*toolRec, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+toolCols+` FROM tools t WHERE t.server_id = ?`, serverID)
	if err != nil {
		return nil, fmt.Errorf("catalog: load tools: %w", err)
	}
	var trs []toolRow
	for rows.Next() {
		tr, err := scanToolRow(rows)
		if err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("catalog: load tools: %w", err)
		}
		trs = append(trs, tr)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("catalog: load tools: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("catalog: load tools: %w", err)
	}
	vrs, err := queryVersionRows(ctx, q, versionsOfServer, false, serverID)
	if err != nil {
		return nil, err
	}
	byTool := make(map[int64][]versionRow, len(trs))
	for _, v := range vrs {
		byTool[v.toolID] = append(byTool[v.toolID], v)
	}
	out := make(map[string]*toolRec, len(trs))
	for _, tr := range trs {
		rec, err := newToolRec(tr, byTool[tr.id])
		if err != nil {
			return nil, err
		}
		out[tr.name] = rec
	}
	return out, nil
}

func checkCanonical(v versionRow) error {
	if gate.DigestOfCanonical(v.canonical) != v.digest {
		return fmt.Errorf("%w: version %d of tool %d does not hash to its stored digest", ErrCorrupt, v.no, v.toolID)
	}
	return nil
}

// newToolRec converts rows into lifecycle types and checks that the approved
// pointer and the version statuses agree, because lifecycle.Apply relies on it.
func newToolRec(row toolRow, vrs []versionRow) (*toolRec, error) {
	rec := &toolRec{id: row.id, serverID: row.serverID, name: row.name}
	rec.tool = lifecycle.Tool{
		State:         lifecycle.State(row.state),
		LastSeen:      row.lastSeen,
		MissingCrawls: row.missing,
	}
	approvedSeen := false
	for _, v := range vrs {
		rec.tool.Versions = append(rec.tool.Versions, lifecycle.Version{
			Digest:       v.digest,
			Status:       lifecycle.VersionStatus(v.status),
			ProposedBy:   v.proposedBy,
			EverApproved: v.ever == 1,
		})
		rec.versionIDs = append(rec.versionIDs, v.id)
		rec.maxNo = v.no
		isPointer := row.approved.Valid && row.approved.Int64 == v.id
		if isPointer {
			rec.tool.Approved = v.digest
			approvedSeen = true
		}
		if isPointer != (v.status == string(lifecycle.VersionApproved)) {
			return nil, fmt.Errorf("%w: tool %q approved pointer and version status disagree", ErrCorrupt, row.name)
		}
	}
	if row.approved.Valid && !approvedSeen {
		return nil, fmt.Errorf("%w: tool %q points at a version that is not its own", ErrCorrupt, row.name)
	}
	return rec, nil
}

// insertTool creates the row for a tool seen for the first time, in the
// Discovered state that lifecycle.ObserveCrawl moves on from.
func insertTool(ctx context.Context, t *txn, serverID int64, name string) (*toolRec, error) {
	id, err := t.insert(ctx,
		`INSERT INTO tools (server_id, name, state, approved_version_id, last_seen_digest, missing_crawls)
		 VALUES (?, ?, ?, NULL, '', 0)`, serverID, name, string(lifecycle.Discovered))
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

// save writes the difference between the loaded tool and after, then adopts
// after. mat is the definition of a digest that is new to this tool, if any.
// Versions already stored are never rewritten except for the three mutable
// columns; new ones are appended with the next version number.
func (r *toolRec) save(ctx context.Context, t *txn, after lifecycle.Tool, mat *preparedTool, crawlID int64) error {
	if err := r.updateVersions(ctx, t, after); err != nil {
		return err
	}
	if err := r.insertVersions(ctx, t, after, mat, crawlID); err != nil {
		return err
	}
	if err := r.updateTool(ctx, t, after); err != nil {
		return err
	}
	r.tool = after
	return nil
}

// updateVersions writes status changes in two passes: versions that stop being
// pending or approved first, so the "one pending, one approved" indexes never
// see two of either.
func (r *toolRec) updateVersions(ctx context.Context, t *txn, after lifecycle.Tool) error {
	if len(after.Versions) < len(r.tool.Versions) {
		return internalf("lifecycle dropped a version of %q", r.name)
	}
	for _, entering := range []bool{false, true} {
		for i, old := range r.tool.Versions {
			nv := after.Versions[i]
			if nv.Digest != old.Digest {
				return internalf("lifecycle reordered the versions of %q", r.name)
			}
			if nv == old || isLive(nv.Status) != entering {
				continue
			}
			if _, err := t.exec(ctx,
				`UPDATE tool_versions SET status = ?, proposed_by = ?, ever_approved = ? WHERE id = ?`,
				string(nv.Status), nv.ProposedBy, boolInt(nv.EverApproved), r.versionIDs[i]); err != nil {
				return fmt.Errorf("catalog: update version: %w", err)
			}
		}
	}
	return nil
}

func (r *toolRec) insertVersions(ctx context.Context, t *txn, after lifecycle.Tool, mat *preparedTool, crawlID int64) error {
	for i := len(r.tool.Versions); i < len(after.Versions); i++ {
		v := after.Versions[i]
		if mat == nil || mat.digest != v.Digest {
			return internalf("no definition supplied for a new version of %q", r.name)
		}
		r.maxNo++
		id, err := t.insert(ctx, insertVersion, r.id, r.maxNo, v.Digest, mat.canonical, mat.raw,
			string(v.Status), v.ProposedBy, boolInt(v.EverApproved), t.ts, crawlID)
		if err != nil {
			return fmt.Errorf("catalog: insert version: %w", err)
		}
		r.versionIDs = append(r.versionIDs, id)
	}
	return nil
}

func (r *toolRec) updateTool(ctx context.Context, t *txn, after lifecycle.Tool) error {
	b := r.tool
	if b.State == after.State && b.Approved == after.Approved && b.LastSeen == after.LastSeen &&
		b.MissingCrawls == after.MissingCrawls {
		return nil
	}
	var approved sql.NullInt64
	if after.Approved != "" {
		i := indexOfDigest(after.Versions, after.Approved)
		if i < 0 || i >= len(r.versionIDs) {
			return internalf("approved digest of %q is not one of its versions", r.name)
		}
		approved = sql.NullInt64{Int64: r.versionIDs[i], Valid: true}
	}
	if _, err := t.exec(ctx,
		`UPDATE tools SET state = ?, approved_version_id = ?, last_seen_digest = ?, missing_crawls = ? WHERE id = ?`,
		string(after.State), approved, after.LastSeen, after.MissingCrawls, r.id); err != nil {
		return fmt.Errorf("catalog: update tool: %w", err)
	}
	return nil
}

func indexOfDigest(vs []lifecycle.Version, digest string) int {
	for i, v := range vs {
		if v.Digest == digest {
			return i
		}
	}
	return -1
}

// versionID returns the row id of the version with this digest.
func (r *toolRec) versionID(digest string) (int64, error) {
	i := indexOfDigest(r.tool.Versions, digest)
	if i < 0 || i >= len(r.versionIDs) {
		return 0, internalf("tool %q has no version %s", r.name, digest)
	}
	return r.versionIDs[i], nil
}
