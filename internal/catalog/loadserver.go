package catalog

import (
	"context"
	"fmt"
	"strings"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// Loading the tools a crawl observes. A crawl reads every live tool of the
// server (a listed one is observed, an absent one is missing) but not the
// deprecated rows: a deprecated tool that stays away changes nothing, and an
// upstream that lists fresh names on every crawl would otherwise make every
// later crawl read every row the server ever had (D13). Two exceptions keep
// the lifecycle rules exact: a deprecated tool the listing names again is
// loaded on demand so that it can reappear, and a deprecated tool that still
// carries the unusable marker from an earlier sighting is loaded once more,
// because the lifecycle clears that marker the first time a crawl does not
// list the tool (observeMissing); after that its LastSeen is empty and it is
// skipped like the rest.

// inChunk is how many ids or names one IN (...) query carries. The rows stream
// through one at a time, so the chunk bounds the statement, not the memory.
const inChunk = 256

const (
	liveToolsOfServer = `SELECT ` + toolCols + ` FROM tools t WHERE t.server_id = ? AND (t.state <> ? OR t.last_seen_digest <> '')`
	toolsByName       = `SELECT ` + toolCols + ` FROM tools t WHERE t.server_id = ? AND t.name IN (%s)`
	versionsByTool    = `SELECT ` + versionCols + ` FROM tool_versions v WHERE v.tool_id IN (%s) ORDER BY v.tool_id, v.version_no`
	proposersByTool   = `SELECT ` + proposerCols + ` FROM tool_version_proposers p JOIN tool_versions v ON v.id = p.version_id
		WHERE v.tool_id IN (%s) ORDER BY p.version_id, p.position`
)

// loadCrawlTools loads the live tools of the server, every deprecated tool
// that still carries a LastSeen marker, and any deprecated tool among the
// listed names, keyed by name.
func loadCrawlTools(ctx context.Context, q queryer, serverID int64, listed []string) (map[string]*toolRec, error) {
	trs, err := queryToolRows(ctx, q, liveToolsOfServer, serverID, string(lifecycle.Deprecated))
	if err != nil {
		return nil, err
	}
	live := make(map[string]bool, len(trs))
	for _, tr := range trs {
		live[tr.name] = true
	}
	var revived []string
	for _, name := range listed {
		if !live[name] {
			revived = append(revived, name)
		}
	}
	for chunk := range chunks(revived) {
		more, err := queryToolRows(ctx, q, fmt.Sprintf(toolsByName, placeholders(len(chunk))), prepend(serverID, stringArgs(chunk))...)
		if err != nil {
			return nil, err
		}
		trs = append(trs, more...)
	}
	return assembleTools(ctx, q, trs)
}

// assembleTools loads the versions and proposers of the given tool rows, in
// chunks by tool id, and builds the records.
func assembleTools(ctx context.Context, q queryer, trs []toolRow) (map[string]*toolRec, error) {
	ids := make([]int64, len(trs))
	for i, tr := range trs {
		ids[i] = tr.id
	}
	byTool := make(map[int64][]versionRow, len(trs))
	var proposers map[int64][]string
	for chunk := range chunks(ids) {
		marks := placeholders(len(chunk))
		vrs, err := queryVersionRows(ctx, q, fmt.Sprintf(versionsByTool, marks), false, int64Args(chunk)...)
		if err != nil {
			return nil, err
		}
		for _, v := range vrs {
			byTool[v.toolID] = append(byTool[v.toolID], v)
		}
		if proposers, err = loadProposers(ctx, q, proposers, fmt.Sprintf(proposersByTool, marks), int64Args(chunk)...); err != nil {
			return nil, err
		}
	}
	out := make(map[string]*toolRec, len(trs))
	for _, tr := range trs {
		rec, err := newToolRec(tr, byTool[tr.id], proposers)
		if err != nil {
			return nil, err
		}
		out[tr.name] = rec
	}
	return out, nil
}

// queryToolRows runs a query that selects toolCols.
func queryToolRows(ctx context.Context, q queryer, query string, args ...any) ([]toolRow, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("catalog: load tools: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var trs []toolRow
	for rows.Next() {
		tr, err := scanToolRow(rows)
		if err != nil {
			return nil, fmt.Errorf("catalog: load tools: %w", err)
		}
		trs = append(trs, tr)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("catalog: load tools: %w", err)
	}
	return trs, nil
}

// countServerTools counts the tool rows a server owns, live and deprecated.
func countServerTools(ctx context.Context, q queryer, serverID int64) (int, error) {
	var n int
	if err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM tools WHERE server_id = ?`, serverID).Scan(&n); err != nil {
		return 0, fmt.Errorf("catalog: count tools: %w", err)
	}
	return n, nil
}

// sumServerBytes adds up the canonical bytes stored for every version of
// every tool of the server. It reads row headers only (SQLite answers length()
// of a BLOB from the record) and runs only when a crawl brings new bytes.
func sumServerBytes(ctx context.Context, q queryer, serverID int64) (int64, error) {
	var n int64
	if err := q.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(length(v.canonical)), 0) FROM tool_versions v JOIN tools t ON t.id = v.tool_id WHERE t.server_id = ?`,
		serverID).Scan(&n); err != nil {
		return 0, fmt.Errorf("catalog: sum stored bytes: %w", err)
	}
	return n, nil
}

// chunks yields items in slices of at most inChunk.
func chunks[T any](items []T) func(func([]T) bool) {
	return func(yield func([]T) bool) {
		for len(items) > 0 {
			n := min(len(items), inChunk)
			if !yield(items[:n]) {
				return
			}
			items = items[n:]
		}
	}
}

// placeholders renders n bound-parameter marks for an IN (...) list.
func placeholders(n int) string { return "?" + strings.Repeat(",?", n-1) }

func int64Args(ids []int64) []any {
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	return args
}

func stringArgs(names []string) []any {
	args := make([]any, len(names))
	for i, name := range names {
		args[i] = name
	}
	return args
}

func prepend(first any, rest []any) []any { return append([]any{first}, rest...) }
