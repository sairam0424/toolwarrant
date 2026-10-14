package catalog

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// The chain anchor of a tool's state (D17 c, extended after the round). The
// tools table is mutable by design, and lifecycle.Serves decides from its
// state column: Disable keeps the approved pointer of a tool that is not
// deprecated, so one UPDATE tools SET state = 'enabled' served a disabled tool
// again while every approval anchor held and only Integrity saw the edit (the
// eighth review). Every entry the Store writes about a tool carries the state
// it left behind (toolDetail: state=before->after), so every path that acts
// on the column (Snapshot, Tools, Tool, Approved, the decisions and the crawl
// through loadTool and loadCrawlTools) now requires the newest lifecycle entry
// about the tool, verified through the chain memory, to have left exactly the
// state the row holds; a disagreement is ErrCorrupt. tool.rejected entries are
// about names no tool row describes and carry no state, so they are not
// consulted.

// toolStateEvents lists the events whose detail carries the tool's state.
const toolStateEvents = `'` + string(lifecycle.EvDiscovered) + `', '` + string(lifecycle.EvProposed) + `', '` +
	string(lifecycle.EvSuperseded) + `', '` + string(lifecycle.EvApproved) + `', '` + string(lifecycle.EvRejected) + `', '` +
	string(lifecycle.EvRolledBack) + `', '` + string(lifecycle.EvDrifted) + `', '` + string(lifecycle.EvReverted) + `', '` +
	string(lifecycle.EvDisabled) + `', '` + string(lifecycle.EvEnabled) + `', '` + string(lifecycle.EvMissing) + `', '` +
	string(lifecycle.EvDeprecated) + `', '` + string(lifecycle.EvReappeared) + `', '` + string(lifecycle.EvReturned) + `', '` +
	string(lifecycle.EvUnusable) + `'`

// The SQL that selects the seq of the newest state-bearing entry about a
// subject, NULL when there is none, in the two forms the queries name the
// subject (see decisionEntryOfSubject and its sibling); the snapshot takes it
// from one pass over the server's entries (newestEntriesOfServer).
const (
	stateEntryHead = `(SELECT MAX(l.seq) FROM audit_log l WHERE l.event IN (` + toolStateEvents + `) AND l.subject = `

	stateEntryOfSubject    = stateEntryHead + `?)`
	stateEntryOfServerTool = stateEntryHead + `s.name || '/' || t.name)`
)

// stateRef is one tool whose state column must be what the chain left it.
type stateRef struct {
	tool  string // server/name
	state lifecycle.State
	entry sql.NullInt64 // seq of the newest state-bearing entry about the tool
}

// anchorToolState is anchorStates for the paths that load one tool.
func anchorToolState(ctx context.Context, q queryer, chain *chainMemory, subject string, state lifecycle.State) error {
	var seq sql.NullInt64
	if err := q.QueryRowContext(ctx, `SELECT `+stateEntryOfSubject, subject).Scan(&seq); err != nil {
		return fmt.Errorf("catalog: find state entry: %w", err)
	}
	return anchorStates(ctx, q, chain, []stateRef{{tool: subject, state: state, entry: seq}})
}

// knownStateRefs names the state of every tool a crawl loaded with the seq of
// the newest state-bearing entry about it, so that anchorKnownTools can anchor
// the states in the same pass as the approvals and the lifecycle starts from
// the state the chain recorded, not from the column.
func knownStateRefs(ctx context.Context, q queryer, server string, known map[string]*toolRec) ([]stateRef, error) {
	refs := make([]stateRef, 0, len(known))
	for name, rec := range known {
		refs = append(refs, stateRef{tool: server + "/" + name, state: rec.tool.State})
	}
	slices.SortFunc(refs, func(a, b stateRef) int { return strings.Compare(a.tool, b.tool) })
	for chunk := range chunks(refs) {
		if err := findStateEntries(ctx, q, chunk); err != nil {
			return nil, err
		}
	}
	return refs, nil
}

// findStateEntries fills in the seq of the newest state-bearing entry about
// each reference's tool, leaving the entry NULL where the log has none.
func findStateEntries(ctx context.Context, q queryer, refs []stateRef) error {
	subjects := make([]string, len(refs))
	for i, r := range refs {
		subjects[i] = r.tool
	}
	rows, err := q.QueryContext(ctx, `SELECT subject, MAX(seq) FROM audit_log WHERE event IN (`+toolStateEvents+`)
		AND subject IN (`+placeholders(len(subjects))+`) GROUP BY subject`, stringArgs(subjects)...)
	if err != nil {
		return fmt.Errorf("catalog: find state entries: %w", err)
	}
	defer func() { _ = rows.Close() }()
	newest := make(map[string]int64, len(refs))
	for rows.Next() {
		var (
			subject string
			seq     int64
		)
		if err := rows.Scan(&subject, &seq); err != nil {
			return fmt.Errorf("catalog: find state entries: %w", err)
		}
		newest[subject] = seq
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("catalog: find state entries: %w", err)
	}
	for i := range refs {
		if seq, ok := newest[refs[i].tool]; ok {
			refs[i].entry = sql.NullInt64{Int64: seq, Valid: true}
		}
	}
	return nil
}

// anchorStates requires, for every reference, the newest state-bearing entry
// about the tool to exist, to be about the tool, to have left the state the
// row holds and to be part of the chain the Store verified. Any failure is
// ErrCorrupt. The paths that also anchor approvals run both rules in one pass
// (anchorTools).
func anchorStates(ctx context.Context, q queryer, chain *chainMemory, refs []stateRef) error {
	_, err := anchorTools(ctx, q, chain, nil, refs)
	return err
}

// checkStateAnchor applies the state rule to one tool.
func checkStateAnchor(check *entryChecker, r stateRef, entries map[int64]audit.Entry) error {
	e, ok := entries[r.entry.Int64]
	if !ok {
		return fmt.Errorf("%w: audit entry %d about %s vanished within one read", ErrCorrupt, r.entry.Int64, quote(r.tool))
	}
	if e.Subject != r.tool {
		return fmt.Errorf("%w: audit entry %d is not about tool %s", ErrCorrupt, e.Seq, quote(r.tool))
	}
	after, ok := transitionAfterIf(detailField(e.Detail, fieldState))
	if !ok {
		return fmt.Errorf("%w: the %s entry (seq %d) about tool %s has no state field", ErrCorrupt, e.Event, e.Seq, quote(r.tool))
	}
	if after != string(r.state) {
		return fmt.Errorf("%w: state of tool %s is %q but its newest audit entry (seq %d, %s) left it %q; the state column was edited", ErrCorrupt, quote(r.tool), r.state, e.Seq, e.Event, after)
	}
	return check.verify(e)
}
