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

// The chain anchor of an approval (D14 a, D15 b). The newest-decision rule
// reads the approvals table, which whoever can drop and re-create a guard
// trigger can rewrite together with the version (the fourth review rewrote
// canonical, raw, digest and hash_seen under byte-identical re-created
// triggers and was served). The audit log is the one table whose rows prove
// themselves, but only as a chain: the fifth review rewrote the approval
// entry in place, re-sealed from its real predecessor, and the check of that
// one entry against its predecessor passed. So every read that hands out or
// acts on an approval also reads the newest version.approved or
// version.rolled_back entry about the tool, requires its after_hash to be the
// approved digest, and requires the entry to be part of the chain the Store
// verified (chainMemory.verify: the hash computed from its fields now equals
// the one the verified walk recorded). A forger must rewrite every entry from
// that one to the head, which the head a running Store pinned betrays while
// that Store runs, and which the head the operator recorded alone betrays once
// no Store holds a pin (chain.go, D17 k).

// The SQL that selects the seq of the newest version.approved or
// version.rolled_back entry about a subject, NULL when there is none. It rests
// on the audit_log_by_subject index, so it costs one probe per tool. Two
// forms exist for the two ways the queries name the subject: a bound
// parameter, and a tool row aliased t joined with its server aliased s. The
// snapshot, which reads every tool of one server, takes the same seq from one
// pass over the server's entries instead (newestEntriesOfServer, D21 d).
const (
	decisionEvents    = `'` + string(lifecycle.EvApproved) + `', '` + string(lifecycle.EvRolledBack) + `'`
	decisionEntryHead = `(SELECT MAX(l.seq) FROM audit_log l WHERE l.subject = `
	decisionEntryTail = ` AND l.event IN (` + decisionEvents + `))`

	decisionEntryOfSubject    = decisionEntryHead + `?` + decisionEntryTail
	decisionEntryOfServerTool = decisionEntryHead + `s.name || '/' || t.name` + decisionEntryTail
)

// newestDecisionEntry returns the seq of the newest decision entry about one
// subject, for the paths that load one tool.
func newestDecisionEntry(ctx context.Context, q queryer, subject string) (sql.NullInt64, error) {
	var seq sql.NullInt64
	if err := q.QueryRowContext(ctx, `SELECT `+decisionEntryOfSubject, subject).Scan(&seq); err != nil {
		return sql.NullInt64{}, fmt.Errorf("catalog: find approval entry: %w", err)
	}
	return seq, nil
}

// anchorOne is anchorApproved for the paths that load one tool: it looks the
// newest approval entry about the tool up and checks the approved version
// against it. A tool without an approval needs nothing.
func anchorOne(ctx context.Context, q queryer, chain *chainMemory, subject string, versionID int64, digest string) error {
	if digest == "" {
		return nil
	}
	entry, err := newestDecisionEntry(ctx, q, subject)
	if err != nil {
		return err
	}
	return anchorApproved(ctx, q, chain, []approvedRef{{id: versionID, tool: subject, digest: digest, entry: entry}})
}

// anchorKnownTools is anchorApproved for a crawl: every loaded tool of the
// server that has an approved version is anchored, with the newest decision
// entries looked up in one query per chunk of subjects, so a crawl never
// records an observation against an approval the log does not back.
func anchorKnownTools(ctx context.Context, q queryer, chain *chainMemory, server string, known map[string]*toolRec) error {
	var refs []approvedRef
	for name, rec := range known {
		if rec.tool.Approved == "" {
			continue
		}
		id, err := rec.versionID(rec.tool.Approved)
		if err != nil {
			return err
		}
		refs = append(refs, approvedRef{id: id, tool: server + "/" + name, digest: rec.tool.Approved})
	}
	slices.SortFunc(refs, func(a, b approvedRef) int { return strings.Compare(a.tool, b.tool) })
	for chunk := range chunks(refs) {
		if err := findDecisionEntries(ctx, q, chunk); err != nil {
			return err
		}
	}
	states, err := knownStateRefs(ctx, q, server, known)
	if err != nil {
		return err
	}
	_, err = anchorTools(ctx, q, chain, refs, states)
	return err
}

// findDecisionEntries fills in the seq of the newest decision entry about each
// reference's tool, leaving the entry NULL where the log has none.
func findDecisionEntries(ctx context.Context, q queryer, refs []approvedRef) error {
	subjects := make([]string, len(refs))
	for i, r := range refs {
		subjects[i] = r.tool
	}
	rows, err := q.QueryContext(ctx, `SELECT subject, MAX(seq) FROM audit_log WHERE event IN (`+decisionEvents+`)
		AND subject IN (`+placeholders(len(subjects))+`) GROUP BY subject`, stringArgs(subjects)...)
	if err != nil {
		return fmt.Errorf("catalog: find approval entries: %w", err)
	}
	defer func() { _ = rows.Close() }()
	newest := make(map[string]int64, len(refs))
	for rows.Next() {
		var (
			subject string
			seq     int64
		)
		if err := rows.Scan(&subject, &seq); err != nil {
			return fmt.Errorf("catalog: find approval entries: %w", err)
		}
		newest[subject] = seq
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("catalog: find approval entries: %w", err)
	}
	for i := range refs {
		if seq, ok := newest[refs[i].tool]; ok {
			refs[i].entry = sql.NullInt64{Int64: seq, Valid: true}
		}
	}
	return nil
}

// anchorApproved requires, for every approved version in refs, the newest
// decision entry about its tool to exist, to have recorded the approved digest
// as after_hash, and to be part of the chain the Store verified. Any failure
// is ErrCorrupt.
func anchorApproved(ctx context.Context, q queryer, chain *chainMemory, refs []approvedRef) error {
	_, err := anchorTools(ctx, q, chain, refs, nil)
	return err
}

// anchorTools is the one anchor pass of a checked read: the approval of every
// tool in refs (the rule of anchorApproved) and the state column of every
// tool in states (the rule of anchorStates) are checked against the entries
// they name, read in one pass and each verified against the chain memory
// once. The two anchors of an approved tool are the same entry whenever its
// approval is the newest lifecycle entry about it, so a reload of n approved
// tools costs one indexed read and between n and 2n entry hashes, never 2n
// reads and 2n hashes (D21 d). It returns the verified entries by seq, so that
// Approved can take the approver and the time of every exported version from
// the entry the chain vouches for instead of from the approvals row (D17 e).
// Nothing of the pass outlives the read: the next read hashes every entry it
// anchors to again (chain.go, the fifth review's lesson).
func anchorTools(ctx context.Context, q queryer, chain *chainMemory, refs []approvedRef, states []stateRef) (map[int64]audit.Entry, error) {
	seqs, err := anchorSeqs(refs, states)
	if err != nil {
		return nil, err
	}
	entries, err := readAllEntries(ctx, q, seqs)
	if err != nil {
		return nil, err
	}
	check := newEntryChecker(chain)
	for _, r := range refs {
		if err := checkAnchor(check, r, entries); err != nil {
			return nil, err
		}
	}
	for _, r := range states {
		if err := checkStateAnchor(check, r, entries); err != nil {
			return nil, err
		}
	}
	return entries, nil
}

// anchorSeqs collects, once each, the seqs of the entries the references name.
// A reference the log has no entry for is ErrCorrupt: an approved version
// without an approval entry, or a tool without any state-bearing entry (every
// tool the catalog created has at least a tool.discovered entry).
func anchorSeqs(refs []approvedRef, states []stateRef) ([]int64, error) {
	seen := make(map[int64]struct{}, len(refs)+len(states))
	seqs := make([]int64, 0, len(refs)+len(states))
	add := func(seq int64) {
		if _, ok := seen[seq]; !ok {
			seen[seq] = struct{}{}
			seqs = append(seqs, seq)
		}
	}
	for _, r := range refs {
		if !r.entry.Valid {
			return nil, fmt.Errorf("%w: approved version of %s has no version.approved or version.rolled_back audit entry", ErrCorrupt, quote(r.tool))
		}
		add(r.entry.Int64)
	}
	for _, r := range states {
		if !r.entry.Valid {
			return nil, fmt.Errorf("%w: tool %s has no audit entry about its state; every tool the catalog created has at least a tool.discovered entry", ErrCorrupt, quote(r.tool))
		}
		add(r.entry.Int64)
	}
	return seqs, nil
}

// readAllEntries reads the entries with the given seqs, in chunks of inChunk.
func readAllEntries(ctx context.Context, q queryer, seqs []int64) (map[int64]audit.Entry, error) {
	entries := make(map[int64]audit.Entry, len(seqs))
	for chunk := range chunks(seqs) {
		if err := readEntries(ctx, q, chunk, entries); err != nil {
			return nil, err
		}
	}
	return entries, nil
}

// entryChecker verifies the entries one checked read anchors to, each distinct
// seq once: both anchors of a tool name the same entry whenever its approval
// is the newest lifecycle entry about it, and the entry read once from one
// snapshot hashes the same twice. It belongs to one read and is dropped with
// it; it never keys on the stored hash column or on any other column (the
// fifth review edited an entry under a memory keyed by that column, chain.go).
type entryChecker struct {
	chain *chainMemory
	seen  map[int64]struct{}
}

// newEntryChecker starts the checker of one read over the Store's chain memory.
func newEntryChecker(chain *chainMemory) *entryChecker {
	return &entryChecker{chain: chain, seen: map[int64]struct{}{}}
}

// verify is chainMemory.verify run once per seq within this read.
func (c *entryChecker) verify(e audit.Entry) error {
	if _, ok := c.seen[e.Seq]; ok {
		return nil
	}
	if err := c.chain.verify(e); err != nil {
		return err
	}
	c.seen[e.Seq] = struct{}{}
	return nil
}

// readEntries reads the entries with the given seqs into out.
func readEntries(ctx context.Context, q queryer, seqs []int64, out map[int64]audit.Entry) error {
	rows, err := q.QueryContext(ctx, `SELECT `+auditCols+` FROM audit_log WHERE seq IN (`+placeholders(len(seqs))+`)`, int64Args(seqs)...)
	if err != nil {
		return fmt.Errorf("catalog: read approval entries: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		e, err := scanAudit(rows)
		if err != nil {
			return fmt.Errorf("catalog: read approval entries: %w", err)
		}
		out[e.Seq] = e
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("catalog: read approval entries: %w", err)
	}
	return nil
}

// checkAnchor applies the anchor rule to one approved version: the entry must
// be about the tool, be an approval, name the digest, carry the approver and
// time the approvals row shows when the caller shows them, and be the entry
// the verified chain holds at its seq.
func checkAnchor(check *entryChecker, r approvedRef, entries map[int64]audit.Entry) error {
	e, ok := entries[r.entry.Int64]
	if !ok {
		return fmt.Errorf("%w: audit entry %d about %s vanished within one read", ErrCorrupt, r.entry.Int64, quote(r.tool))
	}
	if e.Subject != r.tool || (e.Event != string(lifecycle.EvApproved) && e.Event != string(lifecycle.EvRolledBack)) {
		return fmt.Errorf("%w: audit entry %d is not an approval entry about %s", ErrCorrupt, e.Seq, quote(r.tool))
	}
	if e.AfterHash != r.digest {
		return fmt.Errorf("%w: approved digest of %s is not the one its newest approval entry (seq %d) recorded", ErrCorrupt, quote(r.tool), e.Seq)
	}
	if r.showsApprover && (e.Actor != r.approver || e.TS != r.at) {
		return fmt.Errorf("%w: the approver or time of the newest approvals row of %s is not what its approval entry (seq %d) recorded; the approvals row was rewritten", ErrCorrupt, quote(r.tool), e.Seq)
	}
	return check.verify(e)
}
