package catalog

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// The chain anchor of an approval (D14 a). The newest-decision rule reads the
// approvals table, which whoever can drop and re-create a guard trigger can
// rewrite together with the version (the fourth review rewrote canonical, raw,
// digest and hash_seen under byte-identical re-created triggers and was
// served). The audit log is the one table whose rows prove themselves: every
// entry's hash covers its fields and its predecessor's hash. So every read that
// hands out or acts on an approval also reads the newest version.approved or
// version.rolled_back entry about the tool, requires its after_hash to be the
// approved digest, and requires the entry to re-seal from its predecessor. A
// forger must now rewrite that entry and re-chain every entry after it, which
// the head the operator records outside the file betrays (the limit D14
// states). The Store remembers each entry it re-sealed for RecheckTTL
// (Store.sealed), so a reload hashes an entry at most once per RecheckTTL.

// The SQL that selects the seq of the newest version.approved or
// version.rolled_back entry about a subject, NULL when there is none. It rests
// on the audit_log_by_subject index, so it costs one probe per tool. Three
// forms exist for the three ways the queries name the subject: a bound
// parameter, a tool row aliased t whose server name is a bound parameter, and
// a tool row aliased t joined with its server aliased s.
const (
	decisionEvents    = `'` + string(lifecycle.EvApproved) + `', '` + string(lifecycle.EvRolledBack) + `'`
	decisionEntryHead = `(SELECT MAX(l.seq) FROM audit_log l WHERE l.subject = `
	decisionEntryTail = ` AND l.event IN (` + decisionEvents + `))`

	decisionEntryOfSubject    = decisionEntryHead + `?` + decisionEntryTail
	decisionEntryOfTool       = decisionEntryHead + `? || '/' || t.name` + decisionEntryTail
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
func anchorOne(ctx context.Context, q queryer, sealed *verifier, subject string, versionID int64, digest string) error {
	if digest == "" {
		return nil
	}
	entry, err := newestDecisionEntry(ctx, q, subject)
	if err != nil {
		return err
	}
	return anchorApproved(ctx, q, sealed, []approvedRef{{id: versionID, tool: subject, digest: digest, entry: entry}})
}

// anchoredEntry is one decision entry as read for the anchor check, with the
// hash of the entry before it ("" for the first entry of the log).
type anchoredEntry struct {
	entry    audit.Entry
	prevHash string
}

// anchorApproved requires, for every approved version in refs, the newest
// decision entry about its tool to exist, to have recorded the approved digest
// as after_hash, and to re-seal from its predecessor; sealed is the Store's
// memory of entries already verified. Any failure is ErrCorrupt.
func anchorApproved(ctx context.Context, q queryer, sealed *verifier, refs []approvedRef) error {
	var seqs []int64
	for _, r := range refs {
		if !r.entry.Valid {
			return fmt.Errorf("%w: approved version of %s has no version.approved or version.rolled_back audit entry", ErrCorrupt, quote(r.tool))
		}
		seqs = append(seqs, r.entry.Int64)
	}
	entries := make(map[int64]anchoredEntry, len(seqs))
	for chunk := range chunks(seqs) {
		if err := readAnchoredEntries(ctx, q, chunk, entries); err != nil {
			return err
		}
	}
	for _, r := range refs {
		if err := checkAnchor(sealed, r, entries); err != nil {
			return err
		}
	}
	return nil
}

// readAnchoredEntries reads the entries with the given seqs and the hash of
// each one's predecessor into out.
func readAnchoredEntries(ctx context.Context, q queryer, seqs []int64, out map[int64]anchoredEntry) error {
	rows, err := q.QueryContext(ctx, `SELECT `+auditCols+`, COALESCE((SELECT p.hash FROM audit_log p WHERE p.seq = audit_log.seq - 1), '')
		FROM audit_log WHERE seq IN (?`+strings.Repeat(",?", len(seqs)-1)+`)`, int64Args(seqs)...)
	if err != nil {
		return fmt.Errorf("catalog: read approval entries: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var a anchoredEntry
		if err := rows.Scan(&a.entry.Seq, &a.entry.TS, &a.entry.Actor, &a.entry.ActorType, &a.entry.Event, &a.entry.Subject,
			&a.entry.BeforeHash, &a.entry.AfterHash, &a.entry.Detail, &a.entry.PrevHash, &a.entry.Hash, &a.prevHash); err != nil {
			return fmt.Errorf("catalog: read approval entries: %w", err)
		}
		out[a.entry.Seq] = a
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("catalog: read approval entries: %w", err)
	}
	return nil
}

// checkAnchor applies the anchor rule to one approved version.
func checkAnchor(sealed *verifier, r approvedRef, entries map[int64]anchoredEntry) error {
	a, ok := entries[r.entry.Int64]
	if !ok {
		return fmt.Errorf("%w: audit entry %d about %s vanished within one read", ErrCorrupt, r.entry.Int64, quote(r.tool))
	}
	e := a.entry
	if e.Subject != r.tool || (e.Event != string(lifecycle.EvApproved) && e.Event != string(lifecycle.EvRolledBack)) {
		return fmt.Errorf("%w: audit entry %d is not an approval entry about %s", ErrCorrupt, e.Seq, quote(r.tool))
	}
	if e.AfterHash != r.digest {
		return fmt.Errorf("%w: approved digest of %s is not the one its newest approval entry (seq %d) recorded", ErrCorrupt, quote(r.tool), e.Seq)
	}
	if !sealed.verifySeal(e, a.prevHash) {
		return errEntryRewritten(e.Seq, r.tool)
	}
	return nil
}

// errEntryRewritten is the ErrCorrupt for an audit entry whose hash no longer
// covers its fields and its predecessor: the log was rewritten.
func errEntryRewritten(seq int64, subject string) error {
	return fmt.Errorf("%w: audit entry %d about %s does not re-seal from its predecessor; the log was rewritten", ErrCorrupt, seq, quote(subject))
}
