package catalog

import (
	"context"
	"fmt"
	"slices"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// The version history of a decision (D15 b, D17 a). What lifecycle.Apply
// reads about a tool's versions, the status, the ever-approved flag and the
// proposer list, lives in mutable columns: tool_versions.status and
// ever_approved are outside the immutable trigger's column list because every
// decision moves them, and tool_version_proposers is a guarded table that
// whoever can drop and re-create a trigger rewrites. The fifth review rewrote
// alice out of the proposers (with the version.proposed entries about the
// tool rewritten in place as well) and alice approved her own bytes; the
// seventh set ever_approved to 1 on alice's pending version, added an
// approvals row the newest-decision rule never ranks (id -2), and alice, the
// sole proposer, rolled back to her own bytes with no audit entry touched,
// since the self-approval rule does not apply to a rollback and the target's
// eligibility came from the column. So every decision, and the Versions view
// that shows approvers the history, reads every version.* entry about the tool
// from the log (version.proposed, version.superseded, version.rejected,
// version.approved, version.rolled_back), requires each one to be part of the
// chain the Store verified (chainMemory.verify), folds them with the one rule
// Integrity applies (versionTrace.apply), and requires every version's status,
// flag and proposer list to be what those entries leave behind. A
// disagreement, a digest the log never proposed, or an edge the lifecycle
// never takes is ErrCorrupt. Once the check holds, the columns the decision
// reads are the chain's values: a rollback target is a digest a verified
// version.approved or version.rolled_back entry named, and a rejected version
// put back to pending by hand is refused instead of approved (the D14 residual
// that is now closed). A crawl does not pay for this: it adds proposers and
// never approves, and the entries about a tool grow with every re-proposal,
// which a flip-flopping upstream could use to make every crawl read the whole
// history; a crawl anchors the approved version alone (anchorKnownTools).

// versionEvidence is one version as the registry lists it: the columns and
// the proposers a decision or the Versions view would act on.
type versionEvidence struct {
	digest    string
	status    lifecycle.VersionStatus
	ever      bool
	proposers []string
}

// recordedVersions lists the versions of a loaded tool as its rows hold them.
func recordedVersions(rec *toolRec) []versionEvidence {
	out := make([]versionEvidence, 0, len(rec.tool.Versions))
	for _, v := range rec.tool.Versions {
		out = append(out, versionEvidence{digest: v.Digest, status: v.Status, ever: v.EverApproved, proposers: v.Proposers.All()})
	}
	return out
}

// viewedVersions lists the versions of a Versions view as it would show them.
func viewedVersions(views []VersionView) []versionEvidence {
	out := make([]versionEvidence, 0, len(views))
	for _, v := range views {
		out = append(out, versionEvidence{digest: v.Digest, status: v.Status, ever: v.EverApproved, proposers: v.Proposers})
	}
	return out
}

// addProposer folds one version.proposed entry into a version's proposer list
// as the Store writes it: an Enable re-proposal adds nobody (D4, the enabler
// introduced no bytes) and an actor is listed once. Integrity and the decision
// path share it, so the two reconstructions cannot drift apart.
func addProposer(list []string, e audit.Entry) []string {
	if isEnableReproposal(e.Detail) || slices.Contains(list, e.Actor) {
		return list
	}
	return append(list, e.Actor)
}

// versionDigest returns the digest a version.* entry concerns; false for a
// detail that is not of the shape the Store writes (Integrity reports those).
func versionDigest(e audit.Entry) (string, bool) {
	digest, ok := detailField(e.Detail, fieldDigest)
	return digest, ok && digest != noDigest
}

// versionEventList is the SQL list of the events that move a version's status.
const versionEventList = `'` + string(lifecycle.EvProposed) + `', '` + string(lifecycle.EvSuperseded) + `', '` +
	string(lifecycle.EvRejected) + `', '` + string(lifecycle.EvApproved) + `', '` + string(lifecycle.EvRolledBack) + `'`

// versionsFromLog reads every version.* entry about a subject in sequence
// order, requires each to be part of the verified chain, folds them into one
// trace per digest and returns the traces. It rests on the audit_log_by_subject
// index, so it reads only the tool's own entries. An edge the lifecycle never
// takes is ErrCorrupt: the Store writes every status move as an event, so such
// a sequence means the row was edited between the two entries.
func versionsFromLog(ctx context.Context, q queryer, chain *chainMemory, subject string) (map[string]*versionTrace, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+auditCols+` FROM audit_log WHERE subject = ? AND event IN (`+versionEventList+`) ORDER BY seq`, subject)
	if err != nil {
		return nil, fmt.Errorf("catalog: read version entries: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]*versionTrace{}
	for rows.Next() {
		e, err := scanAudit(rows)
		if err != nil {
			return nil, fmt.Errorf("catalog: read version entries: %w", err)
		}
		if err := chain.verify(e); err != nil {
			return nil, err
		}
		digest, ok := versionDigest(e)
		if !ok {
			continue
		}
		t := out[digest]
		if t == nil {
			t = &versionTrace{first: e.Seq}
			out[digest] = t
		}
		if from, legal := t.apply(e); !legal {
			return nil, fmt.Errorf("%w: audit entry %d records %s of version %s of %s from status %s, which the lifecycle never does; the row was edited between the entries",
				ErrCorrupt, e.Seq, e.Event, digest, quote(subject), shownStatus(from))
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("catalog: read version entries: %w", err)
	}
	return out, nil
}

// verifyVersionHistory requires every listed version to have been proposed in
// the log and its status, ever-approved flag and proposer list to be what the
// verified version.* entries about the subject leave behind.
func verifyVersionHistory(ctx context.Context, q queryer, chain *chainMemory, subject string, versions []versionEvidence) error {
	if len(versions) == 0 {
		return nil
	}
	logged, err := versionsFromLog(ctx, q, chain, subject)
	if err != nil {
		return err
	}
	for _, v := range versions {
		t, ok := logged[v.digest]
		if !ok {
			return fmt.Errorf("%w: version %s of %s was never proposed in the audit log", ErrCorrupt, v.digest, quote(subject))
		}
		if t.status != v.status || t.ever != v.ever {
			return fmt.Errorf("%w: version %s of %s is in status %s (ever_approved %t) but the verified audit entries (latest seq %d) leave it %s (ever_approved %t); the status columns were edited",
				ErrCorrupt, v.digest, quote(subject), quote(string(v.status)), v.ever, t.last, t.status, t.ever)
		}
		if !slices.Equal(t.proposers, v.proposers) {
			return fmt.Errorf("%w: the proposers of version %s of %s are not the ones the verified version.proposed entries name; the proposer history was rewritten", ErrCorrupt, v.digest, quote(subject))
		}
	}
	return nil
}
