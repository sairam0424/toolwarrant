package catalog

import (
	"context"
	"fmt"
	"slices"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// The proposer evidence of a decision (D15 b). The two-person rule refuses an
// approval by anyone whose crawl proposed the version, and the list it
// consults is tool_version_proposers, a guarded table that whoever can drop
// and re-create a trigger rewrites (the fifth review rewrote alice out of it
// and, with the version.proposed entries about the tool rewritten in place as
// well, Integrity was clean and alice approved her own bytes). So every
// decision, and the Versions view that shows approvers the history, reads the
// version.proposed entries about the tool from the log, requires each one to
// be part of the chain the Store verified (chainMemory.verify), and requires
// the proposer list of every version to be the one those entries name, built
// by the same rule Integrity applies (addProposer). A disagreement is
// ErrCorrupt. A crawl does not pay for this: it adds proposers and never
// approves, and the entries about a tool grow with every re-proposal, which a
// flip-flopping upstream could use to make every crawl read the whole history;
// a crawl anchors the approved version alone (anchorKnownTools).

// versionProposers names one version and the proposers the registry lists for it.
type versionProposers struct {
	digest string
	names  []string
}

// recordedProposers lists the versions of a loaded tool with their proposers.
func recordedProposers(rec *toolRec) []versionProposers {
	out := make([]versionProposers, 0, len(rec.tool.Versions))
	for _, v := range rec.tool.Versions {
		out = append(out, versionProposers{digest: v.Digest, names: v.Proposers.All()})
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

// proposersFromLog reads every version.proposed entry about a subject in
// sequence order, requires each to be part of the verified chain, and returns
// the proposers of every digest the log proposed. It rests on the
// audit_log_by_subject index, so it reads only the tool's own entries.
func proposersFromLog(ctx context.Context, q queryer, chain *chainMemory, subject string) (map[string][]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+auditCols+` FROM audit_log WHERE subject = ? AND event = ? ORDER BY seq`,
		subject, string(lifecycle.EvProposed))
	if err != nil {
		return nil, fmt.Errorf("catalog: read proposal entries: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string][]string{}
	for rows.Next() {
		e, err := scanAudit(rows)
		if err != nil {
			return nil, fmt.Errorf("catalog: read proposal entries: %w", err)
		}
		if err := chain.verify(e); err != nil {
			return nil, err
		}
		digest, ok := detailField(e.Detail, fieldDigest)
		if !ok || digest == noDigest {
			continue // not of the shape the Store writes; Integrity reports it
		}
		out[digest] = addProposer(out[digest], e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("catalog: read proposal entries: %w", err)
	}
	return out, nil
}

// verifyProposers requires the proposer list of every listed version to be the
// one the verified version.proposed entries about the subject name, and every
// version to have been proposed in the log at all.
func verifyProposers(ctx context.Context, q queryer, chain *chainMemory, subject string, versions []versionProposers) error {
	if len(versions) == 0 {
		return nil
	}
	logged, err := proposersFromLog(ctx, q, chain, subject)
	if err != nil {
		return err
	}
	for _, v := range versions {
		names, ok := logged[v.digest]
		if !ok {
			return fmt.Errorf("%w: version %s of %s was never proposed in the audit log", ErrCorrupt, v.digest, quote(subject))
		}
		if !slices.Equal(names, v.names) {
			return fmt.Errorf("%w: the proposers of version %s of %s are not the ones the verified version.proposed entries name; the proposer history was rewritten", ErrCorrupt, v.digest, quote(subject))
		}
	}
	return nil
}
