package catalog

import (
	"context"
	"database/sql"
	"fmt"
	"slices"

	"github.com/sairam0424/toolwarrant/internal/gate"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// save writes the difference between the loaded tool and after, then adopts
// after. mat is the definition of a digest that is new to this tool, if any.
// Versions already stored are never rewritten except for status and
// ever_approved; proposers are only appended; new versions are appended with
// the next version number. Anything the lifecycle returned that cannot be
// persisted faithfully fails the transaction instead of being guessed at.
func (r *toolRec) save(ctx context.Context, t *txn, after lifecycle.Tool, mat *preparedTool, crawlID int64) error {
	if err := r.checkShape(after); err != nil {
		return err
	}
	if err := r.updateStatuses(ctx, t, after); err != nil {
		return err
	}
	if err := r.appendProposers(ctx, t, after); err != nil {
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

// checkShape verifies the invariants the lifecycle promises for stored
// versions: none dropped or reordered, the first proposer never changes, and
// the proposer list only grows at its end.
func (r *toolRec) checkShape(after lifecycle.Tool) error {
	if len(after.Versions) < len(r.tool.Versions) {
		return internalf("lifecycle dropped a version of %q", r.name)
	}
	for i, old := range r.tool.Versions {
		nv := after.Versions[i]
		if nv.Digest != old.Digest {
			return internalf("lifecycle reordered the versions of %q", r.name)
		}
		if nv.ProposedBy != old.ProposedBy {
			return internalf("lifecycle changed the proposer of a version of %q", r.name)
		}
		was, now := old.Proposers.All(), nv.Proposers.All()
		if len(now) < len(was) || !slices.Equal(now[:len(was)], was) {
			return internalf("lifecycle rewrote the proposer history of a version of %q", r.name)
		}
	}
	return nil
}

// updateStatuses writes status changes in two passes: versions that stop being
// pending or approved first, so the "one pending, one approved" indexes never
// see two of either.
func (r *toolRec) updateStatuses(ctx context.Context, t *txn, after lifecycle.Tool) error {
	for _, entering := range []bool{false, true} {
		for i, old := range r.tool.Versions {
			nv := after.Versions[i]
			if (nv.Status == old.Status && nv.EverApproved == old.EverApproved) || isLive(nv.Status) != entering {
				continue
			}
			if _, err := t.exec(ctx, `UPDATE tool_versions SET status = ?, ever_approved = ? WHERE id = ?`,
				string(nv.Status), boolInt(nv.EverApproved), r.versionIDs[i]); err != nil {
				return fmt.Errorf("catalog: update version: %w", err)
			}
		}
	}
	return nil
}

// appendProposers stores the principals a re-proposal added to existing versions.
func (r *toolRec) appendProposers(ctx context.Context, t *txn, after lifecycle.Tool) error {
	for i, old := range r.tool.Versions {
		names := after.Versions[i].Proposers.All()
		if len(names) <= old.Proposers.Len() {
			continue
		}
		if err := insertProposers(ctx, t, r.versionIDs[i], old.Proposers.Len(), names[old.Proposers.Len():]); err != nil {
			return err
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
		names := v.Proposers.All()
		if len(names) == 0 || names[0] != v.ProposedBy {
			return internalf("a new version of %q has no proposer", r.name)
		}
		r.maxNo++
		id, err := t.insert(ctx, insertVersion, r.id, r.maxNo, v.Digest, gate.DigestProfile, mat.canonical, mat.raw,
			string(v.Status), v.ProposedBy, boolInt(v.EverApproved), t.ts, crawlID)
		if err != nil {
			return fmt.Errorf("catalog: insert version: %w", err)
		}
		if err := insertProposers(ctx, t, id, 0, names); err != nil {
			return err
		}
		r.versionIDs = append(r.versionIDs, id)
		r.budget++
	}
	return nil
}

// insertProposers appends names to a version's proposer list from position start.
func insertProposers(ctx context.Context, t *txn, versionID int64, start int, names []string) error {
	for i, name := range names {
		if _, err := t.exec(ctx, insertProposer, versionID, start+i, name); err != nil {
			return fmt.Errorf("catalog: insert proposer: %w", err)
		}
	}
	return nil
}

// updateTool writes the tool row when anything on it changed.
func (r *toolRec) updateTool(ctx context.Context, t *txn, after lifecycle.Tool) error {
	b := r.tool
	if b.State == after.State && b.Approved == after.Approved && b.LastSeen == after.LastSeen &&
		b.MissingCrawls == after.MissingCrawls && r.budget == r.storedBudget {
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
		`UPDATE tools SET state = ?, approved_version_id = ?, last_seen_digest = ?, missing_crawls = ?,
		 proposals_since_decision = ? WHERE id = ?`,
		string(after.State), approved, after.LastSeen, after.MissingCrawls, r.budget, r.id); err != nil {
		return fmt.Errorf("catalog: update tool: %w", err)
	}
	r.storedBudget = r.budget
	return nil
}
