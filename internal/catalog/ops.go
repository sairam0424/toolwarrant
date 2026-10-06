package catalog

import (
	"context"
	"fmt"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// Values of approvals.decision.
const (
	decisionApprove  = "approve"
	decisionReject   = "reject"
	decisionRollback = "rollback"
)

// change describes one operator command to run through the lifecycle.
type change struct {
	op       string // for error messages
	cmd      lifecycle.Command
	decision string // approvals.decision, or "" when the command records no decision
	digest   string // the digest the operator named, recorded as hash_seen
}

// Approve approves the pending version with this full digest. The digest is
// the hash the approver viewed: if the pending proposal has changed since,
// the call fails with lifecycle.ErrStaleVersion.
func (s *Store) Approve(ctx context.Context, server, tool, digest string, by Actor) error {
	d, err := prepareDecision(digest, by)
	if err != nil {
		return err
	}
	return s.transition(ctx, server, tool, change{
		op: "approve", cmd: lifecycle.Approve{Digest: d, Actor: by.Name}, decision: decisionApprove, digest: d,
	}, by)
}

// Reject rejects the pending version with this full digest.
func (s *Store) Reject(ctx context.Context, server, tool, digest string, by Actor) error {
	d, err := prepareDecision(digest, by)
	if err != nil {
		return err
	}
	return s.transition(ctx, server, tool, change{
		op: "reject", cmd: lifecycle.Reject{Digest: d, Actor: by.Name}, decision: decisionReject, digest: d,
	}, by)
}

// Disable switches a tool off.
func (s *Store) Disable(ctx context.Context, server, tool string, by Actor) error {
	if err := validateActor(by); err != nil {
		return err
	}
	return s.transition(ctx, server, tool, change{op: "disable", cmd: lifecycle.Disable{Actor: by.Name}}, by)
}

// Enable brings a disabled tool back under the store's lifecycle.Policy.
func (s *Store) Enable(ctx context.Context, server, tool string, by Actor) error {
	if err := validateActor(by); err != nil {
		return err
	}
	return s.transition(ctx, server, tool, change{op: "enable", cmd: lifecycle.Enable{Actor: by.Name}}, by)
}

// Rollback re-approves a version that was approved before.
func (s *Store) Rollback(ctx context.Context, server, tool, toDigest string, by Actor) error {
	d, err := prepareDecision(toDigest, by)
	if err != nil {
		return err
	}
	return s.transition(ctx, server, tool, change{
		op: "rollback", cmd: lifecycle.Rollback{To: d, Actor: by.Name}, decision: decisionRollback, digest: d,
	}, by)
}

// prepareDecision validates the actor and the digest of a command that names a
// version, before any lock is taken.
func prepareDecision(digest string, by Actor) (string, error) {
	if err := validateActor(by); err != nil {
		return "", err
	}
	return normalizeDigest(digest)
}

// transition runs one command through the lifecycle inside one transaction. If
// the lifecycle refuses, nothing is written and its error, wrapped with %w, is
// returned so errors.Is(err, lifecycle.ErrSelfApproval) and friends work.
func (s *Store) transition(ctx context.Context, server, tool string, c change, by Actor) error {
	return s.inTx(ctx, func(t *txn) error {
		rec, err := loadTool(ctx, t, server, tool)
		if err != nil {
			return err
		}
		res, err := lifecycle.Apply(rec.tool, c.cmd, s.policy)
		if err != nil {
			return fmt.Errorf("catalog: %s %s/%s: %w", c.op, quote(server), quote(tool), err)
		}
		before := rec.tool
		if err := rec.save(ctx, t, res.Tool, nil, 0); err != nil {
			return err
		}
		if c.decision != "" {
			if err := recordDecision(ctx, t, rec, c, by); err != nil {
				return err
			}
		}
		return t.auditTool(ctx, by, server, tool, before, res.Tool, res.Events)
	})
}

func recordDecision(ctx context.Context, t *txn, rec *toolRec, c change, by Actor) error {
	versionID, err := rec.versionID(c.digest)
	if err != nil {
		return err
	}
	if _, err := t.exec(ctx,
		`INSERT INTO approvals (version_id, decision, approver, actor_type, hash_seen, at) VALUES (?, ?, ?, ?, ?, ?)`,
		versionID, c.decision, by.Name, string(by.Type), c.digest, t.ts); err != nil {
		return fmt.Errorf("catalog: record %s: %w", c.decision, err)
	}
	return nil
}
