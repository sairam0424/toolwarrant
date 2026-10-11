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

// requireHuman normalises the actor and refuses a system actor (D7): only a
// named person approves, rejects, rolls back, disables, enables, pauses or
// resumes. The crawler identity may only observe.
func requireHuman(by Actor) (Actor, error) {
	actor, err := normalizeActor(by)
	if err != nil {
		return Actor{}, err
	}
	if actor.Type != ActorHuman {
		return Actor{}, fmt.Errorf("%w: actor %s is of type %s", ErrHumanRequired, quote(actor.Name), actor.Type)
	}
	return actor, nil
}

// Approve approves the pending version with this full digest. The digest is
// the hash the approver viewed: if the pending proposal has changed since,
// the call fails with lifecycle.ErrStaleVersion. Every principal whose crawl
// ever proposed the version is refused (lifecycle.ErrSelfApproval) unless the
// policy allows self-approval.
func (s *Store) Approve(ctx context.Context, server, tool, digest string, by Actor) error {
	actor, d, err := prepareDecision(digest, by)
	if err != nil {
		return err
	}
	return s.transition(ctx, server, tool, change{
		op: "approve", cmd: lifecycle.Approve{Digest: d, Actor: actor.Name}, decision: decisionApprove, digest: d,
	}, actor)
}

// Reject rejects the pending version with this full digest.
func (s *Store) Reject(ctx context.Context, server, tool, digest string, by Actor) error {
	actor, d, err := prepareDecision(digest, by)
	if err != nil {
		return err
	}
	return s.transition(ctx, server, tool, change{
		op: "reject", cmd: lifecycle.Reject{Digest: d, Actor: actor.Name}, decision: decisionReject, digest: d,
	}, actor)
}

// Disable switches a tool off.
func (s *Store) Disable(ctx context.Context, server, tool string, by Actor) error {
	actor, err := requireHuman(by)
	if err != nil {
		return err
	}
	return s.transition(ctx, server, tool, change{op: "disable", cmd: lifecycle.Disable{Actor: actor.Name}}, actor)
}

// Enable brings a disabled tool back under the store's lifecycle.Policy. The
// enabler proposes nothing and so may approve what the crawl proposed (D4).
func (s *Store) Enable(ctx context.Context, server, tool string, by Actor) error {
	actor, err := requireHuman(by)
	if err != nil {
		return err
	}
	return s.transition(ctx, server, tool, change{op: "enable", cmd: lifecycle.Enable{Actor: actor.Name}}, actor)
}

// Rollback re-approves a version that was approved before.
func (s *Store) Rollback(ctx context.Context, server, tool, toDigest string, by Actor) error {
	actor, d, err := prepareDecision(toDigest, by)
	if err != nil {
		return err
	}
	return s.transition(ctx, server, tool, change{
		op: "rollback", cmd: lifecycle.Rollback{To: d, Actor: actor.Name}, decision: decisionRollback, digest: d,
	}, actor)
}

// prepareDecision validates the actor and the digest of a command that names a
// version, before any lock is taken.
func prepareDecision(digest string, by Actor) (Actor, string, error) {
	actor, err := requireHuman(by)
	if err != nil {
		return Actor{}, "", err
	}
	d, err := normalizeDigest(digest)
	if err != nil {
		return Actor{}, "", err
	}
	return actor, d, nil
}

// transition runs one command through the lifecycle inside one transaction. If
// the lifecycle refuses, nothing is written and its error, wrapped with %w, is
// returned so errors.Is(err, lifecycle.ErrSelfApproval) and friends work. A
// decision (approve, reject, rollback) also resets the tool's proposal budget.
func (s *Store) transition(ctx context.Context, server, tool string, c change, by Actor) error {
	return s.inTx(ctx, func(t *txn) error {
		rec, err := loadTool(ctx, t, s.sealed, server, tool)
		if err != nil {
			return err
		}
		res, err := lifecycle.Apply(rec.tool, c.cmd, s.policy)
		if err != nil {
			return fmt.Errorf("catalog: %s %s/%s: %w", c.op, quote(server), quote(tool), err)
		}
		before := rec.state()
		if c.decision != "" {
			rec.budget = 0
		}
		if err := rec.save(ctx, t, res.Tool, nil, 0); err != nil {
			return err
		}
		if c.decision != "" {
			if err := recordDecision(ctx, t, rec, c, by); err != nil {
				return err
			}
		}
		return t.auditTool(ctx, by, server, tool, before, rec.state(), res.Events, "")
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

// ResetProposalBudget forgets the proposals a tool gained since its last
// decision (tools.proposals_since_decision), so that the next crawl may store
// a new digest again. It is the decision that is always available: approve,
// reject and rollback each need a version in the right status, and a tool
// whose upstream exhausted the budget and then went back to the approved
// definition has none, which left it unable to take any new definition for
// good (limit L6). A revert never resets the budget on its own: a hostile
// upstream could then cycle through MaxProposalsPerDecision digests and one
// revert to grow the file without bound, so a person must look and decide.
// The reset is one audit entry, tool.budget_reset, by a human actor (D7),
// whose proposals field records how many were forgotten (N->0); the tool's
// state, approval and versions do not change. A budget that is already zero is
// ErrInvalid, so a reset is never a silent no-op.
func (s *Store) ResetProposalBudget(ctx context.Context, server, tool string, by Actor) error {
	actor, err := requireHuman(by)
	if err != nil {
		return err
	}
	return s.inTx(ctx, func(t *txn) error {
		rec, err := loadTool(ctx, t, s.sealed, server, tool)
		if err != nil {
			return err
		}
		if rec.budget == 0 {
			return invalidf("tool %s/%s has no proposals since its last decision", quote(server), quote(tool))
		}
		before := rec.state()
		rec.budget = 0
		if err := rec.save(ctx, t, rec.tool, nil, 0); err != nil {
			return err
		}
		return t.appendAudit(ctx, actor, evBudgetReset, server+"/"+tool, rec.tool.Approved, rec.tool.Approved,
			toolDetail("", before, rec.state(), ""))
	})
}
