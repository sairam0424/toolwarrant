package catalog

import (
	"context"
	"fmt"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
	"github.com/sairam0424/toolwarrant/internal/signing"
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

// The six decision methods below are Decide without a signed record (decide.go):
// they write exactly what v0.3 wrote on a catalog without a trust list and are
// ErrSignatureRequired once one is in force. The CLI signs and calls Decide.

// Approve approves the pending version with this full digest. The digest is
// the hash the approver viewed: if the pending proposal has changed since,
// the call fails with lifecycle.ErrStaleVersion. Every principal whose crawl
// ever proposed the version is refused (lifecycle.ErrSelfApproval) unless the
// policy allows self-approval.
func (s *Store) Approve(ctx context.Context, server, tool, digest string, by Actor) error {
	return s.decideUnsigned(ctx, Decision{Kind: signing.KindApprove, Server: server, Tool: tool, Digest: digest, By: by})
}

// Reject rejects the pending version with this full digest.
func (s *Store) Reject(ctx context.Context, server, tool, digest string, by Actor) error {
	return s.decideUnsigned(ctx, Decision{Kind: signing.KindReject, Server: server, Tool: tool, Digest: digest, By: by})
}

// Disable switches a tool off.
func (s *Store) Disable(ctx context.Context, server, tool string, by Actor) error {
	return s.decideUnsigned(ctx, Decision{Kind: signing.KindDisable, Server: server, Tool: tool, By: by})
}

// Enable brings a disabled tool back under the store's lifecycle.Policy. The
// enabler proposes nothing and so may approve what the crawl proposed (D4).
func (s *Store) Enable(ctx context.Context, server, tool string, by Actor) error {
	return s.decideUnsigned(ctx, Decision{Kind: signing.KindEnable, Server: server, Tool: tool, By: by})
}

// Rollback re-approves a version that was approved before.
func (s *Store) Rollback(ctx context.Context, server, tool, toDigest string, by Actor) error {
	return s.decideUnsigned(ctx, Decision{Kind: signing.KindRollback, Server: server, Tool: tool, Digest: toDigest, By: by})
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
	return s.decideUnsigned(ctx, Decision{Kind: signing.KindBudgetReset, Server: server, Tool: tool, By: by})
}

// decideUnsigned is Decide for the methods that carry no record and return no
// receipt.
func (s *Store) decideUnsigned(ctx context.Context, d Decision) error {
	_, err := s.Decide(ctx, d)
	return err
}

// transitionTx runs one command through the lifecycle inside the decision's
// transaction, after the signed entry when there is one. If the lifecycle
// refuses, nothing is written and its error, wrapped with %w, is returned so
// errors.Is(err, lifecycle.ErrSelfApproval) and friends work. A decision
// (approve, reject, rollback) also resets the tool's proposal budget. Every
// entry carries note, the signed= token of the decision.signed entry.
func (s *Store) transitionTx(ctx context.Context, t *txn, server, tool string, c change, by Actor, note string) error {
	rec, err := loadTool(ctx, t, s.chain, server, tool)
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
	return t.auditTool(ctx, by, server, tool, before, rec.state(), res.Events, note)
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

// resetBudgetTx is ResetProposalBudget inside the decision's transaction; see
// that method for the rule. The entry carries note.
func (s *Store) resetBudgetTx(ctx context.Context, t *txn, server, tool string, by Actor, note string) error {
	rec, err := loadTool(ctx, t, s.chain, server, tool)
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
	return t.appendAudit(ctx, by, evBudgetReset, server+"/"+tool, rec.tool.Approved, rec.tool.Approved,
		toolDetail("", before, rec.state(), note))
}
