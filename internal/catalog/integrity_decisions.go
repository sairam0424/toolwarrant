package catalog

import (
	"slices"

	"github.com/sairam0424/toolwarrant/internal/audit"
)

// The decision side of Integrity (D22 (b) and (d)). The walk holds every entry
// after the trust bootstrap to rule 5 (a human decision names the verified
// decision.signed entry of its own transaction) and rule 6 (an entry no
// decision signed moves a tool only as a crawl can) and refuses the file at
// the first break; Integrity streams the log once more and applies the same
// function (checkLifecycleEntry, decisionwalk.go) to every entry in order,
// against the bootstrap and the decision records checkSignedRecords accepted,
// reporting each refusal with the walk's sentence and going on. It then lists
// the approvals in force that predate the bootstrap: served by chain anchoring
// alone (O-12), information rather than a problem.

// checkDecisionEntries applies rules 5 and 6 to every entry of the log that
// carries no signed record, in seq order, and then notes the legacy approvals.
// Without a bootstrap in force nothing applies (the file is a v0.3 catalog in
// every respect) and the legacy list stays nil. The states every tool was left
// in are tracked from the genesis, as the walk tracks them, and a refused
// entry's state is recorded too, so that the entries after it, which the file
// built on it, are not each reported again.
func (c *integrityCheck) checkDecisionEntries() error {
	bootstrap := c.trustFold.state.BootstrapSeq
	if bootstrap == 0 {
		return nil
	}
	states := map[string]toolLast{}
	w := decisionWalk{bootstrap: bootstrap, lookup: func(seq int64) (signedOutcome, bool) {
		o, ok := c.outcomes[seq]
		return o, ok
	}, lastState: func(subject string) (toolLast, bool) {
		l, ok := states[subject]
		return l, ok
	}}
	for next := int64(firstPossibleSeq); ; {
		page, err := queryAudit(c.ctx, c.q, next, auditPage)
		if err != nil {
			return err
		}
		for _, e := range page {
			if e.Seq < 1 {
				continue
			}
			w.open = c.checkDecisionEntry(e, w)
			if l, ok := leftState(e, readStateField(e.Detail)); ok {
				states[e.Subject] = l
			}
		}
		if len(page) < auditPage {
			break
		}
		next = page[len(page)-1].Seq + 1
	}
	c.noteLegacyApprovals(bootstrap)
	return nil
}

// checkDecisionEntry applies the rules to one entry and returns the decision
// transaction open after it: a verified decision.signed entry opens its own,
// a trust entry or a refused entry closes any, and every other entry is
// checkLifecycleEntry's.
func (c *integrityCheck) checkDecisionEntry(e audit.Entry, w decisionWalk) openTxn {
	if isSignedEvent(e.Event) {
		if _, ok := c.outcomes[e.Seq]; ok {
			return openTxn{seq: e.Seq}
		}
		return openTxn{}
	}
	step, err := checkLifecycleEntry(e, w)
	if err != nil {
		c.noteSignedProblem(err)
		return openTxn{}
	}
	return step.open
}

// noteLegacyApprovals lists every tool whose approval in force predates the
// bootstrap: the tool's newest entry leaves an approved digest and its newest
// version.approved or version.rolled_back entry lies below the bootstrap.
func (c *integrityCheck) noteLegacyApprovals(bootstrap int64) {
	for subject, trace := range c.latest {
		d, ok := c.latestApproval[subject]
		if trace.approved != "" && ok && d.seq < bootstrap {
			c.rep.LegacyApprovalsInService = append(c.rep.LegacyApprovalsInService, subject)
		}
	}
	slices.Sort(c.rep.LegacyApprovalsInService)
}
