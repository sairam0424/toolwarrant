package lifecycle

// DecisionMayMove reports whether one command of a person (Approve, Reject,
// Rollback, Disable or Enable, under any Policy) can move a tool from one
// state to another. It is the sibling of CrawlMayMove: the transition table of
// the five decisions, exported so that the catalog's chain walk can bind the
// state=A->B field of every entry that names a signed decision to the
// decision's kind (the v0.4 plan, section 1, rule 5). Without it a
// tool.disabled or version.superseded entry with state=disabled->enabled,
// correctly sealed by whoever can write the file and naming the token of the
// disable whose transaction is still open at the head, would pass every other
// comparison of the binding and re-enable the tool under a clean chain,
// because the state anchor takes the after half of the newest entry and never
// replays the lifecycle. The two cannot drift: the invariants check every
// step the state machine takes against this function (invariants_test.go,
// decisionViolations), so the table cannot be narrower than the machine, and
// TestDecisionMayMove_EqualsTheInvariantsTable spells it out pair by pair and
// reaches every pair it admits through the state machine itself, so it cannot
// be wider. A command this package does not define, an ObserveCrawl (whose
// table is CrawlMayMove) and a state this package does not define move
// nothing.
func DecisionMayMove(c Command, from, to State) bool {
	if !isKnownState(from) || !isKnownState(to) {
		return false
	}
	switch c.(type) {
	case Approve:
		// A pending or changed tool becomes enabled; nothing else approves.
		return (from == PendingReview || from == ChangedPendingReapproval) && to == Enabled
	case Reject:
		// A pending tool stays pending; a changed one returns to its approval.
		return (from == PendingReview && to == PendingReview) || (from == ChangedPendingReapproval && to == Enabled)
	case Rollback:
		return rollbackMayMove(from, to)
	case Disable:
		// Every state but disabled becomes disabled.
		return from != Disabled && to == Disabled
	case Enable:
		// Only disabled is left: to a fresh review, to the retained approval
		// with a proposal still pending, or to the retained approval alone.
		return from == Disabled && (to == PendingReview || to == ChangedPendingReapproval || to == Enabled)
	}
	return false
}

// rollbackMayMove is the Rollback row of the table: an enabled tool stays
// enabled, a changed one stays changed, or becomes enabled when the target is
// the pending version itself (a version approved before, proposed again by a
// crawl or by Enable, is a rollback target, and approving it leaves nothing
// pending).
func rollbackMayMove(from, to State) bool {
	switch from {
	case Enabled:
		return to == Enabled
	case ChangedPendingReapproval:
		return to == Enabled || to == ChangedPendingReapproval
	}
	return false
}
