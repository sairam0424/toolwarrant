package lifecycle

// CrawlMayMove reports whether one crawl observation (ObserveCrawl, under any
// Policy) can move a tool from one state to another; from == to is a move a
// crawl may make, since an observation that changes nothing is one. It is the
// transition table the invariants of this package pin (invariants_test.go,
// crawlViolations), exported so that the catalog's chain walk can apply it to
// every crawl-shaped audit entry appended after the trust bootstrap (the v0.4
// plan, section 1, rule 6): a tool.reverted entry with state=disabled->enabled,
// correctly sealed by whoever can write the file, would otherwise re-enable a
// disabled tool under a clean chain, because the state anchor compares the
// column with the after half of the newest entry and never replays the
// lifecycle. The two cannot drift: the property tests check every step the
// state machine takes against this function, and
// TestCrawlMayMove_EqualsTheInvariantsTable pins the table and reaches every
// pair it admits through the state machine itself. A state this package does
// not define reaches nothing and is reached from nothing.
func CrawlMayMove(from, to State) bool {
	if from == to {
		return isKnownState(from)
	}
	switch from {
	case Discovered, Deprecated:
		// A sighting of a discovered or deprecated tool proposes afresh.
		return to == PendingReview
	case PendingReview:
		// Only a miss at the deprecation threshold moves it.
		return to == Deprecated
	case Enabled:
		return to == ChangedPendingReapproval || to == Deprecated
	case ChangedPendingReapproval:
		return to == Enabled || to == Deprecated
	}
	// Disabled is left only by Enable, a person's command.
	return false
}

// isKnownState reports whether s is one of the six lifecycle states.
func isKnownState(s State) bool {
	switch s {
	case Discovered, PendingReview, Enabled, ChangedPendingReapproval, Disabled, Deprecated:
		return true
	}
	return false
}
