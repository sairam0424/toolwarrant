package lifecycle_test

// Two rule sets checked on every random step:
//
//   - D5, from the ObserveCrawl doc comment: every change of LastSeen or
//     MissingCrawls comes with an event, an unchanged observation emits
//     nothing, and each observation event is emitted exactly when its rule
//     says so.
//   - D4, from the Version doc comment: ProposedBy is set once and never
//     changes, Proposers only grows and keeps its order, its head is
//     ProposedBy, and the only thing that adds a proposer is a crawl that
//     proposes the version, adding its own actor.

import (
	"fmt"
	"slices"

	lc "github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// proposerHistory is the list a version is protected by: the recorded list,
// or ProposedBy alone for a version stored before the list existed.
func proposerHistory(v lc.Version) []string {
	if all := v.Proposers.All(); len(all) > 0 {
		return all
	}
	if v.ProposedBy != "" {
		return []string{v.ProposedBy}
	}
	return nil
}

// proposerViolations covers D4 for one version that existed before the step.
func proposerViolations(rec stepRecord, old, nw lc.Version) []string {
	var out []string
	if old.ProposedBy != "" && nw.ProposedBy != old.ProposedBy {
		out = append(out, fmt.Sprintf("ProposedBy of %s changed %q -> %q", old.Digest, old.ProposedBy, nw.ProposedBy))
	}
	oldP, newP := proposerHistory(old), nw.Proposers.All()
	if len(newP) < len(oldP) || !slices.Equal(newP[:len(oldP)], oldP) {
		return append(out, fmt.Sprintf("proposers of %s shrank or were reordered: %v -> %v", old.Digest, oldP, newP))
	}
	if len(newP) > 0 && nw.ProposedBy != newP[0] {
		out = append(out, fmt.Sprintf("ProposedBy %q of %s is not the first proposer %v", nw.ProposedBy, nw.Digest, newP))
	}
	added := newP[len(oldP):]
	if len(added) == 0 {
		return out
	}
	c, isCrawl := rec.cmd.(lc.ObserveCrawl)
	proposedNow := isCrawl && c.Present && !c.Unusable && c.Digest == nw.Digest && nw.Status == lc.VersionPending
	if len(added) > 1 || !proposedNow || added[0] != c.Actor {
		out = append(out, fmt.Sprintf("proposers %v added to %s by %T %+v", added, nw.Digest, rec.cmd, rec.cmd))
	}
	return out
}

// eventViolations covers D5 for an ObserveCrawl step.
func eventViolations(rec stepRecord) []string {
	c, ok := rec.cmd.(lc.ObserveCrawl)
	if !ok {
		return nil
	}
	before, after := rec.before, rec.res.Tool
	var out []string
	changed := before.LastSeen != after.LastSeen || before.MissingCrawls != after.MissingCrawls
	if changed && len(rec.res.Events) == 0 {
		out = append(out, "LastSeen or MissingCrawls changed without an event")
	}
	if sameTool(before, after) && len(rec.res.Events) != 0 {
		out = append(out, fmt.Sprintf("nothing changed but events %+v were emitted", rec.res.Events))
	}
	for kind, want := range expectedObservationEvents(c, before, after) {
		n := countKind(rec.res.Events, kind)
		switch {
		case n > 1:
			out = append(out, fmt.Sprintf("%s emitted %d times", kind, n))
		case (n == 1) != want:
			out = append(out, fmt.Sprintf("%s emitted=%v, want %v", kind, n == 1, want))
		}
	}
	return out
}

func countKind(events []lc.Event, kind lc.EventKind) int {
	n := 0
	for _, e := range events {
		if e.Kind == kind {
			n++
		}
	}
	return n
}

// expectedObservationEvents states, per event kind, whether the step must
// emit it, straight from the "Events" list on ObserveCrawl.
func expectedObservationEvents(c lc.ObserveCrawl, before, after lc.Tool) map[lc.EventKind]bool {
	sighting := c.Present && !c.Unusable
	deprecatedNow := after.State == lc.Deprecated && before.State != lc.Deprecated
	changed := before.LastSeen != after.LastSeen || before.MissingCrawls != after.MissingCrawls
	return map[lc.EventKind]bool{
		lc.EvReturned:   before.MissingCrawls > 0 && after.MissingCrawls == 0,
		lc.EvUnusable:   after.LastSeen == lc.UnusableDigest && before.LastSeen != lc.UnusableDigest,
		lc.EvDeprecated: deprecatedNow,
		lc.EvMissing:    !c.Present && changed && !deprecatedNow,
		lc.EvReappeared: sighting && before.State == lc.Deprecated,
		lc.EvReverted: sighting && after.Approved != "" && c.Digest == after.Approved &&
			(before.LastSeen != c.Digest || before.State == lc.ChangedPendingReapproval),
		lc.EvDrifted: driftExpected(c, before, after),
	}
}

// driftExpected: "EvDrifted when LastSeen moves to a digest other than the
// approved one ... and whenever enabled becomes changed_pending_reapproval",
// except for the first sighting of a discovered tool and a reappearance.
func driftExpected(c lc.ObserveCrawl, before, after lc.Tool) bool {
	if !c.Present || c.Unusable || before.State == lc.Discovered || before.State == lc.Deprecated {
		return false
	}
	if c.Digest == before.Approved {
		return false
	}
	return before.LastSeen != c.Digest || (before.State == lc.Enabled && after.State == lc.ChangedPendingReapproval)
}
