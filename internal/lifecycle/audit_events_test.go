package lifecycle_test

// D5: every change of LastSeen or MissingCrawls produces an event, so the
// audit log sees every flip between served and hidden. These are the
// reviewers' reproductions (catalog review, "Serving flips without any
// per-tool audit event" and "Return after missing has no event"), ported to
// the lifecycle level. Before D5 the steps marked "was silent" emitted nothing.

import (
	"testing"

	lc "github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// After a Reject the tool is enabled with LastSeen at the rejected digest.
// Each time the upstream flips between the approved and the rejected
// definition, serving flips too, and each flip must be an event.
func TestAuditEvents_FlipsAfterRejectAreEvents(t *testing.T) {
	p := plainPolicy()
	tool := step(t, newTool(), crawl(dA, alice), p)
	tool = step(t, tool, lc.Approve{Digest: dA, Actor: bob}, p)
	tool = step(t, tool, crawl(dB, crawler), p) // drift
	tool = step(t, tool, lc.Reject{Digest: dB, Actor: bob}, p)
	requireState(t, tool, lc.Enabled)
	requireServes(t, tool, tool.LastSeen, false)

	res := applyOK(t, tool, crawl(dA, crawler), p) // back to approved: hidden -> served (was silent)
	requireKinds(t, res, lc.EvReverted)
	requireServes(t, res.Tool, res.Tool.LastSeen, true)

	res = applyOK(t, res.Tool, crawl(dB, crawler), p) // back to rejected: served -> hidden (was silent)
	requireKinds(t, res, lc.EvDrifted)
	requireServes(t, res.Tool, res.Tool.LastSeen, false)
	requireState(t, res.Tool, lc.Enabled)
	if res.Tool.Pending() != "" {
		t.Errorf("a rejected digest came back as pending: %q", res.Tool.Pending())
	}

	res = applyOK(t, res.Tool, crawl(dB, crawler), p) // unchanged: nothing to report
	requireKinds(t, res)
}

// A tool missing from one crawl that comes back with the approved digest goes
// from denied to allowed; that is a returned event plus a revert event.
func TestAuditEvents_ReturnAfterMissingIsAnEvent(t *testing.T) {
	p := plainPolicy()
	tool := step(t, newTool(), crawl(dA, alice), p)
	tool = step(t, tool, lc.Approve{Digest: dA, Actor: bob}, p)
	res := applyOK(t, tool, miss(), p)
	requireKinds(t, res, lc.EvMissing)
	if res.Tool.LastSeen != "" || res.Tool.MissingCrawls != 1 {
		t.Fatalf("after miss: %+v", res.Tool)
	}

	res = applyOK(t, res.Tool, crawl(dA, crawler), p) // was silent
	requireKinds(t, res, lc.EvReturned, lc.EvReverted)
	if res.Tool.LastSeen != dA || res.Tool.MissingCrawls != 0 {
		t.Errorf("after return: %+v", res.Tool)
	}
	requireServes(t, res.Tool, dA, true)
}

// Returning with a different digest is a returned event plus whatever the
// digest means (proposal and drift, or drift alone for a rejected one).
func TestAuditEvents_ReturnWithAnotherDigest(t *testing.T) {
	p := plainPolicy()
	missed := toolOf(lc.Enabled, dA, "", 2,
		ver(dA, lc.VersionApproved, alice, true),
		ver(dB, lc.VersionRejected, bob, false))
	res := applyOK(t, missed, crawl(dC, crawler), p)
	requireKinds(t, res, lc.EvReturned, lc.EvProposed, lc.EvDrifted)
	requireState(t, res.Tool, lc.ChangedPendingReapproval)

	res = applyOK(t, missed, crawl(dB, crawler), p)
	requireKinds(t, res, lc.EvReturned, lc.EvDrifted)
	requireState(t, res.Tool, lc.Enabled)

	res = applyOK(t, missed, unusable(), p)
	requireKinds(t, res, lc.EvReturned, lc.EvUnusable)
	requireState(t, res.Tool, lc.Enabled)
}

// Spec: "EvReverted when LastSeen moves to the approved digest from anything
// else, in any state": a disabled tool and a tool with a rollback behind it
// report the revert too, although neither is served right now.
func TestAuditEvents_RevertIsReportedInEveryState(t *testing.T) {
	p := plainPolicy()
	disabled := toolOf(lc.Disabled, dA, dB, 0,
		ver(dA, lc.VersionApproved, alice, true),
		ver(dB, lc.VersionRejected, bob, false))
	res := applyOK(t, disabled, crawl(dA, crawler), p)
	requireKinds(t, res, lc.EvReverted)
	requireState(t, res.Tool, lc.Disabled)

	rolledBack := toolOf(lc.Enabled, dA, dB, 0,
		ver(dA, lc.VersionApproved, alice, true),
		ver(dB, lc.VersionSuperseded, bob, true))
	res = applyOK(t, rolledBack, crawl(dA, crawler), p)
	requireKinds(t, res, lc.EvReverted)

	// The reverse direction on the disabled tool is drift.
	res = applyOK(t, step(t, disabled, crawl(dA, crawler), p), crawl(dB, crawler), p)
	requireKinds(t, res, lc.EvDrifted)
}

// Spec: "EvDrifted when LastSeen moves to a rejected or already pending digest
// (Approved may be empty)": an unapproved tool whose upstream changes between
// its pending digest and nothing is audited too.
func TestAuditEvents_DriftIsReportedWithoutAnApproval(t *testing.T) {
	p := plainPolicy()
	pending := toolOf(lc.PendingReview, "", "", 1, ver(dA, lc.VersionPending, alice, false))
	res := applyOK(t, pending, crawl(dA, crawler), p)
	requireKinds(t, res, lc.EvReturned, lc.EvDrifted)

	rejected := toolOf(lc.PendingReview, "", "", 0, ver(dA, lc.VersionRejected, alice, false))
	res = applyOK(t, rejected, crawl(dA, crawler), p)
	requireKinds(t, res, lc.EvDrifted)

	// The same digest again: unchanged, silent.
	res = applyOK(t, res.Tool, crawl(dA, crawler), p)
	requireKinds(t, res)
}

// Spec: "a reappearance emits no drift or revert event" but does report the
// return from missing.
func TestAuditEvents_ReappearanceReportsReturnNotDrift(t *testing.T) {
	deprecated := toolOf(lc.Deprecated, dA, "", 3, ver(dA, lc.VersionApproved, alice, true))
	res := applyOK(t, deprecated, crawl(dA, carol), plainPolicy())
	requireKinds(t, res, lc.EvReturned, lc.EvReappeared, lc.EvSuperseded, lc.EvProposed)
	res = applyOK(t, deprecated, crawl(dB, carol), plainPolicy())
	requireKinds(t, res, lc.EvReturned, lc.EvReappeared, lc.EvSuperseded, lc.EvProposed)
}

// Every ObserveCrawl that changes LastSeen or MissingCrawls emits at least one
// event, and one that changes neither emits none: checked over every fixture
// and every observation the tables use.
func TestAuditEvents_EveryVisibleChangeHasAnEventAndNoChangeHasNone(t *testing.T) {
	cmds := []lc.ObserveCrawl{crawl(dA, carol), crawl(dB, carol), crawl(dC, carol), unusable(), miss()}
	for name, start := range fixtureTools() {
		for _, cmd := range cmds {
			res := applyOK(t, start, cmd, plainPolicy())
			changed := res.Tool.LastSeen != start.LastSeen || res.Tool.MissingCrawls != start.MissingCrawls
			if changed && len(res.Events) == 0 {
				t.Errorf("%s %+v: LastSeen %q->%q MissingCrawls %d->%d with no event", name, cmd,
					start.LastSeen, res.Tool.LastSeen, start.MissingCrawls, res.Tool.MissingCrawls)
			}
			if sameTool(res.Tool, start) && len(res.Events) != 0 {
				t.Errorf("%s %+v: nothing changed but events %+v were emitted", name, cmd, res.Events)
			}
		}
	}
}
