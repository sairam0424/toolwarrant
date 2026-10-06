package lifecycle_test

// The unusable observation (D3): the upstream lists the tool, but its
// definition is invalid or its name appears twice, so there is nothing to
// propose and nothing may be served.
//
// Spec: "Unusable (Present must be true and Digest empty, else
// ErrInvalidObservation): LastSeen = UnusableDigest, MissingCrawls = 0,
// nothing else changes."

import (
	"testing"

	lc "github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// unusableFixtures covers every state with a plausible layout.
func unusableFixtures() map[string]lc.Tool {
	return map[string]lc.Tool{
		"discovered":          newTool(),
		"pending":             pendingReviewTool(dA, alice),
		"pending-missing":     toolOf(lc.PendingReview, "", "", 2, ver(dA, lc.VersionPending, alice, false)),
		"enabled":             enabledTool(dA),
		"enabled-missing":     toolOf(lc.Enabled, dA, "", 1, ver(dA, lc.VersionApproved, alice, true)),
		"enabled-rejected":    toolOf(lc.Enabled, dA, dB, 0, ver(dA, lc.VersionApproved, alice, true), ver(dB, lc.VersionRejected, bob, false)),
		"changed":             changedTool(dA, dB, bob),
		"disabled-approved":   toolOf(lc.Disabled, dA, dA, 0, ver(dA, lc.VersionApproved, alice, true)),
		"disabled-unapproved": toolOf(lc.Disabled, "", dA, 0, ver(dA, lc.VersionPending, alice, false)),
		"deprecated":          toolOf(lc.Deprecated, dA, "", 3, ver(dA, lc.VersionApproved, alice, true)),
	}
}

// Serves is a function of the live digest handed to it: the marker never
// matches, so the tool is hidden as long as the upstream serves the unusable
// definition, while the approval itself stands (Serves(approved) stays true,
// exactly as wantServes says).
func TestObserveUnusable_MarksLastSeenAndChangesNothingElse(t *testing.T) {
	for name, start := range unusableFixtures() {
		t.Run(name, func(t *testing.T) {
			res := applyOK(t, start, unusable(), plainPolicy())
			want := cloneTool(start)
			want.LastSeen, want.MissingCrawls = lc.UnusableDigest, 0
			if !sameTool(res.Tool, want) {
				t.Errorf("tool mismatch\n got: %+v\nwant: %+v", res.Tool, want)
			}
			kinds := []lc.EventKind{lc.EvUnusable}
			if start.MissingCrawls > 0 {
				kinds = append(kinds, lc.EvReturned)
			}
			requireKinds(t, res, kinds...)
			requireServes(t, res.Tool, res.Tool.LastSeen, false)
			requireServes(t, res.Tool, lc.UnusableDigest, false)
			requireServes(t, res.Tool, "", false)
			for _, live := range []string{dA, dB} {
				requireServes(t, res.Tool, live, wantServes(res.Tool.State, res.Tool.Approved, live))
			}
			if res.Tool.Drifted() != (start.Approved != "") {
				t.Errorf("Drifted() = %v after an unusable sighting with approved %q", res.Tool.Drifted(), start.Approved)
			}
		})
	}
}

// Spec: "An observation that changes nothing ... emits nothing."
func TestObserveUnusable_RepeatedSightingIsUneventful(t *testing.T) {
	for name, start := range unusableFixtures() {
		t.Run(name, func(t *testing.T) {
			first := step(t, start, unusable(), plainPolicy())
			res := applyOK(t, first, unusable(), plainPolicy())
			if !sameTool(res.Tool, first) {
				t.Errorf("second unusable sighting changed the tool: %+v -> %+v", first, res.Tool)
			}
			requireKinds(t, res)
		})
	}
}

// Spec: a real digest after an unusable one "proceeds as usual": the approved
// digest reverts, anything else is proposed or recorded as drift.
func TestObserveUnusable_ThenRealDigest(t *testing.T) {
	p := plainPolicy()
	tool := step(t, enabledTool(dA), unusable(), p)
	requireState(t, tool, lc.Enabled)
	requireServes(t, tool, dA, true) // the approval stands; only the live definition is unusable
	if !tool.Drifted() {
		t.Error("an unusable live definition must read as drift")
	}

	res := applyOK(t, tool, crawl(dA, bob), p)
	requireKinds(t, res, lc.EvReverted)
	if res.Tool.LastSeen != dA || res.Tool.Drifted() {
		t.Errorf("after the approved digest returned: %+v", res.Tool)
	}

	tool = step(t, res.Tool, unusable(), p)
	res = applyOK(t, tool, crawl(dB, bob), p)
	requireState(t, res.Tool, lc.ChangedPendingReapproval)
	requireKinds(t, res, lc.EvProposed, lc.EvDrifted)
	if res.Tool.Pending() != dB {
		t.Errorf("pending = %q, want %q", res.Tool.Pending(), dB)
	}

	// Unusable while a proposal is pending, then the pending digest again:
	// drift is recorded, the proposal is untouched.
	tool = step(t, res.Tool, unusable(), p)
	res = applyOK(t, tool, crawl(dB, carol), p)
	requireKinds(t, res, lc.EvDrifted)
	if res.Tool.Pending() != dB || len(res.Tool.Versions) != 2 {
		t.Errorf("after re-sighting the pending digest: %+v", res.Tool)
	}
}

// A pending tool whose definition turns unusable keeps its proposal; the
// person reviewing it still sees exactly what was proposed.
func TestObserveUnusable_KeepsThePendingProposal(t *testing.T) {
	tool := step(t, pendingReviewTool(dA, alice), unusable(), plainPolicy())
	if tool.Pending() != dA {
		t.Fatalf("pending = %q", tool.Pending())
	}
	approved := step(t, tool, lc.Approve{Digest: dA, Actor: bob}, plainPolicy())
	requireState(t, approved, lc.Enabled)
	requireServes(t, approved, lc.UnusableDigest, false)
	requireServes(t, approved, dA, true)
	if !approved.Drifted() {
		t.Error("approved while the upstream serves an unusable definition: must read as drifted")
	}
}

// A discovered tool whose first sighting is unusable stays discovered with the
// marker; its first real digest then discovers it as usual.
func TestObserveUnusable_DiscoveredToolStaysDiscovered(t *testing.T) {
	p := plainPolicy()
	res := applyOK(t, newTool(), unusable(), p)
	requireState(t, res.Tool, lc.Discovered)
	requireKinds(t, res, lc.EvUnusable)
	if len(res.Tool.Versions) != 0 || res.Tool.LastSeen != lc.UnusableDigest {
		t.Fatalf("after an unusable first sighting: %+v", res.Tool)
	}
	res = applyOK(t, res.Tool, crawl(dA, alice), p)
	requireState(t, res.Tool, lc.PendingReview)
	requireKinds(t, res, lc.EvDiscovered, lc.EvProposed)
	res = applyOK(t, step(t, newTool(), unusable(), p), miss(), p)
	requireKinds(t, res, lc.EvMissing)
	if !sameTool(res.Tool, newTool()) {
		t.Errorf("a miss must only clear the marker: %+v", res.Tool)
	}
}

// Spec: "Unusable (Present must be true and Digest empty, else
// ErrInvalidObservation)" and "Digest ... must not be UnusableDigest".
func TestObserve_ContradictoryObservationsAreRefused(t *testing.T) {
	for name, start := range unusableFixtures() {
		runErrCases(t, []errCase{
			{name + "/unusable but not present", start, lc.ObserveCrawl{Unusable: true, Actor: crawler}, plainPolicy(), lc.ErrInvalidObservation},
			{name + "/unusable with a digest", start, lc.ObserveCrawl{Present: true, Unusable: true, Digest: dA, Actor: crawler}, plainPolicy(), lc.ErrInvalidObservation},
			{name + "/marker passed as a digest", start, crawl(lc.UnusableDigest, crawler), plainPolicy(), lc.ErrInvalidObservation},
			{name + "/unusable without an actor", start, lc.ObserveCrawl{Present: true, Unusable: true}, plainPolicy(), lc.ErrNoActor},
		})
	}
}

// A digest on a non-present observation is ignored, the marker included: the
// absence is the whole message.
func TestObserve_MarkerOnAMissingObservationIsIgnored(t *testing.T) {
	got := applyOK(t, enabledTool(dA), lc.ObserveCrawl{Present: false, Digest: lc.UnusableDigest, Actor: crawler}, plainPolicy()).Tool
	want := toolOf(lc.Enabled, dA, "", 1, ver(dA, lc.VersionApproved, alice, true))
	if !sameTool(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

// UnusableDigest is a marker, so it must never look like a digest to anyone
// who stores or compares digests.
func TestUnusableDigest_IsNotAHexDigest(t *testing.T) {
	if lc.UnusableDigest == "" || len(lc.UnusableDigest) == 64 {
		t.Fatalf("UnusableDigest = %q must be non-empty and not 64 characters", lc.UnusableDigest)
	}
	for _, c := range lc.UnusableDigest {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			continue
		}
		return // at least one non-hex character: can never collide with a digest
	}
	t.Fatalf("UnusableDigest %q is made of hex digits only", lc.UnusableDigest)
}
