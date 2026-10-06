package lifecycle_test

// ObserveCrawl tables for sightings and misses. Every expectation is derived
// from the specification sentence quoted next to the case group. The unusable
// observation has its own file (unusable_test.go), as do the event rules
// (audit_events_test.go, events_test.go).

import (
	"testing"

	lc "github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// Spec: "Present with Digest d: LastSeen = d, MissingCrawls = 0 ... any other
// d is proposed ... a discovered tool becomes pending_review and an enabled
// tool becomes changed_pending_reapproval."
func TestObservePresent_ProposesUnknownDigest(t *testing.T) {
	p := plainPolicy()
	runApplyCases(t, []applyCase{
		{
			name:  "discovered first crawl proposes and moves to pending_review",
			start: newTool(),
			cmd:   crawl(dA, alice),
			pol:   p,
			want:  toolOf(lc.PendingReview, "", dA, 0, ver(dA, lc.VersionPending, alice, false)),
		},
		{
			name:  "pending_review new digest supersedes the old proposal",
			start: pendingReviewTool(dA, alice),
			cmd:   crawl(dB, bob),
			pol:   p,
			want: toolOf(lc.PendingReview, "", dB, 0,
				ver(dA, lc.VersionSuperseded, alice, false),
				ver(dB, lc.VersionPending, bob, false)),
		},
		{
			name:  "pending_review rejected digest stays rejected when a new one arrives",
			start: toolOf(lc.PendingReview, "", dA, 0, ver(dA, lc.VersionRejected, alice, false)),
			cmd:   crawl(dB, bob),
			pol:   p,
			want: toolOf(lc.PendingReview, "", dB, 0,
				ver(dA, lc.VersionRejected, alice, false),
				ver(dB, lc.VersionPending, bob, false)),
		},
		{
			name:  "enabled new digest becomes changed_pending_reapproval and approval is kept",
			start: enabledTool(dA),
			cmd:   crawl(dB, bob),
			pol:   p,
			want: toolOf(lc.ChangedPendingReapproval, dA, dB, 0,
				ver(dA, lc.VersionApproved, alice, true),
				ver(dB, lc.VersionPending, bob, false)),
		},
		{
			name:  "changed_pending_reapproval newer digest replaces the pending proposal",
			start: changedTool(dA, dB, bob),
			cmd:   crawl(dC, carol),
			pol:   p,
			want: toolOf(lc.ChangedPendingReapproval, dA, dC, 0,
				ver(dA, lc.VersionApproved, alice, true),
				ver(dB, lc.VersionSuperseded, bob, false),
				ver(dC, lc.VersionPending, carol, false)),
		},
	})
}

// Spec: "a superseded version is reused, keeping EverApproved and adding Actor
// to its proposers" and (D4) "ProposedBy ... is set once and never changes".
// Before D4 these rows expected ProposedBy to become the new actor.
func TestObservePresent_ReusesKnownSupersededVersion(t *testing.T) {
	p := plainPolicy()
	runApplyCases(t, []applyCase{
		{
			name: "previously approved superseded digest comes back as a proposal with a second proposer",
			start: toolOf(lc.Enabled, dB, dB, 0,
				ver(dA, lc.VersionSuperseded, alice, true),
				ver(dB, lc.VersionApproved, bob, true)),
			cmd: crawl(dA, carol),
			pol: p,
			want: toolOf(lc.ChangedPendingReapproval, dB, dA, 0,
				verP(dA, lc.VersionPending, alice, true, alice, carol),
				ver(dB, lc.VersionApproved, bob, true)),
		},
		{
			name: "never-approved superseded digest is reused and stays never-approved",
			start: toolOf(lc.Enabled, dB, dB, 0,
				ver(dA, lc.VersionSuperseded, alice, false),
				ver(dB, lc.VersionApproved, bob, true)),
			cmd: crawl(dA, carol),
			pol: p,
			want: toolOf(lc.ChangedPendingReapproval, dB, dA, 0,
				verP(dA, lc.VersionPending, alice, false, alice, carol),
				ver(dB, lc.VersionApproved, bob, true)),
		},
		{
			name: "reusing a superseded digest supersedes the current pending one; a known proposer is not repeated",
			start: toolOf(lc.ChangedPendingReapproval, dB, dC, 0,
				ver(dA, lc.VersionSuperseded, alice, true),
				ver(dB, lc.VersionApproved, bob, true),
				ver(dC, lc.VersionPending, carol, false)),
			cmd: crawl(dA, alice),
			pol: p,
			want: toolOf(lc.ChangedPendingReapproval, dB, dA, 0,
				ver(dA, lc.VersionPending, alice, true),
				ver(dB, lc.VersionApproved, bob, true),
				ver(dC, lc.VersionSuperseded, carol, false)),
		},
		{
			name: "pending_review reuses a superseded digest",
			start: toolOf(lc.PendingReview, "", dB, 0,
				ver(dA, lc.VersionSuperseded, alice, false),
				ver(dB, lc.VersionPending, bob, false)),
			cmd: crawl(dA, carol),
			pol: p,
			want: toolOf(lc.PendingReview, "", dA, 0,
				verP(dA, lc.VersionPending, alice, false, alice, carol),
				ver(dB, lc.VersionSuperseded, bob, false)),
		},
		{
			name: "a third proposer is appended after the second",
			start: toolOf(lc.PendingReview, "", dB, 0,
				verP(dA, lc.VersionSuperseded, alice, false, alice, bob),
				ver(dB, lc.VersionPending, bob, false)),
			cmd: crawl(dA, carol),
			pol: p,
			want: toolOf(lc.PendingReview, "", dA, 0,
				verP(dA, lc.VersionPending, alice, false, alice, bob, carol),
				ver(dB, lc.VersionSuperseded, bob, false)),
		},
		{
			name: "a version stored without its proposer list is protected through ProposedBy",
			start: toolOf(lc.PendingReview, "", dB, 0,
				lc.Version{Digest: dA, Status: lc.VersionSuperseded, ProposedBy: alice},
				ver(dB, lc.VersionPending, bob, false)),
			cmd: crawl(dA, carol),
			pol: p,
			want: toolOf(lc.PendingReview, "", dA, 0,
				verP(dA, lc.VersionPending, alice, false, alice, carol),
				ver(dB, lc.VersionSuperseded, bob, false)),
		},
	})
}

// Spec: "if d is the approved digest, a changed_pending_reapproval tool goes
// back to enabled and its pending proposal is superseded".
func TestObservePresent_ApprovedDigest(t *testing.T) {
	p := plainPolicy()
	runApplyCases(t, []applyCase{
		{
			name:  "enabled same digest only refreshes LastSeen and the miss counter",
			start: toolOf(lc.Enabled, dA, "", 2, ver(dA, lc.VersionApproved, alice, true)),
			cmd:   crawl(dA, bob),
			pol:   p,
			want:  toolOf(lc.Enabled, dA, dA, 0, ver(dA, lc.VersionApproved, alice, true)),
		},
		{
			name:  "changed_pending_reapproval revert supersedes the pending proposal",
			start: changedTool(dA, dB, bob),
			cmd:   crawl(dA, carol),
			pol:   p,
			want: toolOf(lc.Enabled, dA, dA, 0,
				ver(dA, lc.VersionApproved, alice, true),
				ver(dB, lc.VersionSuperseded, bob, false)),
		},
		{
			name: "disabled tool crawled at its approved digest changes nothing but LastSeen",
			start: toolOf(lc.Disabled, dA, dB, 1,
				ver(dA, lc.VersionApproved, alice, true),
				ver(dB, lc.VersionPending, bob, false)),
			cmd: crawl(dA, carol),
			pol: p,
			want: toolOf(lc.Disabled, dA, dA, 0,
				ver(dA, lc.VersionApproved, alice, true),
				ver(dB, lc.VersionPending, bob, false)),
		},
	})
}

// Spec: "if d is a rejected or already pending version nothing else changes".
func TestObservePresent_KnownRejectedOrPending(t *testing.T) {
	p := plainPolicy()
	runApplyCases(t, []applyCase{
		{
			name:  "pending_review known pending digest keeps its proposer",
			start: toolOf(lc.PendingReview, "", "", 2, ver(dA, lc.VersionPending, alice, false)),
			cmd:   crawl(dA, bob),
			pol:   p,
			want:  toolOf(lc.PendingReview, "", dA, 0, ver(dA, lc.VersionPending, alice, false)),
		},
		{
			name:  "pending_review rejected digest is not re-proposed",
			start: toolOf(lc.PendingReview, "", "", 0, ver(dA, lc.VersionRejected, alice, false)),
			cmd:   crawl(dA, bob),
			pol:   p,
			want:  toolOf(lc.PendingReview, "", dA, 0, ver(dA, lc.VersionRejected, alice, false)),
		},
		{
			name: "enabled upstream serving a rejected digest records drift without a proposal",
			start: toolOf(lc.Enabled, dA, dA, 0,
				ver(dA, lc.VersionApproved, alice, true),
				ver(dB, lc.VersionRejected, bob, false)),
			cmd: crawl(dB, carol),
			pol: p,
			want: toolOf(lc.Enabled, dA, dB, 0,
				ver(dA, lc.VersionApproved, alice, true),
				ver(dB, lc.VersionRejected, bob, false)),
		},
		{
			name:  "changed_pending_reapproval known pending digest changes nothing",
			start: changedTool(dA, dB, bob),
			cmd:   crawl(dB, carol),
			pol:   p,
			want:  changedTool(dA, dB, bob),
		},
		{
			name: "changed_pending_reapproval crawl of a rejected digest keeps the other proposal pending",
			start: toolOf(lc.ChangedPendingReapproval, dA, dC, 0,
				ver(dA, lc.VersionApproved, alice, true),
				ver(dB, lc.VersionRejected, bob, false),
				ver(dC, lc.VersionPending, carol, false)),
			cmd: crawl(dB, alice),
			pol: p,
			want: toolOf(lc.ChangedPendingReapproval, dA, dB, 0,
				ver(dA, lc.VersionApproved, alice, true),
				ver(dB, lc.VersionRejected, bob, false),
				ver(dC, lc.VersionPending, carol, false)),
		},
	})
}

// Spec: a disabled tool records what the upstream does but stays disabled.
func TestObservePresent_DisabledToolStaysDisabled(t *testing.T) {
	p := plainPolicy()
	runApplyCases(t, []applyCase{
		{
			name:  "disabled with approval records a proposal but stays disabled",
			start: toolOf(lc.Disabled, dA, dA, 0, ver(dA, lc.VersionApproved, alice, true)),
			cmd:   crawl(dB, bob),
			pol:   p,
			want: toolOf(lc.Disabled, dA, dB, 0,
				ver(dA, lc.VersionApproved, alice, true),
				ver(dB, lc.VersionPending, bob, false)),
		},
		{
			name:  "disabled without approval records a proposal but stays disabled",
			start: toolOf(lc.Disabled, "", "", 0),
			cmd:   crawl(dA, bob),
			pol:   p,
			want:  toolOf(lc.Disabled, "", dA, 0, ver(dA, lc.VersionPending, bob, false)),
		},
	})
}

// Spec: "A deprecated tool reappears: the approval is retired, the state
// becomes pending_review and d is proposed unless it was rejected."
func TestObservePresent_DeprecatedToolReappears(t *testing.T) {
	p := plainPolicy()
	runApplyCases(t, []applyCase{
		{
			name:  "same digest as the retired approval is proposed afresh and gains the crawler as a proposer",
			start: toolOf(lc.Deprecated, dA, "", 3, ver(dA, lc.VersionApproved, alice, true)),
			cmd:   crawl(dA, carol),
			pol:   p,
			want:  toolOf(lc.PendingReview, "", dA, 0, verP(dA, lc.VersionPending, alice, true, alice, carol)),
		},
		{
			name:  "different digest: approval retired and the new digest proposed",
			start: toolOf(lc.Deprecated, dA, "", 3, ver(dA, lc.VersionApproved, alice, true)),
			cmd:   crawl(dB, carol),
			pol:   p,
			want: toolOf(lc.PendingReview, "", dB, 0,
				ver(dA, lc.VersionSuperseded, alice, true),
				ver(dB, lc.VersionPending, carol, false)),
		},
		{
			name:  "rejected digest: approval retired but nothing is proposed",
			start: toolOf(lc.Deprecated, dA, "", 3, ver(dA, lc.VersionApproved, alice, true), ver(dB, lc.VersionRejected, bob, false)),
			cmd:   crawl(dB, carol),
			pol:   p,
			want: toolOf(lc.PendingReview, "", dB, 0,
				ver(dA, lc.VersionSuperseded, alice, true),
				ver(dB, lc.VersionRejected, bob, false)),
		},
		{
			name:  "deprecated tool that never had an approval is proposed",
			start: toolOf(lc.Deprecated, "", "", 3, ver(dA, lc.VersionSuperseded, alice, false)),
			cmd:   crawl(dB, carol),
			pol:   p,
			want: toolOf(lc.PendingReview, "", dB, 0,
				ver(dA, lc.VersionSuperseded, alice, false),
				ver(dB, lc.VersionPending, carol, false)),
		},
		{
			name: "a stale pending proposal is superseded so the new one is the single pending version",
			start: toolOf(lc.Deprecated, dA, "", 3,
				ver(dA, lc.VersionApproved, alice, true),
				ver(dB, lc.VersionPending, bob, false)),
			cmd: crawl(dC, carol),
			pol: p,
			want: toolOf(lc.PendingReview, "", dC, 0,
				ver(dA, lc.VersionSuperseded, alice, true),
				ver(dB, lc.VersionSuperseded, bob, false),
				ver(dC, lc.VersionPending, carol, false)),
		},
		{
			name:  "reappearing from an unusable marker works like reappearing from absence",
			start: toolOf(lc.Deprecated, dA, lc.UnusableDigest, 0, ver(dA, lc.VersionApproved, alice, true)),
			cmd:   crawl(dB, carol),
			pol:   p,
			want: toolOf(lc.PendingReview, "", dB, 0,
				ver(dA, lc.VersionSuperseded, alice, true),
				ver(dB, lc.VersionPending, carol, false)),
		},
	})
}

// Spec: "A crawl (ObserveCrawl) never approves anything." Exhaustive over
// state fixtures and crawled digests, including the unusable observation.
func TestObservePresent_NeverApproves(t *testing.T) {
	fixtures := map[string]lc.Tool{
		"discovered": newTool(),
		"pending":    pendingReviewTool(dA, alice),
		"enabled":    enabledTool(dA),
		"changed":    changedTool(dA, dB, bob),
		"disabled":   toolOf(lc.Disabled, dA, dA, 0, ver(dA, lc.VersionApproved, alice, true)),
		"deprecated": toolOf(lc.Deprecated, dA, "", 3, ver(dA, lc.VersionApproved, alice, true)),
		"superseded-known": toolOf(lc.Enabled, dB, dB, 0,
			ver(dA, lc.VersionSuperseded, alice, true), ver(dB, lc.VersionApproved, bob, true)),
	}
	cmds := []lc.ObserveCrawl{crawl(dA, carol), crawl(dB, carol), crawl(dC, carol), crawl(dD, carol), unusable()}
	for name, start := range fixtures {
		for _, cmd := range cmds {
			got := applyOK(t, start, cmd, plainPolicy())
			for _, v := range got.Tool.Versions {
				wasApproved := false
				for _, old := range start.Versions {
					if old.Digest == v.Digest && old.Status == lc.VersionApproved {
						wasApproved = true
					}
				}
				if v.Status == lc.VersionApproved && !wasApproved {
					t.Errorf("%s %+v: version %s became approved by a crawl", name, cmd, v.Digest)
				}
			}
			if got.Tool.Approved != start.Approved && (start.State != lc.Deprecated || got.Tool.Approved != "") {
				t.Errorf("%s %+v: Approved changed from %q to %q", name, cmd, start.Approved, got.Tool.Approved)
			}
			if hasEvent(got, lc.EvApproved, "") || hasEvent(got, lc.EvRolledBack, "") {
				t.Errorf("%s %+v: a crawl emitted an approval event: %+v", name, cmd, got.Events)
			}
		}
	}
}

// Spec: "Not present: a discovered or deprecated tool only loses an unusable
// marker".
func TestObserveMissing_DiscoveredAndDeprecatedOnlyLoseTheUnusableMarker(t *testing.T) {
	p := plainPolicy()
	runApplyCases(t, []applyCase{
		{
			name:  "discovered",
			start: newTool(),
			cmd:   miss(),
			pol:   p,
			want:  newTool(),
		},
		{
			name:  "deprecated keeps its counter and does not grow it",
			start: toolOf(lc.Deprecated, dA, "", 3, ver(dA, lc.VersionApproved, alice, true)),
			cmd:   miss(),
			pol:   p,
			want:  toolOf(lc.Deprecated, dA, "", 3, ver(dA, lc.VersionApproved, alice, true)),
		},
		{
			name:  "discovered with an unusable marker loses it and nothing else",
			start: toolOf(lc.Discovered, "", lc.UnusableDigest, 0),
			cmd:   miss(),
			pol:   p,
			want:  newTool(),
		},
		{
			name:  "deprecated with an unusable marker loses it and keeps its counter",
			start: toolOf(lc.Deprecated, dA, lc.UnusableDigest, 0, ver(dA, lc.VersionApproved, alice, true)),
			cmd:   miss(),
			pol:   p,
			want:  toolOf(lc.Deprecated, dA, "", 0, ver(dA, lc.VersionApproved, alice, true)),
		},
	})
	res := applyOK(t, toolOf(lc.Deprecated, dA, lc.UnusableDigest, 0, ver(dA, lc.VersionApproved, alice, true)), miss(), p)
	requireKinds(t, res, lc.EvMissing)
	res = applyOK(t, toolOf(lc.Deprecated, dA, "", 3, ver(dA, lc.VersionApproved, alice, true)), miss(), p)
	requireKinds(t, res)
}

// Spec: "any other tool gets LastSeen = "" and MissingCrawls + 1".
func TestObserveMissing_ClearsLastSeenAndCounts(t *testing.T) {
	p := plainPolicy()
	runApplyCases(t, []applyCase{
		{
			name:  "enabled",
			start: enabledTool(dA),
			cmd:   miss(),
			pol:   p,
			want:  toolOf(lc.Enabled, dA, "", 1, ver(dA, lc.VersionApproved, alice, true)),
		},
		{
			name:  "pending_review",
			start: pendingReviewTool(dA, alice),
			cmd:   miss(),
			pol:   p,
			want:  toolOf(lc.PendingReview, "", "", 1, ver(dA, lc.VersionPending, alice, false)),
		},
		{
			name:  "changed_pending_reapproval keeps the proposal",
			start: changedTool(dA, dB, bob),
			cmd:   miss(),
			pol:   p,
			want: toolOf(lc.ChangedPendingReapproval, dA, "", 1,
				ver(dA, lc.VersionApproved, alice, true),
				ver(dB, lc.VersionPending, bob, false)),
		},
		{
			name:  "counter increments from a non-zero value",
			start: toolOf(lc.Enabled, dA, "", 1, ver(dA, lc.VersionApproved, alice, true)),
			cmd:   miss(),
			pol:   p,
			want:  toolOf(lc.Enabled, dA, "", 2, ver(dA, lc.VersionApproved, alice, true)),
		},
		{
			name:  "a digest on a non-present observation is ignored",
			start: enabledTool(dA),
			cmd:   lc.ObserveCrawl{Present: false, Digest: dB, Actor: crawler},
			pol:   p,
			want:  toolOf(lc.Enabled, dA, "", 1, ver(dA, lc.VersionApproved, alice, true)),
		},
		{
			name:  "an unusable marker is cleared like a digest",
			start: toolOf(lc.Enabled, dA, lc.UnusableDigest, 0, ver(dA, lc.VersionApproved, alice, true)),
			cmd:   miss(),
			pol:   p,
			want:  toolOf(lc.Enabled, dA, "", 1, ver(dA, lc.VersionApproved, alice, true)),
		},
	})
}

// Spec: "deprecated when the count reaches Policy.DeprecateAfter (when > 0),
// unless it is disabled".
func TestObserveMissing_DeprecatesWhenThresholdReached(t *testing.T) {
	for _, state := range []lc.State{lc.PendingReview, lc.Enabled, lc.ChangedPendingReapproval} {
		t.Run(string(state), func(t *testing.T) {
			tool := toolForState(state)
			p := plainPolicy()
			for i := 1; i < deprecateAfterThree; i++ {
				tool = step(t, tool, miss(), p)
				requireState(t, tool, state)
				if tool.MissingCrawls != i {
					t.Fatalf("after miss %d MissingCrawls = %d", i, tool.MissingCrawls)
				}
			}
			tool = step(t, tool, miss(), p)
			requireState(t, tool, lc.Deprecated)
			if tool.MissingCrawls != deprecateAfterThree {
				t.Errorf("MissingCrawls = %d, want %d", tool.MissingCrawls, deprecateAfterThree)
			}
		})
	}
}

func TestObserveMissing_ThresholdOfOneDeprecatesImmediately(t *testing.T) {
	got := step(t, enabledTool(dA), miss(), lc.Policy{DeprecateAfter: 1})
	requireState(t, got, lc.Deprecated)
}

func TestObserveMissing_NonPositiveThresholdNeverDeprecates(t *testing.T) {
	for _, after := range []int{0, -1, -100} {
		tool := enabledTool(dA)
		for i := 0; i < 12; i++ {
			tool = step(t, tool, miss(), lc.Policy{DeprecateAfter: after})
		}
		requireState(t, tool, lc.Enabled)
		if tool.MissingCrawls != 12 {
			t.Errorf("DeprecateAfter %d: MissingCrawls = %d, want 12", after, tool.MissingCrawls)
		}
	}
}

func TestObserveMissing_DisabledIsNeverDeprecated(t *testing.T) {
	tool := toolOf(lc.Disabled, dA, dA, 0, ver(dA, lc.VersionApproved, alice, true))
	for i := 1; i <= 10; i++ {
		tool = step(t, tool, miss(), plainPolicy())
		requireState(t, tool, lc.Disabled)
		if tool.MissingCrawls != i {
			t.Fatalf("miss %d: MissingCrawls = %d", i, tool.MissingCrawls)
		}
		if tool.LastSeen != "" {
			t.Fatalf("miss %d: LastSeen = %q, want empty", i, tool.LastSeen)
		}
	}
}

// Spec: "LastSeen = d, MissingCrawls = 0": a sighting resets the streak.
func TestObserveMissing_PresentCrawlResetsTheStreak(t *testing.T) {
	tool := enabledTool(dA)
	tool = step(t, tool, miss(), plainPolicy())
	tool = step(t, tool, miss(), plainPolicy())
	tool = step(t, tool, crawl(dA, bob), plainPolicy())
	if tool.MissingCrawls != 0 || tool.LastSeen != dA {
		t.Fatalf("after sighting: MissingCrawls=%d LastSeen=%q", tool.MissingCrawls, tool.LastSeen)
	}
	tool = step(t, tool, miss(), plainPolicy())
	tool = step(t, tool, miss(), plainPolicy())
	requireState(t, tool, lc.Enabled)
}

// toolForState builds a non-terminal tool in the given state with a plausible
// approval and proposal layout.
func toolForState(state lc.State) lc.Tool {
	switch state {
	case lc.PendingReview:
		return pendingReviewTool(dA, alice)
	case lc.ChangedPendingReapproval:
		return changedTool(dA, dB, bob)
	default:
		return enabledTool(dA)
	}
}
