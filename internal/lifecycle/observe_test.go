package lifecycle_test

// ObserveCrawl tables. Every expectation is derived from the specification
// sentence quoted next to the case group.

import (
	"testing"

	lc "github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// Spec: "ObserveCrawl{Present:true, Digest:d, Actor:a}: sets LastSeen=d and
// MissingCrawls=0, then (first match wins): ... (d) otherwise ..."
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

// Spec: "(d) ... (a known superseded version is reused and set to pending,
// keeping EverApproved)".
func TestObservePresent_ReusesKnownSupersededVersion(t *testing.T) {
	p := plainPolicy()
	runApplyCases(t, []applyCase{
		{
			name: "previously approved superseded digest comes back as a proposal",
			start: toolOf(lc.Enabled, dB, dB, 0,
				ver(dA, lc.VersionSuperseded, alice, true),
				ver(dB, lc.VersionApproved, bob, true)),
			cmd: crawl(dA, carol),
			pol: p,
			want: toolOf(lc.ChangedPendingReapproval, dB, dA, 0,
				ver(dA, lc.VersionPending, carol, true),
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
				ver(dA, lc.VersionPending, carol, false),
				ver(dB, lc.VersionApproved, bob, true)),
		},
		{
			name: "reusing a superseded digest supersedes the current pending one",
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
				ver(dA, lc.VersionPending, carol, false),
				ver(dB, lc.VersionSuperseded, bob, false)),
		},
	})
}

// Spec: "(b) if d equals Approved: no new version; if the state is
// changed_pending_reapproval the upstream reverted, so every pending version
// becomes superseded and the state becomes enabled."
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

// Spec: "(c) if d is a known version whose status is rejected or pending: no
// status changes".
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

// Spec: "disabled ... stay".
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

// Spec: "(e) if the tool is deprecated it reappeared: the approval is retired
// (the approved version becomes superseded and Approved becomes \"\"), the
// state becomes pending_review, and d is proposed (becomes the single pending
// version with ProposedBy a) unless d is a version that was rejected".
func TestObservePresent_DeprecatedToolReappears(t *testing.T) {
	p := plainPolicy()
	runApplyCases(t, []applyCase{
		{
			name:  "same digest as the retired approval is proposed afresh",
			start: toolOf(lc.Deprecated, dA, "", 3, ver(dA, lc.VersionApproved, alice, true)),
			cmd:   crawl(dA, carol),
			pol:   p,
			want:  toolOf(lc.PendingReview, "", dA, 0, ver(dA, lc.VersionPending, carol, true)),
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
	})
}

// Spec: "A crawl NEVER sets Approved to a new digest and never makes a version
// approved." Exhaustive over state fixtures and crawled digests.
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
	for name, start := range fixtures {
		for _, d := range []string{dA, dB, dC, dD} {
			got := applyOK(t, start, crawl(d, carol), plainPolicy())
			for _, v := range got.Tool.Versions {
				wasApproved := false
				for _, old := range start.Versions {
					if old.Digest == v.Digest && old.Status == lc.VersionApproved {
						wasApproved = true
					}
				}
				if v.Status == lc.VersionApproved && !wasApproved {
					t.Errorf("%s crawl %s: version %s became approved by a crawl", name, d, v.Digest)
				}
			}
			if got.Tool.Approved != start.Approved && !(start.State == lc.Deprecated && got.Tool.Approved == "") {
				t.Errorf("%s crawl %s: Approved changed from %q to %q", name, d, start.Approved, got.Tool.Approved)
			}
			if hasEvent(got, lc.EvApproved, "") || hasEvent(got, lc.EvRolledBack, "") {
				t.Errorf("%s crawl %s: a crawl emitted an approval event: %+v", name, d, got.Events)
			}
		}
	}
}

// Spec: "ObserveCrawl{Present:false}: for discovered and deprecated tools
// nothing changes."
func TestObserveMissing_DiscoveredAndDeprecatedUnchanged(t *testing.T) {
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
	})
}

// Spec: "Otherwise LastSeen becomes \"\", MissingCrawls increments".
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
	})
}

// Spec: "if policy.DeprecateAfter > 0 and MissingCrawls reaches it and the
// state is not disabled, the state becomes deprecated; a disabled tool is
// never deprecated."
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

// Spec: "sets LastSeen=d and MissingCrawls=0": a sighting resets the streak.
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
