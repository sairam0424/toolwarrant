package lifecycle_test

// Event emission. The written specification does not define which events a
// transition emits; the only source is the EventKind names and the doc
// comment "Digest is the version it concerns, if any". These tests therefore
// assert only that the obviously-named event is present (and names the right
// digest when the digest is unambiguous). They never assert the absence of
// extra events, except where the name forbids them (a crawl never approves).

import (
	"testing"

	lc "github.com/sairam0424/toolwarrant/internal/lifecycle"
)

func TestEvents_TransitionsEmitTheNamedEvent(t *testing.T) {
	p := plainPolicy()
	type eventCase struct {
		name   string
		start  lc.Tool
		cmd    lc.Command
		pol    lc.Policy
		kind   lc.EventKind
		digest string // empty means any digest
	}
	cases := []eventCase{
		{"first crawl proposes", newTool(), crawl(dA, alice), p, lc.EvProposed, dA},
		// Name-derived: the Discovered state is "a tool row before its first
		// observation is applied", so the first observation announces it.
		{"first crawl discovers the tool", newTool(), crawl(dA, alice), p, lc.EvDiscovered, ""},
		{"drift is flagged", enabledTool(dA), crawl(dB, bob), p, lc.EvDrifted, ""},
		{"drift proposes the new digest", enabledTool(dA), crawl(dB, bob), p, lc.EvProposed, dB},
		{"a newer proposal supersedes the old one", pendingReviewTool(dA, alice), crawl(dB, bob), p, lc.EvSuperseded, dA},
		{"revert is flagged", changedTool(dA, dB, bob), crawl(dA, carol), p, lc.EvReverted, ""},
		{"revert supersedes the pending proposal", changedTool(dA, dB, bob), crawl(dA, carol), p, lc.EvSuperseded, dB},
		{"approve", pendingReviewTool(dA, alice), lc.Approve{Digest: dA, Actor: bob}, p, lc.EvApproved, dA},
		{"approve supersedes the old approval", changedTool(dA, dB, alice), lc.Approve{Digest: dB, Actor: bob}, p, lc.EvSuperseded, dA},
		{"reject", pendingReviewTool(dA, alice), lc.Reject{Digest: dA, Actor: bob}, p, lc.EvRejected, dA},
		{
			"rollback",
			toolOf(lc.Enabled, dB, dB, 0, ver(dA, lc.VersionSuperseded, alice, true), ver(dB, lc.VersionApproved, bob, true)),
			lc.Rollback{To: dA, Actor: carol}, p, lc.EvRolledBack, dA,
		},
		{
			"rollback supersedes the current approval",
			toolOf(lc.Enabled, dB, dB, 0, ver(dA, lc.VersionSuperseded, alice, true), ver(dB, lc.VersionApproved, bob, true)),
			lc.Rollback{To: dA, Actor: carol}, p, lc.EvSuperseded, dB,
		},
		{"disable", enabledTool(dA), lc.Disable{Actor: bob}, p, lc.EvDisabled, ""},
		{
			"enable",
			toolOf(lc.Disabled, dA, dA, 0, ver(dA, lc.VersionApproved, alice, true)),
			lc.Enable{Actor: bob}, p, lc.EvEnabled, "",
		},
		{"missing", enabledTool(dA), miss(), p, lc.EvMissing, ""},
		{
			"deprecation",
			toolOf(lc.Enabled, dA, "", deprecateAfterThree-1, ver(dA, lc.VersionApproved, alice, true)),
			miss(), p, lc.EvDeprecated, "",
		},
		{
			"reappearance",
			toolOf(lc.Deprecated, dA, "", deprecateAfterThree, ver(dA, lc.VersionApproved, alice, true)),
			crawl(dA, carol), p, lc.EvReappeared, "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := applyOK(t, tc.start, tc.cmd, tc.pol)
			if !hasEvent(res, tc.kind, tc.digest) {
				t.Errorf("missing event %s (digest %q) in %+v", tc.kind, tc.digest, res.Events)
			}
		})
	}
}

// Observing the approved digest on a healthy tool changes nothing, so it must
// not claim a transition happened.
func TestEvents_UneventfulCrawlEmitsNoTransitionEvents(t *testing.T) {
	res := applyOK(t, enabledTool(dA), crawl(dA, bob), plainPolicy())
	forbidden := []lc.EventKind{
		lc.EvDiscovered, lc.EvProposed, lc.EvSuperseded, lc.EvApproved, lc.EvRejected, lc.EvRolledBack,
		lc.EvDrifted, lc.EvReverted, lc.EvDisabled, lc.EvEnabled, lc.EvDeprecated, lc.EvReappeared,
	}
	for _, kind := range forbidden {
		if hasEvent(res, kind, "") {
			t.Errorf("unchanged tool emitted %s: %+v", kind, res.Events)
		}
	}
}
