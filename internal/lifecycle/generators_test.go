package lifecycle_test

// Random command sequences for the property tests.
//
// Digests come from a four-element alphabet (plus the digests the tool already
// knows, plus occasionally the empty string) so collisions, reverts, re-proposals
// and stale approvals happen constantly. Actors come from three names so the
// proposer and the approver coincide often. Unusable sightings and, rarely,
// contradictory observations are drawn too, so the D3 marker and its
// validation are exercised on every shape of tool.

import (
	"fmt"
	"reflect"

	lc "github.com/sairam0424/toolwarrant/internal/lifecycle"
	"pgregory.net/rapid"
)

const (
	minSequenceLength = 5
	maxSequenceLength = 60

	// guidedPercent is how often a command is chosen to fit the tool's shape.
	guidedPercent = 50

	// Cumulative command mix, in percent of draws; the remainder is Rollback.
	cutCrawlPresent  = 28
	cutCrawlUnusable = 34
	cutCrawlMissing  = 45
	cutApprove       = 62
	cutReject        = 70
	cutDisable       = 78
	cutEnable        = 88
	percentScale     = 100

	// contradictionOdds is the one-in-N chance that an unusable draw is made
	// contradictory (a digest alongside, or not present), to reach
	// ErrInvalidObservation.
	contradictionOdds = 8

	// knownDigestBias is how many times each known digest is repeated in the
	// pool a digest is drawn from, so commands often name an existing version.
	knownDigestBias = 2

	minDeprecateAfter = -1
	maxDeprecateAfter = 4
)

// stepRecord is one Apply call as the property tests saw it.
type stepRecord struct {
	before lc.Tool
	cmd    lc.Command
	pol    lc.Policy
	res    lc.Result
	err    error
}

// actorPool is weighted so an empty actor is rare (about one draw in nineteen).
func actorPool() []string {
	return []string{
		alice, bob, carol, alice, bob, carol, alice, bob, carol,
		alice, bob, carol, alice, bob, carol, alice, bob, carol, "",
	}
}

func drawActor(rt *rapid.T, label string) string {
	return rapid.SampledFrom(actorPool()).Draw(rt, label)
}

// drawDigest draws from the alphabet, the digests tool already knows, and "".
func drawDigest(rt *rapid.T, label string, tool lc.Tool) string {
	pool := []string{dA, dB, dC, dD, ""}
	for _, v := range tool.Versions {
		for i := 0; i < knownDigestBias; i++ {
			pool = append(pool, v.Digest)
		}
	}
	return rapid.SampledFrom(pool).Draw(rt, label)
}

func drawPolicy(rt *rapid.T, label string) lc.Policy {
	return lc.Policy{
		AllowSelfApproval:      rapid.Bool().Draw(rt, label+".allowSelf"),
		ReEnableRequiresReview: rapid.Bool().Draw(rt, label+".review"),
		DeprecateAfter:         rapid.IntRange(minDeprecateAfter, maxDeprecateAfter).Draw(rt, label+".deprecateAfter"),
	}
}

// drawCommand mixes guided commands (likely to succeed, so sequences get deep:
// approvals of the pending proposal, rollbacks, re-enables) with uniformly
// random ones (likely to fail, so every error path is exercised).
func drawCommand(rt *rapid.T, label string, tool lc.Tool) lc.Command {
	if rapid.IntRange(0, percentScale-1).Draw(rt, label+".guided") < guidedPercent {
		return guidedCommand(rt, label, tool)
	}
	return randomCommand(rt, label, tool)
}

// approverFor picks a principal who never proposed the version, so a guided
// approval can succeed under the two-person rule; when every name proposed it
// the approval is left to fail, which is a path worth exercising too.
func approverFor(tool lc.Tool, digest string) string {
	v, _ := findVersion(tool, digest)
	for _, a := range []string{bob, carol, alice} {
		if a != v.ProposedBy && !v.Proposers.Contains(a) {
			return a
		}
	}
	return bob
}

// guidedCommand picks among commands that fit the tool's current shape.
func guidedCommand(rt *rapid.T, label string, tool lc.Tool) lc.Command {
	options := []lc.Command{
		lc.ObserveCrawl{Present: true, Digest: dA, Actor: carol},
		lc.ObserveCrawl{Present: true, Digest: dB, Actor: carol},
		lc.ObserveCrawl{Present: true, Digest: dC, Actor: alice},
		lc.ObserveCrawl{Present: true, Unusable: true, Actor: carol},
		lc.ObserveCrawl{Present: false, Actor: crawler},
	}
	if pending := tool.Pending(); pending != "" {
		approver := approverFor(tool, pending)
		options = append(options,
			lc.Approve{Digest: pending, Actor: approver},
			lc.Approve{Digest: pending, Actor: approver},
			lc.Reject{Digest: pending, Actor: alice})
	}
	for _, v := range tool.Versions {
		options = append(options, lc.ObserveCrawl{Present: true, Digest: v.Digest, Actor: carol})
		if v.EverApproved && v.Status != lc.VersionApproved && v.Status != lc.VersionRejected {
			options = append(options, lc.Rollback{To: v.Digest, Actor: bob}, lc.Rollback{To: v.Digest, Actor: bob})
		}
	}
	if tool.State == lc.Disabled {
		options = append(options, lc.Enable{Actor: bob}, lc.Enable{Actor: alice})
	}
	return rapid.SampledFrom(options).Draw(rt, label+".pick")
}

func randomCommand(rt *rapid.T, label string, tool lc.Tool) lc.Command {
	roll := rapid.IntRange(0, percentScale-1).Draw(rt, label+".kind")
	actor := drawActor(rt, label+".actor")
	digest := drawDigest(rt, label+".digest", tool)
	switch {
	case roll < cutCrawlPresent:
		return lc.ObserveCrawl{Present: true, Digest: digest, Actor: actor}
	case roll < cutCrawlUnusable:
		return randomUnusable(rt, label, actor, digest)
	case roll < cutCrawlMissing:
		return lc.ObserveCrawl{Present: false, Actor: actor}
	case roll < cutApprove:
		return lc.Approve{Digest: digest, Actor: actor}
	case roll < cutReject:
		return lc.Reject{Digest: digest, Actor: actor}
	case roll < cutDisable:
		return lc.Disable{Actor: actor}
	case roll < cutEnable:
		return lc.Enable{Actor: actor}
	default:
		return lc.Rollback{To: digest, Actor: actor}
	}
}

// randomUnusable is mostly a well-formed unusable sighting; one draw in
// contradictionOdds carries a digest or claims absence, which the state
// machine must refuse.
func randomUnusable(rt *rapid.T, label, actor, digest string) lc.Command {
	if rapid.IntRange(0, contradictionOdds-1).Draw(rt, label+".contradict") != 0 {
		return lc.ObserveCrawl{Present: true, Unusable: true, Actor: actor}
	}
	if rapid.Bool().Draw(rt, label+".absent") {
		return lc.ObserveCrawl{Present: false, Unusable: true, Actor: actor}
	}
	return lc.ObserveCrawl{Present: true, Unusable: true, Digest: digest, Actor: actor}
}

// walk draws a random command sequence, applies it to a new tool, and returns
// every step. Purity is checked on every call. When perStepPolicy is set the
// policy is redrawn before each step, as if configuration changed between
// requests.
func walk(rt *rapid.T, perStepPolicy bool) []stepRecord {
	policy := drawPolicy(rt, "policy")
	length := rapid.IntRange(minSequenceLength, maxSequenceLength).Draw(rt, "length")
	tool := newTool()
	records := make([]stepRecord, 0, length)
	for i := 0; i < length; i++ {
		if perStepPolicy && i > 0 {
			policy = drawPolicy(rt, fmt.Sprintf("policy[%d]", i))
		}
		cmd := drawCommand(rt, fmt.Sprintf("cmd[%d]", i), tool)
		res, err := checkPure(rt, tool, cmd, policy)
		records = append(records, stepRecord{before: cloneTool(tool), cmd: cmd, pol: policy, res: res, err: err})
		if err == nil {
			tool = cloneTool(res.Tool)
		}
	}
	return records
}

// replayDiffers re-runs the recorded commands from a new tool and returns a
// description of the first difference from the recorded results, or "".
func replayDiffers(rt *rapid.T, records []stepRecord) string {
	tool := newTool()
	for i, rec := range records {
		res, err := apply(rt, tool, rec.cmd, rec.pol)
		if (err == nil) != (rec.err == nil) {
			return fmt.Sprintf("step %d: error presence differs on replay: %v vs %v", i, err, rec.err)
		}
		if err != nil {
			if err.Error() != rec.err.Error() {
				return fmt.Sprintf("step %d: error differs on replay: %v vs %v", i, err, rec.err)
			}
			continue
		}
		if !sameTool(res.Tool, rec.res.Tool) || !reflect.DeepEqual(res.Events, rec.res.Events) {
			return fmt.Sprintf("step %d: result differs on replay:\n%+v\n%+v", i, res, rec.res)
		}
		tool = cloneTool(res.Tool)
	}
	return ""
}
