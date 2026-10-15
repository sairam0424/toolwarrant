package catalog

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"

	"pgregory.net/rapid"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
	"github.com/sairam0424/toolwarrant/internal/signing"
	"github.com/sairam0424/toolwarrant/internal/trust"
)

// crawlRuns counts every catalog the crawl-transition property built, across
// shards; the shards' run count is compared with it.
var crawlRuns atomic.Int64

// A history the Store itself wrote after a bootstrap, drawn from crawls of
// every shape (sightings of several digests, unusable definitions, misses to
// deprecation under a drawn policy) and from signed decisions of every kind,
// never trips rule 6 or rule 5: no write is ErrCorrupt, a fresh Store opens
// it, and Integrity finds nothing. The property runs in parallel shards that
// together perform rapid's check count, as the model and trust properties do
// and for the same reason (model_shards_test.go).
func TestWalk_AcceptsEveryCrawlTransitionTheLifecycleMakes(t *testing.T) {
	plan := planShards(t)
	built := crawlRuns.Load()
	runs := make([]int, plan.shards)
	alice, bob := newOperator(t, "alice"), newOperator(t, "bob")
	restore := setChecks(t, plan.perShard)
	t.Run("shards", func(t *testing.T) {
		for i := range plan.shards {
			t.Run(fmt.Sprintf("shard%d", i), func(t *testing.T) {
				t.Parallel()
				dir := t.TempDir()
				rapid.Check(t, func(rt *rapid.T) {
					runs[i]++
					checkCrawlHistoryOnce(t, rt, dir, alice, bob)
				})
			})
		}
	})
	restore()
	checkShardRuns(t, plan, runs, crawlRuns.Load()-built)
}

// crawlHistory is the state one check of the property drives: the Store, its
// path and the two signers.
type crawlHistory struct {
	t          *testing.T
	rt         *rapid.T
	s          *Store
	alice, bob operator
}

// crawlSteps bounds the drawn operations of one check.
const crawlSteps = 14

// checkCrawlHistoryOnce is one check of the property: a fresh catalog under
// dir with a drawn policy, bootstrapped, then crawlSteps drawn operations,
// then the fresh open and the integrity report.
func checkCrawlHistoryOnce(t *testing.T, rt *rapid.T, dir string, alice, bob operator) {
	t.Helper()
	n := crawlRuns.Add(1)
	path := filepath.Join(dir, fmt.Sprintf("catalog-%d.db", n))
	policy := lifecycle.Policy{
		AllowSelfApproval:      false,
		ReEnableRequiresReview: rapid.Bool().Draw(rt, "review"),
		DeprecateAfter:         rapid.IntRange(0, 2).Draw(rt, "deprecateAfter"),
	}
	s, err := Open(path, policy)
	if err != nil {
		rt.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	h := crawlHistory{t: t, rt: rt, s: s, alice: alice, bob: bob}
	mustAddServer(t, s, "alpha")
	h.crawl(rapid.SliceOfN(rapid.SampledFrom([]string{"a", "b"}), 2, 2).Draw(rt, "first"))
	mustSetTrust(t, s, 1, alice, alice, bob)
	for i := 0; i < crawlSteps; i++ {
		h.step(rapid.IntRange(0, 9).Draw(rt, fmt.Sprintf("step[%d]", i)))
	}
	_ = s.Close()
	fresh, err := OpenWith(path, OpenOptions{ReadOnly: true})
	if err != nil {
		rt.Fatalf("fresh open: %v", err)
	}
	defer func() { _ = fresh.Close() }()
	if _, err := fresh.Snapshot(bg, "alpha"); err != nil {
		rt.Fatalf("fresh Snapshot: %v", err)
	}
	rep, err := fresh.Integrity(bg)
	if err != nil {
		rt.Fatal(err)
	}
	rep.LegacyApprovalsInService = nil
	if len(rep.Problems) != 0 || rep.UnsignedDecisionsAfterBootstrap != 0 || rep.CrawlTransitionsForged != 0 {
		rt.Fatalf("Integrity = %+v", rep)
	}
}

// step draws and runs one operation; a lifecycle or ErrInvalid refusal is a
// drawn command that did not fit the state and is fine, ErrCorrupt is the
// failure the property hunts.
func (h *crawlHistory) step(roll int) {
	var err error
	switch roll {
	case 0, 1, 2:
		h.crawl([]string{h.digestWord("echo"), h.digestWord("sum")})
		return
	case 3:
		_, err = h.s.RecordCrawl(bg, CrawlInput{Server: "alpha", Complete: true, Tools: []CrawledTool{tool("echo", h.digestWord("echo"))},
			Unusable: []UnusableTool{unusableOf("sum", "not-canonical")}}, crawler)
	case 4:
		_, err = h.s.RecordCrawl(bg, CrawlInput{Server: "alpha", Complete: true}, crawler)
	case 5:
		err = h.decide(signing.KindApprove, h.toolName(), h.pending())
	case 6:
		err = h.decide(signing.KindReject, h.toolName(), h.pending())
	case 7:
		err = h.decide(rapid.SampledFrom([]signing.Kind{signing.KindDisable, signing.KindEnable}).Draw(h.rt, "toggle"), h.toolName(), "")
	case 8:
		err = h.decide(signing.KindRollback, h.toolName(), h.rollbackTarget())
	default:
		err = h.decide(rapid.SampledFrom([]signing.Kind{signing.KindPause, signing.KindResume, signing.KindBudgetReset}).Draw(h.rt, "server"), h.toolName(), "")
	}
	h.accept(err)
}

// crawl records one complete crawl listing echo and sum with the given words.
func (h *crawlHistory) crawl(words []string) {
	_, err := h.s.RecordCrawl(bg, crawlOf(tool("echo", words[0]), tool("sum", words[1])), crawler)
	h.accept(err)
}

// accept fails the check on ErrCorrupt and lets every other refusal pass.
func (h *crawlHistory) accept(err error) {
	if errors.Is(err, ErrCorrupt) {
		h.rt.Fatalf("the Store refused its own history: %v", err)
	}
}

// digestWord draws the definition word of a tool: a small alphabet so digests
// recur.
func (h *crawlHistory) digestWord(name string) string {
	return rapid.SampledFrom([]string{"a", "b", "c"}).Draw(h.rt, name+" word")
}

// toolName draws the tool a decision names.
func (h *crawlHistory) toolName() string {
	return rapid.SampledFrom([]string{"echo", "sum"}).Draw(h.rt, "tool")
}

// pending is the pending digest of the drawn tool, or a drawn one when none.
func (h *crawlHistory) pending() string {
	v, err := h.s.Tool(bg, "alpha", h.toolName())
	if err == nil && v.Pending != "" {
		return v.Pending
	}
	return digestOf(h.t, "echo", h.digestWord("echo"))
}

// rollbackTarget is a drawn digest among the tool's versions.
func (h *crawlHistory) rollbackTarget() string {
	return digestOf(h.t, h.toolName(), h.digestWord("sum"))
}

// decide signs a decision over the current head by a drawn operator and
// records it; pause, resume and the budget reset name the server or the
// tool as their kind requires.
func (h *crawlHistory) decide(kind signing.Kind, name, digest string) error {
	by := h.alice
	if rapid.Bool().Draw(h.rt, "bob signs") {
		by = h.bob
	}
	if !kind.NamesTool() {
		name = ""
	}
	st, err := h.s.SigningState(bg)
	if err != nil {
		return err
	}
	rec := signDecisionPayload(h.t, decisionOf(st.Identity, st.Head, by, kind, "alpha", name, digest), by)
	_, err = h.s.Decide(bg, decisionFor(by, kind, "alpha", name, digest, rec))
	return err
}

// The anchor rule accepts an entry only when it names the decision.signed
// entry of its own transaction: over shuffled seq, subject, actor, time, event
// and digest, requireSigned accepts exactly the entries whose every field is
// the recorded outcome's and whose event the kind writes, and the walk's
// checkSignedBinding accepts those only while that transaction is open. A
// human-only event without a token is refused after the bootstrap and
// accepted before it.
func TestProperty_anchorRuleAcceptsOnlyTheSignedEntryOfTheSameTransaction(t *testing.T) {
	t.Parallel()
	const (
		bootstrap = 2
		n         = 5
	)
	outcome := signedOutcome{kind: signing.KindApprove, subject: "alpha/echo", actor: "alice", ts: "2026-10-16T10:00:00.000000000Z", digest: digestOf(t, "echo", "v1")}
	rapid.Check(t, func(rt *rapid.T) {
		c := newChainMemory()
		c.trust.state = trust.State{BootstrapSeq: bootstrap, ListSeq: bootstrap}
		c.signed[n] = outcome
		e := audit.Entry{
			Seq:       int64(rapid.IntRange(1, 9).Draw(rt, "seq")),
			TS:        rapid.SampledFrom([]string{outcome.ts, "2026-10-16T10:00:01.000000000Z"}).Draw(rt, "ts"),
			Actor:     rapid.SampledFrom([]string{"alice", "bob"}).Draw(rt, "actor"),
			ActorType: rapid.SampledFrom([]string{string(ActorHuman), string(ActorSystem)}).Draw(rt, "type"),
			Event:     rapid.SampledFrom([]string{string(lifecycle.EvApproved), string(lifecycle.EvRolledBack), string(lifecycle.EvSuperseded), string(lifecycle.EvEnabled), string(lifecycle.EvDrifted)}).Draw(rt, "event"),
			Subject:   rapid.SampledFrom([]string{"alpha/echo", "alpha/sum"}).Draw(rt, "subject"),
			AfterHash: rapid.SampledFrom([]string{outcome.digest, digestOf(t, "echo", "v2")}).Draw(rt, "after"),
		}
		token := rapid.SampledFrom([]int64{n, n - 1, 0}).Draw(rt, "token")
		e.Detail = fmt.Sprintf("digest=- state=enabled->enabled last_seen=- proposals=0->0%s", signedNote(token))
		open := rapid.SampledFrom([]int64{n, 0}).Draw(rt, "open")

		binds := token == n && e.Seq > n && e.Subject == outcome.subject && e.Actor == outcome.actor && e.ActorType == string(ActorHuman) && e.TS == outcome.ts &&
			kindWrites(outcome.kind, e.Event) && (!isDecision(e.Event) || e.AfterHash == outcome.digest)
		after := e.Seq > bootstrap
		wantAnchor := !after || !isHumanOnlyEvent(e.Event) || binds
		if got := c.requireSigned(e) == nil; got != wantAnchor {
			rt.Fatalf("requireSigned(%+v) accepted = %v, want %v (binds %v)", e, got, wantAnchor, binds)
		}
		w := decisionWalk{bootstrap: bootstrap, open: open, lookup: c.lookupSigned}
		_, err := checkLifecycleEntry(e, w)
		wantWalk := !after || (token != 0 && binds && open == n) || (token == 0 && !isHumanOnlyEvent(e.Event))
		if got := err == nil; got != wantWalk {
			rt.Fatalf("checkLifecycleEntry(%+v, open %d) accepted = %v, want %v: %v", e, open, got, wantWalk, err)
		}
	})
}

// isDecision reports whether the event decides a digest the binding compares.
func isDecision(event string) bool {
	_, decides := eventDigest(audit.Entry{Event: event})
	return decides
}
