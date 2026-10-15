package catalog

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"sync/atomic"
	"testing"

	"pgregory.net/rapid"

	"github.com/sairam0424/toolwarrant/internal/gate"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// The model test drives random sequences of crawls (usable, unusable and
// absent sightings, rejected names), operator commands and server pauses
// through the Store and through the pure lifecycle model side by side. After
// every step the Store, read back through its public API, must equal the
// model: the database layer may persist the lifecycle but never bend it.

const modelServer = "alpha"

var (
	modelToolNames = []string{"t0", "t1", "t2"}
	modelVariants  = []string{"v0", "v1", "v2"}
	// Crawls are mostly run by the system crawler, sometimes by a person, and
	// operators are people, so both refusals and acceptances of self-approval occur.
	modelCrawlers  = []Actor{crawler, crawler, crawler, alice}
	modelOperators = []Actor{bob, bob, alice, carol}
	modelSentinels = []error{
		lifecycle.ErrInvalidTransition, lifecycle.ErrUnknownVersion, lifecycle.ErrStaleVersion,
		lifecycle.ErrSelfApproval, lifecycle.ErrNotRollbackTarget, lifecycle.ErrNoActor, lifecycle.ErrNoDigest,
	}
	modelActions = []string{
		"crawl", "crawl", "crawl", "crawl", "crawl", "approve", "approve", "approve", "approve", "reject",
		"disable", "enable", "enable", "rollback", "rollback", "rollback", "cycle", "cycle", "cycle", "crawlFail", "reopen",
		"pause", "resume",
	}
)

// sighting is what the random crawl lists for one tool.
type sighting int

const (
	absent sighting = iota
	usable
	unusable
)

type model struct {
	rt        *rapid.T
	path      string
	s         *Store
	policy    lifecycle.Policy
	tools     map[string]lifecycle.Tool
	gen       int64
	audits    int
	approvals int
	paused    bool
	stats     map[string]int // how often each state and event was reached, logged for the reader
	variant   map[string]string
}

// modelRuns counts every model built, across shards and runs of the test, and
// names each store file uniquely; checkShardRuns compares it with the checks
// the shards ran.
var modelRuns atomic.Int64

// TestModel_StoreFollowsTheLifecycleModel runs the property in modelShards
// parallel rapid runs that together perform rapid's check count (100 by
// default, 20 under -short, the same as one rapid.Check did); see
// model_shards_test.go for why the count is split through rapid's flag and
// why this test stays serial while its shards run in parallel.
func TestModel_StoreFollowsTheLifecycleModel(t *testing.T) {
	plan := planShards(t)
	built := modelRuns.Load()
	runs := make([]int, plan.shards)
	stats := make([]map[string]int, plan.shards)
	restore := setChecks(t, plan.perShard)
	t.Run("shards", func(t *testing.T) {
		for i := range plan.shards {
			stats[i] = map[string]int{}
			t.Run(fmt.Sprintf("shard%d", i), func(t *testing.T) {
				t.Parallel()
				dir := t.TempDir()
				rapid.Check(t, func(rt *rapid.T) {
					runs[i]++
					checkModelOnce(rt, dir, stats[i])
				})
			})
		}
	})
	restore()
	t.Logf("model coverage: %v", mergeStats(stats))
	checkShardRuns(t, plan, runs, modelRuns.Load()-built)
}

// checkModelOnce is one check of the property: a fresh store under dir, a
// random number of random steps each compared with the model, then the whole
// log verified and the integrity report clean.
func checkModelOnce(rt *rapid.T, dir string, stats map[string]int) {
	m := newModel(rt, filepath.Join(dir, fmt.Sprintf("m%d.db", modelRuns.Add(1))), stats)
	steps := rapid.IntRange(1, 40).Draw(rt, "steps")
	for i := 0; i < steps; i++ {
		m.step(rapid.SampledFrom(modelActions).Draw(rt, "action"))
		m.check()
	}
	if _, err := m.s.VerifyAudit(bg); err != nil {
		rt.Fatalf("VerifyAudit: %v", err)
	}
	// Whatever the history, a catalog the Store wrote agrees with its log
	// on every column Integrity cross-checks (D13).
	if rep, err := m.s.Integrity(bg); err != nil || len(rep.Problems) != 0 {
		rt.Fatalf("Integrity = %+v, %v; want a clean report", rep, err)
	}
}

func newModel(rt *rapid.T, path string, stats map[string]int) *model {
	policy := lifecycle.Policy{
		AllowSelfApproval:      rapid.Bool().Draw(rt, "allow self approval"),
		ReEnableRequiresReview: rapid.Bool().Draw(rt, "re-enable requires review"),
		DeprecateAfter:         rapid.IntRange(0, 3).Draw(rt, "deprecate after"),
	}
	s, err := Open(path, policy)
	if err != nil {
		rt.Fatalf("Open: %v", err)
	}
	m := &model{rt: rt, path: path, s: s, policy: policy, tools: map[string]lifecycle.Tool{}, stats: stats, variant: map[string]string{}}
	rt.Cleanup(func() { _ = m.s.Close() })
	if _, err := s.AddServer(bg, ServerSpec{Name: modelServer, URL: "https://a.example.com/mcp"}, alice); err != nil {
		rt.Fatalf("AddServer: %v", err)
	}
	m.gen, m.audits = 1, 1
	return m
}

func (m *model) step(action string) {
	switch action {
	case "crawl":
		m.crawl(nil)
	case "cycle":
		m.cycle()
	case "crawlFail":
		m.crawlFail()
	case "reopen":
		if err := m.s.Close(); err != nil {
			m.rt.Fatalf("Close: %v", err)
		}
		s, err := Open(m.path, m.policy)
		if err != nil {
			m.rt.Fatalf("reopen: %v", err)
		}
		m.s = s
	case "pause", "resume":
		m.setPaused(action == "pause")
	default:
		m.decide(action)
	}
}

// crawlFail records an incomplete crawl: refused while paused, otherwise one
// write and one audit entry that changes no tool.
func (m *model) crawlFail() {
	by := rapid.SampledFrom(modelCrawlers).Draw(m.rt, "actor")
	_, err := m.s.RecordCrawl(bg, CrawlInput{Server: modelServer, Error: "down"}, by)
	if m.paused {
		if !errors.Is(err, ErrPaused) {
			m.rt.Fatalf("incomplete RecordCrawl of a paused server: %v, want ErrPaused", err)
		}
		return
	}
	if err != nil {
		m.rt.Fatalf("incomplete RecordCrawl: %v", err)
	}
	m.gen++
	m.audits++
}

// setPaused runs PauseServer or ResumeServer; the store must accept exactly
// the transitions the model's flag allows.
func (m *model) setPaused(paused bool) {
	by := rapid.SampledFrom(modelOperators).Draw(m.rt, "operator")
	var err error
	if paused {
		err = m.s.PauseServer(bg, modelServer, by)
	} else {
		err = m.s.ResumeServer(bg, modelServer, by)
	}
	if m.paused == paused {
		if !errors.Is(err, ErrInvalid) {
			m.rt.Fatalf("paused=%t twice: %v, want ErrInvalid", paused, err)
		}
		return
	}
	if err != nil {
		m.rt.Fatalf("set paused=%t: %v", paused, err)
	}
	m.paused = paused
	m.gen++
	m.audits++
	m.stats[fmt.Sprintf("paused:%t", paused)]++
}

func modelDigest(name, variant string) string {
	d, err := gate.Digest(def(name, variant))
	if err != nil {
		panic(err)
	}
	return d
}

func sortedNames(tools map[string]lifecycle.Tool) []string {
	names := make([]string, 0, len(tools))
	for n := range tools {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// cycle is a change the operator accepts: one tool moves to a new definition
// and the proposal is approved, which is how rollback targets come to exist.
func (m *model) cycle() {
	name := m.drawTool()
	next := modelVariants[0]
	for i, v := range modelVariants {
		if v == m.variant[name] {
			next = modelVariants[(i+1)%len(modelVariants)]
		}
	}
	m.crawl(map[string]string{name: next})
	digest := m.tools[name].Pending()
	if digest == "" {
		digest = modelDigest(name, next)
	}
	m.run("approve", name, bob, digest)
}

// drawSighting decides how one tool is listed. force pins the variant of some
// tools; every other tool is usually listed unchanged, sometimes drifted,
// sometimes unusable, sometimes dropped.
func (m *model) drawSighting(n string, force map[string]string) (sighting, string) {
	forced, isForced := force[n]
	if isForced {
		m.variant[n] = forced
		return usable, forced
	}
	roll := rapid.IntRange(0, 9).Draw(m.rt, "present "+n)
	switch {
	case roll >= 8:
		return absent, ""
	case roll == 7:
		return unusable, ""
	}
	variant := rapid.SampledFrom(modelVariants).Draw(m.rt, "variant "+n)
	if last, ok := m.variant[n]; ok && rapid.IntRange(0, 9).Draw(m.rt, "keep "+n) < 7 {
		variant = last
	}
	m.variant[n] = variant
	return usable, variant
}

// crawl runs one complete crawl through the store and the model. While the
// server is paused the store refuses it and the model stands still.
func (m *model) crawl(force map[string]string) {
	by := rapid.SampledFrom(modelCrawlers).Draw(m.rt, "crawl actor")
	in := CrawlInput{Server: modelServer, Complete: true}
	seen := map[string]sighting{}
	live := map[string]string{} // tool -> digest the upstream serves
	rejected := 0
	for _, n := range modelToolNames {
		how, variant := m.drawSighting(n, force)
		seen[n] = how
		switch how {
		case usable:
			in.Tools = append(in.Tools, tool(n, variant))
			live[n] = modelDigest(n, variant)
		case unusable:
			in.Unusable = append(in.Unusable, unusableOf(n, "not-canonical"))
			if _, known := m.tools[n]; !known {
				// An unusable listing of a name no tool row describes creates
				// nothing: it is rejected, with one audit entry.
				rejected++
				seen[n] = absent
			}
		}
	}
	// Entries no tool row describes: an unknown name and a nameless one. Each
	// costs one tool.rejected entry and appears in Rejected, nothing more.
	extra := rapid.IntRange(0, 2).Draw(m.rt, "rejected entries")
	for i := 0; i < extra; i++ {
		name := ""
		if i == 0 {
			name = "ghost"
		}
		in.Unusable = append(in.Unusable, unusableOf(name, "unreadable"))
	}
	rejected += extra
	rep, err := m.s.RecordCrawl(bg, in, by)
	if m.paused {
		if !errors.Is(err, ErrPaused) {
			m.rt.Fatalf("RecordCrawl of a paused server: %v, want ErrPaused", err)
		}
		return
	}
	if err != nil {
		m.rt.Fatalf("RecordCrawl: %v", err)
	}
	next, events := m.applyCrawl(seen, live, by)
	m.gen++
	m.audits += events + 1 + rejected
	if len(rep.Rejected) != rejected {
		m.rt.Fatalf("report rejected %d entries, model %d", len(rep.Rejected), rejected)
	}
	// A deprecated tool the crawl did not list is neither loaded nor reported
	// (D13), unless it still carried the unusable marker, which this crawl
	// clears with one missing line; every other tool the model knows has one
	// line.
	var names []string
	for _, n := range sortedNames(next) {
		if seen[n] != absent || m.tools[n].State != lifecycle.Deprecated || m.tools[n].LastSeen != "" {
			names = append(names, n)
		}
	}
	if len(rep.Changes) != len(names) {
		m.rt.Fatalf("report lists %d tools, model expects %d (%v)", len(rep.Changes), len(names), names)
	}
	for i, c := range rep.Changes {
		if c.Tool != names[i] || c.State != next[c.Tool].State || c.Digest != live[c.Tool] ||
			(c.Reason != "") != (seen[c.Tool] == unusable) {
			m.rt.Fatalf("report line %d = %+v; model: %s %+v", i, c, names[i], next[names[i]])
		}
	}
	m.tools = next
}

// applyCrawl runs the observations through the pure lifecycle and returns the
// model's next state and how many events it produced.
func (m *model) applyCrawl(seen map[string]sighting, live map[string]string, by Actor) (map[string]lifecycle.Tool, int) {
	next := map[string]lifecycle.Tool{}
	for n, mt := range m.tools {
		next[n] = mt
	}
	for n, how := range seen {
		if _, ok := next[n]; !ok && how != absent {
			next[n] = lifecycle.Tool{State: lifecycle.Discovered}
		}
	}
	events := 0
	for _, n := range sortedNames(next) {
		cmd := lifecycle.ObserveCrawl{Present: seen[n] != absent, Digest: live[n], Unusable: seen[n] == unusable, Actor: by.Name}
		res, err := lifecycle.Apply(next[n], cmd, m.policy)
		if err != nil {
			m.rt.Fatalf("model refused an observation: %v", err)
		}
		next[n] = res.Tool
		events += len(res.Events)
		m.countEvents(res.Events)
	}
	return next, events
}
