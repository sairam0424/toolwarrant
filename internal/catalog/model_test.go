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

// The model test drives random sequences of crawls and operator commands
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
	modelOperators = []Actor{bob, bob, alice, {Name: "carol", Type: ActorHuman}}
	modelSentinels = []error{
		lifecycle.ErrInvalidTransition, lifecycle.ErrUnknownVersion, lifecycle.ErrStaleVersion,
		lifecycle.ErrSelfApproval, lifecycle.ErrNotRollbackTarget, lifecycle.ErrNoActor, lifecycle.ErrNoDigest,
	}
	modelActions = []string{
		"crawl", "crawl", "crawl", "crawl", "crawl", "approve", "approve", "approve", "approve", "reject",
		"disable", "enable", "enable", "rollback", "rollback", "rollback", "cycle", "cycle", "cycle", "crawlFail", "reopen",
	}
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
	stats     map[string]int // how often each state and event was reached, logged for the reader
	variant   map[string]string
}

var modelRuns atomic.Int64

func TestModel_StoreFollowsTheLifecycleModel(t *testing.T) {
	dir := t.TempDir()
	stats := map[string]int{}
	defer func() { t.Logf("model coverage: %v", stats) }()
	rapid.Check(t, func(rt *rapid.T) {
		m := newModel(rt, filepath.Join(dir, fmt.Sprintf("m%d.db", modelRuns.Add(1))), stats)
		steps := rapid.IntRange(1, 40).Draw(rt, "steps")
		for i := 0; i < steps; i++ {
			m.step(rapid.SampledFrom(modelActions).Draw(rt, "action"))
			m.check()
		}
		if _, err := m.s.VerifyAudit(bg); err != nil {
			rt.Fatalf("VerifyAudit: %v", err)
		}
	})
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
		by := rapid.SampledFrom(modelCrawlers).Draw(m.rt, "actor")
		if _, err := m.s.RecordCrawl(bg, CrawlInput{Server: modelServer, Error: "down"}, by); err != nil {
			m.rt.Fatalf("incomplete RecordCrawl: %v", err)
		}
		m.gen++
		m.audits++
	case "reopen":
		if err := m.s.Close(); err != nil {
			m.rt.Fatalf("Close: %v", err)
		}
		s, err := Open(m.path, m.policy)
		if err != nil {
			m.rt.Fatalf("reopen: %v", err)
		}
		m.s = s
	default:
		m.decide(action)
	}
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

// crawl runs one complete crawl. force pins the variant of some tools; every
// other tool is listed, drifted or dropped at random.
func (m *model) crawl(force map[string]string) {
	by := rapid.SampledFrom(modelCrawlers).Draw(m.rt, "crawl actor")
	live := map[string]string{} // tool -> digest the upstream serves
	var crawled []CrawledTool
	for _, n := range modelToolNames {
		// Tools are usually listed and usually unchanged, so that approvals survive
		// long enough to be rolled back; the rest of the time they drift or vanish.
		forced, isForced := force[n]
		if !isForced && rapid.IntRange(0, 9).Draw(m.rt, "present "+n) >= 8 {
			continue
		}
		variant := rapid.SampledFrom(modelVariants).Draw(m.rt, "variant "+n)
		if last, ok := m.variant[n]; ok && rapid.IntRange(0, 9).Draw(m.rt, "keep "+n) < 7 {
			variant = last
		}
		if isForced {
			variant = forced
		}
		m.variant[n] = variant
		crawled = append(crawled, tool(n, variant))
		live[n] = modelDigest(n, variant)
	}

	next := map[string]lifecycle.Tool{}
	for n, mt := range m.tools {
		next[n] = mt
	}
	for n := range live {
		if _, ok := next[n]; !ok {
			next[n] = lifecycle.Tool{State: lifecycle.Discovered}
		}
	}
	events := 0
	for _, n := range sortedNames(next) {
		d, present := live[n]
		res, err := lifecycle.Apply(next[n], lifecycle.ObserveCrawl{Present: present, Digest: d, Actor: by.Name}, m.policy)
		if err != nil {
			m.rt.Fatalf("model refused an observation: %v", err)
		}
		next[n] = res.Tool
		events += len(res.Events)
		m.countEvents(res.Events)
	}

	rep, err := m.s.RecordCrawl(bg, CrawlInput{Server: modelServer, Complete: true, Tools: crawled}, by)
	if err != nil {
		m.rt.Fatalf("RecordCrawl: %v", err)
	}
	m.gen++
	m.audits += events + 1
	names := sortedNames(next)
	if len(rep.Changes) != len(names) {
		m.rt.Fatalf("report lists %d tools, model knows %d", len(rep.Changes), len(names))
	}
	for i, c := range rep.Changes {
		if c.Tool != names[i] || c.State != next[c.Tool].State || c.Digest != live[c.Tool] {
			m.rt.Fatalf("report line %d = %+v; model: %s %+v", i, c, names[i], next[names[i]])
		}
	}
	m.tools = next
}

// drawTool mostly picks a tool the model has seen, so commands have something to act on.
func (m *model) drawTool() string {
	if known := sortedNames(m.tools); len(known) > 0 && rapid.IntRange(0, 9).Draw(m.rt, "known tool") < 9 {
		return rapid.SampledFrom(known).Draw(m.rt, "tool")
	}
	return rapid.SampledFrom(modelToolNames).Draw(m.rt, "tool")
}

// drawDigest picks the digest a command names. Often it is the one that would
// make the command succeed (the pending proposal to approve or reject, an
// earlier approval to roll back to); otherwise anything, including digests the
// tool never had, so that stale, unknown and ineligible targets are exercised.
func (m *model) drawDigest(name, kind string) string {
	mt, known := m.tools[name]
	if known && rapid.IntRange(0, 9).Draw(m.rt, "sensible") < 6 {
		for _, v := range mt.Versions {
			switch {
			case kind != "rollback" && v.Status == lifecycle.VersionPending:
				return v.Digest
			case kind == "rollback" && v.EverApproved && v.Status != lifecycle.VersionApproved:
				return v.Digest
			}
		}
	}
	cands := []string{modelDigest(name, "never-seen"), modelDigest("other", "v0")}
	for _, v := range modelVariants {
		cands = append(cands, modelDigest(name, v))
	}
	for _, v := range mt.Versions {
		cands = append(cands, v.Digest)
	}
	return rapid.SampledFrom(cands).Draw(m.rt, "digest")
}

// decide runs one operator command on the Store and on the model, and
// requires that both accept it or both refuse it for the same reason.
func (m *model) decide(kind string) {
	name := m.drawTool()
	by := rapid.SampledFrom(modelOperators).Draw(m.rt, "operator")
	m.run(kind, name, by, m.drawDigest(name, kind))
}

// run executes one command on the Store and on the model.
func (m *model) run(kind, name string, by Actor, digest string) {
	var (
		cmd      lifecycle.Command
		storeErr error
		decision bool
	)
	switch kind {
	case "approve":
		cmd, decision = lifecycle.Approve{Digest: digest, Actor: by.Name}, true
		storeErr = m.s.Approve(bg, modelServer, name, digest, by)
	case "reject":
		cmd, decision = lifecycle.Reject{Digest: digest, Actor: by.Name}, true
		storeErr = m.s.Reject(bg, modelServer, name, digest, by)
	case "rollback":
		cmd, decision = lifecycle.Rollback{To: digest, Actor: by.Name}, true
		storeErr = m.s.Rollback(bg, modelServer, name, digest, by)
	case "disable":
		cmd = lifecycle.Disable{Actor: by.Name}
		storeErr = m.s.Disable(bg, modelServer, name, by)
	case "enable":
		cmd = lifecycle.Enable{Actor: by.Name}
		storeErr = m.s.Enable(bg, modelServer, name, by)
	default:
		m.rt.Fatalf("unknown action %q", kind)
	}
	m.expect(name, cmd, storeErr, decision)
}

func (m *model) expect(name string, cmd lifecycle.Command, storeErr error, decision bool) {
	mt, known := m.tools[name]
	if !known {
		if !errors.Is(storeErr, ErrNotFound) {
			m.rt.Fatalf("%T on a tool nobody has seen: %v, want ErrNotFound", cmd, storeErr)
		}
		return
	}
	res, modelErr := lifecycle.Apply(mt, cmd, m.policy)
	if modelErr != nil {
		if storeErr == nil {
			m.rt.Fatalf("%T %+v: the store accepted a command the lifecycle refuses (%v)", cmd, cmd, modelErr)
		}
		for _, sentinel := range modelSentinels {
			if errors.Is(modelErr, sentinel) && !errors.Is(storeErr, sentinel) {
				m.rt.Fatalf("%T: lifecycle says %v, store says %v", cmd, modelErr, storeErr)
			}
		}
		return
	}
	if storeErr != nil {
		m.rt.Fatalf("%T %+v: the lifecycle accepts it but the store refused: %v", cmd, cmd, storeErr)
	}
	m.tools[name] = res.Tool
	m.gen++
	m.audits += len(res.Events)
	m.countEvents(res.Events)
	if decision {
		m.approvals++
	}
}

// check reads everything back through the public API and compares it with the model.
func (m *model) check() {
	rt := m.rt
	names := sortedNames(m.tools)
	views, err := m.s.Tools(bg, modelServer)
	if err != nil {
		rt.Fatalf("Tools: %v", err)
	}
	if len(views) != len(names) {
		rt.Fatalf("store lists %d tools, model %d", len(views), len(names))
	}
	for i, v := range views {
		m.checkTool(names[i], v)
		m.stats["state:"+string(v.State)]++
	}
	m.checkPolicy(names)
	m.checkCounters()
}

func (m *model) checkTool(name string, v ToolView) {
	rt, mt := m.rt, m.tools[name]
	if v.Name != name || v.State != mt.State || v.Approved != mt.Approved || v.LastSeen != mt.LastSeen ||
		v.MissingCrawls != mt.MissingCrawls || v.Versions != len(mt.Versions) || v.Pending != mt.Pending() ||
		v.Drifted != mt.Drifted() {
		rt.Fatalf("tool %s: store %+v, model %+v", name, v, mt)
	}
	vs, err := m.s.Versions(bg, modelServer, name)
	if err != nil || len(vs) != len(mt.Versions) {
		rt.Fatalf("Versions(%s) = %d, %v; model has %d", name, len(vs), err, len(mt.Versions))
	}
	for i, got := range vs {
		want := mt.Versions[i]
		if got.No != i+1 || got.Digest != want.Digest || got.Status != want.Status ||
			got.ProposedBy != want.ProposedBy || got.EverApproved != want.EverApproved {
			rt.Fatalf("tool %s version %d: store %+v, model %+v", name, i+1, got, want)
		}
	}
}

func (m *model) checkPolicy(names []string) {
	rt := m.rt
	snap, err := m.s.Snapshot(bg, modelServer)
	if err != nil {
		rt.Fatalf("Snapshot: %v", err)
	}
	served := 0
	var approved []string
	for _, n := range names {
		mt := m.tools[n]
		if mt.State == lifecycle.Enabled || mt.State == lifecycle.ChangedPendingReapproval {
			approved = append(approved, n)
		}
		if mt.State == lifecycle.Deprecated {
			if _, ok := snap.Tools[n]; ok {
				rt.Fatalf("deprecated tool %s is in the snapshot", n)
			}
			continue
		}
		served++
		if p := snap.Tools[n]; p.State != mt.State || p.Approved != mt.Approved || p.LastSeen != mt.LastSeen {
			rt.Fatalf("snapshot of %s = %+v, model %+v", n, p, mt)
		}
		for _, v := range modelVariants {
			live := modelDigest(n, v)
			if snap.Serves(n, live) != mt.Serves(live) {
				rt.Fatalf("Serves(%s, %s) disagrees with the model (state %s)", n, v, mt.State)
			}
		}
	}
	if len(snap.Tools) != served || snap.Generation != m.gen {
		rt.Fatalf("snapshot has %d tools at generation %d; model %d at %d", len(snap.Tools), snap.Generation, served, m.gen)
	}
	list, err := m.s.Approved(bg)
	if err != nil || len(list) != len(approved) {
		rt.Fatalf("Approved = %d, %v; model %v", len(list), err, approved)
	}
	for i, a := range list {
		if a.Name != approved[i] || a.Digest != m.tools[a.Name].Approved || a.ApprovedBy == "" {
			rt.Fatalf("Approved[%d] = %+v, model %+v", i, a, m.tools[approved[i]])
		}
	}
}

func (m *model) checkCounters() {
	rt := m.rt
	if gen, err := m.s.Generation(bg); err != nil || gen != m.gen {
		rt.Fatalf("Generation = %d, %v; model %d", gen, err, m.gen)
	}
	entries, err := m.s.AuditEntries(bg, 0, 0)
	if err != nil || len(entries) != m.audits {
		rt.Fatalf("audit entries = %d, %v; model %d", len(entries), err, m.audits)
	}
	var n int
	if err := m.s.rdb.QueryRowContext(bg, `SELECT COUNT(*) FROM approvals`).Scan(&n); err != nil || n != m.approvals {
		rt.Fatalf("approvals rows = %d, %v; model %d", n, err, m.approvals)
	}
}

func (m *model) countEvents(events []lifecycle.Event) {
	for _, ev := range events {
		m.stats["event:"+string(ev.Kind)]++
	}
}
