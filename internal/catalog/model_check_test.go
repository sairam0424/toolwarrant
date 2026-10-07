package catalog

import (
	"errors"
	"slices"

	"pgregory.net/rapid"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// The operator half of the model test and the checks that compare the Store
// with the model after every step.

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
		v.Drifted != mt.Drifted() || v.Unusable != (mt.LastSeen == lifecycle.UnusableDigest) {
		rt.Fatalf("tool %s: store %+v, model %+v", name, v, mt)
	}
	vs, err := m.s.Versions(bg, modelServer, name)
	if err != nil || len(vs) != len(mt.Versions) {
		rt.Fatalf("Versions(%s) = %d, %v; model has %d", name, len(vs), err, len(mt.Versions))
	}
	for i, got := range vs {
		want := mt.Versions[i]
		if got.No != i+1 || got.Digest != want.Digest || got.Status != want.Status ||
			got.ProposedBy != want.ProposedBy || got.EverApproved != want.EverApproved ||
			!slices.Equal(got.Proposers, want.Proposers.All()) {
			rt.Fatalf("tool %s version %d: store %+v, model %+v (proposers %v)", name, i+1, got, want, want.Proposers.All())
		}
	}
}

func (m *model) checkPolicy(names []string) {
	rt := m.rt
	snap, err := m.s.Snapshot(bg, modelServer)
	if err != nil {
		rt.Fatalf("Snapshot: %v", err)
	}
	if snap.Generation != m.gen {
		rt.Fatalf("snapshot generation %d, model %d", snap.Generation, m.gen)
	}
	if m.paused {
		if len(snap.Tools) != 0 {
			rt.Fatalf("a paused server has %d tools in its snapshot", len(snap.Tools))
		}
	} else {
		m.checkServing(snap, names)
	}
	var approved []string
	for _, n := range names {
		if mt := m.tools[n]; mt.State == lifecycle.Enabled || mt.State == lifecycle.ChangedPendingReapproval {
			approved = append(approved, n)
		}
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

// checkServing compares the snapshot of a running server with the model.
func (m *model) checkServing(snap Snapshot, names []string) {
	rt := m.rt
	served := 0
	for _, n := range names {
		mt := m.tools[n]
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
		if snap.Serves(n, lifecycle.UnusableDigest) || snap.Serves(n, "") {
			rt.Fatalf("Serves(%s) is true for a non-digest live value", n)
		}
	}
	if len(snap.Tools) != served {
		rt.Fatalf("snapshot has %d tools; model %d", len(snap.Tools), served)
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
	srv, err := m.s.Server(bg, modelServer)
	if err != nil || srv.Paused != m.paused {
		rt.Fatalf("Server = %+v, %v; model paused=%t", srv, err, m.paused)
	}
}

func (m *model) countEvents(events []lifecycle.Event) {
	for _, ev := range events {
		m.stats["event:"+string(ev.Kind)]++
	}
}
