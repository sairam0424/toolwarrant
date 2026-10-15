package catalog

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"

	"pgregory.net/rapid"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
	"github.com/sairam0424/toolwarrant/internal/signing"
	"github.com/sairam0424/toolwarrant/internal/trust"
)

// trustRuns counts every catalog the property built, across shards; the
// shards' run count is compared with it.
var trustRuns atomic.Int64

// The trust list a fresh Store's walk puts in force equals the list obtained
// by replaying the stored records through internal/trust alone, for any
// history of valid rotations among a pool of four keys with crawls in between:
// the walk adds nothing to the rules and loses nothing of the records. The
// property runs in parallel shards that together perform rapid's check count,
// as the model test does and for the same reason (model_shards_test.go: one
// catalog per check costs a schema and several synced commits, so one rapid
// run of a hundred checks takes half a minute under the race detector); the
// test stays serial while its shards run.
func TestProperty_trustStateAfterAWalkEqualsTheStateAfterReplayingTheRecords(t *testing.T) {
	plan := planShards(t)
	built := trustRuns.Load()
	runs := make([]int, plan.shards)
	pool := []operator{newOperator(t, "alice"), newOperator(t, "bob"), newOperator(t, "carol"), newOperator(t, "dave")}
	restore := setChecks(t, plan.perShard)
	t.Run("shards", func(t *testing.T) {
		for i := range plan.shards {
			t.Run(fmt.Sprintf("shard%d", i), func(t *testing.T) {
				t.Parallel()
				dir := t.TempDir()
				rapid.Check(t, func(rt *rapid.T) {
					runs[i]++
					checkTrustOnce(t, rt, dir, pool)
				})
			})
		}
	})
	restore()
	checkShardRuns(t, plan, runs, trustRuns.Load()-built)
}

// checkTrustOnce is one check of the property: a fresh catalog under dir, a
// drawn bootstrap and up to six drawn rotations with crawls between, then the
// fresh walk and the replay compared with the expected fold.
func checkTrustOnce(t *testing.T, rt *rapid.T, dir string, pool []operator) {
	t.Helper()
	n := trustRuns.Add(1)
	path := filepath.Join(dir, fmt.Sprintf("catalog-%d.db", n))
	s, err := Open(path, lifecycle.DefaultPolicy())
	if err != nil {
		rt.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	mustAddServer(t, s, "alpha")
	expected := trust.State{}
	members := drawMembers(rt, pool, -1)
	by := members[rapid.IntRange(0, len(members)-1).Draw(rt, "bootstrapper")]
	root := by.fp()
	r, list := setTrustDrawn(rt, s, 1, by, members)
	expected = foldExpected(rt, expected, r.Seq, trust.KindBootstrap, list, by)
	rotations := rapid.IntRange(0, 6).Draw(rt, "rotations")
	for i := 0; i < rotations; i++ {
		if rapid.Bool().Draw(rt, "crawl between") {
			mustCrawl(t, s, "alpha", tool("echo", "v"+itoa(int64(i))))
		}
		by = members[rapid.IntRange(0, len(members)-1).Draw(rt, "signer")]
		members = drawMembers(rt, pool, poolIndex(pool, by))
		r, list = setTrustDrawn(rt, s, expected.Current.Version+1, by, members)
		expected = foldExpected(rt, expected, r.Seq, trust.KindRotated, list, by)
	}
	_ = s.Close()

	fresh, err := OpenWith(path, OpenOptions{ReadOnly: true})
	if err != nil {
		rt.Fatalf("fresh open: %v", err)
	}
	defer func() { _ = fresh.Close() }()
	view, err := fresh.TrustList(bg)
	if err != nil {
		rt.Fatal(err)
	}
	compareWithState(rt, "the walk", view, expected, members)
	if view.Root != root || view.Lists != rotations+1 {
		rt.Fatalf("the view's root is %s and it counts %d lists; the bootstrap was signed by %s and %d lists were written", view.Root, view.Lists, root, rotations+1)
	}
	replayed := replayRecords(rt, path)
	if replayed.Current.Version != expected.Current.Version || replayed.BootstrapSeq != expected.BootstrapSeq || replayed.ListSeq != expected.ListSeq ||
		!slices.Equal(namesOf(replayed.Current), namesOf(expected.Current)) {
		rt.Fatalf("replay = v%d (%d, %d, %v), expected v%d (%d, %d, %v)", replayed.Current.Version, replayed.BootstrapSeq, replayed.ListSeq, namesOf(replayed.Current),
			expected.Current.Version, expected.BootstrapSeq, expected.ListSeq, namesOf(expected.Current))
	}
}

// drawMembers draws a non-empty subset of the pool, in pool order, that
// includes pool[must] when must is not negative.
func drawMembers(rt *rapid.T, pool []operator, must int) []operator {
	picked := rapid.SliceOfNDistinct(rapid.IntRange(0, len(pool)-1), 1, len(pool), rapid.ID[int]).Draw(rt, "members")
	if must >= 0 && !slices.Contains(picked, must) {
		picked = append(picked, must)
	}
	slices.Sort(picked)
	out := make([]operator, 0, len(picked))
	for _, i := range picked {
		out = append(out, pool[i])
	}
	return out
}

// poolIndex is the position of op in the pool, by name (a Key holds a slice,
// so the struct is not comparable).
func poolIndex(pool []operator, op operator) int {
	return slices.IndexFunc(pool, func(p operator) bool { return p.name == op.name })
}

// setTrustDrawn signs and records a list of version v naming members, by by.
func setTrustDrawn(rt *rapid.T, s *Store, v int, by operator, members []operator) (Receipt, signing.TrustList) {
	head, err := s.AuditHead(bg)
	if err != nil {
		rt.Fatal(err)
	}
	list := listFor(s.identity, head, v, by, members...)
	payload, err := signing.MarshalTrustList(list)
	if err != nil {
		rt.Fatal(err)
	}
	rec, err := signing.Sign(bg, payload, by.key.Signer, signing.NamespaceTrust)
	if err != nil {
		rt.Fatal(err)
	}
	r, err := s.SetTrust(bg, rec, by.actor())
	if err != nil {
		rt.Fatalf("SetTrust v%d by %s: %v", v, by.name, err)
	}
	return r, list
}

// foldExpected folds one accepted list into the expected state through
// internal/trust alone.
func foldExpected(rt *rapid.T, state trust.State, seq int64, kind trust.Kind, list signing.TrustList, by operator) trust.State {
	record, err := trust.Validate(list)
	if err != nil {
		rt.Fatal(err)
	}
	next, err := state.Apply(seq, kind, record, by.fp(), "")
	if err != nil {
		rt.Fatalf("expected fold refused what SetTrust accepted: %v", err)
	}
	return next
}

// compareWithState requires a view to equal a state and to name members.
func compareWithState(rt *rapid.T, label string, view TrustView, state trust.State, members []operator) {
	names := make([]string, 0, len(members))
	for _, m := range members {
		names = append(names, m.name)
	}
	if view.Version != state.Current.Version || view.BootstrapSeq != state.BootstrapSeq || view.ListSeq != state.ListSeq ||
		!slices.Equal(signerNames(view), names) || !slices.Equal(signerNames(view), namesOf(state.Current)) {
		rt.Fatalf("%s: view %+v, expected v%d (%d, %d, %v)", label, view, state.Current.Version, state.BootstrapSeq, state.ListSeq, namesOf(state.Current))
	}
}

// namesOf lists a record's operator names in order.
func namesOf(r *trust.Record) []string {
	if r == nil {
		return nil
	}
	out := make([]string, 0, len(r.Signers))
	for _, op := range r.Signers {
		out = append(out, op.Name)
	}
	return out
}

// replayRecords folds every trust record of the file through internal/trust
// from the raw rows, in seq order, as an auditor without the catalog would.
func replayRecords(rt *rapid.T, path string) trust.State {
	db, err := sql.Open(driverName, dsnFor(path, connReader, DefaultBusyTimeout))
	if err != nil {
		rt.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.QueryContext(bg, `SELECT l.seq, l.event, r.payload, r.signer_fingerprint FROM audit_log l JOIN signed_records r ON r.seq = l.seq ORDER BY l.seq`)
	if err != nil {
		rt.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	state := trust.State{}
	for rows.Next() {
		var (
			seq           int64
			event, signer string
			payload       []byte
		)
		if err := rows.Scan(&seq, &event, &payload, &signer); err != nil {
			rt.Fatal(err)
		}
		list, err := signing.ParseTrustList(payload)
		if err != nil {
			rt.Fatal(err)
		}
		record, err := trust.Validate(list)
		if err != nil {
			rt.Fatal(err)
		}
		if state, err = state.Apply(seq, trust.Kind(event), record, signer, ""); err != nil {
			rt.Fatalf("replay refused entry %d: %v", seq, err)
		}
	}
	if err := rows.Err(); err != nil {
		rt.Fatal(err)
	}
	return state
}
