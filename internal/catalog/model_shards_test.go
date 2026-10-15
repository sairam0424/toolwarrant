package catalog

import (
	"flag"
	"strconv"
	"testing"
)

// The model test's checks are split across parallel rapid runs. rapid v1.3.0
// takes the number of checks only from its rapid.checks flag, so the test
// lowers the flag to the per-shard share while the shards run and restores it
// afterwards. The shards run while no other test of the package does: the
// model test is a serial test with parallel subtests, the go tool starts
// parallel top-level tests only after every serial one has returned, and a
// serial test returns only after its subtests have finished. No other
// rapid.Check therefore reads the lowered value, which is also why the model
// test itself must never call t.Parallel.
//
// A failing shard is reproduced the way rapid says: its printed
// -run="TestModel_StoreFollowsTheLifecycleModel/shards/shardN" plus the
// -rapid.failfile or -rapid.seed it names. That runs the one shard, so
// checkShardRuns compares the count only when every shard ran
// (TestCheckShardRuns_toleratesAShardDeselectedByRun).

const (
	// modelShards is how many parallel rapid runs the model test is split
	// into. rapid's default of 100 checks gives ten per shard; the ci runner's
	// four cores run four shards at a time, a ten-core laptop all ten.
	modelShards = 10
	// rapidChecksFlag is the flag rapid reads the number of checks from.
	rapidChecksFlag = "rapid.checks"
	// rapidShortDivisor is the share of the checks rapid v1.3.0 runs under
	// -short (engine.go, checkTB: checks /= 5). A shard's share must be a
	// multiple of it so that the shards together still run a fifth of the
	// total, and the run count the shards report is compared with the full
	// total and with that fifth.
	rapidShortDivisor = 5
)

// shardPlan is how the model test splits rapid's check count.
type shardPlan struct {
	total, shards, perShard int
}

// planShards reads rapid's check count and splits it into modelShards equal
// shards. When the count does not split evenly, or a shard's share would not
// shorten evenly under -short, the test runs as one shard, which is the plain
// rapid.Check of before: the split never changes how many checks run.
func planShards(t *testing.T) shardPlan {
	t.Helper()
	f := flag.Lookup(rapidChecksFlag)
	if f == nil {
		t.Fatalf("flag %s is not registered; rapid is not linked into this test binary", rapidChecksFlag)
	}
	total, err := strconv.Atoi(f.Value.String())
	if err != nil || total <= 0 {
		t.Fatalf("flag %s = %q: %v", rapidChecksFlag, f.Value.String(), err)
	}
	p := shardPlan{total: total, shards: modelShards, perShard: total / modelShards}
	if total%modelShards != 0 || p.perShard%rapidShortDivisor != 0 {
		t.Logf("%s=%d does not split into %d shards of a multiple of %d checks; running one shard", rapidChecksFlag, total, modelShards, rapidShortDivisor)
		p.shards, p.perShard = 1, total
	}
	return p
}

// setChecks sets rapid's check count and returns the function that restores
// the previous value.
func setChecks(t *testing.T, n int) func() {
	t.Helper()
	f := flag.Lookup(rapidChecksFlag)
	was := f.Value.String()
	if err := f.Value.Set(strconv.Itoa(n)); err != nil {
		t.Fatalf("set %s=%d: %v", rapidChecksFlag, n, err)
	}
	return func() {
		if err := f.Value.Set(was); err != nil {
			t.Errorf("restore %s=%s: %v", rapidChecksFlag, was, err)
		}
	}
}

// checkShardRuns logs how many checks the shards ran and fails when they did
// not run the whole count between them: every shard ran the same number, the
// models built agree with the sum, and the sum is rapid's full count or,
// under -short, its fifth. After a failure the count says nothing, since rapid
// re-runs a failing case while it shrinks it, so only the log line is kept.
// A shard that ran no check was left out by -run, which is how rapid's
// reproduction command runs one shard: a shard the go tool runs performs at
// least perShard/rapidShortDivisor checks, at least one whenever the plan is
// sharded, since perShard is then a positive multiple of rapidShortDivisor.
// The count is not compared then either.
func checkShardRuns(t *testing.T, plan shardPlan, runs []int, built int64) {
	t.Helper()
	sum := 0
	for _, n := range runs {
		sum += n
	}
	t.Logf("model runs: %d checks across %d shards (%s=%d)", sum, plan.shards, rapidChecksFlag, plan.total)
	if t.Failed() {
		return
	}
	for i, n := range runs {
		if n == 0 {
			t.Logf("shard %d ran no check: -run selected a subset of the shards, so the count is not compared", i)
			return
		}
	}
	for i, n := range runs {
		if n != runs[0] {
			t.Errorf("shard %d ran %d checks, shard 0 ran %d; the shards must share the count equally", i, n, runs[0])
		}
	}
	if int64(sum) != built {
		t.Errorf("the shards ran %d checks but built %d models", sum, built)
	}
	if sum != plan.total && sum != plan.total/rapidShortDivisor {
		t.Errorf("the shards ran %d checks in all, want %d (or %d under -short)", sum, plan.total, plan.total/rapidShortDivisor)
	}
}

// TestCheckShardRuns_toleratesAShardDeselectedByRun is the reproduction
// path: rapid's printed -run selects one shard, the other slots stay at zero,
// and the count check must not fail the parent. checkShardRuns reports
// through this test's t, so any t.Errorf it made would fail this test.
func TestCheckShardRuns_toleratesAShardDeselectedByRun(t *testing.T) {
	t.Parallel()
	plan := shardPlan{total: 100, shards: modelShards, perShard: 10}
	runs := make([]int, plan.shards)
	runs[3] = 2
	checkShardRuns(t, plan, runs, 2)
}

// mergeStats adds the shards' coverage counters into one map for the log.
func mergeStats(parts []map[string]int) map[string]int {
	merged := map[string]int{}
	for _, part := range parts {
		for k, v := range part {
			merged[k] += v
		}
	}
	return merged
}
