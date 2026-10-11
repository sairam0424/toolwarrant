package processor

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	api "github.com/sairam0424/toolwarrant/internal/extmcpv1"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// stubSource lets a test script every answer, including a Source that lies.
type stubSource struct {
	gen  func(ctx context.Context) (int64, error)
	snap func(ctx context.Context, server string) (catalog.Snapshot, error)
}

func (s stubSource) Generation(ctx context.Context) (int64, error) { return s.gen(ctx) }
func (s stubSource) Snapshot(ctx context.Context, server string) (catalog.Snapshot, error) {
	return s.snap(ctx, server)
}

func TestCache_ReloadsOnlyWhenTheGenerationMoves(t *testing.T) {
	d1 := mustDigest(t, echoV1)
	tools := map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)}
	src := newFakeSource(tools)
	s, _ := newTestServer(src)

	for i := 0; i < 10; i++ {
		servedNames(t, list(t, s, listBody("", echoV1)))
		requireAllowed(t, call(t, s, callReq("echo")))
	}
	if g, sn := src.calls(); g != 20 || sn != 1 {
		t.Fatalf("20 hooks made %d generation reads and %d snapshot loads; want 20 and 1", g, sn)
	}

	src.publish(tools)
	requireAllowed(t, call(t, s, callReq("echo")))
	if _, sn := src.calls(); sn != 2 {
		t.Fatalf("a generation change should cost exactly one more snapshot load, got %d total", sn)
	}
}

func TestCache_GenerationChangeTakesEffectOnTheVeryNextHook(t *testing.T) {
	d1, d2 := mustDigest(t, echoV1), mustDigest(t, echoV2)
	src := newFakeSource(map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)})
	s, _ := newTestServer(src)

	servedNames(t, list(t, s, listBody("", echoV1)))
	requireAllowed(t, call(t, s, callReq("echo")))

	// Disable: the very next list hides it and the very next call is denied.
	src.publish(map[string]catalog.ToolPolicy{"echo": policy(lifecycle.Disabled, d1, d1)})
	if got := servedNames(t, list(t, s, listBody("", echoV1))); len(got) != 0 {
		t.Fatalf("a disabled tool was served: %v", got)
	}
	requireCallDenied(t, call(t, s, callReq("echo")), "echo", causeNotApproved)

	// Re-enable: served again at once.
	src.publish(map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)})
	servedNames(t, list(t, s, listBody("", echoV1)))
	requireAllowed(t, call(t, s, callReq("echo")))

	// The owner approves the new definition: v2 is served, v1 is now the drift.
	src.publish(map[string]catalog.ToolPolicy{"echo": servedPolicy(d2)})
	if got := servedNames(t, list(t, s, listBody("", echoV1))); len(got) != 0 {
		t.Fatalf("the old definition is still served after re-approval: %v", got)
	}
	requireCallDenied(t, call(t, s, callReq("echo")), "echo", causeChanged)
	if got := servedNames(t, list(t, s, listBody("", echoV2))); len(got) != 1 {
		t.Fatalf("the newly approved definition is not served: %v", got)
	}
	requireAllowed(t, call(t, s, callReq("echo")))
}

func TestCache_NeverFallsBackToAStaleSnapshot(t *testing.T) {
	d1 := mustDigest(t, echoV1)
	enabled := map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)}
	src := newFakeSource(enabled)
	s, _ := newTestServer(src)
	requireAllowed(t, call(t, s, callReq("echo"))) // the cache now says "enabled"

	// The owner disables the tool, but the processor cannot read the new snapshot.
	src.publish(map[string]catalog.ToolPolicy{"echo": policy(lifecycle.Disabled, d1, d1)})
	src.failSnapshot(errors.New("disk I/O error"))
	requireCallDenied(t, call(t, s, callReq("echo")), "echo", causeUnavailable)
	requireListDenied(t, list(t, s, listBody("", echoV1)), api.AuthorizationError_PERMISSION_DENIED)

	// It recovers by retrying, and then sees the disabled state.
	src.failSnapshot(nil)
	requireCallDenied(t, call(t, s, callReq("echo")), "echo", causeNotApproved)

	// A generation read that fails must not fall back to the cache either.
	src.publish(enabled)
	requireAllowed(t, call(t, s, callReq("echo")))
	_, loadsBefore := src.calls()
	src.failGeneration(errors.New("database is locked"))
	requireCallDenied(t, call(t, s, callReq("echo")), "echo", causeUnavailable)
	src.failGeneration(nil)
	requireAllowed(t, call(t, s, callReq("echo")))
	if _, loads := src.calls(); loads != loadsBefore {
		t.Errorf("the generation did not move, so recovery should reuse the cache (%d loads, was %d)", loads, loadsBefore)
	}
	if n := s.Stats().SourceErrors; n != 3 {
		t.Errorf("SourceErrors = %d, want 3", n)
	}
}

func TestCache_RejectsSnapshotsItCannotTrust(t *testing.T) {
	d1 := mustDigest(t, echoV1)
	tools := map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)}
	build := func(gen int64, snap catalog.Snapshot) (*Server, *int) {
		loads := 0
		src := stubSource{
			gen: func(context.Context) (int64, error) { return gen, nil },
			snap: func(context.Context, string) (catalog.Snapshot, error) {
				loads++
				return snap, nil
			},
		}
		s, _ := newTestServer(src)
		return s, &loads
	}

	t.Run("snapshot of another server", func(t *testing.T) {
		s, _ := build(5, catalog.Snapshot{Server: "other", Generation: 5, Tools: tools})
		requireCallDenied(t, call(t, s, callReq("echo")), "echo", causeUnavailable)
		if s.Stats().SourceErrors != 1 {
			t.Errorf("stats = %+v", s.Stats())
		}
	})
	t.Run("snapshot older than the generation just read", func(t *testing.T) {
		s, _ := build(5, catalog.Snapshot{Server: testServer, Generation: 3, Tools: tools})
		requireCallDenied(t, call(t, s, callReq("echo")), "echo", causeUnavailable)
	})
	t.Run("unstamped snapshot is accepted", func(t *testing.T) {
		s, _ := build(5, catalog.Snapshot{Tools: tools})
		requireAllowed(t, call(t, s, callReq("echo")))
	})
	t.Run("snapshot newer than the generation read is accepted and cached under the earlier read", func(t *testing.T) {
		s, loads := build(5, catalog.Snapshot{Server: testServer, Generation: 6, Tools: tools})
		requireAllowed(t, call(t, s, callReq("echo")))
		requireAllowed(t, call(t, s, callReq("echo")))
		if *loads != 1 {
			t.Errorf("loads = %d, want 1", *loads)
		}
	})
}

func TestCache_SourceCannotMutateTheCachedSnapshot(t *testing.T) {
	d1 := mustDigest(t, echoV1)
	tools := map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)}
	src := stubSource{
		gen:  func(context.Context) (int64, error) { return 1, nil },
		snap: func(context.Context, string) (catalog.Snapshot, error) { return catalog.Snapshot{Tools: tools}, nil },
	}
	s, _ := newTestServer(src)
	requireAllowed(t, call(t, s, callReq("echo")))

	// A Source that keeps writing to the map it handed over, without bumping
	// the generation, must not change what the processor serves.
	delete(tools, "echo")
	maps.Copy(tools, map[string]catalog.ToolPolicy{"wipe_database": servedPolicy(d1)})
	requireAllowed(t, call(t, s, callReq("echo")))
	requireCallDenied(t, call(t, s, callReq("wipe_database")), "wipe_database", causeNotApproved)
}

// D14(g): when a tool leaves a non-empty snapshot, evidence that agreed with
// its approval is forgotten, so a tool re-created under the same name starts
// clean; a contradiction (a changed digest or the conflict marker) is kept,
// because losing it would re-allow a call the gateway's own listing had denied,
// and the re-created tool is denied as changed until a listing records what
// the upstream serves. Before this round every absent name was forgotten.
func TestCache_ObservedEvidenceIsPrunedWhenAToolLeavesTheCatalog(t *testing.T) {
	d1 := mustDigest(t, echoV1)
	other := tool("other", "o")
	dOther := mustDigest(t, other)
	withBoth := map[string]catalog.ToolPolicy{"echo": servedPolicy(d1), "other": servedPolicy(dOther)}
	onlyOther := map[string]catalog.ToolPolicy{"other": servedPolicy(dOther)}

	t.Run("agreeing evidence is forgotten", func(t *testing.T) {
		src := newFakeSource(withBoth)
		s, _ := newTestServer(src)
		servedNames(t, list(t, s, listBody("", echoV1, other))) // both agree with their approvals
		src.publish(onlyOther)
		requireCallDenied(t, call(t, s, callReq("echo")), "echo", causeNotApproved)
		if _, ok := s.observedDigest("echo"); ok || s.trackedCount() != 1 {
			t.Fatalf("agreeing evidence for a tool that left the catalog was kept (%d tracked)", s.trackedCount())
		}
		src.publish(withBoth) // re-created under the same name: no stale evidence
		requireAllowed(t, call(t, s, callReq("echo")))
	})
	t.Run("a contradiction is kept", func(t *testing.T) {
		src := newFakeSource(withBoth)
		s, _ := newTestServer(src)
		servedNames(t, list(t, s, listBody("", echoV2, other))) // drifted: observed = d2
		requireCallDenied(t, call(t, s, callReq("echo")), "echo", causeChanged)
		src.publish(onlyOther)
		requireCallDenied(t, call(t, s, callReq("echo")), "echo", causeNotApproved)
		if seen, ok := s.observedDigest("echo"); !ok || seen != mustDigest(t, echoV2) {
			t.Fatalf("the contradiction for echo was pruned: %q, %v", seen, ok)
		}
		src.publish(withBoth) // re-created: still denied until a listing shows the approved bytes
		requireCallDenied(t, call(t, s, callReq("echo")), "echo", causeChanged)
		servedNames(t, list(t, s, listBody("", echoV1)))
		requireAllowed(t, call(t, s, callReq("echo")))
	})
}

// A tools/list hook that read the previous snapshot can reach observe after a
// reload has pruned the table for the newer one. Such a late write must not
// resurrect a name the catalog dropped (deterministic form of the reviewers'
// race), while a late write about a tool still in the catalog is kept: it is
// the newest evidence about the upstream.
func TestCache_LateObservationForADroppedToolIsNotRecorded(t *testing.T) {
	d1, d2 := mustDigest(t, echoV1), mustDigest(t, echoV2)
	zzz := tool("zzz", "Z")
	dz := mustDigest(t, zzz)
	src := newFakeSource(map[string]catalog.ToolPolicy{"echo": servedPolicy(d1), "zzz": servedPolicy(dz)})
	s, _ := newTestServer(src)
	servedNames(t, list(t, s, listBody("", zzz, echoV1)))

	src.publish(map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)}) // zzz leaves the catalog
	requireAllowed(t, call(t, s, callReq("echo")))                       // reload and prune
	if _, ok := s.observedDigest("zzz"); ok {
		t.Fatal("the prune left zzz tracked")
	}

	// The late writer computed against the old snapshot, in which zzz existed.
	s.observe("zzz", dz)
	if _, ok := s.observedDigest("zzz"); ok {
		t.Fatal("a late observation resurrected a tool the catalog dropped")
	}
	s.observe("echo", d2)
	if seen, ok := s.observedDigest("echo"); !ok || seen != d2 {
		t.Fatalf("a late observation for a tool still in the catalog was dropped: %q, %v", seen, ok)
	}
	requireCallDenied(t, call(t, s, callReq("echo")), "echo", causeChanged)

	// zzz re-created under the same name with a new approval starts clean.
	src.publish(map[string]catalog.ToolPolicy{"echo": servedPolicy(d1), "zzz": servedPolicy(mustDigest(t, tool("zzz", "Z v2")))})
	requireAllowed(t, call(t, s, callReq("zzz")))
}

// The reviewers' probabilistic race, kept as a sanity check: no round may
// leave zzz tracked after the reload that dropped it.
func TestCache_ObservationsNeverOutliveThePruneUnderConcurrentReloads(t *testing.T) {
	d1 := mustDigest(t, echoV1)
	zzz := tool("zzz", "Z")
	withZ := map[string]catalog.ToolPolicy{"echo": servedPolicy(d1), "zzz": servedPolicy(mustDigest(t, zzz))}
	without := map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)}

	var gen atomic.Int64
	var cur atomic.Pointer[map[string]catalog.ToolPolicy]
	gen.Store(1)
	cur.Store(&withZ)
	src := stubSource{
		gen: func(context.Context) (int64, error) { return gen.Load(), nil },
		snap: func(context.Context, string) (catalog.Snapshot, error) {
			return catalog.Snapshot{Server: testServer, Generation: gen.Load(), Tools: *cur.Load()}, nil
		},
	}
	s := New(src, Config{Server: testServer, Logger: slog.New(slog.DiscardHandler)})
	page := listBody("", zzz, echoV1)
	for round := 0; round < 30; round++ {
		gen.Add(1)
		cur.Store(&withZ)
		var wg sync.WaitGroup
		for w := 0; w < 4; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < 10; i++ {
					_, _ = s.CheckResponse(context.Background(), listMsg(page))
				}
			}()
		}
		runtime.Gosched()
		cur.Store(&without)
		gen.Add(1)
		_, _ = s.CheckRequest(context.Background(), callReq("echo")) // forces the reload and the prune
		wg.Wait()
		if _, ok := s.observedDigest("zzz"); ok {
			t.Fatalf("round %d: an observation for zzz survived the reload that dropped it", round)
		}
	}
}

// D2: a processor without a target name can be about no backend, so every
// hooked method is refused as "wrong backend" before the catalog is consulted;
// a processor with a target but no server name reaches the catalog check and
// denies as unavailable.
func TestCache_MisconfiguredServerDeniesInsteadOfPanicking(t *testing.T) {
	d1 := mustDigest(t, echoV1)
	src := newFakeSource(map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)})
	quiet := slog.New(slog.DiscardHandler)
	cases := map[string]struct {
		s    *Server
		want cause
	}{
		"nil source":           {New(nil, Config{Server: testServer, Logger: quiet}), causeUnavailable},
		"target but no server": {New(src, Config{Target: testServer, Logger: quiet}), causeUnavailable},
		"empty name":           {New(src, Config{Logger: quiet}), causeWrongBackend},
		"both absent":          {New(nil, Config{Logger: quiet}), causeWrongBackend},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			res := call(t, tc.s, callReq("echo"))
			if tc.want == causeWrongBackend {
				requireRefused(t, res, api.AuthorizationError_PERMISSION_DENIED, causeWrongBackend)
			} else {
				requireCallDenied(t, res, "echo", tc.want)
			}
			requireListDenied(t, list(t, tc.s, listBody("", echoV1)), api.AuthorizationError_PERMISSION_DENIED)
		})
	}
}

func TestNew_AppliesDefaults(t *testing.T) {
	for _, n := range []int{0, -5} {
		s := New(nil, Config{Server: testServer, MaxTracked: n})
		if s.maxTracked != DefaultMaxTracked {
			t.Errorf("MaxTracked %d gave %d, want the default %d", n, s.maxTracked, DefaultMaxTracked)
		}
		if s.log == nil || s.log != slog.Default() {
			t.Error("a nil Logger should fall back to slog.Default()")
		}
		if s.target != testServer {
			t.Errorf("target = %q, want the server name", s.target)
		}
		if s.now == nil || cap(s.slots) != maxConcurrentHooks {
			t.Errorf("clock %v, slots %d: the defaults were not applied", s.now != nil, cap(s.slots))
		}
	}
	if s := New(nil, Config{MaxTracked: 7}); s.maxTracked != 7 {
		t.Errorf("maxTracked = %d, want 7", s.maxTracked)
	}
	if s := New(nil, Config{Server: testServer, Target: "route-7"}); s.target != "route-7" {
		t.Errorf("target = %q, want the configured route-7", s.target)
	}
}

func TestCache_ASlowSourceDeniesWhenTheHookContextExpires(t *testing.T) {
	src := stubSource{
		gen: func(ctx context.Context) (int64, error) {
			<-ctx.Done()
			return 0, ctx.Err()
		},
		snap: func(context.Context, string) (catalog.Snapshot, error) { return catalog.Snapshot{}, nil },
	}
	s, _ := newTestServer(src)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	res, err := s.CheckRequest(ctx, callReq("echo"))
	if err != nil {
		t.Fatal(err)
	}
	requireCallDenied(t, res, "echo", causeUnavailable)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the hook waited %v on a stuck source", elapsed)
	}
}
