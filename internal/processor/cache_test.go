package processor

import (
	"context"
	"errors"
	"log/slog"
	"maps"
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

func TestCache_ObservedEvidenceIsPrunedWhenAToolLeavesTheCatalog(t *testing.T) {
	d1 := mustDigest(t, echoV1)
	src := newFakeSource(map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)})
	s, _ := newTestServer(src)
	servedNames(t, list(t, s, listBody("", echoV2))) // drifted: observed = d2
	requireCallDenied(t, call(t, s, callReq("echo")), "echo", causeChanged)

	src.publish(map[string]catalog.ToolPolicy{})
	requireCallDenied(t, call(t, s, callReq("echo")), "echo", causeNotApproved)
	if n := s.trackedCount(); n != 0 {
		t.Fatalf("%d digests still tracked for tools that left the catalog", n)
	}

	// A tool re-created under the same name starts without stale evidence.
	src.publish(map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)})
	requireAllowed(t, call(t, s, callReq("echo")))
}

func TestCache_MisconfiguredServerDeniesInsteadOfPanicking(t *testing.T) {
	d1 := mustDigest(t, echoV1)
	src := newFakeSource(map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)})
	quiet := slog.New(slog.DiscardHandler)
	for name, s := range map[string]*Server{
		"nil source":  New(nil, Config{Server: testServer, Logger: quiet}),
		"empty name":  New(src, Config{Logger: quiet}),
		"both absent": New(nil, Config{Logger: quiet}),
	} {
		t.Run(name, func(t *testing.T) {
			requireCallDenied(t, call(t, s, callReq("echo")), "echo", causeUnavailable)
			requireListDenied(t, list(t, s, listBody("", echoV1)), api.AuthorizationError_PERMISSION_DENIED)
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
	}
	if s := New(nil, Config{MaxTracked: 7}); s.maxTracked != 7 {
		t.Errorf("maxTracked = %d, want 7", s.maxTracked)
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
