package processor

import (
	"context"
	"log/slog"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	api "github.com/sairam0424/toolwarrant/internal/extmcpv1"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// Hooks run concurrently in the gateway, and the catalog changes under them.
// Run with -race. The invariants: no hook ever panics, a list is never passed
// through unfiltered, a call result is only ever Pass or Error, and once the
// writer stops the very next hook reflects the final catalog.
func TestConcurrency_HooksRaceWithCatalogUpdates(t *testing.T) {
	d1, d2 := mustDigest(t, echoV1), mustDigest(t, echoV2)
	variants := []map[string]catalog.ToolPolicy{
		{"echo": servedPolicy(d1)},
		{"echo": policy(lifecycle.Disabled, d1, d1)},
		{"echo": servedPolicy(d2)},
		{"echo": policy(lifecycle.Enabled, d1, d2)},
		{},
	}
	src := newFakeSource(variants[0])
	s := New(src, Config{Server: testServer, Logger: slog.New(slog.DiscardHandler), MaxTracked: 4})

	const (
		workers    = 8
		iterations = 300
	)
	stop := make(chan struct{})
	var writer sync.WaitGroup
	writer.Add(1)
	go func() {
		defer writer.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			src.publish(variants[i%len(variants)])
			runtime.Gosched()
		}
	}()

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			ctx := context.Background()
			live := [][]byte{echoV1, echoV2}
			for i := 0; i < iterations; i++ {
				res, err := s.CheckResponse(ctx, listMsg(listBody("", live[(w+i)%2])))
				if err != nil || res.GetPass() != nil || (res.GetMutated() == nil && res.GetError() == nil) {
					t.Errorf("list: result %v, err %v", res, err)
					return
				}
				req, err := s.CheckRequest(ctx, callReq("echo"))
				if err != nil || (req.GetPass() == nil && req.GetError() == nil) {
					t.Errorf("call: result %v, err %v", req, err)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(stop)
	writer.Wait()

	st := s.Stats()
	if st.ListsServed+st.ListsDenied != workers*iterations {
		t.Errorf("lists accounted for = %d, want %d", st.ListsServed+st.ListsDenied, workers*iterations)
	}
	if st.CallsAllowed+st.CallsDenied != workers*iterations {
		t.Errorf("calls accounted for = %d, want %d", st.CallsAllowed+st.CallsDenied, workers*iterations)
	}
	if st.WrongBackend != 0 || st.Throttled != 0 {
		t.Errorf("hooks for the right backend under the slot limit were refused: %+v", st)
	}
	if n := s.trackedCount(); n > 4 {
		t.Errorf("tracked %d digests, over the bound of 4", n)
	}

	// Writer stopped: the very next hook must reflect the final catalog.
	src.publish(map[string]catalog.ToolPolicy{"echo": policy(lifecycle.Disabled, d1, d1)})
	res, err := s.CheckRequest(context.Background(), callReq("echo"))
	if err != nil {
		t.Fatal(err)
	}
	requireCallDenied(t, res, "echo", causeNotApproved)
}

// A burst of hooks right after a change must not stampede the database.
func TestConcurrency_ABurstAfterAChangeReloadsOnce(t *testing.T) {
	d1 := mustDigest(t, echoV1)
	src := newFakeSource(map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)})
	s := New(src, Config{Server: testServer, Logger: slog.New(slog.DiscardHandler)})

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < maxConcurrentHooks; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if res, err := s.CheckRequest(context.Background(), callReq("echo")); err != nil || res.GetPass() == nil {
				t.Errorf("call: %v, %v", res, err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if _, loads := src.calls(); loads != 1 {
		t.Fatalf("%d concurrent cold-start hooks made %d snapshot loads, want 1", maxConcurrentHooks, loads)
	}
}

// blockingSource holds every Generation call until released, so hooks pile up
// inside the processor while holding their concurrency slots.
type blockingSource struct {
	entered chan struct{}
	release chan struct{}
	snap    catalog.Snapshot
}

func (b *blockingSource) Generation(ctx context.Context) (int64, error) {
	b.entered <- struct{}{}
	select {
	case <-b.release:
		return 1, nil
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

func (b *blockingSource) Snapshot(context.Context, string) (catalog.Snapshot, error) {
	return b.snap, nil
}

// D6: once every slot is taken, further hooks are denied at once with
// RESOURCE_EXHAUSTED instead of queueing; the gateway fails closed on the
// denial, and nothing piles up in memory. The slots are reusable afterwards.
func TestConcurrency_HooksBeyondTheSlotLimitAreDeniedNotQueued(t *testing.T) {
	d1 := mustDigest(t, echoV1)
	src := &blockingSource{
		entered: make(chan struct{}, maxConcurrentHooks+1),
		release: make(chan struct{}),
		snap:    snapshotOf(map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)}),
	}
	s, _ := newTestServer(src)

	results := make(chan *api.McpRequestResult, maxConcurrentHooks)
	for i := 0; i < maxConcurrentHooks; i++ {
		go func() {
			res, err := s.CheckRequest(context.Background(), callReq("echo"))
			if err != nil {
				t.Errorf("CheckRequest: %v", err)
			}
			results <- res
		}()
	}
	for i := 0; i < maxConcurrentHooks; i++ {
		<-src.entered // every slot is now held by a hook waiting on the source
	}

	start := time.Now()
	extraCall := call(t, s, callReq("echo"))
	extraList := list(t, s, listBody("", echoV1))
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("the surplus hooks waited %v; they must be denied, not queued", elapsed)
	}
	requireRefused(t, extraCall, api.AuthorizationError_RESOURCE_EXHAUSTED, causeThrottled)
	if got := extraCall.GetError().GetReason(); got != reasonCallThrottled {
		t.Errorf("call reason = %q, want %q", got, reasonCallThrottled)
	}
	if e := requireListDenied(t, extraList, api.AuthorizationError_RESOURCE_EXHAUSTED); e.GetReason() != reasonListThrottled {
		t.Errorf("list reason = %q, want %q", e.GetReason(), reasonListThrottled)
	}
	if st := s.Stats(); st.Throttled != 2 || st.CallsDenied != 1 || st.ListsDenied != 1 {
		t.Errorf("stats = %+v", st)
	}

	close(src.release)
	for i := 0; i < maxConcurrentHooks; i++ {
		requireAllowed(t, <-results)
	}
	// The slots are free again.
	requireAllowed(t, call(t, s, callReq("echo")))
	if st := s.Stats(); st.Throttled != 2 || st.CallsAllowed != maxConcurrentHooks+1 {
		t.Errorf("stats = %+v", st)
	}
}
