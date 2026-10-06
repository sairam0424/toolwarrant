package processor

import (
	"context"
	"log/slog"
	"runtime"
	"sync"
	"testing"

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
				res, err := s.CheckResponse(ctx, &api.McpResponse{Method: "tools/list", McpResponse: listBody("", live[(w+i)%2])})
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
	for i := 0; i < 32; i++ {
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
		t.Fatalf("32 concurrent cold-start hooks made %d snapshot loads, want 1", loads)
	}
}
