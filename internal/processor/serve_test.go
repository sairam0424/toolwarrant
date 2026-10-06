package processor

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	api "github.com/sairam0424/toolwarrant/internal/extmcpv1"
)

const serveStopTimeout = 20 * time.Second

// startServer runs s.Serve on an in-process listener and returns a client plus
// a function that cancels the server and waits for Serve to return.
func startServer(t *testing.T, s *Server) (api.ExtMcpClient, func() error) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, lis) }()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	var once sync.Once
	var stopErr error
	stop := func() error {
		once.Do(func() {
			_ = conn.Close()
			cancel()
			select {
			case stopErr = <-done:
			case <-time.After(serveStopTimeout):
				stopErr = context.DeadlineExceeded
			}
		})
		return stopErr
	}
	t.Cleanup(func() {
		if err := stop(); err != nil {
			t.Errorf("Serve returned %v, want nil after cancellation", err)
		}
	})
	return api.NewExtMcpClient(conn), stop
}

func TestServe_EndToEndOverGRPC(t *testing.T) {
	d1 := mustDigest(t, echoV1)
	wipe := tool("wipe_database", "Danger.")
	s, _ := newTestServer(newFakeSource(map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)}))
	client, _ := startServer(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), serveStopTimeout)
	defer cancel()

	res, err := client.CheckResponse(ctx, &api.McpResponse{Method: "tools/list", McpResponse: listBody("c1", echoV1, wipe)})
	if err != nil {
		t.Fatal(err)
	}
	if got := servedNames(t, res); len(got) != 1 || got[0] != "echo" {
		t.Fatalf("served %v over gRPC, want [echo]", got)
	}
	if !strings.Contains(string(res.GetMutated()), `"nextCursor":"c1"`) {
		t.Errorf("nextCursor lost over gRPC: %s", res.GetMutated())
	}

	allowed, err := client.CheckRequest(ctx, callReq("echo"))
	if err != nil {
		t.Fatal(err)
	}
	requireAllowed(t, allowed)

	denied, err := client.CheckRequest(ctx, callReq("wipe_database"))
	if err != nil {
		t.Fatal(err)
	}
	requireCallDenied(t, denied, "wipe_database", causeNotApproved)

	passed, err := client.CheckRequest(ctx, &api.McpRequest{Method: "initialize"})
	if err != nil || passed.GetPass() == nil {
		t.Fatalf("initialize: %v, %v", passed, err)
	}
}

func TestServe_ManyConcurrentRPCs(t *testing.T) {
	d1 := mustDigest(t, echoV1)
	s, _ := newTestServer(newFakeSource(map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)}))
	client, _ := startServer(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), serveStopTimeout)
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := client.CheckRequest(ctx, callReq("echo"))
			if err != nil || res.GetPass() == nil {
				t.Errorf("call: %v, %v", res, err)
			}
		}()
	}
	wg.Wait()
	if got := s.Stats().CallsAllowed; got != 64 {
		t.Errorf("CallsAllowed = %d, want 64", got)
	}
}

func TestServe_AcceptsPagesBeyondGRPCsDefaultLimitButNotBeyondOurs(t *testing.T) {
	d1 := mustDigest(t, echoV1)
	s, _ := newTestServer(newFakeSource(map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)}))
	client, _ := startServer(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), serveStopTimeout)
	defer cancel()

	// 6 MiB: over gRPC's 4 MiB default, under our 32 MiB. The junk tool is not in
	// the catalog, so it is hidden and the page shrinks to the one approved tool.
	junk := tool("junk", strings.Repeat("x", 6<<20))
	res, err := client.CheckResponse(ctx, &api.McpResponse{Method: "tools/list", McpResponse: listBody("", junk, echoV1)})
	if err != nil {
		t.Fatalf("a 6 MiB page must be accepted: %v", err)
	}
	if got := servedNames(t, res); len(got) != 1 || got[0] != "echo" {
		t.Fatalf("served %v", got)
	}

	// Just over 32 MiB is refused by the transport, which the gateway treats as
	// a failed hook (fail closed), not as a passed one.
	_, err = client.CheckResponse(ctx, &api.McpResponse{Method: "tools/list", McpResponse: make([]byte, maxRecvMsgSize+1024)})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("oversized message: err = %v, want ResourceExhausted", err)
	}
}

func TestServe_StopsGracefullyWhenTheContextIsCancelled(t *testing.T) {
	s, _ := newTestServer(newFakeSource(nil))
	client, stop := startServer(t, s)

	ctx, cancel := context.WithTimeout(context.Background(), serveStopTimeout)
	defer cancel()
	if _, err := client.CheckRequest(ctx, callReq("echo")); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	if err := stop(); err != nil {
		t.Fatalf("Serve returned %v, want nil", err)
	}
	if elapsed := time.Since(start); elapsed > shutdownGrace+5*time.Second {
		t.Fatalf("shutdown took %v", elapsed)
	}
	if _, err := client.CheckRequest(ctx, callReq("echo")); err == nil {
		t.Fatal("the server still answers after shutdown")
	}
}

func TestServe_ReturnsAnErrorWhenTheListenerIsBroken(t *testing.T) {
	s, _ := newTestServer(newFakeSource(nil))

	if err := s.Serve(context.Background(), nil); err == nil {
		t.Error("a nil listener must be an error")
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen on loopback: %v", err)
	}
	_ = lis.Close()
	done := make(chan error, 1)
	go func() { done <- s.Serve(context.Background(), lis) }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("Serve on a closed listener returned nil")
		}
	case <-time.After(serveStopTimeout):
		t.Fatal("Serve did not return for a closed listener")
	}
}

func TestServe_CancelledBeforeStartIsACleanStop(t *testing.T) {
	s, _ := newTestServer(newFakeSource(nil))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, bufconn.Listen(1<<10)) }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve = %v, want nil", err)
		}
	case <-time.After(serveStopTimeout):
		t.Fatal("Serve did not return")
	}
}

func TestServe_KeepaliveEnforcementToleratesAnIdleGatewayPinging(t *testing.T) {
	p := enforcementPolicy()
	if !p.PermitWithoutStream {
		t.Error("pings on an idle connection must be permitted, or the gateway is disconnected between hooks")
	}
	if p.MinTime <= 0 || p.MinTime > time.Minute {
		t.Errorf("MinTime = %v; gRPC's 5 minute default drops gateways that ping more often", p.MinTime)
	}
}
