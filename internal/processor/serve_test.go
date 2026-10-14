package processor

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
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
	return serveAndDial(t, s, lis, lis)
}

// serveAndDial runs s.Serve on lis and dials it through buf in plaintext. The
// two differ only when a test wraps the in-memory listener to report another
// address.
func serveAndDial(t *testing.T, s *Server, lis net.Listener, buf *bufconn.Listener) (api.ExtMcpClient, func() error) {
	t.Helper()
	return serveAndDialWith(t, s, lis, buf, insecure.NewCredentials())
}

// serveAndDialWith is serveAndDial with the client's transport credentials
// chosen by the test, so a TLS test can present, or withhold, a certificate.
func serveAndDialWith(t *testing.T, s *Server, lis net.Listener, buf *bufconn.Listener, creds credentials.TransportCredentials) (api.ExtMcpClient, func() error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, lis) }()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return buf.DialContext(ctx) }),
		grpc.WithTransportCredentials(creds))
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

// addrListener reports another address than the listener it wraps, so a test
// can see how Serve treats an address without binding it.
type addrListener struct {
	net.Listener
	addr net.Addr
}

func (l addrListener) Addr() net.Addr { return l.addr }

// fakeAddr is a net.Addr of any network and text, for addresses the standard
// library never produces.
type fakeAddr struct{ network, text string }

func (a fakeAddr) Network() string { return a.network }
func (a fakeAddr) String() string  { return a.text }

func TestServe_EndToEndOverGRPC(t *testing.T) {
	d1 := mustDigest(t, echoV1)
	wipe := tool("wipe_database", "Danger.")
	s, _ := newTestServer(newFakeSource(map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)}))
	client, _ := startServer(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), serveStopTimeout)
	defer cancel()

	res, err := client.CheckResponse(ctx, listMsg(listBody("c1", echoV1, wipe)))
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

// D8: the shared secret travels in metadata_context and is checked on the
// transport path exactly as in the unit tests.
func TestServe_SharedSecretIsCheckedOverGRPC(t *testing.T) {
	const secret = "s3cret"
	d1 := mustDigest(t, echoV1)
	s, _ := newTestServer(newFakeSource(map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)}), func(c *Config) { c.Secret = secret })
	client, _ := startServer(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), serveStopTimeout)
	defer cancel()

	withSecret := callReq("echo")
	withSecret.MetadataContext = secretMeta(t, secret)
	res, err := client.CheckRequest(ctx, withSecret)
	if err != nil {
		t.Fatal(err)
	}
	requireAllowed(t, res)

	res, err = client.CheckRequest(ctx, callReq("echo"))
	if err != nil {
		t.Fatal(err)
	}
	requireRefused(t, res, api.AuthorizationError_PERMISSION_DENIED, causeUnauthenticated)

	page := listMsg(listBody("", echoV1))
	page.MetadataContext = secretMeta(t, "wrong")
	list, err := client.CheckResponse(ctx, page)
	if err != nil {
		t.Fatal(err)
	}
	e := requireListDenied(t, list, api.AuthorizationError_PERMISSION_DENIED)
	if !strings.Contains(e.GetReason(), string(causeUnauthenticated)) {
		t.Errorf("reason = %q", e.GetReason())
	}
	if st := s.Stats(); st.Unauthenticated != 2 || st.CallsAllowed != 1 {
		t.Errorf("stats = %+v", st)
	}
}

func TestServe_ManyConcurrentRPCs(t *testing.T) {
	d1 := mustDigest(t, echoV1)
	s, _ := newTestServer(newFakeSource(map[string]catalog.ToolPolicy{"echo": servedPolicy(d1)}))
	client, _ := startServer(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), serveStopTimeout)
	defer cancel()

	// Twice the stream limit: the transport queues the surplus streams, so
	// every call completes and none is throttled.
	var wg sync.WaitGroup
	for i := 0; i < 2*maxConcurrentHooks; i++ {
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
	if st := s.Stats(); st.CallsAllowed != 2*maxConcurrentHooks || st.Throttled != 0 {
		t.Errorf("stats = %+v, want %d allowed and none throttled", st, 2*maxConcurrentHooks)
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

// D8: a TCP listener that other hosts can reach is refused unless the operator
// opted in, and opting in without a shared secret is called out in the log.
func TestServe_RefusesAListenerReachableFromOtherHosts(t *testing.T) {
	remote := &net.TCPAddr{IP: net.ParseIP("10.0.0.7"), Port: 9001}

	t.Run("refused by default", func(t *testing.T) {
		s, _ := newTestServer(newFakeSource(nil))
		buf := bufconn.Listen(1 << 10)
		defer func() { _ = buf.Close() }()
		err := s.Serve(context.Background(), addrListener{Listener: buf, addr: remote})
		if !errors.Is(err, errRemoteListener) {
			t.Fatalf("Serve = %v, want errRemoteListener", err)
		}
		if !strings.Contains(err.Error(), `"10.0.0.7:9001"`) {
			t.Errorf("the error should name the address: %v", err)
		}
	})

	t.Run("allowed without a secret, with a warning", func(t *testing.T) {
		s, logs := newTestServer(newFakeSource(nil), func(c *Config) { c.AllowRemoteListener = true })
		buf := bufconn.Listen(1 << 10)
		client, stop := serveAndDial(t, s, addrListener{Listener: buf, addr: remote}, buf)
		ctx, cancel := context.WithTimeout(context.Background(), serveStopTimeout)
		defer cancel()
		if _, err := client.CheckRequest(ctx, &api.McpRequest{Method: "initialize"}); err != nil {
			t.Fatal(err)
		}
		if err := stop(); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(logs.String(), "without a shared secret") {
			t.Errorf("no warning about the unauthenticated remote listener:\n%s", logs.String())
		}
	})

	t.Run("allowed with a secret, no warning", func(t *testing.T) {
		s, logs := newTestServer(newFakeSource(nil), func(c *Config) {
			c.AllowRemoteListener = true
			c.Secret = "s3cret"
		})
		buf := bufconn.Listen(1 << 10)
		_, stop := serveAndDial(t, s, addrListener{Listener: buf, addr: remote}, buf)
		if err := stop(); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(logs.String(), "without a shared secret") {
			t.Errorf("warned although a secret is configured:\n%s", logs.String())
		}
	})
}

func TestIsLocalAddr(t *testing.T) {
	cases := []struct {
		name    string
		addr    net.Addr
		local   bool
		wantErr bool
	}{
		{"ipv4 loopback", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}, true, false},
		{"ipv6 loopback", &net.TCPAddr{IP: net.IPv6loopback, Port: 1}, true, false},
		{"private address", &net.TCPAddr{IP: net.IPv4(10, 0, 0, 7), Port: 1}, false, false},
		{"all ipv4 interfaces", &net.TCPAddr{IP: net.IPv4zero, Port: 1}, false, false},
		{"all ipv6 interfaces", &net.TCPAddr{IP: net.IPv6unspecified, Port: 1}, false, false},
		{"tcp address without an ip", &net.TCPAddr{Port: 1}, false, false},
		{"nil tcp address", (*net.TCPAddr)(nil), false, true},
		{"unix socket", &net.UnixAddr{Name: "/tmp/p.sock", Net: "unix"}, true, false},
		{"in-memory listener", bufconn.Listen(1).Addr(), true, false},
		{"no address", nil, false, true},
		{"tcp text with a host name", fakeAddr{"tcp", "example.com:9001"}, false, true},
		{"tcp text that is not host:port", fakeAddr{"tcp", "nonsense"}, false, true},
		{"tcp4 text loopback", fakeAddr{"tcp4", "127.0.0.1:9001"}, true, false},
		{"tcp text ipv6 loopback", fakeAddr{"tcp", "[::1]:9001"}, true, false},
		{"tcp text private", fakeAddr{"tcp", "10.0.0.7:9001"}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			local, err := isLocalAddr(tc.addr)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if local != tc.local {
				t.Errorf("local = %v, want %v", local, tc.local)
			}
		})
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
