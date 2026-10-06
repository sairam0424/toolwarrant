package processor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	api "github.com/sairam0424/toolwarrant/internal/extmcpv1"
)

const (
	// maxRecvMsgSize lets a large tools/list page through; gRPC's 4 MiB default
	// would turn a big catalog page into a transport error. It equals the
	// payload cap, so a page the hook would refuse is refused by the transport.
	maxRecvMsgSize = maxPayloadBytes

	// keepaliveMinPing is the shortest ping interval the server tolerates from
	// the gateway. gRPC-Go's default (5 minutes) answers a gateway that pings
	// more often with GOAWAY "too_many_pings", which drops the connection and
	// so fails every hook until it reconnects.
	keepaliveMinPing = 10 * time.Second

	// shutdownGrace is how long in-flight hooks get to finish after the context
	// is cancelled before connections are closed.
	shutdownGrace = 5 * time.Second
)

// errRemoteListener means Serve was given a TCP listener that is reachable
// from other hosts while Config.AllowRemoteListener is off.
var errRemoteListener = errors.New("processor: refusing a listener that is not loopback; set AllowRemoteListener to serve on it anyway")

// Serve runs the ExtMCP gRPC service on lis until ctx is cancelled, then stops
// gracefully (finishing in-flight hooks for a few seconds, then closing what
// is left) and returns nil. It returns an error if the listener fails.
//
// The ExtMCP protocol carries no authentication of its own and every reply
// decides what the gateway serves, so lis must be a loopback or unix-socket
// listener that only the gateway can reach. A TCP listener on any other
// address is refused unless Config.AllowRemoteListener is set, and then only
// Config.Secret stands between the port and the gateway's tool list.
func (s *Server) Serve(ctx context.Context, lis net.Listener) error {
	if lis == nil {
		return errors.New("processor: nil listener")
	}
	if err := s.checkListener(lis.Addr()); err != nil {
		return err
	}
	gs := grpc.NewServer(
		grpc.MaxRecvMsgSize(maxRecvMsgSize),
		grpc.MaxConcurrentStreams(maxConcurrentHooks),
		grpc.KeepaliveEnforcementPolicy(enforcementPolicy()),
	)
	api.RegisterExtMcpServer(gs, s)

	done := make(chan error, 1)
	go func() { done <- gs.Serve(lis) }()

	select {
	case err := <-done:
		gs.Stop()
		return serveResult(ctx, err)
	case <-ctx.Done():
		stopWithin(gs, shutdownGrace)
		return serveResult(ctx, <-done)
	}
}

// checkListener refuses a TCP listener that is reachable from off the host
// unless the operator opted in. Opting in without a shared secret is logged,
// because then whoever reaches the port decides what the gateway serves.
func (s *Server) checkListener(addr net.Addr) error {
	local, err := isLocalAddr(addr)
	if err != nil {
		return fmt.Errorf("processor: listener address: %w", err)
	}
	if local {
		return nil
	}
	if !s.allowRemote {
		return fmt.Errorf("%w: %s", errRemoteListener, strconv.Quote(addr.String()))
	}
	if s.secret == "" {
		s.log.Warn("serving hooks on a non-loopback listener without a shared secret: anyone who reaches it decides what the gateway serves",
			"server", s.server, "addr", strconv.Quote(addr.String()))
	}
	return nil
}

// isLocalAddr classifies a listener address. Only TCP addresses are checked
// against loopback: a unix socket is reachable only through the file system
// and an in-memory listener (as tests use) is not reachable at all. A TCP
// address that cannot be classified is an error, so the caller fails closed.
func isLocalAddr(addr net.Addr) (bool, error) {
	switch a := addr.(type) {
	case nil:
		return false, errors.New("listener has no address")
	case *net.TCPAddr:
		if a == nil {
			return false, errors.New("listener has no tcp address")
		}
		return a.IP.IsLoopback(), nil
	case *net.UnixAddr:
		return true, nil
	}
	if !strings.HasPrefix(addr.Network(), "tcp") {
		return true, nil
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false, fmt.Errorf("tcp listener host %s is not an ip literal", strconv.Quote(host))
	}
	return ip.IsLoopback(), nil
}

// enforcementPolicy says how often the gateway may ping. PermitWithoutStream
// matters: the gateway keeps one idle connection between hooks, and a ping on
// it with no stream open is otherwise counted as a violation.
func enforcementPolicy() keepalive.EnforcementPolicy {
	return keepalive.EnforcementPolicy{MinTime: keepaliveMinPing, PermitWithoutStream: true}
}

// serveResult maps grpc's return value to Serve's. A server stopped on
// purpose is not an error, even when Stop won the race with Serve starting.
func serveResult(ctx context.Context, err error) error {
	if err == nil || (ctx.Err() != nil && errors.Is(err, grpc.ErrServerStopped)) {
		return nil
	}
	return fmt.Errorf("processor: serve: %w", err)
}

// stopWithin drains the server for at most grace, then closes what remains.
func stopWithin(gs *grpc.Server, grace time.Duration) {
	stopped := make(chan struct{})
	go func() {
		gs.GracefulStop()
		close(stopped)
	}()
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-stopped:
	case <-timer.C:
		gs.Stop()
		<-stopped
	}
}
