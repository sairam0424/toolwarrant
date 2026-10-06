package processor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	api "github.com/sairam0424/toolwarrant/internal/extmcpv1"
)

const (
	// maxRecvMsgSize lets a large tools/list page through; gRPC's 4 MiB default
	// would turn a big catalog page into a transport error.
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

// Serve runs the ExtMCP gRPC service on lis until ctx is cancelled, then stops
// gracefully (finishing in-flight hooks for a few seconds, then closing what
// is left) and returns nil. It returns an error if the listener fails.
//
// The ExtMCP protocol carries no authentication and every reply decides what
// the gateway serves, so lis must be a loopback or unix-socket listener that
// only the gateway can reach.
func (s *Server) Serve(ctx context.Context, lis net.Listener) error {
	if lis == nil {
		return errors.New("processor: nil listener")
	}
	gs := grpc.NewServer(
		grpc.MaxRecvMsgSize(maxRecvMsgSize),
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
