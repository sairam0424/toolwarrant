package processor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	api "github.com/sairam0424/toolwarrant/internal/extmcpv1"
)

const (
	// maxRecvMsgSize lets a large tools/list page through; gRPC's 4 MiB default
	// would turn a big catalog page into a transport error. It equals the
	// payload cap, so a page the hook would refuse is refused by the transport:
	// the serialised hook message is the payload plus the method and the
	// service names, so a payload within a few dozen bytes of the cap, or over
	// it, never reaches CheckResponse. gRPC answers ResourceExhausted from the
	// length prefix, before the body is read, and the processor learns of the
	// refusal through the wrapped decoder of serviceDesc (pageRefused), which
	// marks every catalog tool of the snapshot as if CheckResponse had seen the
	// page (D15).
	maxRecvMsgSize = maxPayloadBytes

	// checkResponseMethod is the short name of the CheckResponse method in the
	// generated ServiceDesc, whose decoder serviceDesc wraps.
	checkResponseMethod = "CheckResponse"

	// keepaliveMinPing is the shortest ping interval the server tolerates from
	// the gateway. gRPC-Go's default (5 minutes) answers a gateway that pings
	// more often with GOAWAY "too_many_pings", which drops the connection and
	// so fails every hook until it reconnects.
	keepaliveMinPing = 10 * time.Second

	// shutdownGrace is how long in-flight hooks get to finish after the context
	// is cancelled before connections are closed.
	shutdownGrace = 5 * time.Second
)

var (
	// errRemoteListener means Serve was given a TCP listener that is reachable
	// from other hosts while Config.AllowRemoteListener is off.
	errRemoteListener = errors.New("processor: refusing a listener that is not loopback; set AllowRemoteListener to serve on it anyway")

	// errServiceDesc means the generated ServiceDesc no longer carries the
	// CheckResponse method under the expected name, so the size refusals of the
	// transport could not be observed. Serve refuses to run rather than serve
	// without the marking (fail closed).
	errServiceDesc = errors.New("processor: generated service has no CheckResponse method to wrap")
)

// Serve runs the ExtMCP gRPC service on lis until ctx is cancelled, then stops
// gracefully (finishing in-flight hooks for a few seconds, then closing what
// is left) and returns nil. It returns an error if the listener fails.
//
// The ExtMCP protocol carries no authentication of its own and every reply
// decides what the gateway serves, so lis must be a loopback or unix-socket
// listener that only the gateway can reach. A TCP listener on any other
// address is refused unless Config.AllowRemoteListener is set, and then only
// Config.Secret stands between the port and the gateway's tool list.
//
// A tools/list page over the payload cap never reaches CheckResponse: gRPC
// refuses the message with ResourceExhausted from its length prefix, the
// gateway sees a failed hook and fails the listing closed. The processor
// observes that refusal on the CheckResponse decoder (serviceDesc) and, before
// the status is written, marks every catalog tool of the snapshot as
// conflicting exactly as CheckResponse does for an oversized page it reads
// itself, so the evidence older listings left cannot outlive a page the
// processor could not read (D15). The refused message's secret and service
// names are inside the bytes that were never read, so the marking cannot be
// gated by them: whoever can reach the listener can mark (deny) tools until
// the next clean listing, never pass one, which is one more reason the
// listener is loopback.
func (s *Server) Serve(ctx context.Context, lis net.Listener) error {
	if lis == nil {
		return errors.New("processor: nil listener")
	}
	if err := s.checkListener(lis.Addr()); err != nil {
		return err
	}
	desc, err := s.serviceDesc()
	if err != nil {
		return err
	}
	gs := grpc.NewServer(
		grpc.MaxRecvMsgSize(maxRecvMsgSize),
		grpc.MaxConcurrentStreams(maxConcurrentHooks),
		grpc.KeepaliveEnforcementPolicy(enforcementPolicy()),
	)
	gs.RegisterService(desc, s)

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

// serviceDesc is a copy of the generated ServiceDesc whose CheckResponse
// method decodes the request through watchRefusal, so a message the transport
// refuses for size is reported to pageRefused within the same handler call,
// before the handler returns the error. The order on the wire is tighter than
// that comment once suggested: grpc-go's server stream writes the status to
// the client inside RecvMsg, before it returns the error to the decoder, so
// the gateway sees the failed hook a moment before the marking completes and
// a tools/call in that moment is judged against the evidence the previous
// listing left, exactly as one an instant earlier would have been; the
// marking then lands and holds until a clean listing (the eighth review's ci
// run caught a test that read the statistics inside that moment). gRPC's own
// hooks are no better placed: a unary interceptor runs after the request was
// decoded, so it never sees a refused one, and a stats handler sees the RPC
// end only after the status was written, which would leave a window in which a tools/call
// passes on the older evidence. The generated variable is never modified; the
// methods slice is cloned before the one entry is replaced.
func (s *Server) serviceDesc() (*grpc.ServiceDesc, error) {
	desc := api.ExtMcp_ServiceDesc
	desc.Methods = slices.Clone(desc.Methods)
	i := slices.IndexFunc(desc.Methods, func(m grpc.MethodDesc) bool { return m.MethodName == checkResponseMethod })
	if i < 0 {
		return nil, errServiceDesc
	}
	inner := desc.Methods[i].Handler
	desc.Methods[i].Handler = func(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
		return inner(srv, ctx, s.watchRefusal(ctx, dec), interceptor)
	}
	return &desc, nil
}

// watchRefusal wraps the request decoder of one CheckResponse call: a decode
// that fails with ResourceExhausted is the transport refusing the message for
// size (the handler itself never returns a gRPC status, and the send limit is
// unbounded), and the page behind it is treated as one the processor could
// not read. Any other outcome is passed through untouched.
func (s *Server) watchRefusal(ctx context.Context, dec func(any) error) func(any) error {
	return func(m any) error {
		err := dec(m)
		if err != nil && status.Code(err) == codes.ResourceExhausted {
			s.pageRefused(ctx, err)
		}
		return err
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
