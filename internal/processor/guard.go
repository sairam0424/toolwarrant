package processor

import (
	"context"
	"crypto/subtle"

	"google.golang.org/protobuf/types/known/structpb"

	api "github.com/sairam0424/toolwarrant/internal/extmcpv1"
)

// denial is a refusal decided before any payload work: the hook is not from
// the gateway, not about this upstream, or there is no room to do the work.
type denial struct {
	code  api.AuthorizationError_Code
	cause cause
}

// admit runs the checks that precede any payload work, cheapest first: the
// shared secret (who is asking) and then, for a hooked method, the backend
// name (what the hook is about). Each decides the hook on its own, so the
// catalog is not read and no byte of the payload is parsed for a hook that
// fails them. A nil result admits the hook.
func (s *Server) admit(ctx context.Context, md *structpb.Struct, services []string, hooked bool) *denial {
	if !s.authenticated(md) {
		s.stats.unauthenticated.Add(1)
		return &denial{code: api.AuthorizationError_PERMISSION_DENIED, cause: causeUnauthenticated}
	}
	if !hooked {
		return nil
	}
	if !s.targets(services) {
		s.stats.wrongBackend.Add(1)
		s.noteWrongBackend(ctx, services)
		return &denial{code: api.AuthorizationError_PERMISSION_DENIED, cause: causeWrongBackend}
	}
	return nil
}

// authenticated compares the secret in the gateway's metadata_context with the
// configured one in constant time. With no secret configured every hook is
// accepted, which is only safe on a loopback or unix listener (see Serve). A
// missing field or a non-string value compares as the empty string and fails.
func (s *Server) authenticated(md *structpb.Struct) bool {
	if s.secret == "" {
		return true
	}
	got := md.GetFields()[SecretMetadataKey].GetStringValue()
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.secret)) == 1
}

// targets reports whether the hook is about exactly the one backend this
// processor guards. A hook for another backend, for several backends or for
// none is somebody else's, and judging it with this server's approvals would
// let an approval for one upstream serve a tool on another.
func (s *Server) targets(services []string) bool {
	return s.target != "" && len(services) == 1 && services[0] == s.target
}

// noteWrongBackend logs the first mismatching service_names value, quoted and
// bounded, so an operator can see the exact name the gateway uses for the
// route and fix Target. Later mismatches only count.
func (s *Server) noteWrongBackend(ctx context.Context, services []string) {
	if !s.wrongBackendSeen.CompareAndSwap(false, true) {
		return
	}
	s.log.DebugContext(ctx, "hook names another backend",
		"server", s.server, "target", quoteName(s.target), "service_names", quoteNames(services))
}

// acquire takes a concurrency slot without waiting and returns the function
// that frees it. A hook that finds every slot taken is denied rather than
// queued: queueing would let a slow upstream pile pages up in memory, and the
// gateway fails closed on the denial anyway.
func (s *Server) acquire() (release func(), ok bool) {
	select {
	case s.slots <- struct{}{}:
		return func() { <-s.slots }, true
	default:
		s.stats.throttled.Add(1)
		return nil, false
	}
}
