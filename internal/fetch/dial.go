package fetch

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"
)

const (
	// tcpKeepAlive is the TCP keep-alive period of dialled connections.
	tcpKeepAlive = 30 * time.Second
	// maxDialAddrs bounds how many of the (already vetted) answers one dial
	// tries, so a name with hundreds of addresses cannot stall a crawl.
	maxDialAddrs = 8
)

// dialFunc is the signature of net.Dialer.DialContext. The guard keeps it as a
// field only so tests can observe which address was really dialled.
type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// guardDialer makes the connect-time decision. It resolves names itself,
// refuses the whole name if any answer is forbidden, and dials by IP literal
// so the vetted answer is the address that is used.
type guardDialer struct {
	resolver     Resolver
	allowPrivate bool
	dialTimeout  time.Duration
	dialer       *net.Dialer
	dial         dialFunc
}

func newGuardDialer(cfg config) *guardDialer {
	g := &guardDialer{
		resolver:     cfg.resolver,
		allowPrivate: cfg.allowPrivate,
		dialTimeout:  cfg.dialTimeout,
	}
	if g.resolver == nil {
		g.resolver = net.DefaultResolver
	}
	// Control runs on the socket just before connect(2), with the ip:port the
	// kernel is about to use. It is the independent second check.
	g.dialer = &net.Dialer{
		Timeout:   cfg.dialTimeout,
		KeepAlive: tcpKeepAlive,
		Control:   g.control,
	}
	g.dial = g.dialer.DialContext
	return g
}

// DialContext implements the http.Transport dial hook. Only "tcp" is
// accepted: a different network would be a different kind of egress.
func (g *guardDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("fetch: unsupported network %s", quoteShort(network))
	}
	host, port, err := splitHostPort(address)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, g.dialTimeout)
	defer cancel()
	addrs, err := g.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	return g.dialSerial(ctx, addrs, port)
}

func splitHostPort(address string) (string, uint16, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, fmt.Errorf("fetch: dial address %s: %w", quoteShort(address), err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return "", 0, fmt.Errorf("fetch: dial address %s: invalid port", quoteShort(address))
	}
	return host, uint16(port), nil
}

// resolve returns the addresses to dial for host. Every answer is vetted, not
// only the one that will be used: a name that resolves to one public and one
// private address is an attacker's name, and is refused whole.
func (g *guardDialer) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	t, err := parseTarget(host)
	if err != nil {
		return nil, err
	}
	if t.isLiteral() {
		if err := checkAddr(t.addr, g.allowPrivate); err != nil {
			return nil, err
		}
		return []netip.Addr{t.addr.Unmap()}, nil
	}
	answers, err := g.resolver.LookupIPAddr(ctx, t.name)
	if err != nil {
		return nil, fmt.Errorf("fetch: resolve %s: %w", quoteShort(t.name), err)
	}
	return g.vet(t.name, answers)
}

func (g *guardDialer) vet(name string, answers []net.IPAddr) ([]netip.Addr, error) {
	if len(answers) == 0 {
		return nil, fmt.Errorf("fetch: resolve %s: no addresses", quoteShort(name))
	}
	out := make([]netip.Addr, 0, len(answers))
	for _, answer := range answers {
		addr, ok := netip.AddrFromSlice(answer.IP)
		if !ok || answer.Zone != "" {
			return nil, fmt.Errorf("%w: resolver returned an unusable address for %s", ErrBlockedAddress, quoteShort(name))
		}
		if err := checkAddr(addr, g.allowPrivate); err != nil {
			return nil, fmt.Errorf("%w (resolved from %s)", err, quoteShort(name))
		}
		out = append(out, addr.Unmap())
	}
	return out, nil
}

// dialSerial tries the vetted addresses one after another, each by IP literal.
// It never hands a name back to the standard library, so there is no second
// resolution and no silent fallback to the system resolver or to another
// address family.
func (g *guardDialer) dialSerial(ctx context.Context, addrs []netip.Addr, port uint16) (net.Conn, error) {
	if len(addrs) == 0 {
		return nil, errors.New("fetch: dial: no addresses")
	}
	if len(addrs) > maxDialAddrs {
		addrs = addrs[:maxDialAddrs]
	}
	var lastErr error
	for i, addr := range addrs {
		attempt, cancel := attemptContext(ctx, len(addrs)-i)
		conn, err := g.dial(attempt, "tcp", netip.AddrPortFrom(addr, port).String())
		cancel()
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, fmt.Errorf("fetch: dial: %w", lastErr)
}

// attemptContext gives each remaining address an equal share of the time that
// is left, so one black-holed address cannot starve the others.
func attemptContext(ctx context.Context, remaining int) (context.Context, context.CancelFunc) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, time.Until(deadline)/time.Duration(remaining))
}

// control is net.Dialer.Control. It sees the final ip:port of the socket and
// applies the same classifier as resolve, so even a bug or a future change in
// the code above cannot connect to a forbidden address.
func (g *guardDialer) control(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: cannot parse connect address", ErrBlockedAddress)
	}
	return checkAddr(ap.Addr(), g.allowPrivate)
}
