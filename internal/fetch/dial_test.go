package fetch

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

var errStubDial = errors.New("stub dial failure")

// dialRecorder is a dialFunc that records every address it is asked to dial
// and fails the first failFirst attempts.
type dialRecorder struct {
	mu        sync.Mutex
	addrs     []string
	failFirst int
}

func (r *dialRecorder) dial(_ context.Context, network, address string) (net.Conn, error) {
	r.mu.Lock()
	r.addrs = append(r.addrs, network+" "+address)
	attempt := len(r.addrs)
	r.mu.Unlock()
	if attempt <= r.failFirst {
		return nil, errStubDial
	}
	client, server := net.Pipe()
	_ = server.Close()
	return client, nil
}

func (r *dialRecorder) recorded() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.addrs...)
}

func stubDialer(resolver Resolver, allowPrivate bool, dial dialFunc) *guardDialer {
	g := newGuardDialer(config{resolver: resolver, allowPrivate: allowPrivate, dialTimeout: time.Second})
	g.dial = dial
	return g
}

func TestDialPinsToResolvedAddressesByLiteral(t *testing.T) {
	resolver := newFakeResolver(t, map[string][]string{
		"example.test": {"93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"},
	})
	rec := &dialRecorder{failFirst: 1}
	g := stubDialer(resolver, false, rec.dial)

	conn, err := g.DialContext(context.Background(), "tcp", "example.test:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	_ = conn.Close()

	want := []string{"tcp 93.184.216.34:443", "tcp [2606:2800:220:1:248:1893:25c8:1946]:443"}
	got := rec.recorded()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("dialled %v, want %v (an IP literal each time, never the name)", got, want)
	}
	if resolver.callCount() != 1 {
		t.Fatalf("resolver called %d times, want exactly 1", resolver.callCount())
	}
}

func TestDialRejectsWholeNameIfAnyAnswerForbidden(t *testing.T) {
	for _, answers := range [][]string{
		{"93.184.216.34", "127.0.0.1"},
		{"127.0.0.1", "93.184.216.34"},
		{"93.184.216.34", "2606:4700:4700::1111", "169.254.169.254"},
		{"93.184.216.34", "::ffff:10.0.0.1"},
	} {
		resolver := newFakeResolver(t, map[string][]string{"mixed.test": answers})
		rec := &dialRecorder{}
		g := stubDialer(resolver, false, rec.dial)
		_, err := g.DialContext(context.Background(), "tcp", "mixed.test:80")
		if !errors.Is(err, ErrBlockedAddress) {
			t.Errorf("answers %v: got %v, want ErrBlockedAddress", answers, err)
		}
		if len(rec.recorded()) != 0 {
			t.Errorf("answers %v: dialled %v although one answer is forbidden", answers, rec.recorded())
		}
	}
}

// TestDialRebindingSecondAnswerIgnored models a DNS-rebinding server that
// answers with a public address first and a loopback address afterwards.
func TestDialRebindingSecondAnswerIgnored(t *testing.T) {
	resolver := &seqResolver{t: t, seq: [][]string{{"93.184.216.34"}, {"127.0.0.1"}}}
	rec := &dialRecorder{}
	g := stubDialer(resolver, false, rec.dial)

	conn, err := g.DialContext(context.Background(), "tcp", "rebind.test:80")
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	_ = conn.Close()
	if resolver.callCount() != 1 {
		t.Fatalf("one dial consulted the resolver %d times; pinning needs exactly 1", resolver.callCount())
	}
	if got := rec.recorded(); len(got) != 1 || got[0] != "tcp 93.184.216.34:80" {
		t.Fatalf("dialled %v, want only the first answer", got)
	}

	// A later dial re-resolves and sees the poisoned answer: it is refused.
	if _, err := g.DialContext(context.Background(), "tcp", "rebind.test:80"); !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("second dial: got %v, want ErrBlockedAddress", err)
	}
	if len(rec.recorded()) != 1 {
		t.Fatalf("second dial reached the network: %v", rec.recorded())
	}
}

func TestDialResolverFailures(t *testing.T) {
	boom := errors.New("boom")
	cases := []struct {
		name     string
		resolver Resolver
		want     error
	}{
		{"resolver error", resolverFunc(func(context.Context, string) ([]net.IPAddr, error) { return nil, boom }), boom},
		{"no answers", resolverFunc(func(context.Context, string) ([]net.IPAddr, error) { return nil, nil }), nil},
		{"invalid ip", resolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.IP{1, 2, 3}}}, nil
		}), ErrBlockedAddress},
		{"scoped answer", resolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("2606:4700:4700::1111"), Zone: "eth0"}}, nil
		}), ErrBlockedAddress},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &dialRecorder{}
			g := stubDialer(tc.resolver, false, rec.dial)
			_, err := g.DialContext(context.Background(), "tcp", "x.test:80")
			if err == nil {
				t.Fatal("expected an error")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if len(rec.recorded()) != 0 {
				t.Fatalf("dialled %v after a resolver failure", rec.recorded())
			}
		})
	}
}

func TestDialRejectsBadInput(t *testing.T) {
	cases := []struct{ network, address string }{
		{"udp", "example.test:80"},
		{"tcp4", "example.test:80"},
		{"tcp", "example.test"},
		{"tcp", "example.test:0"},
		{"tcp", "example.test:99999"},
		{"tcp", "example.test:http"},
		{"tcp", ":80"},
		{"tcp", "127.1:80"},
	}
	for _, tc := range cases {
		rec := &dialRecorder{}
		g := stubDialer(newFakeResolver(t, nil), false, rec.dial)
		if _, err := g.DialContext(context.Background(), tc.network, tc.address); err == nil {
			t.Errorf("%s %s: expected an error", tc.network, tc.address)
		}
		if len(rec.recorded()) != 0 {
			t.Errorf("%s %s: dialled %v", tc.network, tc.address, rec.recorded())
		}
	}
}

func TestDialLiteralSkipsResolver(t *testing.T) {
	resolver := newFakeResolver(t, nil) // any lookup fails the test
	rec := &dialRecorder{}
	g := stubDialer(resolver, true, rec.dial)
	conn, err := g.DialContext(context.Background(), "tcp", "[::ffff:127.0.0.1]:8080")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	_ = conn.Close()
	if got := rec.recorded(); len(got) != 1 || got[0] != "tcp 127.0.0.1:8080" {
		t.Fatalf("dialled %v, want the unmapped IPv4 literal", got)
	}
}

func TestDialTriesAtMostMaxDialAddrs(t *testing.T) {
	var answers []string
	for i := 1; i <= 3*maxDialAddrs; i++ {
		answers = append(answers, fmt.Sprintf("8.8.8.%d", i))
	}
	resolver := newFakeResolver(t, map[string][]string{"many.test": answers})
	rec := &dialRecorder{failFirst: 1000}
	g := stubDialer(resolver, false, rec.dial)
	if _, err := g.DialContext(context.Background(), "tcp", "many.test:80"); !errors.Is(err, errStubDial) {
		t.Fatalf("got %v, want the last dial error", err)
	}
	if n := len(rec.recorded()); n != maxDialAddrs {
		t.Fatalf("tried %d addresses, want %d", n, maxDialAddrs)
	}
}

func TestDialSerialWithoutAddresses(t *testing.T) {
	g := stubDialer(nil, false, (&dialRecorder{}).dial)
	if _, err := g.dialSerial(context.Background(), nil, 80); err == nil {
		t.Fatal("expected an error for an empty address list")
	}
}

func TestDialHonoursDialTimeout(t *testing.T) {
	resolver := newFakeResolver(t, map[string][]string{"slow.test": {"93.184.216.34"}})
	g := newGuardDialer(config{resolver: resolver, dialTimeout: 100 * time.Millisecond})
	g.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done() // a black-holed address: never answers
		return nil, ctx.Err()
	}
	start := time.Now()
	_, err := g.DialContext(context.Background(), "tcp", "slow.test:80")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want a deadline error", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("dial took %v, the 100ms timeout was not applied", elapsed)
	}
}

func TestDialTimeoutIsSharedBetweenAddresses(t *testing.T) {
	resolver := newFakeResolver(t, map[string][]string{"two.test": {"8.8.8.8", "8.8.4.4"}})
	g := newGuardDialer(config{resolver: resolver, dialTimeout: 400 * time.Millisecond})
	var mu sync.Mutex
	var calls int
	g.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		mu.Lock()
		calls++
		first := calls == 1
		mu.Unlock()
		if first {
			<-ctx.Done() // first address black-holed: must not eat the whole budget
			return nil, ctx.Err()
		}
		client, server := net.Pipe()
		_ = server.Close()
		return client, nil
	}
	conn, err := g.DialContext(context.Background(), "tcp", "two.test:80")
	if err != nil {
		t.Fatalf("the second address should have been tried: %v", err)
	}
	_ = conn.Close()
}

func TestControlChecksTheConnectedAddress(t *testing.T) {
	cases := []struct {
		address      string
		allowPrivate bool
		blocked      bool
	}{
		{"8.8.8.8:80", false, false},
		{"[2606:4700:4700::1111]:443", false, false},
		{"127.0.0.1:80", false, true},
		{"127.0.0.1:80", true, false},
		{"[::1]:80", false, true},
		{"10.1.2.3:80", false, true},
		{"10.1.2.3:80", true, false},
		{"169.254.169.254:80", false, true},
		{"169.254.169.254:80", true, true},
		{"[fd00:ec2::254]:80", true, true},
		{"[::ffff:169.254.169.254]:80", true, true},
		{"0.0.0.0:80", true, true},
		{"not-an-address", false, true},
		{"example.test:80", false, true},
		{"", false, true},
	}
	for _, tc := range cases {
		g := newGuardDialer(config{allowPrivate: tc.allowPrivate, dialTimeout: time.Second})
		err := g.control("tcp", tc.address, nil)
		if tc.blocked != errors.Is(err, ErrBlockedAddress) {
			t.Errorf("control(%q, allowPrivate=%v) = %v, blocked=%v expected", tc.address, tc.allowPrivate, err, tc.blocked)
		}
	}
}

// TestSocketLevelCheckStopsADirectDial dials a live loopback listener through
// the real net.Dialer with the dialer's Control hook, bypassing the vetting in
// DialContext. It proves the second line of defence works on its own.
func TestSocketLevelCheckStopsADirectDial(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accepted := make(chan struct{}, 1)
	go func() {
		if conn, err := ln.Accept(); err == nil {
			accepted <- struct{}{}
			_ = conn.Close()
		}
	}()

	strict := newGuardDialer(config{allowPrivate: false, dialTimeout: time.Second})
	if _, err := strict.dialer.DialContext(context.Background(), "tcp", ln.Addr().String()); !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("Control did not block the connect: %v", err)
	}
	select {
	case <-accepted:
		t.Fatal("the listener saw a connection that Control should have stopped")
	case <-time.After(100 * time.Millisecond):
	}

	lenient := newGuardDialer(config{allowPrivate: true, dialTimeout: time.Second})
	conn, err := lenient.dialer.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("AllowPrivate dial failed: %v", err)
	}
	_ = conn.Close()
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("the listener never saw the allowed connection")
	}
}

func TestNewGuardDialerDefaultsToSystemResolver(t *testing.T) {
	g := newGuardDialer(config{dialTimeout: time.Second})
	if g.resolver != Resolver(net.DefaultResolver) {
		t.Fatal("a nil Policy.Resolver must mean net.DefaultResolver")
	}
}
