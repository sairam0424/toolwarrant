package fetch

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

// Defaults applied by NewClient to zero-valued Policy fields.
const (
	// DefaultTimeout bounds one whole request, including reading the body.
	DefaultTimeout = 15 * time.Second
	// DefaultDialTimeout bounds name resolution plus connecting.
	DefaultDialTimeout = 5 * time.Second
	// DefaultMaxResponseBytes caps a response body after decompression.
	DefaultMaxResponseBytes int64 = 8 << 20
)

const (
	// maxRedirectsCeiling keeps a misconfigured policy from allowing an
	// effectively unbounded redirect chain.
	maxRedirectsCeiling = 10
	// expectContinueTimeout is how long a request body waits for a 100-continue.
	expectContinueTimeout = time.Second
)

// Resolver looks up the addresses of a host name. The dialer uses it instead
// of letting net/http resolve, so the answers it vets are the answers it dials.
// *net.Resolver satisfies it; tests inject a fake.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// Policy configures the SSRF-hardened client. The zero value is the strictest
// useful policy: public addresses only, no redirects, no allow-list.
type Policy struct {
	// AllowPrivate relaxes loopback (127.0.0.0/8, ::1), RFC 1918 and
	// unique-local (fc00::/7) addresses so a local or in-cluster upstream can
	// be crawled. It never relaxes link-local (and so the cloud metadata
	// address), multicast, unspecified, reserved or cloud-metadata ranges.
	AllowPrivate bool

	// AllowHosts, when non-empty, restricts requests to these host names. The
	// request host (lower-cased, without port) must equal an entry exactly;
	// there are no wildcards. It narrows what AllowPrivate and the address
	// policy already allow; it never widens them.
	AllowHosts []string

	// Timeout bounds one request end to end. Zero means DefaultTimeout.
	Timeout time.Duration

	// DialTimeout bounds resolving and connecting. Zero means
	// DefaultDialTimeout.
	DialTimeout time.Duration

	// MaxResponseBytes caps a response body, counted after decompression so a
	// gzip bomb stops at the cap. Zero means DefaultMaxResponseBytes.
	MaxResponseBytes int64

	// MaxRedirects is how many same-origin redirects may be followed. Zero,
	// the default, refuses every redirect with ErrRedirect.
	MaxRedirects int

	// Resolver resolves host names. Nil means net.DefaultResolver.
	Resolver Resolver
}

// config is a validated, defaulted, immutable copy of a Policy. Keeping it
// separate means later changes to the caller's Policy (or its AllowHosts
// slice) cannot alter a client that already exists.
type config struct {
	allowPrivate bool
	allowHosts   map[string]struct{}
	timeout      time.Duration
	dialTimeout  time.Duration
	maxBytes     int64
	maxRedirects int
	resolver     Resolver
}

// newConfig validates p and fills in defaults. It rejects negative limits and
// malformed allow-list entries so a typo fails at start-up, not as a silently
// open or silently closed gate.
func newConfig(p Policy) (config, error) {
	if p.Timeout < 0 || p.DialTimeout < 0 || p.MaxResponseBytes < 0 || p.MaxRedirects < 0 {
		return config{}, errors.New("fetch: policy: limits must not be negative")
	}
	if p.MaxRedirects > maxRedirectsCeiling {
		return config{}, fmt.Errorf("fetch: policy: MaxRedirects %d exceeds the limit of %d", p.MaxRedirects, maxRedirectsCeiling)
	}
	hosts, err := normalizeAllowHosts(p.AllowHosts)
	if err != nil {
		return config{}, err
	}
	cfg := config{
		allowPrivate: p.AllowPrivate,
		allowHosts:   hosts,
		timeout:      p.Timeout,
		dialTimeout:  p.DialTimeout,
		maxBytes:     p.MaxResponseBytes,
		maxRedirects: p.MaxRedirects,
		resolver:     p.Resolver,
	}
	if cfg.timeout == 0 {
		cfg.timeout = DefaultTimeout
	}
	if cfg.dialTimeout == 0 {
		cfg.dialTimeout = DefaultDialTimeout
	}
	if cfg.maxBytes == 0 {
		cfg.maxBytes = DefaultMaxResponseBytes
	}
	return cfg, nil
}

// normalizeAllowHosts turns the allow-list into a lookup set. Entries are
// bare host names or IP literals; anything that looks like a URL, a path or a
// host:port pair is a configuration mistake and is rejected.
func normalizeAllowHosts(entries []string) (map[string]struct{}, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	set := make(map[string]struct{}, len(entries))
	for i, entry := range entries {
		host, err := normalizeAllowEntry(entry)
		if err != nil {
			return nil, fmt.Errorf("fetch: policy: AllowHosts[%d]: %w", i, err)
		}
		set[host] = struct{}{}
	}
	return set, nil
}

// normalizeAllowEntry validates one allow-list entry and returns its
// canonical comparison form (see hostKey).
func normalizeAllowEntry(entry string) (string, error) {
	host := strings.TrimSpace(entry)
	if host == "" {
		return "", errors.New("entry is empty")
	}
	if strings.ContainsAny(host, "/@?# \t\r\n") {
		return "", errors.New("entry must be a bare host name, not a URL")
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if strings.Contains(host, ":") {
		addr, err := netip.ParseAddr(host)
		if err != nil || addr.Zone() != "" {
			return "", errors.New("entry must not contain a port; only IPv6 literals may contain a colon")
		}
	}
	return hostKey(host), nil
}

// hostKey is the form in which host names are compared against the allow-list:
// lower case, and IP literals in their canonical text form so that
// "0:0:0:0:0:0:0:1" and "::1" are the same entry.
func hostKey(host string) string {
	host = strings.ToLower(host)
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.String()
	}
	return host
}
