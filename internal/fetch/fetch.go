// Package fetch is the only egress path toolwarrant uses to crawl upstream MCP
// servers. The URL of an upstream is operator input and everything it sends
// back is hostile, so this package makes the network-level decisions itself
// instead of trusting a check on the URL string.
//
// Several 2026 gateway projects shipped hand-written SSRF guards that were
// bypassed (decimal and octal IPv4 spellings, IPv4-mapped IPv6, DNS
// rebinding, redirects). The design here avoids that class of bug by deciding
// at connect time, on the address that is really dialled:
//
//   - the dialer resolves the name itself, rejects the whole name if any
//     answer is forbidden, and then dials one allowed answer by IP, so a
//     second DNS answer cannot change the target (pinning);
//   - net.Dialer.Control re-checks the final ip:port of the socket, using the
//     same classifier, as a second and independent line of defence;
//   - proxies are never used, because through a proxy the dial check would
//     only ever see the proxy's address;
//   - redirects are refused by default and never carry credentials;
//   - response headers and bodies are size capped after decompression.
//
// Build a client with NewClient and use it for every upstream request.
package fetch

import (
	"crypto/tls"
	"errors"
	"net/http"
)

// Sentinel errors. Every refusal made by this package wraps exactly one of
// these so callers can tell "the policy said no" from "the network failed"
// with errors.Is, without matching on message text.
var (
	// ErrBlockedAddress means a literal or resolved address is forbidden by
	// the SSRF policy (loopback, private, link-local, metadata and so on).
	ErrBlockedAddress = errors.New("fetch: address not allowed")

	// ErrBlockedHost means the request URL is unacceptable before any address
	// is considered: user info, an empty or malformed host, or a host that is
	// not in Policy.AllowHosts.
	ErrBlockedHost = errors.New("fetch: host not allowed")

	// ErrBlockedScheme means the URL (or a redirect target) uses a scheme
	// other than http or https.
	ErrBlockedScheme = errors.New("fetch: scheme not allowed")

	// ErrRedirect means the upstream answered with a redirect that policy
	// does not allow following: any redirect when MaxRedirects is 0, a
	// cross-origin redirect, or a chain longer than MaxRedirects.
	ErrRedirect = errors.New("fetch: redirect refused")

	// ErrTooLarge means a response header or body exceeded its size cap.
	ErrTooLarge = errors.New("fetch: response too large")
)

// maxResponseHeaderBytes caps the total size of response headers. Legitimate
// MCP servers send a few hundred bytes; the cap stops header-stuffing.
const maxResponseHeaderBytes = 64 << 10

// NewClient validates p, applies defaults and returns an *http.Client whose
// transport enforces the policy on every request, including redirects.
//
// The client is safe for concurrent use. It performs no retries: keep-alive is
// off so every request uses a fresh, freshly vetted connection and the
// standard library never silently replays a request on a stale one. HTTP/2 is
// off too, which keeps the header cap and the pinned dial simple and exact.
func NewClient(p Policy) (*http.Client, error) {
	cfg, err := newConfig(p)
	if err != nil {
		return nil, err
	}
	dialer := newGuardDialer(cfg)
	base := &http.Transport{
		// Proxy stays nil on purpose: see the package comment.
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    cfg.dialTimeout,
		ExpectContinueTimeout:  expectContinueTimeout,
		MaxResponseHeaderBytes: maxResponseHeaderBytes,
		DisableKeepAlives:      true,
		ForceAttemptHTTP2:      false,
		// A non-nil empty map switches HTTP/2 off even if a future Go release
		// changes the default.
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	guard := &guardTransport{
		base:         base,
		allowHosts:   cfg.allowHosts,
		maxBytes:     cfg.maxBytes,
		maxRedirects: cfg.maxRedirects,
	}
	return &http.Client{
		Transport:     guard,
		Timeout:       cfg.timeout,
		CheckRedirect: guard.checkRedirect,
	}, nil
}
