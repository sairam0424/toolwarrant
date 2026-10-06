package fetch

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// headerOverflowFormat is the message net/http builds (go1.27.1,
// net/http/transport.go, persistConn.readLoop) when response headers pass
// Transport.MaxResponseHeaderBytes, with the cap filled in. The standard
// library exports no sentinel for the condition, so the guard recognises the
// message instead, under three conditions that keep server-written bytes from
// forging it: no response came with the error, the innermost error carries this
// text, and it carries nothing else. TestResponseHeaderOverflow pins the
// wording against the Go version the tests run with, so a release that changes
// it fails loudly instead of silently turning the condition into a generic
// transport error.
const headerOverflowFormat = "net/http: server response headers exceeded %d bytes; aborted"

// maxUnwrapDepth bounds the walk to the innermost error, so that an Unwrap
// cycle cannot hang the error path.
const maxUnwrapDepth = 32

// credentialHeaders must never follow a redirect, not even to the same host.
var credentialHeaders = []string{"Authorization", "Proxy-Authorization", "Cookie", "Cookie2"}

// guardTransport is the http.RoundTripper every request goes through. It
// checks what can be checked on the request before any socket exists, delegates
// the connect-time checks to the dialer underneath, and polices the response.
type guardTransport struct {
	base         http.RoundTripper
	allowHosts   map[string]struct{}
	maxBytes     int64
	maxRedirects int
}

// RoundTrip implements http.RoundTripper.
func (g *guardTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := g.checkRequest(req); err != nil {
		// The RoundTripper contract: the body is closed on every path.
		if req != nil && req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, err
	}
	resp, err := g.base.RoundTrip(outgoing(req))
	if err != nil {
		return nil, mapTransportError(resp, err)
	}
	return g.vetResponse(resp)
}

// checkRequest rejects requests that are unacceptable regardless of where the
// host resolves. Order matters only for which sentinel a caller sees.
func (g *guardTransport) checkRequest(req *http.Request) error {
	if req == nil || req.URL == nil {
		return fmt.Errorf("%w: request has no URL", ErrBlockedHost)
	}
	if err := checkScheme(req.URL.Scheme); err != nil {
		return err
	}
	if req.URL.User != nil {
		return fmt.Errorf("%w: URL carries user info", ErrBlockedHost)
	}
	host := req.URL.Hostname()
	if host == "" {
		return fmt.Errorf("%w: URL has no host", ErrBlockedHost)
	}
	if len(g.allowHosts) > 0 {
		if _, ok := g.allowHosts[hostKey(host)]; !ok {
			return fmt.Errorf("%w: %s is not in the allow-list", ErrBlockedHost, quoteShort(host))
		}
	}
	_, err := parseTarget(host)
	return err
}

func checkScheme(scheme string) error {
	switch strings.ToLower(scheme) {
	case "http", "https":
		return nil
	}
	return fmt.Errorf("%w: %s", ErrBlockedScheme, quoteShort(scheme))
}

// outgoing returns the request that is actually sent. The caller's request is
// never modified: a copy is made only when something has to change.
//
//   - Accept-Encoding is dropped so the standard transport negotiates gzip
//     itself and decodes it transparently; the body cap then counts decoded
//     bytes rather than whatever the caller asked to receive raw.
//   - On a redirect hop (Request.Response is set by net/http) credentials are
//     removed, even for same-origin redirects.
func outgoing(req *http.Request) *http.Request {
	dropEncoding := req.Header.Get("Accept-Encoding") != ""
	isRedirect := req.Response != nil
	if !dropEncoding && !isRedirect {
		return req
	}
	out := req.Clone(req.Context())
	out.Header.Del("Accept-Encoding")
	if isRedirect {
		for _, name := range credentialHeaders {
			out.Header.Del(name)
		}
	}
	return out
}

// vetResponse enforces the redirect and size policy on a response that the
// transport obtained.
func (g *guardTransport) vetResponse(resp *http.Response) (*http.Response, error) {
	if g.refusesRedirect(resp) {
		_ = resp.Body.Close()
		return nil, redirectRefusal(resp)
	}
	if resp.ContentLength > g.maxBytes {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("%w: content-length %d exceeds %d bytes", ErrTooLarge, resp.ContentLength, g.maxBytes)
	}
	if resp.Body == nil {
		resp.Body = http.NoBody
	}
	resp.Body = newCappedBody(resp.Body, g.maxBytes)
	return resp, nil
}

// headerOverflowText is the exact message for the cap this package configures.
func headerOverflowText() string {
	return fmt.Sprintf(headerOverflowFormat, maxResponseHeaderBytes)
}

// mapTransportError turns the header-overflow failure into ErrTooLarge and
// leaves every other error alone. Only the innermost error is compared, and
// only for its whole text: every net/http error that embeds bytes a server sent
// (a malformed status line, a malformed header line, ...) starts with a fixed
// prefix of its own, so no header the server writes can produce this text at
// the innermost level. A response returned alongside an error breaks the
// RoundTripper contract; it is closed and the error passes unmapped.
func mapTransportError(resp *http.Response, err error) error {
	if resp != nil {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		return err
	}
	if leafError(err).Error() == headerOverflowText() {
		return fmt.Errorf("%w: %w", ErrTooLarge, err)
	}
	return err
}

// leafError follows single-error Unwrap chains to the innermost error. Joined
// errors are not entered: net/http does not join here, and leaving an error
// unmapped is the safe direction, since the caller sees a transport failure
// either way.
func leafError(err error) error {
	for i := 0; i < maxUnwrapDepth; i++ {
		inner := errors.Unwrap(err)
		if inner == nil {
			return err
		}
		err = inner
	}
	return err
}
