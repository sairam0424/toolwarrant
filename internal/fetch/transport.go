package fetch

import (
	"fmt"
	"net/http"
	"strings"
)

// headerOverflowText is the fragment net/http puts in the error it returns
// when response headers pass MaxResponseHeaderBytes. The standard library has
// no sentinel for it, so the guard recognises the text and reports ErrTooLarge
// instead; a test pins the text so a Go upgrade that changes it fails loudly.
const headerOverflowText = "server response headers exceeded"

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
		return nil, mapTransportError(err)
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

func mapTransportError(err error) error {
	if strings.Contains(err.Error(), headerOverflowText) {
		return fmt.Errorf("%w: %w", ErrTooLarge, err)
	}
	return err
}
