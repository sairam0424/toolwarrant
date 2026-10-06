package fetch

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// maxRedirectChain bounds the walk from a redirect-hop request back to the
// request the caller made. net/http links hops through Request.Response and
// never builds a chain longer than its redirect limit, so a longer chain is not
// one net/http built; initialRequest then reports failure and the redirect is
// refused rather than guessed about.
const maxRedirectChain = 2 * maxRedirectsCeiling

// refusesRedirect reports whether a 3xx response must be turned into
// ErrRedirect instead of being handed to the client's redirect machinery.
//
// With MaxRedirects 0 that is every 3xx. With a positive limit it is every 3xx
// the client would not follow anyway (300, 304, a missing Location, a 307 or
// 308 whose request body cannot be sent again, and so on), so that no 3xx ever
// reaches the caller as if it were a normal answer.
func (g *guardTransport) refusesRedirect(resp *http.Response) bool {
	if resp.StatusCode < 300 || resp.StatusCode > 399 {
		return false
	}
	return g.maxRedirects == 0 || !followable(resp)
}

// followable reports whether net/http would follow this response. It mirrors
// net/http's redirectBehavior: 301, 302 and 303 need only a Location, because
// the retry is a GET without a body; 307 and 308 keep the method and the body,
// so they also need a body that can be sent again. When it cannot be, net/http
// does not fail: it hands the 3xx back to the caller as the final response,
// which this package promises never to do, so such a response is refused here.
func followable(resp *http.Response) bool {
	if resp.Header.Get("Location") == "" {
		return false
	}
	switch resp.StatusCode {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther:
		return true
	case http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		first, ok := initialRequest(resp)
		return ok && bodyReplayable(first)
	}
	return false
}

// initialRequest returns the request the caller made. On a redirect hop
// resp.Request is a request net/http created, linked to the response that
// caused it through Request.Response; net/http decides about 307 and 308 by
// looking at the caller's request (a POST with a one-shot body that was
// redirected with 302 and then 307 still counts as unreplayable), so the walk
// goes all the way back. ok is false when the chain is broken or longer than
// net/http could have built.
func initialRequest(resp *http.Response) (*http.Request, bool) {
	req := resp.Request
	for hops := 0; req != nil && req.Response != nil; hops++ {
		if hops >= maxRedirectChain {
			return nil, false
		}
		req = req.Response.Request
	}
	return req, req != nil
}

// bodyReplayable mirrors net/http's rule for 307 and 308: the request can be
// sent again when it has no body or when GetBody can produce a fresh copy.
// http.NewRequest sets GetBody for bytes and strings readers only; any other
// reader is consumed by the first attempt.
func bodyReplayable(req *http.Request) bool {
	return req.Body == nil || req.Body == http.NoBody || req.GetBody != nil
}

// redirectRefusal builds the error for a refused redirect. A redirect to a
// scheme other than http(s) is both a refused redirect and a blocked scheme,
// and the error matches both sentinels. The Location value itself is hostile
// and is never echoed except for a short, quoted scheme.
func redirectRefusal(resp *http.Response) error {
	target, err := url.Parse(resp.Header.Get("Location"))
	if err == nil && target.Scheme != "" {
		if schemeErr := checkScheme(target.Scheme); schemeErr != nil {
			return fmt.Errorf("%w (status %d): %w", ErrRedirect, resp.StatusCode, schemeErr)
		}
	}
	return fmt.Errorf("%w (status %d)", ErrRedirect, resp.StatusCode)
}

// checkRedirect is http.Client.CheckRedirect. It runs only for redirects that
// reached the client, which happens only when MaxRedirects is positive and the
// redirect is one net/http would follow. It allows a hop only if the target
// uses http(s), the chain is within the limit, and the target has exactly the
// scheme, host and port of the request it came from. Credentials are removed
// in RoundTrip, where the request can be copied instead of modified.
func (g *guardTransport) checkRedirect(req *http.Request, via []*http.Request) error {
	if g.maxRedirects == 0 || len(via) == 0 {
		return fmt.Errorf("%w: redirects are disabled", ErrRedirect)
	}
	if err := checkScheme(req.URL.Scheme); err != nil {
		return fmt.Errorf("%w: %w", ErrRedirect, err)
	}
	if len(via) > g.maxRedirects {
		return fmt.Errorf("%w: stopped after %d redirects", ErrRedirect, g.maxRedirects)
	}
	if !sameOrigin(via[len(via)-1].URL, req.URL) {
		return fmt.Errorf("%w: redirect leaves the original scheme, host or port", ErrRedirect)
	}
	return nil
}

// sameOrigin compares scheme, host and port, with default ports filled in and
// host names compared case-insensitively.
func sameOrigin(a, b *url.URL) bool {
	return originKey(a) == originKey(b)
}

func originKey(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	if port == "" {
		port = defaultPort(scheme)
	}
	return scheme + "://" + net.JoinHostPort(hostKey(u.Hostname()), port)
}

func defaultPort(scheme string) string {
	if scheme == "https" {
		return "443"
	}
	return "80"
}
