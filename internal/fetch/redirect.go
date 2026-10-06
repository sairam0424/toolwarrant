package fetch

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// refusesRedirect reports whether a 3xx response must be turned into
// ErrRedirect instead of being handed to the client's redirect machinery.
//
// With MaxRedirects 0 that is every 3xx. With a positive limit it is every 3xx
// the client would not follow anyway (300, 304, a missing Location and so on),
// so that no 3xx ever reaches the caller as if it were a normal answer.
func (g *guardTransport) refusesRedirect(resp *http.Response) bool {
	if resp.StatusCode < 300 || resp.StatusCode > 399 {
		return false
	}
	return g.maxRedirects == 0 || !followable(resp)
}

// followable reports whether net/http would follow this response.
func followable(resp *http.Response) bool {
	switch resp.StatusCode {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return resp.Header.Get("Location") != ""
	}
	return false
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
