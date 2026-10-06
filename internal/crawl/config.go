package crawl

import (
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// config is Options with defaults applied and the endpoint validated. It is
// built once per crawl so that a caller changing its Options afterwards
// cannot alter a crawl in progress.
type config struct {
	endpoint      string
	client        *http.Client
	headers       http.Header
	maxPages      int
	maxTools      int
	maxMessage    int
	maxToolBytes  int
	maxTotal      int
	timeout       time.Duration
	clientName    string
	clientVersion string
}

// newConfig validates endpoint and opt and applies defaults. It never puts
// the endpoint in an error because it may carry credentials in its query.
func newConfig(endpoint string, opt Options) (config, error) {
	if opt.Client == nil {
		return config{}, fmt.Errorf("%w: Client is required", ErrInvalidOptions)
	}
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return config{}, fmt.Errorf("%w: endpoint must be an absolute http or https URL", ErrInvalidOptions)
	}
	if err := checkLimits(opt); err != nil {
		return config{}, err
	}
	return config{
		endpoint:      endpoint,
		client:        opt.Client,
		headers:       callerHeaders(opt.Headers),
		maxPages:      orDefault(opt.MaxPages, defaultMaxPages),
		maxTools:      orDefault(opt.MaxTools, defaultMaxTools),
		maxMessage:    orDefault(opt.MaxMessageBytes, defaultMaxMessageBytes),
		maxToolBytes:  orDefault(opt.MaxToolBytes, defaultMaxToolBytes),
		maxTotal:      orDefault(opt.MaxTotalBytes, defaultMaxTotalBytes),
		timeout:       orDefaultDuration(opt.Timeout, defaultTimeout),
		clientName:    orDefaultString(opt.ClientName, defaultClientName),
		clientVersion: orDefaultString(opt.ClientVersion, defaultClientVersion),
	}, nil
}

// checkLimits refuses negative limits. A negative value is a mistake, not a
// request for "unlimited", and silently replacing it with a default would hide
// the mistake.
func checkLimits(opt Options) error {
	if opt.MaxPages < 0 || opt.MaxTools < 0 || opt.MaxMessageBytes < 0 || opt.MaxToolBytes < 0 || opt.MaxTotalBytes < 0 {
		return fmt.Errorf("%w: limits must not be negative", ErrInvalidOptions)
	}
	if opt.Timeout < 0 {
		return fmt.Errorf("%w: Timeout must not be negative", ErrInvalidOptions)
	}
	return nil
}

// callerHeaders copies the caller's headers, leaving out the ones this package
// owns, so that a caller can neither forge a session nor change how the body
// is framed, and so that later changes to the caller's map do not reach the
// crawl.
func callerHeaders(in http.Header) http.Header {
	out := http.Header{}
	for k, v := range in {
		key := http.CanonicalHeaderKey(k)
		if isProtocolHeader(key) {
			continue
		}
		out[key] = append([]string(nil), v...)
	}
	return out
}

// isProtocolHeader reports whether key is a header this package owns.
func isProtocolHeader(key string) bool {
	switch key {
	case "Content-Type", "Accept", "Content-Length", http.CanonicalHeaderKey(headerSessionID), http.CanonicalHeaderKey(headerProtocol):
		return true
	}
	return false
}

func orDefault(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

func orDefaultDuration(v, def time.Duration) time.Duration {
	if v == 0 {
		return def
	}
	return v
}

func orDefaultString(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
