package emit

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// Port and name limits. The server name ends up in a URL path, a route name
// and a backend target name, so it is held to a strict, boring alphabet.
const (
	minPort       = 1
	maxPort       = 65535
	maxPortDigits = 5
	maxHostLen    = 253
	maxNameShown  = 64
)

// ErrInvalidInput is wrapped by every error AgentGateway returns for input it
// refuses to turn into gateway configuration, so callers can tell "fix the
// catalog" apart from an internal failure with errors.Is.
var ErrInvalidInput = errors.New("emit: invalid input")

var (
	serverNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	// hostPattern accepts DNS names and IPv4 literals only. agentgateway
	// v1.6.0 rejects bracketed IPv6 in a processor host, so refusing it here
	// turns a gateway start-up failure into an error at generation time.
	hostPattern = regexp.MustCompile(`^[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?(\.[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)*$`)
)

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidInput, fmt.Sprintf(format, args...))
}

// shown renders hostile text for an error message: quoted so control
// characters are visible, and truncated so a huge name cannot flood a log.
func shown(s string) string {
	if len(s) > maxNameShown {
		s = s[:maxNameShown] + "..."
	}
	return fmt.Sprintf("%q", s)
}

// validate checks the whole input and returns a copy of the servers sorted by
// name. The caller's slice is never modified. Nothing is emitted for input
// that fails any check, because a half-written gateway config is worse than
// none: it could leave a route without an authorization rule.
func validate(in Input) ([]Server, error) {
	if in.ListenPort < minPort || in.ListenPort > maxPort {
		return nil, invalid("listen port %d is outside %d-%d", in.ListenPort, minPort, maxPort)
	}
	if len(in.Servers) == 0 {
		return nil, invalid("no servers: a gateway with no routes would serve nothing")
	}
	seen := make(map[string]struct{}, len(in.Servers))
	out := make([]Server, 0, len(in.Servers))
	for _, s := range in.Servers {
		if err := validateServer(s); err != nil {
			return nil, err
		}
		if _, dup := seen[s.Name]; dup {
			return nil, invalid("duplicate server name %s", shown(s.Name))
		}
		seen[s.Name] = struct{}{}
		out = append(out, s)
	}
	sortServers(out)
	return out, nil
}

func validateServer(s Server) error {
	if !serverNamePattern.MatchString(s.Name) {
		return invalid("server name %s does not match %s", shown(s.Name), serverNamePattern)
	}
	if err := validateUpstreamURL(s.URL); err != nil {
		return invalid("server %s: %v", s.Name, err)
	}
	if err := validateProcessorAddr(s.ProcessorAddr); err != nil {
		return invalid("server %s: %v", s.Name, err)
	}
	return nil
}

// validateUpstreamURL requires an absolute http or https URL with a host and
// no embedded credentials. The URL itself is deliberately not echoed in the
// error: it comes from a catalog that may hold tokens in the query string.
func validateUpstreamURL(raw string) error {
	if !isPrintableASCII(raw) || strings.ContainsAny(raw, " ") {
		return errors.New("url must be printable ASCII without spaces")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("url does not parse")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("url scheme must be http or https")
	}
	if u.Hostname() == "" {
		return errors.New("url has no host")
	}
	if u.User != nil {
		return errors.New("url must not contain credentials")
	}
	if port := u.Port(); port != "" && !isPortNumber(port) {
		return fmt.Errorf("url port must be %d-%d", minPort, maxPort)
	}
	return nil
}

// validateProcessorAddr requires host:port with a DNS-name or IPv4 host and a
// decimal port in range.
func validateProcessorAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return errors.New("processor address must be host:port")
	}
	if len(host) > maxHostLen || !hostPattern.MatchString(host) {
		return errors.New("processor host must be a DNS name or IPv4 address")
	}
	if !isPortNumber(port) {
		return fmt.Errorf("processor port must be %d-%d", minPort, maxPort)
	}
	return nil
}

// isPortNumber accepts only plain decimal digits, so forms strconv.Atoi
// tolerates ("+80", " 80") are refused.
func isPortNumber(s string) bool {
	if s == "" || len(s) > maxPortDigits {
		return false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n >= minPort && n <= maxPort
}
