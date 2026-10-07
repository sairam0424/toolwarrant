package emit

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
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

// Secret bounds. A shared secret shorter than MinSecretLen gives false
// assurance (a burst of hooks can guess it), and MaxSecretLen keeps the config
// line and the processor's constant-time comparison small.
const (
	MinSecretLen = 16
	MaxSecretLen = 256
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

// validated is the checked input: the servers sorted by name and the address
// the serving gateway binds, in canonical form.
type validated struct {
	servers []Server
	bind    netip.Addr
}

// validate checks the whole input and returns a copy of the servers sorted by
// name plus the bind address. The caller's slice is never modified. Nothing is
// emitted for input that fails any check, because a half-written gateway
// config is worse than none: it could leave a route without an authorization
// rule.
//
// A processor address may appear once: the processor serves exactly one
// target and denies hooks for any other, so two servers on one address would
// leave the second one with every tool denied and nothing in the config to
// say why. The comparison is textual; two spellings of one listener are the
// operator's problem to avoid.
func validate(in Input) (validated, error) {
	if in.ListenPort < minPort || in.ListenPort > maxPort {
		return validated{}, invalid("listen port %d is outside %d-%d", in.ListenPort, minPort, maxPort)
	}
	bind, err := validateBindAddress(in)
	if err != nil {
		return validated{}, err
	}
	if len(in.Servers) == 0 {
		return validated{}, invalid("no servers: a gateway with no routes would serve nothing")
	}
	names := make(map[string]struct{}, len(in.Servers))
	processors := make(map[string]string, len(in.Servers))
	out := make([]Server, 0, len(in.Servers))
	for _, s := range in.Servers {
		if err := validateServer(s); err != nil {
			return validated{}, err
		}
		if _, dup := names[s.Name]; dup {
			return validated{}, invalid("duplicate server name %s", shown(s.Name))
		}
		if other, dup := processors[s.ProcessorAddr]; dup {
			return validated{}, invalid("duplicate processor address %s: used by servers %s and %s", shown(s.ProcessorAddr), other, s.Name)
		}
		names[s.Name] = struct{}{}
		processors[s.ProcessorAddr] = s.Name
		out = append(out, s)
	}
	sortServers(out)
	return validated{servers: out, bind: bind}, nil
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
	if err := validateSecret(s.Secret); err != nil {
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
// decimal port in range. agentgateway's --validate-only also accepts http://,
// https:// and unix:// forms in this field, but its schema documents the field
// only as "Hostname or IP address", so those forms stay refused until an
// end-to-end run proves what the gateway does with them.
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

// validateSecret accepts an empty secret (the check is off) or printable ASCII
// within the length bounds. The value is never echoed: it is a credential.
func validateSecret(secret string) error {
	if secret == "" {
		return nil
	}
	if !isPrintableASCII(secret) {
		return errors.New("secret must be printable ASCII")
	}
	if len(secret) < MinSecretLen || len(secret) > MaxSecretLen {
		return fmt.Errorf("secret must be %d-%d bytes", MinSecretLen, MaxSecretLen)
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
