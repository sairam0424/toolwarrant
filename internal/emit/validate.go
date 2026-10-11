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
	minPort          = 1
	maxPort          = 65535
	maxPortDigits    = 5
	maxHostLen       = 253
	maxNameShown     = 64
	maxServerNameLen = 63
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
	// serverNamePattern is agentgateway v1.6.0's MCP target-name rule minus
	// the dot: the gateway refuses '_' (a reserved MCP delimiter) and a leading
	// or trailing '-' with "invalid MCP target name", and keeps serving its
	// previous configuration when a reload fails, so a name it would refuse is
	// refused here first. The length cap is separate because the gateway
	// enforces none at load time and 63 bytes is the SectionName limit.
	serverNamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
	// hostPattern accepts DNS names and IPv4 literals only. agentgateway
	// v1.6.0 rejects bracketed IPv6 in a processor host, so refusing it here
	// turns a gateway start-up failure into an error at generation time. The
	// shape admits the resolver's numeric shorthand ("127.1", "0x7f.0.0.1");
	// refuseAmbiguousHost refuses those before this pattern is consulted.
	hostPattern = regexp.MustCompile(`^[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?(\.[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)*$`)
)

// urlPunctuation is every non-alphanumeric character RFC 3986 allows in a
// URI (the unreserved marks, gen-delims and sub-delims) plus the percent sign
// that introduces an encoded byte. agentgateway's URI parser refuses a URL
// with anything else ("invalid uri character" for a double quote, an angle
// bracket or a space), and the characters it happens to tolerate at load time
// (| ^ { } ` and backslash) are refused here as well, so that the alphabet is
// a standard and not a reading of one parser version.
const urlPunctuation = "-._~:/?#[]@!$&'()*+,;=%"

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

// validated is the checked input: the servers sorted by name, the address
// the serving gateway binds in canonical form, and the three listeners.
type validated struct {
	servers   []Server
	bind      netip.Addr
	listeners []listener
}

// validate checks the whole input and returns a copy of the servers sorted by
// name plus the addresses. The caller's slice is never modified. Nothing is
// emitted for input that fails any check, because a half-written gateway
// config is worse than none: it could leave a route without an authorization
// rule.
//
// A processor address may appear once: the processor serves exactly one
// target and denies hooks for any other, so two servers on one address would
// leave the second one with every tool denied and nothing in the config to
// say why. The comparison is textual; two spellings of one listener are the
// operator's problem to avoid.
//
// A processor address may not be one of the gateway's own sockets either: a
// loopback, localhost or wildcard host with the serving port or a listener
// port, or the very address the input binds for that socket, is the socket
// the gateway binds itself, so the gateway would dial its own HTTP listener
// for every hook (fail closed, every route of that server dark) or, if the
// processor started first, fail to bind. A host that is not an IP literal is
// refused with such a port as well, because a name may resolve to this host
// (D15 h; the names common resolvers map to loopback without DNS,
// IsLoopbackName, are this host like 127.0.0.1). A numeric host that is not a
// canonical dotted quad ("127.1", "0x7f.0.0.1") is refused before that rule,
// because the resolver reads it as an address the rule cannot see
// (refuseAmbiguousHost). --validate-only accepts the collision, the names and
// the spellings alike (TestGatewayAcceptsAProcessorOnItsOwnSocket,
// TestGatewayAcceptsAProcessorNamedForItsOwnSocket,
// TestGatewayAcceptsAmbiguousProcessorSpellings), so these checks are the
// only ones between emit and the reload.
func validate(in Input) (validated, error) {
	if in.ListenPort < minPort || in.ListenPort > maxPort {
		return validated{}, invalid("listen port %d is outside %d-%d", in.ListenPort, minPort, maxPort)
	}
	bind, err := validateBindAddress(in)
	if err != nil {
		return validated{}, err
	}
	listeners, reserved, err := validateListeners(in, bind)
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
		if err := validateServer(s, reserved); err != nil {
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
	return validated{servers: out, bind: bind, listeners: listeners}, nil
}

// validateServer checks one server; reserved is the socket map
// validateListeners returned. The name is checked first so that every later
// error can carry it.
func validateServer(s Server, reserved map[int]gatewaySocket) error {
	if err := validateServerName(s.Name); err != nil {
		return err
	}
	if err := validateUpstreamURL(s.URL); err != nil {
		return invalid("server %s: %v", s.Name, err)
	}
	if err := validateProcessorAddr(s.ProcessorAddr, reserved); err != nil {
		return invalid("server %s: %v", s.Name, err)
	}
	if err := validateSecret(s.Secret); err != nil {
		return invalid("server %s: %v", s.Name, err)
	}
	return nil
}

// validateServerName applies the gateway's target-name rule (see
// serverNamePattern) and the 63-byte cap. The length is checked first so a
// huge name gets a short error.
func validateServerName(name string) error {
	if len(name) > maxServerNameLen {
		return invalid("server name %s is longer than %d bytes", shown(name), maxServerNameLen)
	}
	if !serverNamePattern.MatchString(name) {
		return invalid("server name %s does not match %s: agentgateway's MCP target rule reserves '_' and refuses a leading or trailing '-'; '.' is refused here on purpose", shown(name), serverNamePattern)
	}
	return nil
}

// validateUpstreamURL requires an absolute http or https URL within the
// RFC 3986 alphabet, with a host and no embedded credentials. The URL itself
// is deliberately not echoed in the error: it comes from a catalog that may
// hold tokens in the query string.
func validateUpstreamURL(raw string) error {
	if !hasOnlyURLBytes(raw) {
		return errors.New("url contains a character outside the RFC 3986 alphabet (letters, digits and " + urlPunctuation + "), which the gateway's URI parser refuses")
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

// hasOnlyURLBytes reports whether every byte of s is a letter, a digit or one
// of urlPunctuation. Space, control characters, non-ASCII bytes and the
// printable characters RFC 3986 leaves out all fail.
func hasOnlyURLBytes(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isURLByte(s[i]) {
			return false
		}
	}
	return true
}

func isURLByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte(urlPunctuation, c) >= 0
}

// validateProcessorAddr requires host:port with a DNS-name or IPv4 host and a
// decimal port in range, refuses a numeric host spelling that is not the
// canonical dotted quad (refuseAmbiguousHost), and refuses the gateway's own
// sockets (refuseGatewaySocket; reserved maps each port the gateway binds for
// itself to the socket). The spelling rule runs first because the rules after
// it read the host as an address; the socket rule runs before the host-shape
// rule so that an IPv6 loopback spelling such as "[::1]:15000", which the
// shape rule refuses anyway, is reported as the collision it is.
// agentgateway's --validate-only also accepts http://, https:// and unix://
// forms in this field, but its schema documents the field only as "Hostname
// or IP address", so those forms stay refused until an end-to-end run proves
// what the gateway does with them.
func validateProcessorAddr(addr string, reserved map[int]gatewaySocket) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return errors.New("processor address must be host:port")
	}
	if err := refuseAmbiguousHost(host); err != nil {
		return err
	}
	if err := refuseGatewaySocket(addr, host, port, reserved); err != nil {
		return err
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

// parsePort accepts only plain decimal digits within the port range, so
// forms strconv.Atoi tolerates ("+80", " 80") are refused.
func parsePort(s string) (int, bool) {
	if s == "" || len(s) > maxPortDigits {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + int(s[i]-'0')
	}
	if n < minPort || n > maxPort {
		return 0, false
	}
	return n, true
}

func isPortNumber(s string) bool {
	_, ok := parsePort(s)
	return ok
}
