package fetch

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

const (
	maxHostnameLen = 253
	maxLabelLen    = 63
	// maxQuotedLen bounds how much of a hostile host string is echoed into an
	// error message.
	maxQuotedLen = 64
)

// target is what a request host turns into: an IP literal to vet, or a DNS
// name to resolve. Exactly one of the two is set.
type target struct {
	addr netip.Addr
	name string
}

func (t target) isLiteral() bool { return t.addr.IsValid() }

// parseTarget classifies a host (no port, no brackets) taken from a URL or a
// dial address. It is strict on purpose: parsers disagree about what
// "127.1", "2130706433", "0x7f.0.0.1" and "0177.0.0.1" mean, so none of those
// spellings are accepted. Only a canonical IP literal or a plain DNS name
// passes.
func parseTarget(host string) (target, error) {
	if host == "" {
		return target{}, fmt.Errorf("%w: empty host", ErrBlockedHost)
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return target{}, fmt.Errorf("%w: scoped address literal", ErrBlockedAddress)
		}
		return target{addr: addr}, nil
	}
	if strings.Contains(host, ":") {
		return target{}, fmt.Errorf("%w: malformed address literal %s", ErrBlockedHost, quoteShort(host))
	}
	if endsInNumber(host) {
		return target{}, fmt.Errorf("%w: non-canonical numeric host %s", ErrBlockedAddress, quoteShort(host))
	}
	if err := validateHostname(host); err != nil {
		return target{}, fmt.Errorf("%w: %w (%s)", ErrBlockedHost, err, quoteShort(host))
	}
	return target{name: strings.ToLower(host)}, nil
}

// endsInNumber reports whether the last label of host is numeric (decimal, or
// 0x-prefixed hexadecimal). Real top-level domains are never numeric, while
// every legacy IPv4 spelling ends in a number, so this catches them all
// without having to implement each parser's rules.
func endsInNumber(host string) bool {
	trimmed := strings.TrimSuffix(host, ".")
	label := trimmed[strings.LastIndexByte(trimmed, '.')+1:]
	if label == "" {
		return false
	}
	if lower := strings.ToLower(label); strings.HasPrefix(lower, "0x") {
		return isAll(lower[2:], isHexDigit)
	}
	return isAll(label, isDigit)
}

// validateHostname accepts ASCII letters, digits, hyphen and underscore in
// non-empty labels. Internationalised names must be supplied as punycode: a
// host that is not plain ASCII is refused rather than guessed at.
func validateHostname(host string) error {
	trimmed := strings.TrimSuffix(host, ".")
	if trimmed == "" || len(trimmed) > maxHostnameLen {
		return errors.New("host name has an invalid length")
	}
	for _, label := range strings.Split(trimmed, ".") {
		if label == "" || len(label) > maxLabelLen {
			return errors.New("host name has an empty or over-long label")
		}
		if !isAll(label, isHostnameByte) {
			return errors.New("host name contains characters outside letters, digits, '-' and '_'")
		}
	}
	return nil
}

func isAll(s string, ok func(byte) bool) bool {
	for i := 0; i < len(s); i++ {
		if !ok(s[i]) {
			return false
		}
	}
	return true
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isHexDigit(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isHostnameByte(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-' || c == '_'
}

// quoteShort quotes s for an error message, truncating it so a hostile value
// cannot flood logs.
func quoteShort(s string) string {
	if len(s) > maxQuotedLen {
		return fmt.Sprintf("%q...", s[:maxQuotedLen])
	}
	return fmt.Sprintf("%q", s)
}
