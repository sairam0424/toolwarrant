package catalog

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/sairam0424/toolwarrant/internal/toolname"
)

// Limits on everything that crosses the package boundary. They bound memory
// and storage, and keep hostile input from becoming hostile output.
const (
	maxServerNameLen = 63
	// serverNamePattern is the rule agentgateway v1.6.0 applies to an MCP
	// target name, which the emitted configuration derives from the server
	// name; validateServerName enforces it by hand.
	serverNamePattern = "^[a-z0-9]([a-z0-9-]*[a-z0-9])?$"
	// urlPunctuation is every non-alphanumeric byte a server URL may hold: the
	// RFC 3986 unreserved marks "-._~", the gen-delims ":/?#[]@", the
	// sub-delims "!$&'()*+,;=" and the percent sign that encodes the rest.
	urlPunctuation     = "-._~:/?#[]@!$&'()*+,;=%"
	maxURLBytes        = 2048
	maxOwnerGroupBytes = 256
	maxActorNameBytes  = 256 // before normalisation; the normalised form is bounded by the pattern
	maxActorNameLen    = 64  // ^[a-z0-9][a-z0-9._@-]{0,63}$
	maxCrawlErrorBytes = 1024
	maxClassLen        = 64
	maxDetailBytes     = 256
	maxQuotedBytes     = 64
	digestHexLen       = 64
	minDigestPrefix    = 8
	maxPort            = 65535
)

// quote renders untrusted text for an error message: truncated and escaped.
func quote(s string) string {
	if len(s) > maxQuotedBytes {
		s = s[:maxQuotedBytes] + "..."
	}
	return strconv.Quote(s)
}

func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, args...)...)
}

// forbiddenRune reports whether r is a control or invisible character. A plain
// space is the only whitespace allowed: lookalike spaces, zero-width joiners
// and bidi overrides let two different strings render identically.
func forbiddenRune(r rune) bool {
	if r == ' ' {
		return false
	}
	return unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp, unicode.Zs, unicode.Co, unicode.Cs)
}

// checkText validates untrusted text: valid UTF-8, bounded, no control or
// invisible characters.
func checkText(kind, s string, maxBytes int) error {
	if len(s) > maxBytes {
		return invalidf("%s is longer than %d bytes", kind, maxBytes)
	}
	if !utf8.ValidString(s) {
		return invalidf("%s is not valid UTF-8", kind)
	}
	for _, r := range s {
		if forbiddenRune(r) {
			return invalidf("%s contains a control or invisible character (U+%04X)", kind, r)
		}
	}
	return nil
}

// validateToolName delegates to the one rule every component shares
// (internal/toolname): NFC, visible characters only, no padding or double
// spaces, at most toolname.MaxBytes. The error never echoes the name.
func validateToolName(name string) error {
	if err := toolname.Validate(name); err != nil {
		return invalidf("tool name: %v", err)
	}
	return nil
}

// validateServerName enforces serverNamePattern, ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$
// in at most maxServerNameLen bytes, by hand: the name ends up in the gateway
// configuration, in file names, log lines and audit subjects, and a
// hand-written loop cannot be surprised by regexp end-of-line semantics.
//
// The rule is the gateway's own. agentgateway v1.6.0 refuses an MCP target
// name with an underscore (it reserves '_' as an MCP delimiter) or a trailing
// hyphen, and it refuses the whole file: a name the catalog accepted but the
// gateway did not would freeze every server's configuration at the next emit,
// so such a name is refused before it is ever registered. The gateway would
// accept a dot; it is refused here on purpose, because the name becomes a path
// segment (/<name>/mcp), an export directory and an audit subject, and dotted
// names ('.', '..', a look-alike of a host name) have no place in any of those.
func validateServerName(name string) error {
	if name == "" || len(name) > maxServerNameLen {
		return invalidf("server name %s must be 1 to %d characters", quote(name), maxServerNameLen)
	}
	last := len(name) - 1
	for i := 0; i < len(name); i++ {
		c := name[i]
		if isLowerAlnum(c) || (c == '-' && i > 0 && i < last) {
			continue
		}
		return invalidf("server name %s must match %s: lower-case letters, digits and inner hyphens only", quote(name), serverNamePattern)
	}
	return nil
}

func isLowerAlnum(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') }

// validateURL accepts only plain http(s) URLs that every parser, the gateway's
// included, reads the same way: letters, digits and urlPunctuation (the
// RFC 3986 unreserved and reserved characters plus '%'), no user info, no
// fragment. agentgateway v1.6.0's URI parser refuses '"', '<', '>', '|', '^',
// '{', '}' and '`', and with them the whole file, which would freeze every
// server's configuration at the next emit; a URL that two components could
// parse differently is also an SSRF primitive. Space, backslash and every
// control or non-ASCII byte are outside the set as before.
func validateURL(raw string) error {
	if raw == "" || len(raw) > maxURLBytes {
		return invalidf("server URL must be 1 to %d bytes", maxURLBytes)
	}
	for i := 0; i < len(raw); i++ {
		if c := raw[i]; !isURLByte(c) {
			return invalidf("server URL contains a character that is not allowed (byte 0x%02x)", c)
		}
	}
	if strings.Contains(raw, "#") {
		return invalidf("server URL must not have a fragment")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return invalidf("server URL does not parse")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return invalidf("server URL must use http or https")
	}
	if u.Opaque != "" || u.Hostname() == "" {
		return invalidf("server URL needs a host")
	}
	if u.User != nil {
		return invalidf("server URL must not carry user info")
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > maxPort {
			return invalidf("server URL has a bad port")
		}
	}
	return nil
}

// isURLByte reports whether c may appear in a server URL: an ASCII letter or
// digit, or one of urlPunctuation.
func isURLByte(c byte) bool {
	if isLowerAlnum(c) || (c >= 'A' && c <= 'Z') {
		return true
	}
	return strings.IndexByte(urlPunctuation, c) >= 0
}

func validateServerSpec(spec ServerSpec) error {
	if err := validateServerName(spec.Name); err != nil {
		return err
	}
	if err := validateURL(spec.URL); err != nil {
		return err
	}
	return checkText("owner group", spec.OwnerGroup, maxOwnerGroupBytes)
}

// normalizeActor returns the actor under its canonical name: NFKC, then
// lower-cased, then checked against ^[a-z0-9][a-z0-9._@-]{0,63}$. The
// two-person rule compares names, so "Alice", "alice" and a full-width or
// ligature spelling must be one identity, and nothing that renders like
// another name may be accepted. The normalised actor is what is stored.
func normalizeActor(a Actor) (Actor, error) {
	if a.Name == "" {
		return Actor{}, invalidf("actor name is empty")
	}
	if len(a.Name) > maxActorNameBytes {
		return Actor{}, invalidf("actor name is longer than %d bytes", maxActorNameBytes)
	}
	if !utf8.ValidString(a.Name) {
		return Actor{}, invalidf("actor name is not valid UTF-8")
	}
	name := strings.ToLower(norm.NFKC.String(a.Name))
	if !isActorName(name) {
		return Actor{}, invalidf("actor name %s must match ^[a-z0-9][a-z0-9._@-]{0,63}$ after NFKC normalisation and lower-casing", quote(a.Name))
	}
	if a.Type != ActorHuman && a.Type != ActorSystem {
		return Actor{}, invalidf("actor type %s is not human or system", quote(string(a.Type)))
	}
	return Actor{Name: name, Type: a.Type}, nil
}

// isActorName matches ^[a-z0-9][a-z0-9._@-]{0,63}$ by hand, for the same
// reason as validateServerName.
func isActorName(name string) bool {
	if name == "" || len(name) > maxActorNameLen {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if isLowerAlnum(c) || (i > 0 && (c == '.' || c == '_' || c == '@' || c == '-')) {
			continue
		}
		return false
	}
	return true
}

// isClassToken reports whether s is a short machine-readable class: one or
// more lower-case words of letters, digits, '_', '.' and '-' separated by
// single spaces, such as "timeout", "not-canonical" or "http status 401". It
// is the only shape of caller text that is stored and printed as it is: it
// cannot carry an escape sequence, a quote, a URL or an invisible character.
func isClassToken(s string) bool {
	if s == "" || len(s) > maxClassLen || !isLowerAlnum(s[0]) || s[len(s)-1] == ' ' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if c == ' ' && s[i-1] != ' ' {
			continue
		}
		if !isLowerAlnum(c) && c != '_' && c != '.' && c != '-' {
			return false
		}
	}
	return true
}

// auditClass renders a class for an audit detail: bare when it is a single
// word, quoted when it has spaces, so key=value pairs stay unambiguous.
func auditClass(class string) string {
	if strings.Contains(class, " ") {
		return strconv.Quote(class)
	}
	return class
}

// classOf reduces a caller-supplied reason to a class token. Anything that is
// not already a token becomes the generic fallback rather than being echoed.
func classOf(reason, fallback string) string {
	if r := strings.ToLower(strings.TrimSpace(reason)); isClassToken(r) {
		return r
	}
	return fallback
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isHexDigit(s[i]) {
			return false
		}
	}
	return true
}

// normalizeDigest accepts a full SHA-256 in hex, either case, and returns it in
// the lower case that is stored.
func normalizeDigest(d string) (string, error) {
	if len(d) != digestHexLen || !isHex(d) {
		return "", invalidf("a full %d-character hex digest is required, got %s", digestHexLen, quote(d))
	}
	return strings.ToLower(d), nil
}

// normalizePrefix accepts 8 to 64 hex characters, either case.
func normalizePrefix(p string) (string, error) {
	if len(p) < minDigestPrefix || len(p) > digestHexLen || !isHex(p) {
		return "", invalidf("a digest prefix is %d to %d hex characters, got %s", minDigestPrefix, digestHexLen, quote(p))
	}
	return strings.ToLower(p), nil
}

// sanitizeText makes untrusted text safe to store and print: control and
// invisible characters become '?', whitespace becomes a space, and the result
// is cut to maxBytes on a rune boundary.
func sanitizeText(s string, maxBytes int) string {
	cleaned := strings.Map(func(r rune) rune {
		switch {
		case r == utf8.RuneError:
			return '?'
		case unicode.IsSpace(r):
			return ' '
		case forbiddenRune(r):
			return '?'
		}
		return r
	}, s)
	if len(cleaned) <= maxBytes {
		return cleaned
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(cleaned[cut]) {
		cut--
	}
	return cleaned[:cut]
}
