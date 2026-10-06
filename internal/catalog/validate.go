package catalog

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Limits on everything that crosses the package boundary. They bound memory
// and storage, and keep hostile input from becoming hostile output.
const (
	maxServerNameLen   = 63
	maxURLBytes        = 2048
	maxOwnerGroupBytes = 256
	maxActorNameBytes  = 256
	maxToolNameBytes   = 256
	maxCrawlErrorBytes = 1024
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
// and bidi overrides let two different names render identically.
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

func validateToolName(name string) error {
	if name == "" {
		return invalidf("tool name is empty")
	}
	return checkText("tool name", name, maxToolNameBytes)
}

// validateServerName enforces ^[a-z0-9][a-z0-9_-]{0,62}$ by hand: the name ends
// up in file names, log lines and audit subjects, and a hand-written loop
// cannot be surprised by regexp end-of-line semantics.
func validateServerName(name string) error {
	if name == "" || len(name) > maxServerNameLen {
		return invalidf("server name %s must be 1 to %d characters", quote(name), maxServerNameLen)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		isAlnum := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
		if isAlnum || (i > 0 && (c == '_' || c == '-')) {
			continue
		}
		return invalidf("server name %s must match ^[a-z0-9][a-z0-9_-]{0,62}$", quote(name))
	}
	return nil
}

// validateURL accepts only plain http(s) URLs that every parser reads the same
// way: printable ASCII, no backslashes, no user info, no fragment. A URL that
// two components could parse differently is an SSRF primitive.
func validateURL(raw string) error {
	if raw == "" || len(raw) > maxURLBytes {
		return invalidf("server URL must be 1 to %d bytes", maxURLBytes)
	}
	for i := 0; i < len(raw); i++ {
		if c := raw[i]; c <= ' ' || c >= 0x7f || c == '\\' {
			return invalidf("server URL contains a character that is not allowed")
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

func validateServerSpec(spec ServerSpec) error {
	if err := validateServerName(spec.Name); err != nil {
		return err
	}
	if err := validateURL(spec.URL); err != nil {
		return err
	}
	return checkText("owner group", spec.OwnerGroup, maxOwnerGroupBytes)
}

// validateActor requires a name that cannot be confused with another one by
// padding: the self-approval rule compares names exactly, so " alice" must not
// be accepted as someone other than "alice".
func validateActor(a Actor) error {
	if a.Name == "" {
		return invalidf("actor name is empty")
	}
	if a.Name != strings.TrimSpace(a.Name) {
		return invalidf("actor name must not start or end with whitespace")
	}
	if err := checkText("actor name", a.Name, maxActorNameBytes); err != nil {
		return err
	}
	if a.Type != ActorHuman && a.Type != ActorSystem {
		return invalidf("actor type %s is not human or system", quote(string(a.Type)))
	}
	return nil
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
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
