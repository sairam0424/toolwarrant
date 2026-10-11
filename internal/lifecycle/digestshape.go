package lifecycle

// DigestHexLen is the length of a gate digest on the wire: SHA-256 as 64
// lowercase hexadecimal characters.
const DigestHexLen = 64

// IsDigest reports whether s has the shape of a gate digest. The state machine
// itself uses a looser rule (any non-empty value other than UnusableDigest is
// treated as a digest, so tests can use short stand-ins), but at the gateway
// boundary the processor and the canary must agree on one strict rule: a
// LastSeen value that is neither "" nor a 64-character lowercase hex string is
// a marker (UnusableDigest from a crawl, or a processor-local marker such as a
// conflict), and a tool carrying a marker is neither listed nor callable until
// a clean crawl records a digest (D9, D12). This is that rule.
func IsDigest(s string) bool {
	if len(s) != DigestHexLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// LastSeenVerifiable reports whether a LastSeen value is one the gateway rule
// can act on: "" (the tool was absent from the latest crawl) or a digest. A
// marker is neither, and hides the tool from listings and calls alike.
func LastSeenVerifiable(lastSeen string) bool {
	return lastSeen == "" || IsDigest(lastSeen)
}
