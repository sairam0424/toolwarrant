package lifecycle

import (
	"strings"
	"testing"
)

// The strict shape rule is shared by the processor and the canary, so each
// edge is pinned: only exactly 64 lowercase hex characters is a digest, and
// only "" or a digest is verifiable; every marker is neither.
func TestIsDigestAndLastSeenVerifiable(t *testing.T) {
	hex64 := strings.Repeat("0123456789abcdef", 4)
	cases := []struct {
		in         string
		digest     bool
		verifiable bool
	}{
		{"", false, true},
		{hex64, true, true},
		{UnusableDigest, false, false},
		{"conflict", false, false},
		{hex64[:63], false, false},
		{hex64 + "0", false, false},
		{strings.ToUpper(hex64), false, false},
		{strings.Repeat("g", 64), false, false},
		{strings.Repeat("0", 63) + "\u00e9", false, false}, // 64 runes, not 64 bytes of hex
		{" " + hex64[1:], false, false},
	}
	for _, c := range cases {
		if got := IsDigest(c.in); got != c.digest {
			t.Errorf("IsDigest(%q) = %v, want %v", c.in, got, c.digest)
		}
		if got := LastSeenVerifiable(c.in); got != c.verifiable {
			t.Errorf("LastSeenVerifiable(%q) = %v, want %v", c.in, got, c.verifiable)
		}
	}
}
