package trust

import (
	"errors"
	"strings"
	"testing"
)

// NormalizeName is internal/catalog's normalizeActor re-implemented, and this
// is that function's own table (TestNormalizeActor in
// internal/catalog/validate_test.go), name column only: the catalog exports no
// normaliser, so the two are pinned on the same rows. The catalog's two rows
// about the actor type ("alice" with an empty or unknown type) have no name
// counterpart and are left out. A change to either rule must land in both
// tables.
func TestNormalizeName_AgreesWithCatalogsNormalizeActorTable(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in   string
		want string // "" means refused
	}{
		{"alice", "alice"},
		{"Alice", "alice"},
		{"ALICE", "alice"},
		{"ci-bot_2", "ci-bot_2"},
		{"jose@example.com", "jose@example.com"},
		{"a", "a"},
		{"a" + strings.Repeat("b", 63), "a" + strings.Repeat("b", 63)},
		// NFKC folds full-width letters, the Kelvin sign and ligatures onto their ASCII forms.
		{cp(0xFF21, 0xFF2C, 0xFF29, 0xFF23, 0xFF25), "alice"},
		{cp(kelvin) + "elvin", "kelvin"},
		{cp(fiLigat) + "ona", "fiona"},
		{"", ""},
		{" alice", ""},
		{"alice ", ""},
		{"ci bot", ""},
		{"al\tice", ""},
		{"al" + cp(zwsp) + "ice", ""},
		{"alice\n", ""},
		{"jos" + cp(eAcute), ""},
		{"rene" + cp(acuteMark), ""},
		{"-alice", ""},
		{".alice", ""},
		{"a" + strings.Repeat("b", 64), ""},
		{strings.Repeat("a", maxNameBytes+1), ""},
		{"bad\xffutf8", ""},
	} {
		got, err := NormalizeName(tc.in)
		if (tc.want == "") != (err != nil) || got != tc.want {
			t.Errorf("NormalizeName(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
		if err != nil && !errors.Is(err, ErrName) {
			t.Errorf("NormalizeName(%q) error %v is not ErrName", tc.in, err)
		}
		if err == nil {
			again, err := NormalizeName(got)
			if err != nil || again != got {
				t.Errorf("NormalizeName(%q) is not a fixed point: %q, %v", got, again, err)
			}
		}
	}
	if !strings.Contains(namePattern, "{0,63}") || maxNameLen != 64 || maxNameBytes != 256 {
		t.Errorf("the bounds drifted from the catalog's: pattern %s, len %d, bytes %d", namePattern, maxNameLen, maxNameBytes)
	}
}
