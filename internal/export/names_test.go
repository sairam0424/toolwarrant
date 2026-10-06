package export

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

func TestEncodeName_Table(t *testing.T) {
	cases := map[string]string{
		"echo":        "echo",
		"Echo_Tool-1": "Echo_Tool-1",
		"a.b":         "a%2Eb",
		".":           "%2E",
		"..":          "%2E%2E",
		".hidden":     "%2Ehidden",
		"../x":        "%2E%2E%2Fx",
		"a/b":         "a%2Fb",
		`a\b`:         "a%5Cb",
		"a\x00b":      "a%00b",
		"100%":        "100%25",
		"%2E":         "%252E",
		"a b":         "a%20b",
		"é":           "%C3%A9",
		"CON:":        "CON%3A",
	}
	for raw, want := range cases {
		got, err := encodeName("tool", raw)
		if err != nil {
			t.Errorf("encodeName(%q): %v", raw, err)
			continue
		}
		if got != want {
			t.Errorf("encodeName(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestEncodeName_Refusals(t *testing.T) {
	cases := map[string]string{
		"empty":                "",
		"invalid utf-8":        "ab\xff",
		"raw too long":         strings.Repeat("a", maxEncodedNameBytes+1),
		"encoded too long":     strings.Repeat("/", maxEncodedNameBytes/3+1),
		"huge":                 strings.Repeat("a", 5<<20),
		"just over, escaped":   strings.Repeat("a", maxEncodedNameBytes-2) + "/",
		"lone surrogate bytes": "\xed\xa0\x80",
	}
	for label, raw := range cases {
		if _, err := encodeName("tool", raw); err == nil {
			t.Errorf("%s: want an error", label)
		}
	}
}

func TestEncodeName_LengthBoundary(t *testing.T) {
	exact := strings.Repeat("a", maxEncodedNameBytes)
	got, err := encodeName("server", exact)
	if err != nil || got != exact {
		t.Fatalf("200 bytes must be accepted, got %q err %v", got, err)
	}
	if _, err := encodeName("server", exact+"a"); !errors.Is(err, errNameTooLong) {
		t.Fatalf("201 bytes: err = %v, want errNameTooLong", err)
	}
}

func TestEncodeName_ErrorsDoNotEchoTheName(t *testing.T) {
	_, err := encodeName("tool", "secret-token-\xff")
	if err == nil || strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("error must not echo hostile names: %v", err)
	}
}

// Encoded names must be injective (distinct names never share a file), use
// only the safe alphabet, and always be a local path component.
func TestEncodeName_Properties(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := rapid.StringN(1, 60, -1).Draw(t, "a")
		b := rapid.StringN(1, 60, -1).Draw(t, "b")
		ea, errA := encodeName("tool", a)
		eb, errB := encodeName("tool", b)
		if errA != nil || errB != nil {
			return // too long once encoded is a legitimate refusal
		}
		if ea == eb && a != b {
			t.Fatalf("collision: %q and %q both encode to %q", a, b, ea)
		}
		for i := 0; i < len(ea); i++ {
			c := ea[i]
			if !isSafeByte(c) && c != '%' && !strings.ContainsRune(upperHex, rune(c)) {
				t.Fatalf("unsafe byte %q in %q", c, ea)
			}
		}
		rel := relPath(ea, eb)
		if !filepath.IsLocal(rel) || strings.HasPrefix(ea, ".") || strings.Count(rel, "/") != 1 {
			t.Fatalf("not a local two-part path: %q", rel)
		}
	})
}

// The manifest stores encoded names and is read back, so only the canonical
// spelling of an encoding may be accepted: anything else is somebody else's
// edit and must not steer a deletion.
func TestIsEncodedName_Table(t *testing.T) {
	for _, enc := range []string{"echo", "Echo_Tool-1", "a%2Eb", "%2E%2E", "%C3%A9", "-rf", "%00", "%252E"} {
		if !isEncodedName("tool", enc) {
			t.Errorf("isEncodedName(%q) = false, want true", enc)
		}
	}
	bad := map[string]string{
		"empty":                 "",
		"raw dot":               "a.b",
		"lower-case hex":        "a%2eb",
		"needless escape":       "%41",
		"escape of a safe byte": "a%2Db",
		"short escape":          "%4",
		"lone percent":          "%",
		"space":                 "a b",
		"slash":                 "a/b",
		"non-hex digits":        "%ZZ",
		"too long":              strings.Repeat("a", maxEncodedNameBytes+1),
		"invalid utf-8":         "%FF",
	}
	for label, enc := range bad {
		if isEncodedName("tool", enc) {
			t.Errorf("%s: isEncodedName(%q) = true, want false", label, enc)
		}
	}
}

func TestIsEncodedName_AcceptsEveryEncoding(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		raw := rapid.StringN(1, 60, -1).Draw(t, "raw")
		enc, err := encodeName("tool", raw)
		if err != nil {
			return
		}
		if !isEncodedName("tool", enc) {
			t.Fatalf("encodeName(%q) = %q is not accepted back", raw, enc)
		}
		back, ok := percentDecode(enc)
		if !ok || string(back) != raw {
			t.Fatalf("percentDecode(%q) = %q, %v; want %q", enc, back, ok, raw)
		}
	})
}

// A case-insensitive file system folds only ASCII letters in encoded names, so
// the lower-cased comparison must treat "A" and "a" as colliding.
func TestLowerASCII(t *testing.T) {
	if got := lowerASCII("Srv/ToOl%2E.json"); got != "srv/tool%2e.json" {
		t.Fatalf("lowerASCII = %q", got)
	}
}
