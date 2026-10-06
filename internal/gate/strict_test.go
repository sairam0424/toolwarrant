package gate

import (
	"errors"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/strictjson"
)

// A tool with a repeated top-level key must not get a digest: decoding into a
// map would keep only the last value, so the digest would describe a definition
// that is not what the raw bytes (and a first-wins client) say.
func TestDigest_RejectsAmbiguousDefinitions(t *testing.T) {
	cases := map[string]string{
		"duplicate description": `{"name":"x","description":"evil","description":"safe"}`,
		"duplicate name":        `{"name":"a","name":"b"}`,
		"case-variant name":     `{"name":"a","Name":"b"}`,
	}
	for label, raw := range cases {
		t.Run(label, func(t *testing.T) {
			if _, err := Digest([]byte(raw)); !errors.Is(err, strictjson.ErrAmbiguousKeys) {
				t.Fatalf("Digest(%s) error = %v, want ErrAmbiguousKeys", raw, err)
			}
			if _, err := CanonicalTool([]byte(raw)); !errors.Is(err, strictjson.ErrAmbiguousKeys) {
				t.Fatalf("CanonicalTool(%s) error = %v, want ErrAmbiguousKeys", raw, err)
			}
		})
	}
}

// Nested property names that differ only by case are legitimate schema content
// and must keep working.
func TestDigest_AllowsCaseVariantNestedNames(t *testing.T) {
	raw := `{"name":"a","inputSchema":{"type":"object","properties":{"name":{"type":"string"},"Name":{"type":"string"}}}}`
	if _, err := Digest([]byte(raw)); err != nil {
		t.Fatalf("Digest rejected a valid schema: %v", err)
	}
}
