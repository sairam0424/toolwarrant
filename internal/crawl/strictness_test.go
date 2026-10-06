package crawl

import (
	"errors"
	"testing"
)

// The crawler must refuse the same ambiguous definitions as the digest and the
// processor, so the catalog never stores a tool the gateway would judge
// differently.
func TestParseToolName_RejectsAmbiguousKeys(t *testing.T) {
	cases := map[string]string{
		"duplicate description": `{"name":"x","description":"evil","description":"safe"}`,
		"duplicate name":        `{"name":"a","name":"b"}`,
		"case-variant name":     `{"name":"a","Name":"b"}`,
		"upper-case name only":  `{"NAME":"a"}`,
	}
	for label, raw := range cases {
		t.Run(label, func(t *testing.T) {
			if _, err := parseToolName([]byte(raw)); !errors.Is(err, ErrMalformed) {
				t.Fatalf("parseToolName(%s) error = %v, want ErrMalformed", raw, err)
			}
		})
	}
}

func TestParseToolName_AcceptsOrdinaryTools(t *testing.T) {
	name, err := parseToolName([]byte(`{"name":"echo","inputSchema":{"properties":{"name":{},"Name":{}}}}`))
	if err != nil || name != "echo" {
		t.Fatalf("parseToolName = %q, %v", name, err)
	}
}
