package crawl

import "testing"

// Top-level key ambiguity is the differential the processor and the gate refuse
// (Go keeps the last duplicate key and matches "name" case-insensitively; other
// parsers do not). The crawler must classify such tools as unusable so that the
// catalog never stores a definition the gateway would read differently. These
// cases were covered by an earlier test that the D3 rewrite replaced; they are
// kept explicit here so the protection cannot be lost silently.
func TestVet_TopLevelAmbiguousKeysAreUnusable(t *testing.T) {
	cases := map[string]string{
		"duplicate top-level key":    `{"name":"x","description":"evil","description":"safe"}`,
		"duplicate name":             `{"name":"a","name":"b"}`,
		"case-variant name":          `{"name":"a","Name":"b"}`,
		"upper-case name only":       `{"NAME":"a"}`,
		"escaped duplicate spelling": `{"name":"a","name":"b"}`,
	}
	for label, raw := range cases {
		t.Run(label, func(t *testing.T) {
			name, reason, _ := vetTool([]byte(raw), 1<<20)
			if reason == "" {
				t.Fatalf("vetTool(%s) accepted an ambiguous definition (name %q)", raw, name)
			}
		})
	}
}

// Nested property names that differ only by case are legitimate schema content.
func TestVet_NestedCaseVariantNamesAreFine(t *testing.T) {
	name, reason, detail := vetTool([]byte(`{"name":"echo","inputSchema":{"properties":{"name":{},"Name":{}}}}`), 1<<20)
	if reason != "" || name != "echo" {
		t.Fatalf("vetTool rejected a valid schema: name=%q reason=%q detail=%q", name, reason, detail)
	}
}
