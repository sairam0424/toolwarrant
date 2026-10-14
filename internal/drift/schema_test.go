package drift

import (
	"strings"
	"testing"
)

// The tests of the inputSchema rules that keep two different documents from
// grading none; the other schema rules are tested beside the taxonomy in
// drift_test.go.

// Two documents that differ never grade none. A type member that changes
// between two values typeOf renders alike (two values outside the JSON Schema
// vocabulary, or a type array reordered) is input-schema-changed at the type
// member, a WARNING, so a drift line never reads none above a unified diff that
// shows the change.
func TestCompare_TypeChangesOutsideTheVocabularyAreWarning(t *testing.T) {
	cases := []struct{ name, from, to string }{
		{"two unknown names", `"foo"`, `"bar"`},
		{"two numbers", `5`, `6`},
		{"two objects", `{"a":1}`, `{"a":2}`},
		{"reordered array", `["string","null"]`, `["null","string"]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			from := strings.Replace(baseTool, `"mode":{"type":"integer"}`, `"mode":{"type":`+tc.from+`}`, 1)
			to := strings.Replace(baseTool, `"mode":{"type":"integer"}`, `"mode":{"type":`+tc.to+`}`, 1)
			r := mustCompare(t, from, to)
			wantOnly(t, r, finding(InputSchemaChanged, propertiesPath+".mode.type", "changed"))
			if r.Max() != Warning || r.Summary() != "WARNING (input-schema-changed)" {
				t.Errorf("Max %v Summary %q", r.Max(), r.Summary())
			}
		})
	}
	// Next to another change of the same parameter it stays one finding per
	// member, and a type that leaves the vocabulary is still the CRITICAL kind.
	from := strings.Replace(baseTool, `"mode":{"type":"integer"}`, `"mode":{"type":"foo"}`, 1)
	wantOnly(t, mustCompare(t, from, strings.Replace(baseTool, `"mode":{"type":"integer"}`, `"mode":{"type":"bar","enum":[1]}`, 1)),
		finding(InputSchemaChanged, propertiesPath+".mode", "changed"),
		finding(InputSchemaChanged, propertiesPath+".mode.type", "changed"))
	wantOnly(t, mustCompare(t, baseTool, from),
		finding(ParameterTypeChanged, propertiesPath+".mode.type", "integer -> other"))
}

// An empty properties object that appears or vanishes changes the bytes and
// no parameter explains it, so it is input-schema-changed at the properties
// member rather than none.
func TestCompare_EmptyPropertiesObjectAddedOrRemovedIsWarning(t *testing.T) {
	without := `{"name":"x","inputSchema":{"type":"object"}}`
	with := `{"name":"x","inputSchema":{"type":"object","properties":{}}}`
	wantOnly(t, mustCompare(t, without, with), finding(InputSchemaChanged, propertiesPath, "added"))
	wantOnly(t, mustCompare(t, with, without), finding(InputSchemaChanged, propertiesPath, "removed"))
	// With a parameter inside, the parameter is the finding.
	wantOnly(t, mustCompare(t, without, `{"name":"x","inputSchema":{"type":"object","properties":{"a":{}}}}`),
		finding(OptionalParameterAdded, propertiesPath+".a", "added"))
}
