package crawl

import (
	"encoding/json"
	"testing"
	"unicode/utf8"

	"pgregory.net/rapid"

	"github.com/sairam0424/toolwarrant/internal/gate"
	"github.com/sairam0424/toolwarrant/internal/mcpwire"
	"github.com/sairam0424/toolwarrant/internal/strictjson"
	"github.com/sairam0424/toolwarrant/internal/toolname"
)

// TestAgreementWithGateToolnameAndProcessor ports the review's agreement
// matrix. The review ran every hostile tool shape through the crawler, the
// digest and the processor's name extraction side by side and found three
// different rules: a tool the crawler accepted could have no digest, and one
// decoy of that kind made the catalog refuse a whole crawl. The property now
// is an equivalence: the crawler calls a tool usable exactly when the digest
// exists, the shared name rule accepts the name and the tool fits both caps;
// and for a usable tool the processor extracts the very same name.
func TestAgreementWithGateToolnameAndProcessor(t *testing.T) {
	for name, tc := range vetCases(t) {
		t.Run(name, func(t *testing.T) {
			raw := []byte(tc.raw)
			gotName, reason, _ := vetTool(raw, defaultMaxToolBytes)
			_, gateErr := gate.Digest(raw)
			depth, wellFormed := jsonDepth(raw)
			// utf8.Valid is the catalog's leg of the rule: the gate alone
			// tolerates invalid UTF-8 in object keys, because encoding/json
			// replaces it with U+FFFD before the canonicaliser runs, and the
			// crawler sides with the catalog, which refuses it.
			wantUsable := utf8.Valid(raw) && gateErr == nil && wellFormed && depth <= maxToolDepth &&
				len(raw) <= defaultMaxToolBytes && nameRuleAccepts(raw)
			if (reason == "") != wantUsable {
				t.Errorf("crawler says usable=%v (reason %q); gate, name rule and caps say %v (gate: %v)", reason == "", reason, wantUsable, gateErr)
			}
			if reason != "" {
				return
			}
			processorName, ok := processorToolName(raw)
			if !ok || processorName != gotName {
				t.Errorf("processor extracts %q (ok=%v), crawler reports %q", processorName, ok, gotName)
			}
		})
	}
}

// nameRuleAccepts applies the shared name rule the way the catalog does: the
// top-level keys must be unambiguous and the decoded "name" must validate.
func nameRuleAccepts(raw []byte) bool {
	if strictjson.Object(raw) != nil {
		return false
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return false
	}
	var name string
	if json.Unmarshal(obj["name"], &name) != nil {
		return false
	}
	return toolname.Validate(name) == nil
}

// processorToolName extracts the name the ExtMCP processor would route by, from
// a tools/list result that lists only raw. ok is false unless exactly one tool
// was seen.
func processorToolName(raw []byte) (string, bool) {
	page := append(append([]byte(`{"tools":[`), raw...), []byte(`]}`)...)
	var name string
	seen := 0
	_, _, err := mcpwire.FilterToolsListRaw(page, func(n string, _ []byte) bool {
		name, seen = n, seen+1
		return true
	})
	return name, err == nil && seen == 1
}

// TestVetToolAgreesWithToolnameOnRandomNames: for any name, the crawler calls
// {"name":<name>} usable exactly when the shared rule accepts the name, and
// then reports the name unchanged.
func TestVetToolAgreesWithToolnameOnRandomNames(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		name := rapid.String().Draw(rt, "name")
		literal, err := json.Marshal(name)
		if err != nil {
			rt.Fatal(err)
		}
		raw := append(append([]byte(`{"name":`), literal...), '}')
		gotName, reason, _ := vetTool(raw, defaultMaxToolBytes)
		wantUsable := toolname.Validate(name) == nil
		if (reason == "") != wantUsable {
			rt.Fatalf("name %q: crawler reason %q, shared rule accepts=%v", name, reason, wantUsable)
		}
		if wantUsable && gotName != name {
			rt.Fatalf("name %q was reported as %q", name, gotName)
		}
		if !wantUsable && (reason != ReasonInvalidName || gotName != "") {
			rt.Fatalf("name %q: got (%q, %q), want no name and invalid-name", name, gotName, reason)
		}
	})
}
