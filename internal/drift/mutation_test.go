package drift

import (
	"encoding/json"
	"testing"

	"pgregory.net/rapid"
)

// slot is one member of one object inside a decoded document.
type slot struct {
	parent map[string]any
	key    string
}

// slots lists every member of every object in the tree, a parent before its
// children, in key order.
func slots(v any) []slot {
	var out []slot
	switch x := v.(type) {
	case map[string]any:
		for _, k := range mergedKeys(x, nil) {
			out = append(out, slot{parent: x, key: k})
			out = append(out, slots(x[k])...)
		}
	case []any:
		for _, el := range x {
			out = append(out, slots(el)...)
		}
	}
	return out
}

// otherValue draws a value of the same JSON shape as v: another string (a
// type name inside and outside the vocabulary among them), the number plus
// one, the negated boolean, the array reversed, the object with one member
// more, or true for null. The draw may equal v (an array of one reversed, the
// same string again), which the invariant below allows for.
func otherValue(t *rapid.T, v any) any {
	switch x := v.(type) {
	case string:
		return rapid.SampledFrom([]string{"string", "integer", "weird", "weirder", "path", "", "line\nbreak"}).Draw(t, "string")
	case float64:
		return x + 1
	case bool:
		return !x
	case []any:
		out := make([]any, len(x))
		for i, el := range x {
			out[len(x)-1-i] = el
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x)+1)
		for k, el := range x {
			out[k] = el
		}
		out[names().Draw(t, "newKey")] = rapid.IntRange(0, 2).Draw(t, "newValue")
		return out
	}
	return true
}

// Two documents that differ never grade none, member by member: for every
// member of a drawn definition, the copy with that member deleted or replaced
// by another value of its shape decodes equal to the original exactly when the
// report is empty. Independent draws of two whole definitions almost never
// differ in one member only, so this is the test that reaches a type array
// reordered or a type renamed outside the vocabulary.
func TestProperty_everyMemberChangedOnItsOwnYieldsAFinding(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		from := toolDoc().Draw(t, "from")
		var tree map[string]any
		if err := json.Unmarshal(from, &tree); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		for _, s := range slots(tree) {
			kept := s.parent[s.key]
			if rapid.Bool().Draw(t, "delete") {
				delete(s.parent, s.key)
			} else {
				s.parent[s.key] = otherValue(t, kept)
			}
			to, err := json.Marshal(tree)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			checkDifferImpliesFinding(t, from, to, mustCompareBytes(t, from, to))
			s.parent[s.key] = kept
		}
	})
}
