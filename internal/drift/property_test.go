package drift

import (
	"encoding/json"
	"sort"
	"testing"

	"pgregory.net/rapid"
)

// The generators below draw tool definitions from a small vocabulary, so two
// independent draws share most members and differ in a few, which is what a
// drifted version looks like; the hostile names carry the characters the
// paths must escape.
func names() *rapid.Generator[string] {
	return rapid.SampledFrom([]string{"path", "mode", "force", "a b", "", "ev\u200bil", "x\u001b[31m", `q"uote\`, "line\nbreak", "\u65e5\u672c"})
}

func schemaType() *rapid.Generator[any] {
	return rapid.OneOf(
		rapid.Map(rapid.SampledFrom([]string{"string", "integer", "number", "boolean", "object", "array", "null", "weird"}), func(s string) any { return s }),
		rapid.Map(rapid.SliceOfN(rapid.SampledFrom([]string{"string", "null", "integer"}), 1, 3), func(ss []string) any {
			out := make([]any, len(ss))
			for i, s := range ss {
				out[i] = s
			}
			return out
		}),
		rapid.Just[any](nil),
	)
}

// parameter draws one property schema: an object with an optional type and
// an optional enum, or a boolean schema.
func parameter() *rapid.Generator[any] {
	return rapid.Custom(func(t *rapid.T) any {
		if rapid.IntRange(0, 9).Draw(t, "bool") == 0 {
			return rapid.Bool().Draw(t, "schema")
		}
		p := map[string]any{}
		if ty := schemaType().Draw(t, "type"); ty != nil {
			p["type"] = ty
		}
		if rapid.Bool().Draw(t, "hasEnum") {
			p["enum"] = []any{rapid.IntRange(0, 2).Draw(t, "enum")}
		}
		return p
	})
}

func inputSchema() *rapid.Generator[any] {
	return rapid.Custom(func(t *rapid.T) any {
		if rapid.IntRange(0, 9).Draw(t, "junk") == 0 {
			return rapid.Bool().Draw(t, "schemaBool")
		}
		s := map[string]any{"type": "object"}
		props := map[string]any{}
		for _, n := range rapid.SliceOfN(names(), 0, 4).Draw(t, "props") {
			props[n] = parameter().Draw(t, "param")
		}
		if rapid.IntRange(0, 9).Draw(t, "propsJunk") == 0 {
			s["properties"] = "not an object"
		} else if len(props) > 0 || rapid.Bool().Draw(t, "emptyProps") {
			s["properties"] = props
		}
		required := []any{}
		for _, n := range rapid.SliceOfN(names(), 0, 3).Draw(t, "required") {
			required = append(required, n)
		}
		switch rapid.IntRange(0, 9).Draw(t, "reqShape") {
		case 0:
			s["required"] = "path"
		case 1:
		default:
			s["required"] = required
		}
		if rapid.Bool().Draw(t, "additional") {
			s["additionalProperties"] = rapid.Bool().Draw(t, "additionalValue")
		}
		return s
	})
}

func annotations() *rapid.Generator[any] {
	return rapid.Custom(func(t *rapid.T) any {
		if rapid.IntRange(0, 9).Draw(t, "junk") == 0 {
			return "not an object"
		}
		a := map[string]any{}
		for _, h := range hintRules() {
			switch rapid.IntRange(0, 3).Draw(t, h.name) {
			case 0:
				a[h.name] = true
			case 1:
				a[h.name] = false
			case 2:
				a[h.name] = "yes"
			}
		}
		if rapid.Bool().Draw(t, "title") {
			a["title"] = names().Draw(t, "titleText")
		}
		return a
	})
}

// toolDoc draws a whole definition and encodes it; encoding/json sorts the
// keys and escapes what JSON must, so the result is always a valid object.
func toolDoc() *rapid.Generator[[]byte] {
	return rapid.Custom(func(t *rapid.T) []byte {
		doc := map[string]any{}
		if rapid.Bool().Draw(t, "hasName") {
			doc["name"] = names().Draw(t, "name")
		}
		if rapid.Bool().Draw(t, "hasDescription") {
			doc["description"] = names().Draw(t, "description")
		}
		if rapid.Bool().Draw(t, "hasTitle") {
			doc["title"] = names().Draw(t, "title")
		}
		if rapid.Bool().Draw(t, "hasIcons") {
			doc["icons"] = []any{map[string]any{"src": names().Draw(t, "icon")}}
		}
		if rapid.Bool().Draw(t, "hasAnnotations") {
			doc["annotations"] = annotations().Draw(t, "annotations")
		}
		if rapid.Bool().Draw(t, "hasInputSchema") {
			doc["inputSchema"] = inputSchema().Draw(t, "inputSchema")
		}
		if rapid.Bool().Draw(t, "hasOutputSchema") {
			doc["outputSchema"] = map[string]any{"type": names().Draw(t, "outputType")}
		}
		if rapid.Bool().Draw(t, "hasMeta") {
			meta := map[string]any{}
			for _, n := range rapid.SliceOfN(names(), 0, 2).Draw(t, "metaKeys") {
				meta[n] = rapid.IntRange(0, 2).Draw(t, "metaValue")
			}
			doc["_meta"] = meta
		}
		if rapid.Bool().Draw(t, "hasOther") {
			doc[names().Draw(t, "otherKey")] = rapid.Bool().Draw(t, "otherValue")
		}
		b, err := json.Marshal(doc)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return b
	})
}

func mustCompareBytes(t *rapid.T, from, to []byte) Report {
	t.Helper()
	r, err := Compare(from, to)
	if err != nil {
		t.Fatalf("Compare(%s, %s): %v", from, to, err)
	}
	return r
}

func count(r Report, kinds ...Kind) int {
	n := 0
	for _, f := range r.Findings {
		for _, k := range kinds {
			if f.Kind == k {
				n++
			}
		}
	}
	return n
}

func countDetail(r Report, kind Kind, detail string) int {
	n := 0
	for _, f := range r.Findings {
		if f.Kind == kind && f.Detail == detail {
			n++
		}
	}
	return n
}

func paths(r Report) []string {
	out := make([]string, 0, len(r.Findings))
	for _, f := range r.Findings {
		out = append(out, f.Path)
	}
	sort.Strings(out)
	return out
}

// Swapping the documents swaps what was removed with what was added, and the
// members that differ are the same members: every parameter removed one way
// is a parameter added (required or optional) the other way, and the set of
// paths is the same in both directions.
func TestProperty_compareSwapsAddedAndRemovedKinds(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		from, to := toolDoc().Draw(t, "from"), toolDoc().Draw(t, "to")
		forward, back := mustCompareBytes(t, from, to), mustCompareBytes(t, to, from)
		if count(forward, ParameterRemoved) != count(back, RequiredParameterAdded, OptionalParameterAdded) {
			t.Fatalf("removed forward %d, added back %d:\n%+v\n%+v", count(forward, ParameterRemoved),
				count(back, RequiredParameterAdded, OptionalParameterAdded), forward.Findings, back.Findings)
		}
		if count(back, ParameterRemoved) != count(forward, RequiredParameterAdded, OptionalParameterAdded) {
			t.Fatalf("removed back %d, added forward %d", count(back, ParameterRemoved),
				count(forward, RequiredParameterAdded, OptionalParameterAdded))
		}
		if count(forward, ParameterMadeRequired) != countDetail(back, InputSchemaChanged, "made optional") {
			t.Fatalf("made required forward %d, made optional back %d", count(forward, ParameterMadeRequired),
				countDetail(back, InputSchemaChanged, "made optional"))
		}
		fp, bp := paths(forward), paths(back)
		if len(fp) != len(bp) {
			t.Fatalf("paths differ by direction:\n%v\n%v", fp, bp)
		}
		for i := range fp {
			if fp[i] != bp[i] {
				t.Fatalf("paths differ by direction at %d: %q vs %q", i, fp[i], bp[i])
			}
		}
		if (len(forward.Findings) == 0) != (len(back.Findings) == 0) {
			t.Fatal("one direction has findings and the other none")
		}
	})
}

func TestProperty_maxSeverityIsTheLargestFinding(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		from, to := toolDoc().Draw(t, "from"), toolDoc().Draw(t, "to")
		r := mustCompareBytes(t, from, to)
		want := None
		seen := map[Kind]bool{}
		for _, f := range r.Findings {
			if f.Severity > want {
				want = f.Severity
			}
			if f.Severity != f.Kind.Severity() {
				t.Fatalf("finding %+v carries another severity than its kind", f)
			}
			seen[f.Kind] = true
		}
		if r.Max() != want {
			t.Fatalf("Max = %v, largest finding %v", r.Max(), want)
		}
		if len(r.Kinds()) != len(seen) {
			t.Fatalf("Kinds = %v, seen %v", r.Kinds(), seen)
		}
		for i := 1; i < len(r.Findings); i++ {
			a, b := r.Findings[i-1], r.Findings[i]
			if a.Severity < b.Severity || (a.Severity == b.Severity && a.Path > b.Path) {
				t.Fatalf("not sorted at %d: %+v before %+v", i, a, b)
			}
		}
		if (len(r.Findings) == 0) != (r.Summary() == "none") {
			t.Fatalf("Summary %q for %d findings", r.Summary(), len(r.Findings))
		}
	})
}

// randomJSON draws any JSON value, nested, with hostile strings, so that the
// classifier meets every shape a decoder can produce at every member.
func randomJSON() *rapid.Generator[any] {
	var gen *rapid.Generator[any]
	gen = rapid.Custom(func(t *rapid.T) any {
		switch rapid.IntRange(0, 6).Draw(t, "shape") {
		case 0:
			return nil
		case 1:
			return rapid.Bool().Draw(t, "bool")
		case 2:
			return rapid.Float64().Draw(t, "number")
		case 3:
			return names().Draw(t, "string")
		case 4:
			n := rapid.IntRange(0, 3).Draw(t, "len")
			out := make([]any, n)
			for i := range out {
				out[i] = gen.Draw(t, "element")
			}
			return out
		default:
			out := map[string]any{}
			for _, k := range rapid.SliceOfN(rapid.OneOf(names(), rapid.SampledFrom([]string{"name", "description", "inputSchema", "annotations", "_meta", "properties", "required", "type", "readOnlyHint", "title", "icons", "outputSchema"})), 0, 4).Draw(t, "keys") {
				out[k] = gen.Draw(t, "member")
			}
			return out
		}
	})
	return gen
}

func TestProperty_compareNeverPanicsOnRandomJSON(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		var from, to []byte
		if rapid.Bool().Draw(t, "rawBytes") {
			from = rapid.SliceOf(rapid.Byte()).Draw(t, "fromBytes")
			to = rapid.SliceOf(rapid.Byte()).Draw(t, "toBytes")
		} else {
			var err error
			if from, err = json.Marshal(randomJSON().Draw(t, "from")); err != nil {
				t.Fatal(err)
			}
			if to, err = json.Marshal(randomJSON().Draw(t, "to")); err != nil {
				t.Fatal(err)
			}
		}
		r, err := Compare(from, to)
		if err != nil {
			if len(r.Findings) != 0 {
				t.Fatalf("findings alongside error %v", err)
			}
			return
		}
		checkReport(t, r)
		if same, err := Compare(from, from); err != nil || len(same.Findings) != 0 {
			t.Fatalf("Compare(x, x) = %+v, %v", same.Findings, err)
		}
	})
}
