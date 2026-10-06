package textdiff

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// stdPretty is what encoding/json produces with the settings prettyJSON
// claims to reproduce.
func stdPretty(t rapid.TB, v any) string {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", indentUnit)
	if err := enc.Encode(v); err != nil {
		t.Fatalf("encoding/json: %v", err)
	}
	return strings.TrimSuffix(buf.String(), "\n")
}

// jsonValue generates decoded documents as decodeJSON would produce them:
// json.Number for numbers, map[string]any, []any, string, bool and nil. depth
// bounds the nesting so the generator terminates.
func jsonValue(depth int) *rapid.Generator[any] {
	text := rapid.OneOf(rapid.String(), hostileString())
	scalar := rapid.OneOf(
		rapid.Just[any](nil),
		rapid.Map(rapid.Bool(), func(b bool) any { return b }),
		rapid.Map(rapid.Int64(), func(i int64) any { return json.Number(strconv.FormatInt(i, 10)) }),
		rapid.Map(rapid.Float64(), func(f float64) any { return json.Number(strconv.FormatFloat(f, 'g', -1, 64)) }),
		rapid.Map(text, func(s string) any { return s }),
	)
	if depth == 0 {
		return scalar
	}
	return rapid.OneOf(
		scalar,
		rapid.Map(rapid.SliceOfN(jsonValue(depth-1), 0, 4), func(xs []any) any { return xs }),
		rapid.Map(rapid.MapOfN(text, jsonValue(depth-1), 0, 4), func(m map[string]any) any { return m }),
	)
}

// Within maxIndentDepth levels the renderer must be byte-identical to
// encoding/json, so every existing expectation about the diff still holds.
func TestProperty_prettyJSONMatchesEncodingJSONWithinTheIndentCap(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		v := jsonValue(maxIndentDepth).Draw(t, "v")
		got, err := prettyJSON(v)
		if err != nil {
			t.Fatalf("prettyJSON: %v", err)
		}
		if want := stdPretty(t, v); got != want {
			t.Fatalf("prettyJSON = %q\nencoding/json = %q", got, want)
		}
	})
}

func TestPrettyJSON_tableMatchesEncodingJSON(t *testing.T) {
	cases := []any{
		"a\x7fb",                        // DEL is written raw, as encoding/json does
		"a\u2028b\u2029c",               // the two separators are escaped
		"x\xffy",                        // an invalid byte becomes U+FFFD
		"\x00\x01\x1f\b\f\n\r\t\"\\<>&", // controls, quotes, HTML
		json.Number("1.0e2"),
		map[string]any{"b": []any{}, "a": map[string]any{}, "c": nil, "d": true},
		[]any{json.Number("1"), []any{json.Number("2"), []any{}}},
	}
	for _, v := range cases {
		got, err := prettyJSON(v)
		if err != nil {
			t.Fatalf("prettyJSON(%v): %v", v, err)
		}
		if want := stdPretty(t, v); got != want {
			t.Errorf("prettyJSON(%#v) = %q, want %q", v, got, want)
		}
	}
}

// Past maxIndentDepth the indentation stops growing but the document is still
// the same JSON value, so nothing is lost for the approver.
func TestPrettyJSON_indentStopsGrowingPastTheCap(t *testing.T) {
	raw := []byte(strings.Repeat("[", 40) + `"x"` + strings.Repeat("]", 40))
	v, err := decodeJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	out, err := prettyJSON(v)
	if err != nil {
		t.Fatal(err)
	}
	maxIndent := strings.Repeat(indentUnit, maxIndentDepth)
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, maxIndent+indentUnit) {
			t.Fatalf("line %q is indented beyond %d levels", l, maxIndentDepth)
		}
	}
	if !strings.Contains(out, maxIndent+`"x"`) {
		t.Fatalf("the deepest value must sit at the capped indent:\n%s", out)
	}
	var back any
	dec := json.NewDecoder(strings.NewReader(out))
	dec.UseNumber()
	if err := dec.Decode(&back); err != nil || !reflect.DeepEqual(back, v) {
		t.Fatalf("capped output does not decode to the same value: %v", err)
	}
}

func TestPrettyJSON_refusesUnexpectedTypes(t *testing.T) {
	if _, err := prettyJSON(map[string]any{"a": 42}); err == nil {
		t.Fatal("an int is not a value decodeJSON produces and must be refused")
	}
}
