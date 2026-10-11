package gate

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/sairam0424/toolwarrant/internal/strictjson"
)

// Only a surrogate problem is reported as ErrNotUTF8. A definition the RFC
// 8785 step refuses for another reason keeps that reason alone, so the
// sentinel means exactly what docs/decisions.md D1 says. A well-formed pair,
// even next to the refused content, is not a surrogate problem.
func TestCanonicalTool_OtherCanonicalisationFailuresAreNotErrNotUTF8(t *testing.T) {
	pair := esc("d83d") + esc("de00")
	refused := map[string]string{
		"nested duplicate key":                `{"name":"a","s":{"k":1,"k":2}}`,
		"nested duplicate key next to a pair": `{"name":"a","s":{"` + pair + `":1,"` + string(rune(0x1f600)) + `":2}}`,
		"nesting beyond the limit":            `{"name":"a","x":` + strings.Repeat("[", 20000) + strings.Repeat("]", 20000) + `}`,
	}
	for name, raw := range refused {
		_, err := CanonicalTool([]byte(raw))
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if errors.Is(err, ErrNotUTF8) || errors.Is(err, ErrNumberPrecision) || errors.Is(err, strictjson.ErrAmbiguousKeys) {
			t.Errorf("%s: error %v claims a sentinel that does not describe it", name, err)
		}
	}
	if _, err := CanonicalTool([]byte(`{"name":"a","d":"` + pair + `","` + pair + `":1}`)); err != nil {
		t.Errorf("well-formed surrogate pairs were refused: %v", err)
	}
}

// encoding/json is the independent oracle for the classifier: it decodes
// every \u escape that is not part of a well-formed surrogate pair as U+FFFD.
// For random strings of escapes and characters, in a value and in a key,
// CanonicalTool reports ErrNotUTF8 exactly when encoding/json would have put
// a U+FFFD where the source spelled none, and never accepts such a string.
func TestCanonicalTool_SurrogateClassificationAgreesWithEncodingJSON(t *testing.T) {
	pieces := []string{
		esc("d83d"), esc("de00"), esc("d800"), esc("dbff"), esc("dc00"), esc("dfff"),
		`A`, `u`, `\\`, `\"`, `\/`, `\n`, `\\u`, esc("0041"), esc("00e9"), esc("fffd"), string(rune(0x1f600)),
	}
	rapid.Check(t, func(rt *rapid.T) {
		var sb strings.Builder
		for _, piece := range rapid.SliceOfN(rapid.SampledFrom(pieces), 0, 8).Draw(rt, "pieces") {
			sb.WriteString(piece)
		}
		source := sb.String()
		literal := `"` + source + `"`
		var decoded string
		if err := json.Unmarshal([]byte(literal), &decoded); err != nil {
			rt.Fatalf("setup: %s is not a JSON string: %v", literal, err)
		}
		ill := strings.Count(decoded, string(rune(0xfffd))) > strings.Count(source, esc("fffd"))
		for _, doc := range []string{`{"name":"a","d":` + literal + `}`, `{"name":"a",` + literal + `:1}`} {
			_, err := CanonicalTool([]byte(doc))
			if ill && err == nil {
				rt.Fatalf("%s: accepted although encoding/json reads a U+FFFD into it", doc)
			}
			if got := errors.Is(err, ErrNotUTF8); got != ill {
				rt.Fatalf("%s: ErrNotUTF8 = %v, want %v (err %v)", doc, got, ill, err)
			}
		}
	})
}
