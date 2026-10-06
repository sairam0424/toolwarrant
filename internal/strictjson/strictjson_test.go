package strictjson

import (
	"errors"
	"testing"
)

func TestObject_Accepts(t *testing.T) {
	ok := map[string]string{
		"plain tool":               `{"name":"a","description":"d"}`,
		"nested name is fine":      `{"name":"a","arguments":{"name":"b","Name":"c"}}`,
		"escaped spelling of name": `{"name":"a"}`,
		"whitespace":               " \n{ \"name\" : \"a\" }\n ",
		"empty object":             `{}`,
		"no name at all":           `{"description":"d"}`,
		"duplicate inside array":   `{"name":"a","list":[{"k":1,"k":2}]}`, // below the top level: the RFC 8785 step rejects it
		"other keys in any case":   `{"name":"a","Description":"x","DESCRIPTION":"y"}`,
	}
	for name, raw := range ok {
		if err := Object([]byte(raw)); err != nil {
			t.Errorf("%s: unexpected error %v", name, err)
		}
	}
}

func TestObject_Rejects(t *testing.T) {
	bad := map[string]string{
		"duplicate key":              `{"a":1,"a":2}`,
		"duplicate after unescaping": `{"name":"a","name":"b"}`,
		"name in another case":       `{"NAME":"a"}`,
		"name title case":            `{"Name":"a"}`,
		"exact and case variant":     `{"name":"a","nAmE":"b"}`,
		"array":                      `[{"name":"a"}]`,
		"string":                     `"name"`,
		"number":                     `1`,
		"null":                       `null`,
		"empty":                      ``,
		"only whitespace":            ` `,
		"truncated":                  `{"name":"a"`,
		"truncated in value":         `{"name":`,
		"missing colon":              `{"name" "a"}`,
		"two objects":                `{"name":"a"}{"name":"b"}`,
		"trailing comma":             `{"name":"a",}`,
		"trailing garbage":           `{"name":"a"} x`,
		"non-string key":             `{1:2}`,
	}
	for name, raw := range bad {
		if err := Object([]byte(raw)); err == nil {
			t.Errorf("%s: %q was accepted", name, raw)
		}
	}
}

func TestObject_NamesTheProblem(t *testing.T) {
	if err := Object([]byte(`{"a":1,"a":2}`)); !errors.Is(err, ErrAmbiguousKeys) {
		t.Errorf("duplicate key: got %v, want ErrAmbiguousKeys", err)
	}
	if err := Object([]byte(`{"Name":"x"}`)); !errors.Is(err, ErrAmbiguousKeys) {
		t.Errorf("case variant: got %v, want ErrAmbiguousKeys", err)
	}
	if err := Object([]byte(`[1]`)); !errors.Is(err, ErrNotObject) {
		t.Errorf("array: got %v, want ErrNotObject", err)
	}
}

func FuzzObject(f *testing.F) {
	for _, seed := range []string{`{"name":"a"}`, `{"a":1,"a":2}`, `[`, `{"Name":1}`, `{"name":1,"name":2}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		// Must never panic. When it accepts, a second call must agree.
		first := Object(raw)
		if second := Object(raw); (first == nil) != (second == nil) {
			t.Fatalf("not deterministic for %q", raw)
		}
	})
}
