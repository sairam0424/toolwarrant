package mcpwire

import (
	"encoding/json"
	"strings"
	"testing"
)

const listResult = `{"tools":[` +
	`{"name":"echo","description":"Echoes.","inputSchema":{"type":"object","properties":{"n":{"type":"integer","maximum":10}}}},` +
	`{"name":"add","description":"Adds.","inputSchema":{"type":"object"},"annotations":{"readOnlyHint":true}},` +
	`{"name":"wipe_database","description":"Danger.","inputSchema":{"type":"object"}}` +
	`],"nextCursor":"abc","_meta":{"k":"v"}}`

func names(t *testing.T, raw []byte) []string {
	t.Helper()
	var r struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("result is not valid JSON: %v\n%s", err, raw)
	}
	out := make([]string, 0, len(r.Tools))
	for _, tl := range r.Tools {
		out = append(out, tl.Name)
	}
	return out
}

func TestFilterToolsList_KeepsOnlyAllowedInOriginalOrder(t *testing.T) {
	out, dropped, err := FilterToolsList([]byte(listResult), func(n string) bool { return n == "add" || n == "echo" })
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(names(t, out), ","); got != "echo,add" {
		t.Fatalf("kept tools = %q, want %q", got, "echo,add")
	}
	if len(dropped) != 1 || dropped[0] != "wipe_database" {
		t.Fatalf("dropped = %v, want [wipe_database]", dropped)
	}
}

func TestFilterToolsList_PreservesOtherFieldsAndToolBytes(t *testing.T) {
	out, _, err := FilterToolsList([]byte(listResult), func(n string) bool { return n == "echo" })
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{`"nextCursor":"abc"`, `"_meta":{"k":"v"}`, `"maximum":10`} {
		if !strings.Contains(s, want) {
			t.Errorf("output lost %s: %s", want, s)
		}
	}
	// the kept tool's bytes are untouched, so a hash over the served definition stays stable
	wantTool := `{"name":"echo","description":"Echoes.","inputSchema":{"type":"object","properties":{"n":{"type":"integer","maximum":10}}}}`
	if !strings.Contains(s, wantTool) {
		t.Errorf("kept tool bytes changed:\n got %s\nwant %s", s, wantTool)
	}
}

func TestFilterToolsList_EmptyAllowlistYieldsEmptyArrayNotNull(t *testing.T) {
	out, dropped, err := FilterToolsList([]byte(listResult), func(string) bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"tools":[]`) {
		t.Fatalf("want an empty tools array, got %s", out)
	}
	if len(dropped) != 3 {
		t.Fatalf("dropped = %v, want 3 names", dropped)
	}
}

func TestFilterToolsList_Errors(t *testing.T) {
	cases := map[string]string{
		"not json":           `nope`,
		"no tools key":       `{"nextCursor":"x"}`,
		"tools not an array": `{"tools":{"name":"echo"}}`,
		"tool without name":  `{"tools":[{"description":"x"}]}`,
	}
	for name, in := range cases {
		if _, _, err := FilterToolsList([]byte(in), func(string) bool { return true }); err == nil {
			t.Errorf("%s: want an error so the caller can fail closed, got nil", name)
		}
	}
}

func TestToolCallName(t *testing.T) {
	got, err := ToolCallName([]byte(`{"name":"echo","arguments":{"message":"hi"}}`))
	if err != nil || got != "echo" {
		t.Fatalf("got (%q, %v), want (echo, nil)", got, err)
	}
	for name, in := range map[string]string{
		"empty":        ``,
		"not json":     `x`,
		"no name":      `{"arguments":{}}`,
		"name not str": `{"name":7}`,
		"empty name":   `{"name":""}`,
	} {
		if _, err := ToolCallName([]byte(in)); err == nil {
			t.Errorf("%s: want an error, got nil", name)
		}
	}
}

func TestFilterToolsList_DoesNotHTMLEscapeKeptTools(t *testing.T) {
	in := `{"tools":[{"name":"q","description":"a < b && c > d"}]}`
	out, _, err := FilterToolsList([]byte(in), func(string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"description":"a < b && c > d"`) {
		t.Fatalf("kept tool bytes were rewritten (HTML-escaped): %s", out)
	}
}
