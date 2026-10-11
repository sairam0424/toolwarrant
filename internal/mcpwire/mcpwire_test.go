package mcpwire

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
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
		"not json":                   `nope`,
		"empty":                      ``,
		"an array":                   `[{"name":"echo"}]`,
		"no tools key":               `{"nextCursor":"x"}`,
		"tools not an array":         `{"tools":{"name":"echo"}}`,
		"tools null":                 `{"tools":null}`,
		"tools a string":             `{"tools":"x"}`,
		"last tools not an array":    `{"tools":[{"name":"echo"}],"tools":7}`,
		"tool without name":          `{"tools":[{"description":"x"}]}`,
		"tool with empty name":       `{"tools":[{"name":""}]}`,
		"tool with null name":        `{"tools":[{"name":null}]}`,
		"tool with numeric name":     `{"tools":[{"name":5}]}`,
		"tool is a number":           `{"tools":[7]}`,
		"tool is null":               `{"tools":[null]}`,
		"tool is an array":           `{"tools":[[]]}`,
		"tool is a string":           `{"tools":["echo"]}`,
		"unterminated tool":          `{"tools":[{"name":"echo"}`,
		"elements without a comma":   `{"tools":[{"name":"a"} {"name":"b"}]}`,
		"member without a value":     `{"tools":[],"a":}`,
		"members without a comma":    `{"tools":[] "a":1}`,
		"trailing data":              `{"tools":[]} x`,
		"a second object":            `{"tools":[]}{}`,
		"broken member before tools": `{"a":{,"tools":[]}`,
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

func TestFilterToolsListRaw_PassesExactToolBytesToTheCallback(t *testing.T) {
	seen := map[string]string{}
	_, _, err := FilterToolsListRaw([]byte(listResult), func(name string, tool []byte) bool {
		seen[name] = string(tool)
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	wantAdd := `{"name":"add","description":"Adds.","inputSchema":{"type":"object"},"annotations":{"readOnlyHint":true}}`
	if seen["add"] != wantAdd {
		t.Fatalf("callback got %q, want the tool's exact bytes %q", seen["add"], wantAdd)
	}
	if len(seen) != 3 {
		t.Fatalf("callback saw %d tools, want 3", len(seen))
	}
}

// The entry bytes handed to a caller are found by the decoder's offsets, so
// whitespace and separators around them must be trimmed exactly: a page laid
// out with spaces and newlines yields the same bytes as a compact one, and the
// rewritten result carries every member and kept tool as written.
func TestFilterToolsListRaw_ExactBytesUnderWhitespace(t *testing.T) {
	in := "{ \"nextCursor\" :\t\"c\" ,\n \"tools\" : [\n  {\"name\" : \"a\", \"n\": 1} ,\n\n {\"name\":\"b\"}\n ] , \"_meta\": { \"k\" : [ 1 , 2 ] } }"
	var got []string
	out, dropped, err := FilterToolsListRaw([]byte(in), func(name string, tool []byte) bool {
		got = append(got, string(tool))
		return name == "a"
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{`{"name" : "a", "n": 1}`, `{"name":"b"}`}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("callback bytes = %q, want %q", got, want)
	}
	if !reflect.DeepEqual(dropped, []string{"b"}) {
		t.Errorf("dropped = %v, want [b]", dropped)
	}
	wantOut := `{"nextCursor":"c","tools":[{"name" : "a", "n": 1}],"_meta":{ "k" : [ 1 , 2 ] }}`
	if string(out) != wantOut {
		t.Errorf("output = %s, want %s (members in first-seen order, values as written)", out, wantOut)
	}
}

// Entries are slices of the input, not copies: the processor hashes them in
// place and a page costs its own bytes once.
func TestToolsList_EntriesAliasTheInput(t *testing.T) {
	raw := []byte(listResult)
	l, err := ParseToolsList(raw, 0)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	err = l.Walk(func(_ string, tool []byte) error {
		n++
		i := bytes.Index(raw, tool)
		if i < 0 {
			t.Fatalf("entry %q is not a substring of the input", tool)
		}
		if &raw[i] != &tool[0] {
			t.Errorf("entry %q was copied out of the input", tool)
		}
		return nil
	})
	if err != nil || n != 3 {
		t.Fatalf("walked %d entries, err %v", n, err)
	}
}

// Top-level members that repeat are read the way encoding/json reads them, the
// last value winning, and the result carries each key once at the position of
// its first appearance: a client sees no duplicate that another parser could
// resolve the other way.
func TestFilterToolsList_RepeatedTopLevelKeysKeepTheLastValueOnce(t *testing.T) {
	in := `{"tools":[{"name":"evil"}],"nextCursor":"a","tools":[{"name":"good"}],"nextCursor":"b"}`
	out, dropped, err := FilterToolsList([]byte(in), func(string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"tools":[{"name":"good"}],"nextCursor":"b"}`; string(out) != want {
		t.Errorf("output = %s, want %s", out, want)
	}
	if len(dropped) != 0 {
		t.Errorf("dropped = %v, want nothing: the first tools array was never offered", dropped)
	}
}

// capPage lists n tiny entries followed by one entry that has no name.
func capPage(n int) []byte {
	var sb strings.Builder
	sb.WriteString(`{"tools":[`)
	for i := 0; i < n; i++ {
		fmt.Fprintf(&sb, `{"name":"t%d"},`, i)
	}
	sb.WriteString(`{"description":"no name"}]}`)
	return []byte(sb.String())
}

// The cap is enforced while the page is surveyed, before any entry is handed
// to a caller: a page with more entries than the cap is ErrTooManyTools even
// when the entry past the cap could not have been read, and the same page
// with no cap fails only when the walk reaches that entry.
func TestParseToolsList_StopsAtTheCapBeforeReadingTheEntryPastIt(t *testing.T) {
	const limit = 3
	page := capPage(limit)
	if _, err := ParseToolsList(page, limit); !errors.Is(err, ErrTooManyTools) {
		t.Fatalf("err = %v, want ErrTooManyTools before the fourth entry is read", err)
	}
	l, err := ParseToolsList(page, 0)
	if err != nil {
		t.Fatalf("without a cap the survey must pass: %v", err)
	}
	seen := 0
	err = l.Walk(func(string, []byte) error {
		seen++
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "tool 3 has no string name") || seen != limit {
		t.Fatalf("walk saw %d entries, err %v; want %d and the unnamed fourth entry", seen, err, limit)
	}
	// Exactly at the cap the page is read in full.
	exact := []byte(`{"tools":[{"name":"a"},{"name":"b"},{"name":"c"}]}`)
	if _, err := ParseToolsList(exact, limit); err != nil {
		t.Fatalf("a page of exactly %d entries must pass: %v", limit, err)
	}
	// The cap applies to every tools array on the page, not only the last.
	twice := []byte(`{"tools":[{"name":"a"},{"name":"b"},{"name":"c"},{"name":"d"}],"tools":[]}`)
	if _, err := ParseToolsList(twice, limit); !errors.Is(err, ErrTooManyTools) {
		t.Fatalf("err = %v, want ErrTooManyTools for the first array", err)
	}
}

// An error from the visitor stops the walk and comes back unchanged, so a
// caller can park its own failure and recognise it afterwards.
func TestToolsList_WalkStopsOnTheVisitorsError(t *testing.T) {
	l, err := ParseToolsList([]byte(listResult), 0)
	if err != nil {
		t.Fatal(err)
	}
	stop := errors.New("stop here")
	seen := 0
	err = l.Walk(func(string, []byte) error {
		seen++
		if seen == 2 {
			return stop
		}
		return nil
	})
	if !errors.Is(err, stop) || seen != 2 {
		t.Fatalf("walk saw %d entries, err %v; want 2 and the visitor's error", seen, err)
	}
	// Filter reports the same error.
	if _, _, err := l.Filter(func(string, []byte) bool { return true }); err != nil {
		t.Fatalf("Filter after a stopped Walk: %v", err)
	}
}

// Walk names the index of an entry it cannot read, whatever its shape.
func TestToolsList_WalkRejectsEntriesWithoutAStringName(t *testing.T) {
	for _, bad := range []string{`{"name":""}`, `{"description":"x"}`, `{"name":null}`, `{"name":5}`, `7`, `null`, `[]`, `"s"`, `{}`} {
		l, err := ParseToolsList([]byte(`{"tools":[{"name":"ok"},`+bad+`]}`), 0)
		if err != nil {
			t.Fatalf("%s: survey failed: %v", bad, err)
		}
		err = l.Walk(func(string, []byte) error { return nil })
		if err == nil || !strings.Contains(err.Error(), "tool 1 has no string name") {
			t.Errorf("%s: err = %v, want the unnamed entry at index 1", bad, err)
		}
	}
}

// The decoder helpers keep their error branches although json.Valid makes them
// unreachable through ParseToolsList: a token stream that stops agreeing with
// the validator must fail the page, never pass it. Each is exercised directly.
func TestInternals_DecoderDisagreementsFailClosed(t *testing.T) {
	dec := func(s string) *json.Decoder { return json.NewDecoder(strings.NewReader(s)) }
	noop := func(int, []byte) error { return nil }
	skip := func() any { return &skipValue{} }
	if err := eachElement(dec(`7`), []byte(`7`), 0, skip, noop); !errors.Is(err, ErrNoTools) {
		t.Errorf("not an array: err = %v, want ErrNoTools", err)
	}
	if err := eachElement(dec(`[1}`), []byte(`[1}`), 0, skip, noop); !errors.Is(err, ErrNoTools) {
		t.Errorf("array closed by a brace: err = %v, want ErrNoTools", err)
	}
	if _, _, err := readKey(dec(`[1]`), []byte(`[1]`)); err == nil {
		t.Error("a delimiter where a member name belongs must be an error")
	}
	if _, err := parse([]byte(`{"tools":[]`), 0); !errors.Is(err, errNotObject) {
		t.Errorf("unterminated object: err = %v, want errNotObject", err)
	}
	if _, err := parse([]byte(`{"a":}`), 0); !errors.Is(err, errNotObject) {
		t.Errorf("member without a value: err = %v, want errNotObject", err)
	}
	if _, err := parse([]byte(`{"tools":[],"a":1,}`), 0); !errors.Is(err, errNotObject) {
		t.Errorf("trailing comma then end: err = %v, want errNotObject", err)
	}
	if _, err := parse([]byte(`{"a":1`), 0); !errors.Is(err, errNotObject) {
		t.Errorf("member then end of input: err = %v, want errNotObject", err)
	}
	if _, err := parse([]byte(`{"tools":[]]`), 0); !errors.Is(err, errNotObject) {
		t.Errorf("object closed by a bracket: err = %v, want errNotObject", err)
	}
	if _, err := parse([]byte(`{"tools":[]} x`), 0); !errors.Is(err, errNotObject) {
		t.Errorf("data after the object: err = %v, want errNotObject", err)
	}
	// A member whose key is not the tools key but whose value is byte-equal to
	// the tools array is written as written, not filtered.
	l, err := ParseToolsList([]byte(`{"copy":[{"name":"x"}],"tools":[{"name":"x"}]}`), 0)
	if err != nil {
		t.Fatal(err)
	}
	out, _, err := l.Filter(func(string, []byte) bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"copy":[{"name":"x"}],"tools":[]}`; string(out) != want {
		t.Errorf("output = %s, want %s", out, want)
	}
	if l.keyOf(0) != "copy" || (&ToolsList{members: []member{{key: []byte(`nope`)}}}).keyOf(0) != "" {
		t.Error("keyOf must decode a key and return nothing for bytes that are not a string")
	}
}
