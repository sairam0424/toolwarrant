package textdiff

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// lookAlikeSection returns the text after the "Look-alike changes" heading.
func lookAlikeSection(t *testing.T, out string) string {
	t.Helper()
	parts := strings.SplitN(out, "\n"+sectionLookAlike+"\n", 2)
	if len(parts) != 2 {
		t.Fatalf("no %s section:\n%s", sectionLookAlike, out)
	}
	return parts[1]
}

// A parameter renamed to a look-alike of itself and a description changed by
// one look-alike letter are both invisible in the diff; the section names
// them by code point and script, with the byte offset, and the renamed key is
// also a mixed-script word.
func TestTool_lookAlikeSwapIsListedWithCodePoints(t *testing.T) {
	from := `{"name":"copy","description":"Copies a file.","inputSchema":{"type":"object","properties":{"path":{"type":"string"}}}}`
	to := `{"name":"copy","description":"Copies \u0430 file.","inputSchema":{"type":"object","properties":{"p\u0430th":{"type":"string"}}}}`
	out := mustTool(t, from, to)
	section := lookAlikeSection(t, out)
	want := "  3 (look-alike: 2, mixed-script: 1)\n" +
		"    $.description: U+0430 (Cyrillic) for U+0061 (Latin) at byte 7 (look-alike)\n" +
		"    $.inputSchema.properties[\"p\u0430th\"] (key): U+0430 (Cyrillic) for U+0061 (Latin) at byte 1 (look-alike)\n" +
		"    $.inputSchema.properties[\"p\u0430th\"] (key) byte 0: Cyrillic (U+0430) with Latin (U+0070 U+0074 U+0068) (mixed-script)\n"
	if section != want {
		t.Fatalf("section:\n%s\nwant:\n%s", section, want)
	}
	// The same documents through the exported list.
	changes, err := LookAlikeChanges([]byte(from), []byte(to))
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 2 || changes[0].Where() != "$.description" || changes[1].Where() != "$.inputSchema.properties[\"p\u0430th\"] (key)" || !changes[1].IsKey {
		t.Fatalf("LookAlikeChanges = %+v", changes)
	}
	if changes[1].Detail() != "U+0430 (Cyrillic) for U+0061 (Latin) at byte 1" {
		t.Fatalf("key detail = %q", changes[1].Detail())
	}
}

// A visible change is not a look-alike, and a value present on one side only
// is not either: the diff and the Changed text section show those.
func TestTool_visibleChangesAreNotLookAlikes(t *testing.T) {
	out := mustTool(t, `{"description":"Copies a file.","a":"gone"}`, `{"description":"Copies a directory.","b":"new"}`)
	if got := lookAlikeSection(t, out); got != "  none\n" {
		t.Fatalf("section = %q", got)
	}
	changes, err := LookAlikeChanges([]byte(`{"a":"path"}`), []byte(`{"b":"p\u0430th"}`))
	if err != nil || len(changes) != 0 {
		t.Fatalf("a key that moved is not a swap: %+v, %v", changes, err)
	}
	changes, err = LookAlikeChanges([]byte(`{"x":{"path":1}}`), []byte(`{"y":{"p\u0430th":1}}`))
	if err != nil || len(changes) != 0 {
		t.Fatalf("keys are paired within one object only: %+v, %v", changes, err)
	}
}

// Mixed-script words of the new document are listed with their path and byte
// offset; the old document was reviewed when it was approved, so its words are
// not, and the words of a Japanese, Korean or Chinese text with a Latin
// acronym pass.
func TestTool_mixedScriptWordsAreListed(t *testing.T) {
	// The description is the same on both sides, so it is no change at all;
	// only the words of the new document are read.
	from := `{"description":"Fetch the \u0410PI t\u043Eken"}`
	to := `{"description":"Fetch the \u0410PI t\u043Eken","inputSchema":{"properties":{"\u0442oken":{"description":"\u6771\u4EAC\u306EAPI\u3092\u547C\u3076 \uD55C\uAD6DAPI \u3105\u3106API"}}}}`
	out := mustTool(t, from, to)
	section := lookAlikeSection(t, out)
	want := "  3 (mixed-script: 3)\n" +
		"    $.description byte 10: Cyrillic (U+0410) with Latin (U+0050 U+0049) (mixed-script)\n" +
		"    $.description byte 15: Cyrillic (U+043E) with Latin (U+0074 U+006B U+0065 U+006E) (mixed-script)\n" +
		"    $.inputSchema.properties[\"\u0442oken\"] (key) byte 0: Cyrillic (U+0442) with Latin (U+006F U+006B U+0065 U+006E) (mixed-script)\n"
	if section != want {
		t.Fatalf("section:\n%s\nwant:\n%s", section, want)
	}
	out = mustTool(t, to, `{"description":"Fetch the token"}`)
	if got := lookAlikeSection(t, out); got != "  none\n" {
		t.Fatalf("the old document's words were listed, or a visible change counted: %q", got)
	}
}

// The detail lines are capped like the suspicious characters; the counts stay
// complete.
func TestTool_lookAlikeSectionIsCappedButCountsAreComplete(t *testing.T) {
	const n = maxLookAlikeLines + 50
	from, to := map[string]any{}, map[string]any{}
	for i := 0; i < n; i++ {
		from["a"+strconv.Itoa(i)] = 1
		to["\u0430"+strconv.Itoa(i)] = 1
	}
	fromDoc, _ := json.Marshal(map[string]any{"inputSchema": map[string]any{"properties": from}})
	toDoc, _ := json.Marshal(map[string]any{"inputSchema": map[string]any{"properties": to}})
	out := mustTool(t, string(fromDoc), string(toDoc))
	section := lookAlikeSection(t, out)
	if !strings.HasPrefix(section, "  "+strconv.Itoa(n)+" (look-alike: "+strconv.Itoa(n)+")\n") {
		t.Fatalf("count line missing:\n%s", section[:200])
	}
	if !strings.HasSuffix(section, "    ... 50 more not listed\n") {
		t.Fatalf("cap line missing, section ends with %q", section[len(section)-120:])
	}
	if got := strings.Count(section, "(look-alike)\n"); got != maxLookAlikeLines {
		t.Fatalf("listed %d lines, want %d", got, maxLookAlikeLines)
	}
}

func TestLookAlikeChange_detailCapsTheSwaps(t *testing.T) {
	from := strings.Repeat("a ", maxSwapsListed+3)
	to := strings.Repeat("\u0430 ", maxSwapsListed+3)
	changes, err := LookAlikeChanges([]byte(strconv.Quote(from)), []byte(strconv.Quote(to)))
	if err != nil || len(changes) != 1 {
		t.Fatalf("changes = %+v, %v", changes, err)
	}
	detail := changes[0].Detail()
	if strings.Count(detail, "U+0430 (Cyrillic) for U+0061 (Latin)") != maxSwapsListed || !strings.HasSuffix(detail, ", +3 more") {
		t.Fatalf("detail = %q", detail)
	}
}

func TestLookAlikeChanges_refusesInvalidDocumentsWithoutEchoingThem(t *testing.T) {
	cases := []struct {
		name     string
		from, to string
		wantSide string
	}{
		{"from truncated", `{"secret":"hunter2"`, `{}`, "from"},
		{"to not json", `{}`, `hunter2`, "to"},
		{"to invalid utf-8", `{}`, "{\"d\":\"hunter2\xff\"}", "to"},
		{"trailing data", `{"a":1} {"hunter2":2}`, `{}`, "from"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			changes, err := LookAlikeChanges([]byte(tc.from), []byte(tc.to))
			if err == nil || changes != nil {
				t.Fatalf("want an error and no changes, got %+v, %v", changes, err)
			}
			if !strings.HasPrefix(err.Error(), "textdiff: "+tc.wantSide+" document") || strings.Contains(err.Error(), "hunter2") {
				t.Fatalf("error = %q", err)
			}
		})
	}
}
