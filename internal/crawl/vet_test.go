package crawl

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/gate"
	"github.com/sairam0424/toolwarrant/internal/strictjson"
	"github.com/sairam0424/toolwarrant/internal/toolname"
)

// Code points the cases below spell out through jsonEscape or string(rune),
// never as characters: every one of them is invisible or looks like another.
const (
	zeroWidthSpace      = 0x200b
	rightToLeftOverride = 0x202e
	combiningDiaeresis  = 0x0308
	lineSeparator       = 0x2028
	loneHighSurrogate   = 0xd800
	loneLowSurrogate    = 0xdc00
)

// toolOfSize builds a tool named name, with extra members spliced in after the
// name, padded so that its raw form is exactly size bytes.
func toolOfSize(t testing.TB, name string, size int, extra string) string {
	t.Helper()
	frame := fmt.Sprintf(`{"name":%q,%s"d":""}`, name, extra)
	if size < len(frame) {
		t.Fatalf("size %d is smaller than the frame of %d bytes", size, len(frame))
	}
	return fmt.Sprintf(`{"name":%q,%s"d":"%s"}`, name, extra, strings.Repeat("x", size-len(frame)))
}

// nested returns a tool named a whose member x nests arrays depth levels deep,
// so that the tool as a whole is depth+1 levels deep.
func nested(depth int) string {
	return `{"name":"a","x":` + strings.Repeat("[", depth) + strings.Repeat("]", depth) + `}`
}

type vetCase struct {
	raw        string
	wantName   string
	wantReason Reason
}

// vetCases is the per-tool rule book: every shape the review found one
// component accepting and another refusing, with the verdict the crawler must
// now give. The verdicts mirror internal/gate, internal/toolname and the caps.
func vetCases(t testing.TB) map[string]vetCase {
	t.Helper()
	const sizeCap = defaultMaxToolBytes
	return map[string]vetCase{
		"ordinary tool":          {`{"name":"echo","inputSchema":{"properties":{"name":{},"Name":{}}}}`, "echo", ""},
		"surrounding whitespace": {" {\"name\":\"a\"} \n", "a", ""},
		"escaped key":            {`{"na` + jsonEscape('m') + `e":"a"}`, "a", ""},
		"escaped name value":     {`{"name":"` + jsonEscape('a') + `"}`, "a", ""},
		"unicode name in NFC":    {`{"name":"` + jsonEscape(0xfc) + `ber"}`, "über", ""},
		"number -0":              {`{"name":"a","n":-0}`, "a", ""},
		"_meta member":           {`{"name":"a","_meta":{"ui":{"resourceUri":"ui://x"}}}`, "a", ""},
		"raw U+2028":             {`{"name":"a","d":"` + string(rune(lineSeparator)) + `"}`, "a", ""},
		"escaped U+2028":         {`{"name":"a","d":"` + jsonEscape(lineSeparator) + `"}`, "a", ""},
		"exactly the size cap":   {toolOfSize(t, "big", sizeCap, ""), "big", ""},
		"exactly the depth cap":  {nested(maxToolDepth - 1), "a", ""},

		"tool is a string":           {`"str"`, "", ReasonUnreadable},
		"tool is a number":           {`1`, "", ReasonUnreadable},
		"tool is null":               {`null`, "", ReasonUnreadable},
		"tool is an array":           {`[]`, "", ReasonUnreadable},
		"empty object":               {`{}`, "", ReasonUnreadable},
		"tool without name":          {`{"description":"x"}`, "", ReasonUnreadable},
		"name is a number":           {`{"name":5}`, "", ReasonUnreadable},
		"name is null":               {`{"name":null}`, "", ReasonUnreadable},
		"name is an array":           {`{"name":["a"]}`, "", ReasonUnreadable},
		"name key in wrong case":     {`{"Name":"x"}`, "", ReasonUnreadable},
		"case-variant name":          {`{"name":"a","Name":"b"}`, "", ReasonUnreadable},
		"duplicate name":             {`{"name":"a","name":"b"}`, "", ReasonUnreadable},
		"duplicate description":      {`{"name":"x","description":"evil","description":"safe"}`, "", ReasonUnreadable},
		"invalid UTF-8 in a value":   {"{\"name\":\"a\",\"description\":\"\xff\"}", "", ReasonUnreadable},
		"invalid UTF-8 in the name":  {"{\"name\":\"a\xff\"}", "", ReasonUnreadable},
		"encoded surrogate in a key": {"{\"name\":\"a\",\"x\xed\xa0\x80\":1}", "", ReasonUnreadable},
		"trailing NUL":               {"{\"name\":\"a\"}\x00", "", ReasonUnreadable},
		"leading BOM":                {"\xef\xbb\xbf{\"name\":\"a\"}", "", ReasonUnreadable},
		"NaN":                        {`{"name":"a","n":NaN}`, "", ReasonUnreadable},
		"leading zero":               {`{"name":"a","n":01}`, "", ReasonUnreadable},
		"hex number":                 {`{"name":"a","n":0x10}`, "", ReasonUnreadable},
		"truncated":                  {`{"name":"a"`, "", ReasonUnreadable},

		"empty name":                  {`{"name":""}`, "", ReasonInvalidName},
		"name over the shared cap":    {`{"name":"` + strings.Repeat("n", toolname.MaxBytes+1) + `"}`, "", ReasonInvalidName},
		"name with NUL":               {`{"name":"a` + jsonEscape(0) + `b"}`, "", ReasonInvalidName},
		"name with zero-width space":  {`{"name":"a` + jsonEscape(zeroWidthSpace) + `b"}`, "", ReasonInvalidName},
		"name with bidi override":     {`{"name":"a` + jsonEscape(rightToLeftOverride) + `b"}`, "", ReasonInvalidName},
		"name not in NFC":             {`{"name":"u` + jsonEscape(combiningDiaeresis) + `ber"}`, "", ReasonInvalidName},
		"name with padding space":     {`{"name":" a"}`, "", ReasonInvalidName},
		"lone surrogate in the name":  {`{"name":"a` + jsonEscape(loneHighSurrogate) + `"}`, "", ReasonInvalidName},
		"invalid name in a huge tool": {toolOfSize(t, "a"+string(rune(zeroWidthSpace))+"b", sizeCap+1, ""), "", ReasonInvalidName},

		"one byte over the size cap":  {toolOfSize(t, "big", sizeCap+1, ""), "big", ReasonTooLarge},
		"too large and not canonical": {toolOfSize(t, "big", sizeCap+1, `"n":1e400,`), "big", ReasonTooLarge},

		"one level over the depth cap": {nested(maxToolDepth), "a", ReasonTooDeep},
		"deep object nesting":          {`{"name":"a","x":` + strings.Repeat(`{"k":`, 40) + `1` + strings.Repeat("}", 40) + `}`, "a", ReasonTooDeep},

		"lone high surrogate in a value": {`{"name":"a","d":"` + jsonEscape(loneHighSurrogate) + `"}`, "a", ReasonNotCanonical},
		"lone low surrogate in a value":  {`{"name":"a","d":"` + jsonEscape(loneLowSurrogate) + `"}`, "a", ReasonNotCanonical},
		// The gate canonicalises the original bytes, so a lone surrogate in a
		// KEY is refused like one in a value; a decoder would have replaced
		// it with U+FFFD and hashed the look-alike.
		"lone surrogate in a key": {`{"name":"a","` + jsonEscape(loneHighSurrogate) + `":1}`, "a", ReasonNotCanonical},
		"number overflow 1e400":   {`{"name":"a","n":1e400}`, "a", ReasonNotCanonical},
		// Numbers that double precision cannot hold exactly would canonicalise
		// to a different value, so two definitions would share one digest; the
		// gate refuses them (ErrNumberPrecision) and so does the crawler.
		"number underflow 1e-400":       {`{"name":"a","n":1e-400}`, "a", ReasonNotCanonical},
		"integer beyond 2^53":           {`{"name":"a","n":9007199254740993}`, "a", ReasonNotCanonical},
		"number overflow -1e400":        {`{"name":"a","n":-1e400}`, "a", ReasonNotCanonical},
		"nested duplicate key":          {`{"name":"a","s":{"k":1,"k":2}}`, "a", ReasonNotCanonical},
		"nested duplicate key in array": {`{"name":"a","s":[{"k":1,"k":2}]}`, "a", ReasonNotCanonical},
	}
}

func TestVetTool(t *testing.T) {
	for name, tc := range vetCases(t) {
		t.Run(name, func(t *testing.T) {
			gotName, gotReason, detail := vetTool([]byte(tc.raw), defaultMaxToolBytes)
			if gotName != tc.wantName || gotReason != tc.wantReason {
				t.Fatalf("vetTool = (%q, %q), want (%q, %q)", gotName, gotReason, tc.wantName, tc.wantReason)
			}
			if (detail == "") != (gotReason == "") {
				t.Errorf("detail %q does not go with reason %q", detail, gotReason)
			}
			assertVetInvariants(t, []byte(tc.raw), gotName, gotReason)
		})
	}
}

// assertVetInvariants checks the agreement the crawler promises, whatever the
// input: a usable tool is one the digest and the shared name rule accept and
// that fits both caps, with the name the definition really carries; a reported
// name always passes the shared rule; an unreadable tool reports no name.
func assertVetInvariants(t *testing.T, raw []byte, name string, reason Reason) {
	t.Helper()
	if name != "" && toolname.Validate(name) != nil {
		t.Errorf("reported name %q breaks the shared rule", name)
	}
	if reason == ReasonUnreadable && name != "" {
		t.Errorf("an unreadable tool reported the name %q", name)
	}
	if reason != "" {
		return
	}
	if _, err := gate.Digest(raw); err != nil {
		t.Errorf("usable tool has no digest: %v", err)
	}
	if err := strictjson.Object(raw); err != nil {
		t.Errorf("usable tool has ambiguous keys: %v", err)
	}
	if len(raw) > defaultMaxToolBytes {
		t.Errorf("usable tool is %d bytes, over the cap", len(raw))
	}
	if depth, ok := jsonDepth(raw); !ok || depth > maxToolDepth {
		t.Errorf("usable tool nests %d levels (well-formed=%v)", depth, ok)
	}
	var decoded struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil || decoded.Name != name {
		t.Errorf("reported name %q but the definition says %q (%v)", name, decoded.Name, err)
	}
}

func TestFinishMarksEveryCopyOfARepeatedName(t *testing.T) {
	ok := func(name string) vetted { return vetted{name: name, raw: json.RawMessage(`{"name":"` + name + `"}`)} }
	bad := func(name string, r Reason) vetted { return vetted{name: name, raw: json.RawMessage("x"), reason: r} }
	cases := map[string]struct {
		in           []vetted
		wantTools    string
		wantUnusable string
	}{
		"no repeats":             {[]vetted{ok("a"), ok("b")}, "a b", ""},
		"repeat across the list": {[]vetted{ok("a"), ok("b"), ok("a")}, "b", "a/duplicate-name a/duplicate-name"},
		"three copies":           {[]vetted{ok("a"), ok("a"), ok("a")}, "", "a/duplicate-name a/duplicate-name a/duplicate-name"},
		"repeat of an unusable":  {[]vetted{bad("a", ReasonNotCanonical), ok("a")}, "", "a/duplicate-name a/duplicate-name"},
		"nameless never match":   {[]vetted{bad("", ReasonUnreadable), bad("", ReasonInvalidName)}, "", "/unreadable /invalid-name"},
		"server order is kept":   {[]vetted{ok("b"), bad("c", ReasonTooLarge), ok("a")}, "b a", "c/too-large"},
		"empty listing":          {nil, "", ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			tools, unusable := finish(tc.in)
			if tools == nil {
				t.Error("Tools must be non-nil even when empty")
			}
			var names, marks []string
			for _, tool := range tools {
				names = append(names, tool.Name)
			}
			for _, u := range unusable {
				marks = append(marks, u.Name+"/"+string(u.Reason))
			}
			if got := strings.Join(names, " "); got != tc.wantTools {
				t.Errorf("tools = %q, want %q", got, tc.wantTools)
			}
			if got := strings.Join(marks, " "); got != tc.wantUnusable {
				t.Errorf("unusable = %q, want %q", got, tc.wantUnusable)
			}
		})
	}
}

func TestJSONDepth(t *testing.T) {
	cases := map[string]struct {
		raw   string
		depth int
		ok    bool
	}{
		"scalar":                       {`"x"`, 0, true},
		"empty object":                 {`{}`, 1, true},
		"nested arrays":                {`[[[]]]`, 3, true},
		"mixed":                        {`{"a":[{"b":[]}],"c":1}`, 4, true},
		"out-of-range number is fine":  {`{"a":1e400}`, 1, true},
		"truncated":                    {`{"a":`, 0, false},
		"trailing garbage":             {`{} x`, 0, false},
		"unbalanced closing delimiter": {`{"a":1}}`, 0, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			depth, ok := jsonDepth([]byte(tc.raw))
			if depth != tc.depth || ok != tc.ok {
				t.Fatalf("jsonDepth = (%d, %v), want (%d, %v)", depth, ok, tc.depth, tc.ok)
			}
		})
	}
}

// TestUnusableToolsDoNotFailTheCrawl is the regression test for the review's
// crawl-poisoning finding. Each decoy used to pass the crawler and then make
// the catalog refuse the whole crawl, so the changed digest of the approved
// tool next to it was never recorded. Now the decoy is reported as unusable,
// the approved tool's new definition is reported as usable, and the crawl is
// complete, in every response framing.
func TestUnusableToolsDoNotFailTheCrawl(t *testing.T) {
	const echo = `{"name":"echo","description":"changed upstream"}`
	decoys := map[string]vetCase{
		"number overflow":        {`{"name":"decoy","x":1e400}`, "decoy", ReasonNotCanonical},
		"nested duplicate key":   {`{"name":"decoy","s":{"k":1,"k":2}}`, "decoy", ReasonNotCanonical},
		"lone surrogate value":   {`{"name":"decoy","d":"` + jsonEscape(loneHighSurrogate) + `"}`, "decoy", ReasonNotCanonical},
		"lone surrogate in name": {`{"name":"decoy` + jsonEscape(loneHighSurrogate) + `"}`, "", ReasonInvalidName},
		"zero-width space name":  {`{"name":"decoy` + jsonEscape(zeroWidthSpace) + `"}`, "", ReasonInvalidName},
		"bare string":            {`"decoy"`, "", ReasonUnreadable},
		"too deep":               {nested(maxToolDepth), "a", ReasonTooDeep},
	}
	for modeName, mode := range allModes {
		for name, d := range decoys {
			t.Run(modeName+"/"+name, func(t *testing.T) {
				page := `{"tools":[` + echo + `,` + d.raw + `]}`
				f := newFake(t, mode, func(int, string) string { return page })
				res, err := ListTools(context.Background(), f.url(), testOptions())
				if err != nil {
					t.Fatalf("one unusable tool failed the crawl: %v", err)
				}
				if len(res.Tools) != 1 || res.Tools[0].Name != "echo" || string(res.Tools[0].Raw) != echo {
					t.Fatalf("usable tools = %+v, want only echo as sent", res.Tools)
				}
				if _, err := gate.Digest(res.Tools[0].Raw); err != nil {
					t.Errorf("the usable tool has no digest: %v", err)
				}
				if len(res.Unusable) != 1 {
					t.Fatalf("unusable = %+v, want exactly the decoy", res.Unusable)
				}
				if u := res.Unusable[0]; u.Name != d.wantName || u.Reason != d.wantReason || string(u.Raw) != d.raw {
					t.Errorf("unusable = (%q, %q, %s), want (%q, %q, the bytes sent)", u.Name, u.Reason, u.Raw, d.wantName, d.wantReason)
				}
			})
		}
	}
}

// TestRepeatedNamesMakeEveryCopyUnusable replaces the old ErrDuplicateTool
// semantics: a repeated name no longer fails the crawl, it marks every copy
// unusable (a gateway may route a call to any of them), while the other tools
// stay usable.
func TestRepeatedNamesMakeEveryCopyUnusable(t *testing.T) {
	spoiled := `{"name":"tool1","x":1e400}`
	cases := map[string]func(int, string) string{
		"within a page": func(int, string) string {
			return fmt.Sprintf(`{"tools":[%s,%s,%s]}`, toolJSON(0), toolJSON(1), toolJSON(1))
		},
		"across pages": func(call int, _ string) string {
			if call == 1 {
				return fmt.Sprintf(`{"tools":[%s,%s],"nextCursor":"c1"}`, toolJSON(0), toolJSON(1))
			}
			return fmt.Sprintf(`{"tools":[%s]}`, toolJSON(1))
		},
		"one copy is unusable on its own": func(int, string) string {
			return fmt.Sprintf(`{"tools":[%s,%s,%s]}`, spoiled, toolJSON(0), toolJSON(1))
		},
	}
	for name, page := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFake(t, modeJSON, page)
			res, err := ListTools(context.Background(), f.url(), testOptions())
			if err != nil {
				t.Fatalf("a repeated name failed the crawl: %v", err)
			}
			if len(res.Tools) != 1 || res.Tools[0].Name != "tool0" {
				t.Fatalf("usable tools = %+v, want only tool0", res.Tools)
			}
			if len(res.Unusable) != 2 {
				t.Fatalf("unusable = %+v, want both copies of tool1", res.Unusable)
			}
			for i, u := range res.Unusable {
				if u.Name != "tool1" || u.Reason != ReasonDuplicateName {
					t.Errorf("copy %d = (%q, %q), want (tool1, duplicate-name)", i, u.Name, u.Reason)
				}
			}
		})
	}
}

// FuzzVetTool checks that no input breaks the agreement invariants or panics.
func FuzzVetTool(f *testing.F) {
	for _, tc := range vetCases(f) {
		if len(tc.raw) < 4096 {
			f.Add([]byte(tc.raw))
		}
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		name, reason, _ := vetTool(raw, defaultMaxToolBytes)
		assertVetInvariants(t, raw, name, reason)
	})
}

// TestUnusableDetailsNameTheRuleWithoutUpstreamBytes: the detail must let an
// operator see what was wrong (the code point, the size, the count) while the
// canary planted in the definition never reaches it. The name itself is
// upstream text and may appear only when it passed the shared rule.
func TestUnusableDetailsNameTheRuleWithoutUpstreamBytes(t *testing.T) {
	const canary = "CANARY-7f3a"
	deep := `{"name":"` + canary + `","x":` + strings.Repeat("[", maxToolDepth) + strings.Repeat("]", maxToolDepth) + `}`
	cases := map[string]struct {
		page       string
		wantReason Reason
		wantDetail string // a fragment the detail must carry
	}{
		"invisible rune in the name": {`{"tools":[{"name":"` + canary + jsonEscape(zeroWidthSpace) + `"}]}`, ReasonInvalidName, "U+200B"},
		"name too long":              {`{"tools":[{"name":"` + canary + strings.Repeat("n", toolname.MaxBytes) + `"}]}`, ReasonInvalidName, "longer than 256 bytes"},
		"lone surrogate in the name": {`{"tools":[{"name":"` + canary + jsonEscape(loneHighSurrogate) + `"}]}`, ReasonInvalidName, "lone surrogate"},
		"no string name":             {`{"tools":[{"name":5,"d":"` + canary + `"}]}`, ReasonUnreadable, "no string name"},
		"ambiguous keys":             {`{"tools":[{"name":"a","Name":"` + canary + `"}]}`, ReasonUnreadable, "ambiguous keys"},
		"bare string":                {`{"tools":["` + canary + `"]}`, ReasonUnreadable, "not a valid JSON object"},
		"too deep":                   {`{"tools":[` + deep + `]}`, ReasonTooDeep, fmt.Sprintf("nests %d levels, the cap is %d", maxToolDepth+1, maxToolDepth)},
		"not canonical":              {`{"tools":[{"name":"` + canary + `","n":1e400}]}`, ReasonNotCanonical, "RFC 8785"},
		"listed twice":               {`{"tools":[{"name":"` + canary + `"},{"name":"` + canary + `"}]}`, ReasonDuplicateName, "listed 2 times"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFake(t, modeJSON, func(int, string) string { return tc.page })
			res, err := ListTools(context.Background(), f.url(), testOptions())
			if err != nil || len(res.Unusable) == 0 {
				t.Fatalf("unusable=%d err=%v", len(res.Unusable), err)
			}
			u := res.Unusable[0]
			if u.Reason != tc.wantReason || !strings.Contains(u.Detail, tc.wantDetail) {
				t.Errorf("got (%q, %q), want reason %q with detail containing %q", u.Reason, u.Detail, tc.wantReason, tc.wantDetail)
			}
			if strings.Contains(u.Detail, canary) || strings.ContainsRune(u.Detail, rune(zeroWidthSpace)) {
				t.Errorf("detail %q carries upstream bytes", u.Detail)
			}
		})
	}
	t.Run("too large", func(t *testing.T) {
		f := newFake(t, modeJSON, func(int, string) string { return `{"tools":[` + toolOfSize(t, "big", 301, `"c":"`+canary+`",`) + `]}` })
		opt := testOptions()
		opt.MaxToolBytes = 300
		res, err := ListTools(context.Background(), f.url(), opt)
		if err != nil || len(res.Unusable) != 1 {
			t.Fatalf("unusable=%d err=%v", len(res.Unusable), err)
		}
		if u := res.Unusable[0]; u.Reason != ReasonTooLarge || u.Detail != "301 bytes, the cap is 300" {
			t.Errorf("got (%q, %q)", u.Reason, u.Detail)
		}
	})
}
