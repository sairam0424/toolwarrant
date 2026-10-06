package crawl

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/gate"
)

// fidelityCase is a tool object the fake server sends byte for byte, with the
// RFC 8785 canonical form written out by hand. The hand-written form is the
// independent oracle: it does not pass through gate or the JCS library. The
// cases carry no _meta member on purpose: whether the digest covers _meta is
// gate's decision (D1 makes it part of the digest), and this oracle must not
// depend on it either way. Escaped spellings in the sent form are built with
// jsonEscape so that the source cannot be normalised into the plain spelling.
type fidelityCase struct {
	name      string
	sent      string
	canonical string
}

func fidelityCases() []fidelityCase {
	eAcute, aRing, oDiaeresis := jsonEscape(0xe9), jsonEscape(0xc5), jsonEscape(0xf6)
	grin := jsonEscape(0xd83d) + jsonEscape(0xde00) // U+1F600 as a surrogate pair
	lineSep := string(rune(lineSeparator))
	return []fidelityCase{
		{
			name: "unusual key order, unknown field, escaped unicode, 1e2, 1e19, whitespace",
			sent: `{ "name" : "zeta` + eAcute + `" ,` + "\n\t" +
				`"inputSchema":{"type":"object","properties":{"n":{"type":"number","default":1e2,"maximum":10000000000000000000}}} ,` + "\n" +
				` "x-unknown" : [ 1 , 2.50 , true , null ] ,` +
				`"description":"caf` + eAcute + ` ` + grin + ` <tag>" , "annotations":{"readOnlyHint":true} }`,
			canonical: `{"annotations":{"readOnlyHint":true},"description":"café 😀 <tag>",` +
				`"inputSchema":{"properties":{"n":{"default":100,"maximum":10000000000000000000,"type":"number"}},"type":"object"},` +
				`"name":"zetaé","x-unknown":[1,2.5,true,null]}`,
		},
		{
			name: "reverse key order, exponent forms, raw U+2028, escaped control character",
			sent: `{"inputSchema":{"required":["b","a"],"properties":{"b":{"type":"integer","minimum":1E2},` +
				`"a":{"type":"string","pattern":"^\\d+$"}},"type":"object"},"name":"alpha",` +
				`"title":"` + aRing + `ngstr` + oDiaeresis + `m\t","outputSchema":null,"annotations":{"idempotentHint":false},` +
				`"big":9.007199254740992E15,"ratio":0.000001,"tiny":1e-7,"note":"a` + lineSep + `b"}`,
			canonical: `{"annotations":{"idempotentHint":false},"big":9007199254740992,` +
				`"inputSchema":{"properties":{"a":{"pattern":"^\\d+$","type":"string"},"b":{"minimum":100,"type":"integer"}},` +
				`"required":["b","a"],"type":"object"},"name":"alpha","note":"a` + lineSep + `b",` +
				`"outputSchema":null,"ratio":0.000001,"tiny":1e-7,"title":"Ångström\t"}`,
		},
	}
}

func TestRawBytesAndDigestsSurviveEveryTransport(t *testing.T) {
	cases := fidelityCases()
	sent := make([]string, len(cases))
	for i, c := range cases {
		sent[i] = c.sent
	}
	for modeName, mode := range allModes {
		t.Run(modeName, func(t *testing.T) {
			f := newFake(t, mode, pagesOf(1, sent)) // one tool per page: also crosses pages
			res, err := ListTools(context.Background(), f.url(), testOptions())
			if err != nil {
				t.Fatalf("ListTools: %v", err)
			}
			if len(res.Tools) != len(cases) || len(res.Unusable) != 0 {
				t.Fatalf("got %d tools and %d unusable, want %d and 0", len(res.Tools), len(res.Unusable), len(cases))
			}
			for i, c := range cases {
				assertFidelity(t, c, res.Tools[i])
			}
		})
	}
}

func assertFidelity(t *testing.T, c fidelityCase, got Tool) {
	t.Helper()
	if !bytes.Equal(got.Raw, []byte(c.sent)) {
		t.Fatalf("%s\nRaw differs from the bytes sent\n got: %q\nwant: %q", c.name, got.Raw, c.sent)
	}
	if !bytes.Contains(got.Raw, []byte(jsonEscape(0xe9))) && !bytes.Contains(got.Raw, []byte(jsonEscape(0xc5))) {
		t.Fatalf("%s: the sent form carries no escaped spelling, so the case proves less than it claims", c.name)
	}
	sum := sha256.Sum256([]byte(c.canonical))
	want := hex.EncodeToString(sum[:])
	have, err := gate.Digest(got.Raw)
	if err != nil {
		t.Fatalf("%s: gate.Digest: %v", c.name, err)
	}
	if have != want {
		canon, _ := gate.CanonicalTool(got.Raw)
		t.Errorf("%s\ngate digest %s != independent digest %s\ngate canonical: %s\nhand canonical: %s", c.name, have, want, canon, c.canonical)
	}
	if bytes.Equal(got.Raw, []byte(c.canonical)) {
		t.Errorf("%s: sent form equals canonical form, so the case proves nothing", c.name)
	}
}

// TestDecodingWouldHaveChangedTheBytes documents why the client keeps raw
// bytes: a decode and re-encode through ordinary Go types changes them.
func TestDecodingWouldHaveChangedTheBytes(t *testing.T) {
	for _, c := range fidelityCases() {
		var v map[string]any
		if err := json.Unmarshal([]byte(c.sent), &v); err != nil {
			t.Fatal(err)
		}
		again, _ := json.Marshal(v)
		if bytes.Equal(again, []byte(c.sent)) {
			t.Errorf("%s: a decode/encode round trip preserved the bytes; the fidelity test is too weak", c.name)
		}
	}
}

func TestRawDoesNotAliasOtherTools(t *testing.T) {
	f := newFake(t, modeSSE, pagesOf(3, nTools(3)))
	res, err := ListTools(context.Background(), f.url(), testOptions())
	if err != nil {
		t.Fatal(err)
	}
	for i := range res.Tools[0].Raw { // scribble over the first tool
		res.Tools[0].Raw[i] = '#'
	}
	for i := 1; i < len(res.Tools); i++ {
		if string(res.Tools[i].Raw) != toolJSON(i) {
			t.Errorf("tool %d changed when tool 0 was overwritten", i)
		}
	}
}
