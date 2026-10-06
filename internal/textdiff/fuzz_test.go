package textdiff

import (
	"encoding/json"
	"testing"
	"unicode/utf8"
)

const maxSeedLen = 10000

// jsonObject builds {"key": "val"}; encoding/json replaces invalid UTF-8 with
// U+FFFD, so the result is always a valid document.
func jsonObject(key, val string) ([]byte, error) {
	return json.Marshal(map[string]string{key: val})
}

func addCorpusSeeds(f *testing.F) {
	for _, tc := range injectionCorpus() {
		if len(tc.input) <= maxSeedLen {
			f.Add(tc.input)
		}
	}
}

func FuzzEscape(f *testing.F) {
	addCorpusSeeds(f)
	f.Fuzz(func(t *testing.T, s string) {
		e := Escape(s)
		assertSafe(t, e)
		back, err := unescape(e, false)
		if err != nil || back != s {
			t.Fatalf("round trip = %q, %v; want %q", back, err, s)
		}
		if countNumericEscapes(e) != len(Findings(s)) {
			t.Fatalf("escapes and findings disagree for %q", s)
		}
		if again := Escape(e); len(again) < len(e) {
			t.Fatalf("second pass shrank the text: %q -> %q", e, again)
		}
	})
}

func FuzzFindings(f *testing.F) {
	addCorpusSeeds(f)
	f.Fuzz(func(t *testing.T, s string) {
		prev := -1
		for _, fd := range Findings(s) {
			if fd.Offset <= prev || fd.Offset >= len(s) || fd.Name == "" || fd.Category == "" {
				t.Fatalf("bad finding %+v in %q", fd, s)
			}
			prev = fd.Offset
			if fd.Category != catInvalidUTF8 {
				if r, _ := utf8.DecodeRuneInString(s[fd.Offset:]); r != fd.Rune {
					t.Fatalf("offset %d holds %U, finding says %U", fd.Offset, r, fd.Rune)
				}
			}
		}
	})
}

func FuzzUnified(f *testing.F) {
	for _, tc := range injectionCorpus() {
		if len(tc.input) <= maxSeedLen {
			f.Add(tc.input, "clean\n"+tc.input)
		}
	}
	f.Add("a\nb\nc", "a\nX\nc")
	f.Add("", "x")
	f.Fuzz(func(t *testing.T, from, to string) {
		out := Unified(from, to, from, to)
		assertSafe(t, out)
		checkApply(t, from, to, out)
	})
}

func FuzzTool(f *testing.F) {
	f.Add([]byte(toolV1), []byte(toolV2))
	f.Add([]byte(`{}`), []byte(`[]`))
	f.Add([]byte(`"a b"`), []byte(`"a  b"`))
	f.Add([]byte(`{"a":{"b":["x",1,null]}}`), []byte(`{"a":{"b":["y"]}}`))
	f.Fuzz(func(t *testing.T, from, to []byte) {
		out, err := Tool("from", "to", from, to)
		if err != nil {
			if out != "" {
				t.Fatalf("output %q alongside error %v", out, err)
			}
			return
		}
		assertSafe(t, out)
	})
}
