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

func FuzzSkeleton(f *testing.F) {
	addCorpusSeeds(f)
	f.Add("p\u0430th")
	f.Add("m rn \uFB01le 1I| 0O")
	f.Add("\u6771\u4EAC\u306EAPI \uD55C\uAD6DAPI \u3105\u3106API")
	for i := 0; i < len(confusables); i += len(confusables) / 50 {
		f.Add("x" + string(confusables[i].src) + "y")
	}
	f.Fuzz(func(t *testing.T, s string) {
		sk := Skeleton(s)
		if again := Skeleton(sk); again != sk {
			t.Fatalf("Skeleton is not idempotent: %q -> %q -> %q", s, sk, again)
		}
		if utf8.ValidString(s) != utf8.ValidString(sk) {
			t.Fatalf("Skeleton(%q) = %q changed the validity of the text", s, sk)
		}
		if LookAlike(s, s) {
			t.Fatalf("LookAlike(s, s) for %q", s)
		}
		prev := -1
		for _, w := range MixedScriptWords(s) {
			if w.Offset <= prev || w.Offset >= len(s) || len(w.Scripts) < 2 {
				t.Fatalf("bad mixed word %+v in %q", w, s)
			}
			prev = w.Offset
			assertSafe(t, w.Detail())
		}
		for _, sw := range swapsBetween(s, sk) {
			assertSafe(t, sw.String())
		}
	})
}
