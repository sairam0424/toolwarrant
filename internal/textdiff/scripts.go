package textdiff

import (
	"sort"
	"strings"
	"sync"
	"unicode"
)

// Script names as the stdlib unicode.Scripts map spells them. Common and
// Inherited carry no script of their own (digits, punctuation, combining
// marks) and are ignored when a word's scripts are counted; Unknown is the
// name given here to a code point in none of the toolchain's script tables,
// such as one assigned after the toolchain's Unicode version or private use.
const (
	scriptCommon    = "Common"
	scriptInherited = "Inherited"
	scriptUnknown   = "Unknown"
	scriptLatin     = "Latin"
	scriptHan       = "Han"
	scriptHiragana  = "Hiragana"
	scriptKatakana  = "Katakana"
	scriptHangul    = "Hangul"
	scriptBopomofo  = "Bopomofo"
)

// maxScriptRunes caps the code points listed per script of a mixed word; the
// counts are always complete.
const maxScriptRunes = 8

// scriptRange is one run of consecutive code points of one script.
type scriptRange struct {
	lo, hi rune
	script string
}

// scriptIndex is every range of unicode.Scripts flattened into one sorted
// slice, strided ranges expanded, so a code point's script is one binary
// search instead of a walk over 170 tables. It is built once and never
// written again, so it is shared immutable data rather than mutable state.
type scriptIndex struct{ ranges []scriptRange }

var (
	scriptsOnce sync.Once
	scripts     scriptIndex
)

func scriptTable() *scriptIndex {
	scriptsOnce.Do(func() { scripts = buildScriptIndex() })
	return &scripts
}

func buildScriptIndex() scriptIndex {
	var ranges []scriptRange
	add := func(lo, hi, stride rune, name string) {
		if stride == 1 {
			ranges = append(ranges, scriptRange{lo, hi, name})
			return
		}
		for c := lo; c <= hi; c += stride {
			ranges = append(ranges, scriptRange{c, c, name})
		}
	}
	for name, t := range unicode.Scripts {
		for _, r := range t.R16 {
			add(rune(r.Lo), rune(r.Hi), rune(r.Stride), name)
		}
		for _, r := range t.R32 {
			add(rune(r.Lo), rune(r.Hi), rune(r.Stride), name)
		}
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].lo < ranges[j].lo })
	return scriptIndex{ranges: ranges}
}

// scriptOf names the script of r, or Unknown when no table of the toolchain's
// unicode package lists it.
func scriptOf(r rune) string {
	rs := scriptTable().ranges
	i := sort.Search(len(rs), func(i int) bool { return rs[i].lo > r }) - 1
	if i >= 0 && r <= rs[i].hi {
		return rs[i].script
	}
	return scriptUnknown
}

// ScriptRunes lists the code points of one script found in a word, in the
// order they appear.
type ScriptRunes struct {
	Script string
	Runes  []rune
}

// MixedWord is one whitespace-delimited word whose scripts UTS #39's Highly
// Restrictive profile does not allow together. Offset is the byte offset of
// the word in the string; Scripts holds every script of the word (Common and
// Inherited left out), the one with the fewest code points first, since that
// is usually the intruder.
type MixedWord struct {
	Offset  int
	Scripts []ScriptRunes
}

// Detail renders the word for an approver as scripts and code points only,
// never as the characters, which is what the rule exists to see through:
// "Cyrillic (U+0430) with Latin (U+0070 U+0074 U+0068)".
func (w MixedWord) Detail() string {
	parts := make([]string, 0, len(w.Scripts))
	for _, s := range w.Scripts {
		parts = append(parts, s.Script+" ("+codePoints(s.Runes, maxScriptRunes)+")")
	}
	return strings.Join(parts, " with ")
}

// MixedScriptWords splits s on whitespace and reports every word whose set of
// scripts, ignoring Common and Inherited, is neither one script nor one of
// the combinations the UTS #39 Highly Restrictive profile allows: Latin with
// Han, Hiragana and Katakana (Japanese), Latin with Han and Hangul (Korean),
// Latin with Han and Bopomofo (Chinese). A Latin acronym inside Japanese or
// Korean text therefore passes; a Cyrillic letter inside a Latin word does
// not. Scripts come from the toolchain's unicode.Scripts tables; a code point
// in none of them counts as the script Unknown.
func MixedScriptWords(s string) []MixedWord {
	var out []MixedWord
	for _, tok := range tokenizeOffsets(s) {
		if found := wordScripts(tok.text); len(found) > 0 && !highlyRestrictive(found) {
			sort.SliceStable(found, func(i, j int) bool {
				if len(found[i].Runes) != len(found[j].Runes) {
					return len(found[i].Runes) < len(found[j].Runes)
				}
				return found[i].Script < found[j].Script
			})
			out = append(out, MixedWord{Offset: tok.offset, Scripts: found})
		}
	}
	return out
}

// token is one non-whitespace run of a string with its byte offset.
type token struct {
	text   string
	offset int
}

// tokenizeOffsets returns the non-whitespace runs of s with their offsets.
// tokenize alternates whitespace and non-whitespace runs, so a run is one or
// the other.
func tokenizeOffsets(s string) []token {
	var out []token
	offset := 0
	for _, t := range tokenize(s) {
		if !isAllSpace(t) {
			out = append(out, token{text: t, offset: offset})
		}
		offset += len(t)
	}
	return out
}

// isAllSpace reports a whitespace run; a byte that is not valid UTF-8 is not
// whitespace.
func isAllSpace(t string) bool {
	for _, r := range t {
		if !unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

// wordScripts groups the code points of one word by script, Common and
// Inherited left out, in order of first appearance.
func wordScripts(word string) []ScriptRunes {
	var found []ScriptRunes
	index := map[string]int{}
	for _, r := range word {
		name := scriptOf(r)
		if name == scriptCommon || name == scriptInherited {
			continue
		}
		i, ok := index[name]
		if !ok {
			i = len(found)
			index[name] = i
			found = append(found, ScriptRunes{Script: name})
		}
		found[i].Runes = append(found[i].Runes, r)
	}
	return found
}

// highlyRestrictive reports whether the scripts are one script or a subset of
// one of the three combinations the profile allows.
func highlyRestrictive(found []ScriptRunes) bool {
	if len(found) <= 1 {
		return true
	}
	allowed := [][]string{
		{scriptLatin, scriptHan, scriptHiragana, scriptKatakana},
		{scriptLatin, scriptHan, scriptHangul},
		{scriptLatin, scriptHan, scriptBopomofo},
	}
	for _, combo := range allowed {
		if subsetOf(found, combo) {
			return true
		}
	}
	return false
}

func subsetOf(found []ScriptRunes, combo []string) bool {
	for _, s := range found {
		member := false
		for _, c := range combo {
			member = member || s.Script == c
		}
		if !member {
			return false
		}
	}
	return true
}
