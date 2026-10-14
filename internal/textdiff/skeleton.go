package textdiff

//go:generate go run gen_confusables.go -in ../../third_party/unicode/confusables.txt -out confusables_table.go

import (
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// maxSwapRunes caps the code points printed on either side of one Swap. The
// count is always complete; a swap that replaces a long run of text is a
// replacement, not a look-alike, and its first code points say so.
const maxSwapRunes = 8

// Skeleton returns the UTS #39 skeleton of s: the string in NFD, every code
// point replaced by its confusable prototype from the vendored table, then
// NFD again. Two strings with the same skeleton look the same to a reader
// (the Cyrillic "а" U+0430 and the Latin "a" U+0061 share one), which is the
// test LookAlike uses. Bytes that are not valid UTF-8 are kept as they are, so
// the function never invents a character; every document Tool handles is
// valid UTF-8 anyway.
//
// The table was generated from confusables.txt version 18.0.0 while the
// toolchain's unicode package knows 17.0.0. The lead is safe: the table maps
// code points to code points without consulting the toolchain's tables, a
// code point the toolchain does not know is still looked up here, reported as
// unassigned by the suspicious-character scan and as script Unknown by
// MixedScriptWords, and nothing in the table is executed.
func Skeleton(s string) string {
	d := norm.NFD.String(s)
	var b strings.Builder
	b.Grow(len(d))
	for i := 0; i < len(d); {
		r, size := utf8.DecodeRuneInString(d[i:])
		if r == utf8.RuneError && size == 1 {
			b.WriteByte(d[i])
		} else if dst, ok := confusableOf(r); ok {
			b.WriteString(dst)
		} else {
			b.WriteString(d[i : i+size])
		}
		i += size
	}
	return norm.NFD.String(b.String())
}

// confusableOf looks r up in the generated table by binary search.
func confusableOf(r rune) (string, bool) {
	i := sort.Search(len(confusables), func(i int) bool { return confusables[i].src >= r })
	if i < len(confusables) && confusables[i].src == r {
		return confusables[i].dst, true
	}
	return "", false
}

// LookAlike reports whether from and to are different strings that read the
// same: their skeletons are equal. Equal strings are not look-alikes, and
// strings whose skeletons differ are an ordinary change the diff shows.
func LookAlike(from, to string) bool {
	return from != to && Skeleton(from) == Skeleton(to)
}

// Swap is one run of code points in the new string that stands where other
// code points stood in the old one, for two strings LookAlike accepts. Offset
// is the byte offset of the run in the new string. Either side may be empty
// when a ligature or a multi-character prototype changed the length.
type Swap struct {
	Offset int
	From   []rune
	To     []rune
}

// String renders the swap for an approver with code points and scripts only,
// never the characters themselves, which would look exactly like the text
// they replaced: "U+0430 (Cyrillic) for U+0061 (Latin) at byte 5".
func (s Swap) String() string {
	return runesWithScripts(s.To) + " for " + runesWithScripts(s.From) + " at byte " + strconv.Itoa(s.Offset)
}

// runesWithScripts renders "U+XXXX U+YYYY (Script, Script)", or "nothing".
func runesWithScripts(rs []rune) string {
	if len(rs) == 0 {
		return "nothing"
	}
	return codePoints(rs, maxSwapRunes) + " (" + strings.Join(scriptNames(rs), ", ") + ")"
}

// codePoints renders up to limit runes as U+XXXX, then counts the rest.
func codePoints(rs []rune, limit int) string {
	var sb strings.Builder
	for i, r := range rs {
		if i == limit {
			sb.WriteString(" +" + strconv.Itoa(len(rs)-limit) + " more")
			break
		}
		if i > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(codePoint(r))
	}
	return sb.String()
}

// scriptNames lists the distinct scripts of rs in byte order of their names.
func scriptNames(rs []rune) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range rs {
		if name := scriptOf(r); !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// swapsBetween aligns the runes of from and to with the diff engine and groups
// every run of differences into one Swap. Bytes that are not valid UTF-8
// decode as U+FFFD here, which only matters for the display.
func swapsBetween(from, to string) []Swap {
	a, b := []rune(from), []rune(to)
	edits := diffSeq(a, b)
	var out []Swap
	toOffset := 0
	for i := 0; i < len(edits); {
		if edits[i].kind == kindEqual {
			toOffset += utf8.RuneLen(b[edits[i].bIdx])
			i++
			continue
		}
		s := Swap{Offset: toOffset}
		for ; i < len(edits) && edits[i].kind != kindEqual; i++ {
			switch edits[i].kind {
			case kindDelete:
				s.From = append(s.From, a[edits[i].aIdx])
			case kindInsert:
				s.To = append(s.To, b[edits[i].bIdx])
				toOffset += utf8.RuneLen(b[edits[i].bIdx])
			}
		}
		out = append(out, s)
	}
	return out
}
