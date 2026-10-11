package gate

import "strconv"

// Surrogate escapes. JSON lets a string spell any UTF-16 code unit as \uXXXX,
// so a text that is valid UTF-8 byte for byte can still name a high surrogate
// (D800 to DBFF) without the low half (DC00 to DFFF) that must follow it, a
// low half on its own, or the two halves in the wrong order. No Unicode string
// has such a spelling. encoding/json decodes each such escape as U+FFFD, so a
// definition spelled that way would hash like its U+FFFD twin if it were ever
// re-encoded; the RFC 8785 step refuses it instead, and CanonicalTool reports
// the refusal as ErrNotUTF8 (D1): the bytes are not the encoding of a string.

const (
	// unicodeEscapeLen is the length of one \uXXXX escape.
	unicodeEscapeLen = 6
	highSurrogateMin = 0xD800
	highSurrogateMax = 0xDBFF
	lowSurrogateMin  = 0xDC00
	lowSurrogateMax  = 0xDFFF
)

// hasIllPairedSurrogate reports whether a JSON document carries a \u escape of
// a surrogate that is not a high half immediately followed by an escaped low
// half. It only names the reason for a canonicalisation failure; the RFC 8785
// step stays the authority on what is refused. The document has been read by
// encoding/json already, so every string is terminated and every \u escape has
// its four hex digits, and a raw surrogate cannot occur in valid UTF-8.
func hasIllPairedSurrogate(doc []byte) bool {
	inString := false
	for i := 0; i < len(doc); i++ {
		c := doc[i]
		if !inString {
			inString = c == '"'
			continue
		}
		switch c {
		case '"':
			inString = false
		case '\\':
			skip, ill := checkEscape(doc, i)
			if ill {
				return true
			}
			i += skip
		}
	}
	return false
}

// checkEscape classifies the escape whose backslash is doc[i]. It returns how
// many further bytes the escape occupies, so the caller steps over what it
// escapes, and whether it is a lone or ill-paired surrogate.
func checkEscape(doc []byte, i int) (skip int, ill bool) {
	unit, ok := unicodeEscapeAt(doc, i)
	if !ok {
		return 1, false // \" \\ \/ \b \f \n \r \t: one escaped character
	}
	switch {
	case unit >= highSurrogateMin && unit <= highSurrogateMax:
		low, ok := unicodeEscapeAt(doc, i+unicodeEscapeLen)
		if !ok || low < lowSurrogateMin || low > lowSurrogateMax {
			return 0, true
		}
		return 2*unicodeEscapeLen - 1, false
	case unit >= lowSurrogateMin && unit <= lowSurrogateMax:
		return 0, true
	}
	return unicodeEscapeLen - 1, false
}

// unicodeEscapeAt decodes the \uXXXX escape that starts at doc[i], if there is
// one there.
func unicodeEscapeAt(doc []byte, i int) (uint16, bool) {
	if i+unicodeEscapeLen > len(doc) || doc[i] != '\\' || doc[i+1] != 'u' {
		return 0, false
	}
	v, err := strconv.ParseUint(string(doc[i+2:i+unicodeEscapeLen]), 16, 16)
	if err != nil {
		return 0, false
	}
	return uint16(v), true
}
