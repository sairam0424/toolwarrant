package gate

// Exactness of numbers under RFC 8785. The canonical form writes every number
// as the ES6 shortest rendering of the nearest IEEE 754 double, so a token
// survives canonicalisation only if that rendering denotes the same decimal
// value as the token did. Tokens that do not (an integer beyond 2^53, a value
// below the smallest double, a decimal with more digits than a double holds)
// would let two different definitions share a digest; they are refused.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"

	"github.com/gowebpki/jcs"
)

// checkNumbers walks every number token of a syntactically valid JSON document
// and returns ErrNumberPrecision for the first one whose RFC 8785 canonical
// form denotes a different value. Strings are skipped: a number spelled inside
// a string is text and is hashed as such.
func checkNumbers(doc []byte) error {
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("gate: read tool definition: %w", err)
		}
		if n, ok := tok.(json.Number); ok && !numberIsExact(string(n)) {
			return ErrNumberPrecision
		}
	}
}

// numberIsExact reports whether tok, a JSON number token, denotes exactly the
// value of its RFC 8785 canonical form.
func numberIsExact(tok string) bool {
	f, err := strconv.ParseFloat(tok, 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return false
	}
	canon, err := jcs.NumberToJSON(f)
	if err != nil {
		return false
	}
	a, okA := decimalOf(tok)
	b, okB := decimalOf(canon)
	return okA && okB && a == b
}

// decimal is the exact value of a JSON number token in normal form: the
// significant digits without leading or trailing zeros, times ten to the power
// exp, with a sign. Zero is the zero value whatever its sign or spelling, so
// "-0", "0.000" and "0e9" compare equal to "0".
type decimal struct {
	negative bool
	digits   string
	exp      int
}

// decimalOf normalises a token that follows the RFC 8259 number grammar. It
// reads the exponent only after the mantissa turned out to be non-zero, so a
// huge exponent on a zero mantissa is still exactly zero and a huge exponent
// on anything else is reported as inexact rather than parsed into a value.
func decimalOf(tok string) (decimal, bool) {
	rest, negative := strings.CutPrefix(tok, "-")
	mantissa, expPart, hasExp := cutExponent(rest)
	intPart, frac, _ := strings.Cut(mantissa, ".")
	digits := strings.TrimLeft(intPart+frac, "0")
	if !isDigits(intPart) || !isDigits(frac) {
		return decimal{}, false
	}
	trimmed := strings.TrimRight(digits, "0")
	if trimmed == "" {
		return decimal{}, true
	}
	exp := len(digits) - len(trimmed) - len(frac)
	if hasExp {
		e, err := strconv.Atoi(expPart)
		if err != nil {
			return decimal{}, false
		}
		exp += e
	}
	return decimal{negative: negative, digits: trimmed, exp: exp}, true
}

// cutExponent splits a mantissa from its exponent at 'e' or 'E'.
func cutExponent(s string) (mantissa, exponent string, found bool) {
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		return s[:i], s[i+1:], true
	}
	return s, "", false
}

// isDigits reports whether s is empty or made of ASCII digits only.
func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
