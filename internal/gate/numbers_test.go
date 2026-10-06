package gate

import (
	"errors"
	"strings"
	"testing"
)

// The fetch reviewer's twins: RFC 8785 canonicalises numbers through float64,
// so these pairs shared a digest and the left member could be served as the
// right one. Under full-v1 the inexact member is refused outright.
func TestCanonicalTool_RejectsNumbersBeyondDoublePrecision(t *testing.T) {
	inexact := map[string]string{
		"big integer 2^53+1":                  `{"name":"a","n":9007199254740993}`,
		"18-digit integer":                    `{"name":"a","n":123456789012345678}`,
		"number underflow 1e-400":             `{"name":"a","n":1e-400}`,
		"tiny underflow":                      `{"name":"a","n":2.4703282292062327e-324}`,
		"RFC 8785 example 333333333.33333329": `{"name":"a","n":333333333.33333329}`,
		"too many fraction digits":            `{"name":"a","n":0.30000000000000004441}`,
		"nested in a schema":                  `{"name":"a","inputSchema":{"properties":{"x":{"maximum":9007199254740993}}}}`,
		"inside an array":                     `{"name":"a","enum":[1,2,9007199254740993]}`,
		"negative beyond 2^53":                `{"name":"a","n":-9007199254740993}`,
		"huge negative exponent":              `{"name":"a","n":1e-99999999999999999999}`,
		"long zero run then a one":            `{"name":"a","n":0.` + strings.Repeat("0", 400) + `1}`,
	}
	for name, raw := range inexact {
		if _, err := CanonicalTool([]byte(raw)); !errors.Is(err, ErrNumberPrecision) {
			t.Errorf("%s: error %v, want ErrNumberPrecision", name, err)
		}
	}
	for name, raw := range map[string]string{
		"number overflow 1e400":  `{"name":"a","n":1e400}`,
		"number overflow -1e400": `{"name":"a","n":-1e400}`,
		"huge exponent":          `{"name":"a","n":1e99999999999999999999}`,
	} {
		if _, err := CanonicalTool([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Numbers whose canonical form denotes the same value are accepted, so real
// schemas keep working: integers up to 2^53, short decimals, exponents,
// alternative spellings of the same value and both zeros.
func TestCanonicalTool_AcceptsExactNumbers(t *testing.T) {
	exact := []string{
		"0", "-0", "0e5", "0.000", "1", "-1", "100000", "9007199254740992", "-9007199254740992",
		"123456789012345680", "100000000000000000000", "1e20", "1e21", "1E30", "0.1", "0.5", "4.50", "2e-3",
		"0.000001", "1e-7", "0.000000000000000000000000001", "5e-324", "1.7976931348623157e308",
		"-1.5", "3.14159", "1.0", "10.0e1", "0e99999999999999999999",
	}
	for _, n := range exact {
		raw := `{"name":"a","n":` + n + `,"s":{"list":[` + n + `]}}`
		if _, err := CanonicalTool([]byte(raw)); err != nil {
			t.Errorf("%s: refused: %v", n, err)
		}
	}
}

// Different spellings of one value must stay one digest; different values must
// stay different digests.
func TestDigest_NumberSpellingsThatDenoteOneValueAgree(t *testing.T) {
	same := [][2]string{
		{"1e20", "100000000000000000000"}, {"4.50", "4.5"}, {"-0", "0"}, {"0e5", "0.0"}, {"2e-3", "0.002"},
		{"1E30", "1e+30"}, {"10.0e1", "100"}, {"123456789012345680", "1.2345678901234568e17"},
	}
	for _, pair := range same {
		a := mustDigest(t, `{"name":"a","n":`+pair[0]+`}`)
		b := mustDigest(t, `{"name":"a","n":`+pair[1]+`}`)
		if a != b {
			t.Errorf("%s and %s denote one value but hash differently", pair[0], pair[1])
		}
	}
	different := [][2]string{{"1", "2"}, {"0.1", "0.2"}, {"1e20", "1e21"}, {"-1", "1"}, {"9007199254740992", "9007199254740990"}}
	for _, pair := range different {
		a := mustDigest(t, `{"name":"a","n":`+pair[0]+`}`)
		b := mustDigest(t, `{"name":"a","n":`+pair[1]+`}`)
		if a == b {
			t.Errorf("%s and %s hash alike", pair[0], pair[1])
		}
	}
}

// A number spelled inside a string is text, not a number, and is never refused.
func TestCanonicalTool_NumbersInsideStringsAreText(t *testing.T) {
	raw := `{"name":"a","d":"9007199254740993 and 1e-400","k9007199254740993":true}`
	if _, err := CanonicalTool([]byte(raw)); err != nil {
		t.Fatalf("refused: %v", err)
	}
}

// decimalOf is the exact comparison behind numberIsExact: equal values give
// equal normal forms, different values do not, and a token whose exponent does
// not fit is reported rather than guessed.
func TestDecimalOf_NormalForm(t *testing.T) {
	equal := [][2]string{
		{"1e20", "100000000000000000000"}, {"4.50", "4.5"}, {"-0", "0"}, {"0e99999999999999999999", "0"},
		{"0.000", "0"}, {"2e-3", "0.002"}, {"1E+30", "1e30"}, {"100", "1e2"}, {"0.10", "1e-1"}, {"-1.50", "-15e-1"},
	}
	for _, pair := range equal {
		a, okA := decimalOf(pair[0])
		b, okB := decimalOf(pair[1])
		if !okA || !okB || a != b {
			t.Errorf("decimalOf(%s)=%+v,%v decimalOf(%s)=%+v,%v, want equal", pair[0], a, okA, pair[1], b, okB)
		}
	}
	different := [][2]string{
		{"9007199254740993", "9007199254740992"}, {"1", "-1"}, {"1e-400", "0"}, {"0.1", "0.01"}, {"1", "10"}, {"1e2", "1e3"},
	}
	for _, pair := range different {
		a, okA := decimalOf(pair[0])
		b, okB := decimalOf(pair[1])
		if !okA || !okB || a == b {
			t.Errorf("decimalOf(%s)=%+v,%v decimalOf(%s)=%+v,%v, want different", pair[0], a, okA, pair[1], b, okB)
		}
	}
	for _, bad := range []string{"1e-99999999999999999999", "1e", "abc", "1.2.3", "1e5.5", "--1", "0x10", "1_000"} {
		if d, ok := decimalOf(bad); ok {
			t.Errorf("decimalOf(%q) = %+v, ok; want a refusal", bad, d)
		}
	}
}

// The walk reports the first inexact number and nothing else about the
// document, and tolerates deep but legal nesting. Syntax is not its job: a
// truncated definition is refused by CanonicalTool before the walk runs.
func TestCheckNumbers_WalksEveryToken(t *testing.T) {
	deep := `{"name":"a","x":` + strings.Repeat("[", 500) + `9007199254740993` + strings.Repeat("]", 500) + `}`
	if err := checkNumbers([]byte(deep)); !errors.Is(err, ErrNumberPrecision) {
		t.Errorf("deep inexact number: %v, want ErrNumberPrecision", err)
	}
	ok := `{"name":"a","x":` + strings.Repeat("[", 500) + `1` + strings.Repeat("]", 500) + `,"y":{"z":[0.5,-2,3e3]}}`
	if err := checkNumbers([]byte(ok)); err != nil {
		t.Errorf("exact numbers refused: %v", err)
	}
	if _, err := CanonicalTool([]byte(`{"name":"a","n":1`)); err == nil {
		t.Error("a truncated definition was accepted")
	}
}
