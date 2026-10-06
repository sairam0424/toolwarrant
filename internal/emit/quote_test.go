package emit

import (
	"strings"
	"testing"
)

func TestQuote(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", `""`},
		{"plain", `"plain"`},
		{`a"b`, `"a\"b"`},
		{`a\b`, `"a\\b"`},
		{`\"`, `"\\\""`},
		{"line\nbreak", `"line\u000abreak"`},
		{"nul\x00", `"nul\u0000"`},
		{"del\x7f", `"del\u007f"`},
		{"café", "\"caf\\u00e9\""},
		{" ", `" "`},
		{"\u2028\u202e", "\"\\u2028\\u202e\""},
		{"\U0001F600", `"\U0001f600"`},
		{"bad\xffbyte", "\"bad\\ufffdbyte\""},
		{"a: b # c", `"a: b # c"`},
	}
	for _, tc := range cases {
		if got := quote(tc.in); got != tc.want {
			t.Errorf("quote(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestQuoteOutputIsSingleLinePrintableASCII(t *testing.T) {
	var sb strings.Builder
	for r := rune(0); r < 0x300; r++ {
		sb.WriteRune(r)
	}
	got := quote(sb.String())
	if !isPrintableASCII(got) || strings.ContainsAny(got, "\n\r") {
		t.Errorf("quote produced raw control or non-ASCII bytes")
	}
}

func TestIsPrintableASCII(t *testing.T) {
	for s, want := range map[string]bool{
		"": true, " ": true, "~": true, "a\x7f": false, "a\x1f": false, "café": false, "\n": false,
	} {
		if got := isPrintableASCII(s); got != want {
			t.Errorf("isPrintableASCII(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestClassifyToolsDoesNotMutateInput(t *testing.T) {
	in := []string{"b", "a", "b"}
	plan := classifyTools("s", in)
	if in[0] != "b" || in[1] != "a" || in[2] != "b" {
		t.Errorf("input mutated: %v", in)
	}
	if len(plan.allowed) != 2 || plan.allowed[0] != "a" || plan.allowed[1] != "b" {
		t.Errorf("allowed = %v", plan.allowed)
	}
}

// TestToolNameLengthBoundary: the cap is the shared rule's, so a name the
// catalog accepted is never too long here.
func TestToolNameLengthBoundary(t *testing.T) {
	if MaxToolNameLen != 256 {
		t.Fatalf("MaxToolNameLen = %d, want the shared rule's 256", MaxToolNameLen)
	}
	ok := strings.Repeat("x", MaxToolNameLen)
	tooLong := ok + "x"
	plan := classifyTools("s", []string{ok, tooLong})
	if len(plan.allowed) != 1 || plan.allowed[0] != ok {
		t.Errorf("allowed = %v", plan.allowed)
	}
	if len(plan.skipped) != 1 || plan.skipped[0].Reason != ReasonNameTooLong {
		t.Errorf("skipped = %v", plan.skipped)
	}
}

// TestSharedRuleThenASCIIRule pins the order of the two name rules: the shared
// rule (internal/toolname) decides validity and reports its own reason; the
// emitter's printable-ASCII requirement only applies to names it accepted.
func TestSharedRuleThenASCIIRule(t *testing.T) {
	cases := map[string]string{
		"Tool Name":                 "",
		strings.Repeat("x", 200):    "",
		"get-user.v2":               "",
		"u\u0308ber":                invalidReason("not in Unicode normalization form C"),
		" a":                        invalidReason("leading or trailing space"),
		"a ":                        invalidReason("leading or trailing space"),
		"a  b":                      invalidReason("consecutive spaces"),
		"a\u200bb":                  invalidReason("contains a control, invisible or non-printing character (U+200B)"),
		"nul\x00":                   invalidReason("contains a control, invisible or non-printing character (U+0000)"),
		"bad\xffbyte":               invalidReason("not valid UTF-8"),
		"café":                      ReasonNotPrintableASCII,
		"über":                      ReasonNotPrintableASCII,
		"日本語":                       ReasonNotPrintableASCII,
		"emoji\U0001F600":           ReasonNotPrintableASCII,
		"":                          ReasonEmptyName,
		strings.Repeat("x", 257):    ReasonNameTooLong,
		strings.Repeat("\x01", 300): ReasonNameTooLong,
	}
	for name, want := range cases {
		if got := unsafeReason(name); got != want {
			t.Errorf("unsafeReason(%q) = %q, want %q", name, got, want)
		}
	}
}

// TestReasonNeverEchoesName: reasons are printed to operators, so a hostile
// name must not ride along in them. Every name carries the marker zqv7, which
// no reason text contains, so a match can only be an echo and never a
// coincidence with the prose (a bare " lead" once matched "leading or
// trailing space").
func TestReasonNeverEchoesName(t *testing.T) {
	const marker = "zqv7"
	names := []string{
		"u\u0308ber" + marker, " lead" + marker, "a\u200bb" + marker, "café" + marker,
		"bad\xffbyte" + marker, "x\x1b[2Jy" + marker, strings.Repeat("z", 300) + marker,
	}
	for _, name := range names {
		reason := unsafeReason(name)
		if reason == "" {
			t.Errorf("%q accepted", name)
			continue
		}
		if strings.Contains(reason, marker) || strings.Contains(reason, name) || !isPrintableASCII(reason) {
			t.Errorf("reason for %q echoes it or is not printable ASCII: %q", name, reason)
		}
	}
}

func TestAllowExpressionNeverEmpty(t *testing.T) {
	if got := allowExpression(nil); got != "false" {
		t.Errorf("allowExpression(nil) = %q", got)
	}
	if got := allowExpression([]string{}); got != "false" {
		t.Errorf("allowExpression(empty) = %q", got)
	}
	want := `mcp.tool.name == "a" || mcp.tool.name == "b"`
	if got := allowExpression([]string{"a", "b"}); got != want {
		t.Errorf("allowExpression = %q, want %q", got, want)
	}
}
