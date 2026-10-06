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
		{" ‮", "\"\\u2028\\u202e\""},
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

func TestToolNameLengthBoundary(t *testing.T) {
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
