package processor

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncate_NeverSplitsARune(t *testing.T) {
	in := strings.Repeat("é", 300) // 2 bytes each
	out := truncate(in, maxNameBytes)
	if !utf8.ValidString(out) {
		t.Fatalf("truncate produced invalid UTF-8: %q", out)
	}
	if !strings.HasSuffix(out, truncationMark) || len(out) > maxNameBytes+len(truncationMark) {
		t.Fatalf("unexpected truncation: %d bytes", len(out))
	}
	if short := truncate("echo", maxNameBytes); short != "echo" {
		t.Fatalf("short names must be untouched, got %q", short)
	}
}

func TestQuoteNames_CapsTheListAndEscapesEveryName(t *testing.T) {
	names := make([]string, 0, maxLoggedNames+3)
	for i := 0; i < maxLoggedNames+3; i++ {
		names = append(names, "t\n"+strings.Repeat("x", i))
	}
	got := quoteNames(names)
	if strings.ContainsAny(got, "\n\r") {
		t.Errorf("raw newline in %q", got)
	}
	if !strings.HasSuffix(got, "(+3 more)") {
		t.Errorf("missing overflow marker: %q", got)
	}
	if got := quoteErr(nil); got != `""` {
		t.Errorf("quoteErr(nil) = %s", got)
	}
}
