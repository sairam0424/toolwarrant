package drift

import (
	"reflect"
	"testing"
	"unicode/utf8"

	"github.com/sairam0424/toolwarrant/internal/textdiff"
)

// failer is what checkReport needs from testing.T and rapid.T alike.
type failer interface {
	Helper()
	Fatalf(format string, args ...any)
}

// checkReport fails on a report that could not be printed as it is or whose
// findings are not in the order the package promises.
func checkReport(t failer, r Report) {
	t.Helper()
	for i, f := range r.Findings {
		for _, s := range []string{f.Path, f.Detail} {
			if !utf8.ValidString(s) {
				t.Fatalf("finding %d: not valid UTF-8: %q", i, s)
			}
			for j := 0; j < len(s); j++ {
				if s[j] < 0x20 || s[j] == 0x7F {
					t.Fatalf("finding %d: raw control byte 0x%02X in %q", i, s[j], s)
				}
			}
			if sus := textdiff.Findings(s); len(sus) != 0 {
				t.Fatalf("finding %d: suspicious rune %+v in %q", i, sus[0], s)
			}
		}
		if f.Severity != f.Kind.Severity() || f.Path == "" {
			t.Fatalf("finding %d is malformed: %+v", i, f)
		}
		if i > 0 {
			a := r.Findings[i-1]
			if a.Severity < f.Severity || (a.Severity == f.Severity && a.Path > f.Path) {
				t.Fatalf("findings out of order at %d: %+v before %+v", i, a, f)
			}
		}
	}
}

// checkDifferImpliesFinding pins the promise that two documents the classifier
// reads as different never grade none and two it reads as equal never carry a
// finding: the decoded values (numbers as their text, as Compare reads them)
// are equal exactly when the report is empty.
func checkDifferImpliesFinding(t failer, from, to []byte, r Report) {
	t.Helper()
	fromDoc, err := decodeObject(from)
	if err != nil {
		t.Fatalf("from document: %v", err)
	}
	toDoc, err := decodeObject(to)
	if err != nil {
		t.Fatalf("to document: %v", err)
	}
	if equal := reflect.DeepEqual(fromDoc, toDoc); equal != (len(r.Findings) == 0) {
		t.Fatalf("documents equal: %v, findings: %+v", equal, r.Findings)
	}
}

func FuzzCompare(f *testing.F) {
	f.Add([]byte(baseTool), []byte(baseTool))
	f.Add([]byte(baseTool), []byte(`{"name":"move","inputSchema":{"properties":{"path":{"type":"integer"}},"required":["path","x"]}}`))
	f.Add([]byte(`{"annotations":{"readOnlyHint":true}}`), []byte(`{"annotations":{"readOnlyHint":"yes"},"_meta":{"ui":1}}`))
	f.Add([]byte(`{"inputSchema":true}`), []byte(`{"inputSchema":{"properties":[],"required":"x"}}`))
	f.Add([]byte(`{}`), []byte(`[]`))
	f.Add([]byte(`{"a\u200b":1}`), []byte("{\"a\":\"\xff\"}"))
	f.Add([]byte(`{} {}`), []byte(``))
	f.Fuzz(func(t *testing.T, from, to []byte) {
		r, err := Compare(from, to)
		if err != nil {
			if len(r.Findings) != 0 {
				t.Fatalf("findings alongside error %v", err)
			}
			if msg := err.Error(); !utf8.ValidString(msg) || len(textdiff.Findings(msg)) != 0 {
				t.Fatalf("error message is not printable: %q", msg)
			}
			return
		}
		checkReport(t, r)
		checkDifferImpliesFinding(t, from, to, r)
		same, err := Compare(from, from)
		if err != nil || len(same.Findings) != 0 {
			t.Fatalf("Compare(x, x) = %+v, %v", same.Findings, err)
		}
		if back, err := Compare(to, from); err != nil || len(back.Findings) != len(r.Findings) {
			t.Fatalf("reverse direction has %d findings, forward %d (%v)", len(back.Findings), len(r.Findings), err)
		}
	})
}
