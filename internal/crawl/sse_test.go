package crawl

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"pgregory.net/rapid"
)

// collectSSE runs readSSE over input and returns every event it dispatched.
func collectSSE(r io.Reader, maxEvent int) ([]sseEvent, error) {
	var got []sseEvent
	err := readSSE(r, maxEvent, func(ev sseEvent) (bool, error) {
		got = append(got, ev)
		return false, nil
	})
	return got, err
}

func describe(events []sseEvent) string {
	parts := make([]string, len(events))
	for i, e := range events {
		parts[i] = fmt.Sprintf("%s|%s", e.Event, e.Data)
	}
	return strings.Join(parts, " ;; ")
}

func TestReadSSEFraming(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []sseEvent
	}{
		{"single event", "data: hello\n\n", []sseEvent{{Data: []byte("hello")}}},
		{"no space after colon", "data:hello\n\n", []sseEvent{{Data: []byte("hello")}}},
		{"only one leading space is stripped", "data:  two\n\n", []sseEvent{{Data: []byte(" two")}}},
		{"multi-line data joins with LF", "data: a\ndata: b\ndata: c\n\n", []sseEvent{{Data: []byte("a\nb\nc")}}},
		{"empty data line keeps its place", "data: a\ndata:\ndata: c\n\n", []sseEvent{{Data: []byte("a\n\nc")}}},
		{"data field with no colon", "data\n\n", []sseEvent{{Data: []byte{}}}},
		{"CRLF", "data: a\r\ndata: b\r\n\r\n", []sseEvent{{Data: []byte("a\nb")}}},
		{"lone CR", "data: a\rdata: b\r\r", []sseEvent{{Data: []byte("a\nb")}}},
		{"mixed endings", "data: a\r\ndata: b\rdata: c\n\r\n", []sseEvent{{Data: []byte("a\nb\nc")}}},
		{"comments are ignored", ": hi\ndata: x\n: there\n\n", []sseEvent{{Data: []byte("x")}}},
		{"comment-only block dispatches nothing", ": keepalive\n\n", nil},
		{"event type", "event: message\ndata: x\n\n", []sseEvent{{Event: "message", Data: []byte("x")}}},
		{"other fields ignored", "id: 5\nretry: 10\nfoo: bar\ndata: x\n\n", []sseEvent{{Data: []byte("x")}}},
		{"event without data is not dispatched", "event: ping\n\n", nil},
		{"state resets between events", "event: a\ndata: 1\n\ndata: 2\n\n", []sseEvent{{Event: "a", Data: []byte("1")}, {Data: []byte("2")}}},
		{"extra blank lines", "\n\n\ndata: x\n\n\n\n", []sseEvent{{Data: []byte("x")}}},
		{"byte order mark", "\xEF\xBB\xBFdata: x\n\n", []sseEvent{{Data: []byte("x")}}},
		{"open event is dispatched at EOF", "data: x", []sseEvent{{Data: []byte("x")}}},
		{"open event after CR at EOF", "data: x\r", []sseEvent{{Data: []byte("x")}}},
		{"colon inside value", "data: a:b:c\n\n", []sseEvent{{Data: []byte("a:b:c")}}},
		{"U+2028 is not a line break", "data: a\u2028b\n\n", []sseEvent{{Data: []byte("a\u2028b")}}},
		{"empty input", "", nil},
	}
	for _, tc := range cases {
		for _, reader := range []struct {
			name string
			wrap func(io.Reader) io.Reader
		}{
			{"whole", func(r io.Reader) io.Reader { return r }},
			{"one byte at a time", iotest.OneByteReader},
			{"data with EOF", iotest.DataErrReader},
		} {
			t.Run(tc.name+"/"+reader.name, func(t *testing.T) {
				got, err := collectSSE(reader.wrap(strings.NewReader(tc.input)), 1024)
				if err != nil {
					t.Fatalf("readSSE: %v", err)
				}
				if describe(got) != describe(tc.want) {
					t.Errorf("events = %q, want %q", describe(got), describe(tc.want))
				}
			})
		}
	}
}

func TestReadSSEStopsEarly(t *testing.T) {
	input := "data: one\n\ndata: two\n\nthis is \x00 not even checked"
	var seen []string
	err := readSSE(strings.NewReader(input), 1024, func(ev sseEvent) (bool, error) {
		seen = append(seen, string(ev.Data))
		return len(seen) == 1, nil
	})
	if err != nil || len(seen) != 1 || seen[0] != "one" {
		t.Fatalf("seen=%v err=%v, want only the first event and no error", seen, err)
	}
}

func TestReadSSEHandlerErrorStops(t *testing.T) {
	boom := errors.New("boom")
	calls := 0
	err := readSSE(strings.NewReader("data: 1\n\ndata: 2\n\n"), 1024, func(sseEvent) (bool, error) {
		calls++
		return false, boom
	})
	if !errors.Is(err, boom) || calls != 1 {
		t.Fatalf("err=%v calls=%d, want boom after one call", err, calls)
	}
}

func TestReadSSEHandlerErrorAtEOF(t *testing.T) {
	boom := errors.New("boom")
	err := readSSE(strings.NewReader("data: open"), 1024, func(sseEvent) (bool, error) { return false, boom })
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the handler's error for the event open at EOF", err)
	}
}

func TestReadSSESizeCaps(t *testing.T) {
	const maxEvent = 10
	ok := map[string]string{
		"exactly the cap":             "data: " + strings.Repeat("x", maxEvent) + "\n\n",
		"two lines, newline counted":  "data: " + strings.Repeat("x", 4) + "\ndata: " + strings.Repeat("y", 5) + "\n\n",
		"long comment within slack":   ": " + strings.Repeat("c", maxEvent) + "\ndata: x\n\n",
		"many small events":           strings.Repeat("data: 0123456789\n\n", 50),
		"cap is per event, not total": "data: 0123456789\n\ndata: 0123456789\n\n",
	}
	for name, in := range ok {
		if _, err := collectSSE(strings.NewReader(in), maxEvent); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	tooBig := map[string]string{
		"one over the cap":           "data: " + strings.Repeat("x", maxEvent+1) + "\n\n",
		"two lines, newline counted": "data: " + strings.Repeat("x", 5) + "\ndata: " + strings.Repeat("y", 5) + "\n\n",
		"line far over the cap":      "data: " + strings.Repeat("x", 10000) + "\n\n",
		"comment far over the cap":   ": " + strings.Repeat("x", 10000) + "\n\n",
		"no line break at all":       strings.Repeat("x", 10000),
	}
	for name, in := range tooBig {
		if _, err := collectSSE(strings.NewReader(in), maxEvent); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: err = %v, want ErrMalformed", name, err)
		}
	}
}

func TestReadSSEReaderError(t *testing.T) {
	boom := errors.New("connection reset")
	r := io.MultiReader(strings.NewReader("data: partial"), iotest.ErrReader(boom))
	_, err := collectSSE(r, 1024)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the reader's error", err)
	}
}

// TestReadSSERoundTrip is a property test: whatever events are written with
// whatever line endings, they are read back unchanged.
func TestReadSSERoundTrip(t *testing.T) {
	line := rapid.StringMatching(`[a-zA-Z0-9 :;,.{}"é\x{2028}-]{0,16}`)
	type genEvent struct {
		Named  bool
		Lines  []string
		Prefix bool
	}
	eventGen := rapid.Custom(func(t *rapid.T) genEvent {
		return genEvent{
			Named:  rapid.Bool().Draw(t, "named"),
			Lines:  rapid.SliceOfN(line, 1, 4).Draw(t, "lines"),
			Prefix: rapid.Bool().Draw(t, "comment first"),
		}
	})
	rapid.Check(t, func(t *rapid.T) {
		events := rapid.SliceOfN(eventGen, 0, 6).Draw(t, "events")
		eol := rapid.SampledFrom([]string{"\n", "\r\n", "\r"}).Draw(t, "eol")
		var b strings.Builder
		var want []sseEvent
		for _, e := range events {
			if e.Prefix {
				b.WriteString(": note" + eol)
			}
			ev := sseEvent{Data: []byte(strings.Join(e.Lines, "\n"))}
			if e.Named {
				b.WriteString("event: message" + eol)
				ev.Event = "message"
			}
			for _, l := range e.Lines {
				b.WriteString("data: " + l + eol)
			}
			b.WriteString(eol)
			want = append(want, ev)
		}
		for _, wrap := range []func(io.Reader) io.Reader{func(r io.Reader) io.Reader { return r }, iotest.OneByteReader} {
			got, err := collectSSE(wrap(strings.NewReader(b.String())), 4096)
			if err != nil {
				t.Fatalf("readSSE(%q): %v", b.String(), err)
			}
			if describe(got) != describe(want) {
				t.Fatalf("input %q\n got: %q\nwant: %q", b.String(), describe(got), describe(want))
			}
		}
	})
}

// refSSE is a deliberately naive reference parser used to cross-check readSSE.
// ok is false when the input has a line longer than max, which the real
// parser may reject.
func refSSE(input string, max int) (events []sseEvent, ok bool) {
	input = strings.TrimPrefix(input, "\xEF\xBB\xBF")
	input = strings.ReplaceAll(strings.ReplaceAll(input, "\r\n", "\n"), "\r", "\n")
	var cur sseEvent
	hasData := false
	flush := func() {
		if hasData {
			events = append(events, cur)
		}
		cur, hasData = sseEvent{}, false
	}
	for _, line := range strings.Split(input, "\n") {
		if len(line) > max {
			return nil, false
		}
		switch {
		case line == "":
			flush()
		case line[0] == ':':
		default:
			field, value, _ := strings.Cut(line, ":")
			value = strings.TrimPrefix(value, " ")
			switch field {
			case "data":
				if hasData {
					cur.Data = append(cur.Data, '\n')
				}
				cur.Data = append(cur.Data, value...)
				hasData = true
			case "event":
				cur.Event = value
			}
		}
	}
	flush()
	return events, true
}

const fuzzMaxEvent = 64

// checkSSEAgainstReference is the body of the fuzz target, kept as a plain
// function so unit tests can call it too.
func checkSSEAgainstReference(t testing.TB, data []byte) {
	t.Helper()
	got, err := collectSSE(bytes.NewReader(data), fuzzMaxEvent)
	gotSlow, errSlow := collectSSE(iotest.OneByteReader(bytes.NewReader(data)), fuzzMaxEvent)
	if (err == nil) != (errSlow == nil) || describe(got) != describe(gotSlow) {
		t.Fatalf("result depends on read sizes for %q:\nwhole: %q %v\nbytes: %q %v", data, describe(got), err, describe(gotSlow), errSlow)
	}
	for _, ev := range got {
		if len(ev.Data) > fuzzMaxEvent {
			t.Fatalf("event of %d bytes exceeds the cap for %q", len(ev.Data), data)
		}
	}
	if err != nil {
		if !errors.Is(err, ErrMalformed) {
			t.Fatalf("unexpected error type %v for %q", err, data)
		}
		return
	}
	want, ok := refSSE(string(data), fuzzMaxEvent)
	if ok && describe(got) != describe(want) {
		t.Fatalf("input %q\n got: %q\nwant: %q", data, describe(got), describe(want))
	}
}

func FuzzReadSSE(f *testing.F) {
	for _, seed := range []string{
		"data: hello\n\n",
		"event: message\r\ndata: a\r\ndata: b\r\n\r\n",
		": comment\r\rdata: x\r\r",
		"\xEF\xBB\xBFdata: x\n\n",
		"data\n\ndata:\n\n",
		"id: 1\nretry: 5\nfoo\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n",
		"data: " + strings.Repeat("x", 200) + "\n\n",
		"\r",
		"\r\r\r\n\n",
		"data:x\rdata:y",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		checkSSEAgainstReference(t, data)
	})
}

func TestReadSSEAgainstReferenceOnTrickyInputs(t *testing.T) {
	for _, in := range []string{
		"", "\r", "\n", "\r\n", "\r\r", "\n\r", "data", "data:", "data: ", ":", "::", "data: a\r\r\ndata: b\n\n",
		"\xEF\xBB\xBF", "\xEF\xBB\xBF\xEF\xBB\xBFdata: x\n\n", "event\ndata: x\n\n", "data: \xff\xfe\n\n",
	} {
		checkSSEAgainstReference(t, []byte(in))
	}
}
