package crawl

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
)

const (
	// sseLineSlack is how much longer than the event cap a single line may be,
	// so that the "data: " field name does not count against the payload.
	sseLineSlack = 64
	// sseInitialBuffer is the scanner's starting buffer size.
	sseInitialBuffer = 4 << 10
)

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// sseEvent is one dispatched server-sent event.
type sseEvent struct {
	// Event is the event type, empty when the stream did not name one.
	Event string
	// Data is the event's data lines joined with a newline.
	Data []byte
}

// readSSE parses a text/event-stream from r and calls handle for every event
// that carries data. If handle returns stop=true, or an error, reading ends
// at once; this is how the caller stops at the response it wants without
// draining a stream a server may keep open.
//
// It follows the WHATWG event-stream rules that matter here: lines end in LF,
// CRLF or CR, lines starting with a colon are comments, "data" lines are
// joined with a newline, a blank line dispatches the event, unknown fields
// are ignored, and a leading byte-order mark is dropped. An event still open
// at end of stream is dispatched too: an event that is cut short is almost
// certainly invalid JSON and fails there, and one that parses is complete.
//
// maxEvent caps the data of one event (and, loosely, any one line). Going
// over it is an error, not a truncation.
func readSSE(r io.Reader, maxEvent int, handle func(sseEvent) (stop bool, err error)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, min(sseInitialBuffer, maxEvent+sseLineSlack)), maxEvent+sseLineSlack)
	sc.Split(splitSSELine)

	var (
		cur     sseEvent
		hasData bool
		first   = true
	)
	dispatch := func() (bool, error) {
		defer func() { cur, hasData = sseEvent{}, false }()
		if !hasData {
			return false, nil
		}
		return handle(cur)
	}
	for sc.Scan() {
		line := sc.Bytes()
		if first {
			line, first = bytes.TrimPrefix(line, utf8BOM), false
		}
		if len(line) == 0 {
			if stop, err := dispatch(); stop || err != nil {
				return err
			}
			continue
		}
		if err := applySSELine(&cur, &hasData, line, maxEvent); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return fmt.Errorf("%w: event line longer than %d bytes", ErrMalformed, maxEvent)
		}
		return fmt.Errorf("crawl: read event stream: %w", err)
	}
	_, err := dispatch()
	return err
}

// applySSELine folds one non-empty line into the event being built.
func applySSELine(cur *sseEvent, hasData *bool, line []byte, maxEvent int) error {
	if line[0] == ':' {
		return nil
	}
	field, value, _ := bytes.Cut(line, []byte(":"))
	value = bytes.TrimPrefix(value, []byte(" "))
	switch string(field) {
	case "data":
		extra := len(value)
		if *hasData {
			extra++
		}
		if len(cur.Data)+extra > maxEvent {
			return fmt.Errorf("%w: event data longer than %d bytes", ErrMalformed, maxEvent)
		}
		if *hasData {
			cur.Data = append(cur.Data, '\n')
		}
		cur.Data = append(cur.Data, value...)
		*hasData = true
	case "event":
		cur.Event = string(value)
	}
	return nil
}

// splitSSELine is a bufio.SplitFunc for LF, CRLF and CR line endings. A CR at
// the very end of the buffered data waits for one more byte, because it may
// be the first half of a CRLF.
func splitSSELine(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	i := bytes.IndexAny(data, "\r\n")
	if i < 0 {
		if atEOF {
			return len(data), data, nil
		}
		return 0, nil, nil
	}
	if data[i] == '\n' {
		return i + 1, data[:i], nil
	}
	switch {
	case i+1 < len(data) && data[i+1] == '\n':
		return i + 2, data[:i], nil
	case i+1 < len(data) || atEOF:
		return i + 1, data[:i], nil
	}
	return 0, nil, nil
}
