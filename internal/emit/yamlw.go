package emit

import "strings"

// yamlWriter is the whole YAML "library": emit indented lines into a buffer.
// It never interprets its input, so callers are responsible for passing only
// fixed keys and values produced by quote. Keeping it this dumb is the point:
// there is no code path that could turn data into structure. It produces the
// body only; seal adds the header and the hash line.
type yamlWriter struct {
	b strings.Builder
}

// line appends s indented by the given number of spaces, then a newline.
func (w *yamlWriter) line(indent int, s string) {
	w.b.WriteString(strings.Repeat(" ", indent))
	w.b.WriteString(s)
	w.b.WriteByte('\n')
}

// bytes returns the accumulated document body.
func (w *yamlWriter) bytes() []byte { return []byte(w.b.String()) }
