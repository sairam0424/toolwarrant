package textdiff

import (
	"strconv"
	"strings"
)

// maxReportBytes caps the text Tool returns. A hostile definition can make the
// diff many times larger than itself; past this size no person reviews it
// anyway, so the report stops and says so instead of handing a pager hundreds
// of megabytes.
const maxReportBytes = 4 << 20

// report accumulates rendered text. With a limit it stores at most that many
// bytes but keeps counting everything written, so the closing line can state
// how large the full report would have been. Without a limit it is a plain
// buffer.
type report struct {
	buf   strings.Builder
	limit int // 0 means unlimited
	bytes int // every byte written, stored or not
	lines int // every newline written, stored or not
}

func (r *report) writeString(s string) {
	r.bytes += len(s)
	r.lines += strings.Count(s, "\n")
	if r.limit <= 0 {
		r.buf.WriteString(s)
		return
	}
	if room := r.limit - r.buf.Len(); room > 0 {
		r.buf.WriteString(s[:min(len(s), room)])
	}
}

func (r *report) writeByte(c byte) {
	r.bytes++
	if c == '\n' {
		r.lines++
	}
	if r.limit <= 0 || r.buf.Len() < r.limit {
		r.buf.WriteByte(c)
	}
}

// truncated reports whether the limit was exceeded.
func (r *report) truncated() bool {
	return r.limit > 0 && r.bytes > r.limit
}

// String returns the stored text. When the limit was exceeded the text is cut
// at the last complete line and ends with one line that gives the size of the
// full report and tells the approver to refuse the definition.
func (r *report) String() string {
	if !r.truncated() {
		return r.buf.String()
	}
	kept := r.buf.String()
	kept = kept[:strings.LastIndexByte(kept, '\n')+1]
	return kept + "... report truncated at " + strconv.Itoa(r.limit) + " bytes: the full report is " +
		strconv.Itoa(r.bytes) + " bytes in " + strconv.Itoa(r.lines) +
		" lines; a definition too large to review should be refused\n"
}
