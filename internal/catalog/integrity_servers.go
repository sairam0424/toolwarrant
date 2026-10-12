package catalog

import (
	"fmt"
	"maps"
	"slices"

	"github.com/sairam0424/toolwarrant/internal/audit"
)

// The server side of Integrity: the servers table is as mutable as the tools
// table (nothing guards it), and its columns decide whether a server is
// crawled and served at all (paused), where the crawler connects (url) and
// whether it may reach private addresses (allow_private). The log records
// each of them: server.added carries allow_private and a SHA-256 of the URL,
// server.paused and server.resumed carry the flag (D13).

// serverTrace is what the log says about one server.
type serverTrace struct {
	// seq is the server.added entry, 0 when the log never registered the
	// server (a paused or resumed entry alone is not a registration).
	seq          int64
	allowPrivate bool
	urlSHA       string
	// paused is the flag after the newest server.added, server.paused or
	// server.resumed entry; pausedSeq is that entry.
	paused    bool
	pausedSeq int64
	// processorAddr is the address the newest server.processor_set entry
	// recorded, "" when there is none; processorSeq is that entry (D14).
	processorAddr string
	processorSeq  int64
}

// noteServerEntry records what a server entry says. A detail that lacks a
// field, or holds one that is not of the shape the writer produces, is
// reported and leaves what earlier entries said.
func (c *integrityCheck) noteServerEntry(e audit.Entry) {
	trace := c.servers[e.Subject]
	if trace == nil {
		trace = &serverTrace{}
		c.servers[e.Subject] = trace
	}
	switch e.Event {
	case evServerAdded:
		private, ok := detailBool(e.Detail, fieldAllowPrivate)
		if !ok {
			c.problem("audit entry %d about server %s has no %s field", e.Seq, quote(e.Subject), fieldAllowPrivate)
			return
		}
		sha, ok := detailField(e.Detail, fieldURLSHA256)
		if !ok || len(sha) != digestHexLen || !isHex(sha) {
			c.problem("audit entry %d about server %s has no %s field", e.Seq, quote(e.Subject), fieldURLSHA256)
			return
		}
		if trace.seq != 0 {
			// A server is registered once; a well-formed second server.added
			// about the same name is an appended forgery and never replaces the
			// first (the server anchor reads the first too).
			c.problem("audit entry %d is a second server.added about server %s, which was registered at entry %d; a server is registered once", e.Seq, quote(e.Subject), trace.seq)
			c.rep.ServersMismatched++
			return
		}
		trace.seq, trace.allowPrivate, trace.urlSHA = e.Seq, private, sha
		trace.paused, trace.pausedSeq = false, e.Seq
	case evServerProcessorSet:
		addr, ok := detailField(e.Detail, fieldProcessorAddr)
		if !ok || validateProcessorAddr(addr) != nil {
			c.problem("audit entry %d about server %s has no %s field", e.Seq, quote(e.Subject), fieldProcessorAddr)
			return
		}
		trace.processorAddr, trace.processorSeq = addr, e.Seq
	default:
		paused, ok := detailBool(e.Detail, fieldPaused)
		if !ok {
			c.problem("audit entry %d about server %s has no %s field", e.Seq, quote(e.Subject), fieldPaused)
			return
		}
		trace.paused, trace.pausedSeq = paused, e.Seq
	}
}

// detailBool reads a field written with %t: exactly "true" or "false".
func detailBool(detail, key string) (value, ok bool) {
	v, found := detailField(detail, key)
	return v == "true", found && (v == "true" || v == "false")
}

// serverRow is what the servers table claims about one server.
type serverRow struct {
	name, url, processorAddr string
	private                  bool
	paused                   bool
}

// checkServers compares every servers row with the log and then reports the
// registrations whose row is gone. A server counts once under
// ServersMismatched however many columns disagree.
func (c *integrityCheck) checkServers() error {
	rows, err := c.q.QueryContext(c.ctx, `SELECT name, url, allow_private, paused, processor_addr FROM servers ORDER BY name`)
	if err != nil {
		return fmt.Errorf("catalog: read servers: %w", err)
	}
	defer func() { _ = rows.Close() }()
	seen := map[string]bool{}
	for rows.Next() {
		var (
			r               serverRow
			private, paused int
		)
		if err := rows.Scan(&r.name, &r.url, &private, &paused, &r.processorAddr); err != nil {
			return fmt.Errorf("catalog: read servers: %w", err)
		}
		r.private, r.paused = private == 1, paused == 1
		seen[r.name] = true
		c.checkServer(r)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("catalog: read servers: %w", err)
	}
	for _, name := range slices.Sorted(maps.Keys(c.servers)) {
		if trace := c.servers[name]; !seen[name] && trace.seq != 0 {
			c.rep.ServersMismatched++
			c.problem("server %s: registered by audit entry %d but no servers row exists", quote(name), trace.seq)
		}
	}
	return nil
}

// checkServer compares one servers row with the log. The URL itself is never
// printed: only that its hash is not the one recorded at registration.
func (c *integrityCheck) checkServer(r serverRow) {
	shown := quote(r.name)
	trace, known := c.servers[r.name]
	if !known || trace.seq == 0 {
		c.rep.ServersMismatched++
		c.problem("server %s: the audit log has no server.added entry about it", shown)
		return
	}
	mismatch := false
	if trace.paused != r.paused {
		c.problem("server %s: paused is %t but the latest server entry (seq %d) left it as %t", shown, r.paused, trace.pausedSeq, trace.paused)
		mismatch = true
	}
	if trace.allowPrivate != r.private {
		c.problem("server %s: allow_private is %t but the server.added entry (seq %d) recorded %t", shown, r.private, trace.seq, trace.allowPrivate)
		mismatch = true
	}
	if urlSHA256(r.url) != trace.urlSHA {
		c.problem("server %s: the URL is not the one the server.added entry (seq %d) recorded (its hash differs)", shown, trace.seq)
		mismatch = true
	}
	if trace.processorAddr != r.processorAddr {
		c.reportProcessorAddr(r, trace, shown)
		mismatch = true
	}
	if mismatch {
		c.rep.ServersMismatched++
	}
}

// reportProcessorAddr names a processor address the log did not record. The
// column is quoted: a row someone edited by hand may hold anything.
func (c *integrityCheck) reportProcessorAddr(r serverRow, trace *serverTrace, shown string) {
	if trace.processorSeq == 0 {
		c.problem("server %s: processor_addr is %s but the audit log has no server.processor_set entry about it", shown, quote(r.processorAddr))
		return
	}
	c.problem("server %s: processor_addr is %s but the latest server.processor_set entry (seq %d) recorded %s",
		shown, quote(r.processorAddr), trace.processorSeq, quote(trace.processorAddr))
}
