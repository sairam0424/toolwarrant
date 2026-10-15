package catalog

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/sairam0424/toolwarrant/internal/audit"
)

// The chain anchor of a server row (D17 c). The servers table is mutable by
// design, and until the seventh review it had no reader-side evidence: Server
// and Servers ran no file check at all and handed processor_addr, url and
// allow_private out as the row held them, so one UPDATE made emit, the
// documented remedy after a CONFIG-EDITED, write a forged processor address
// into the gateway configuration with no change line (the gateway would then
// dial the forger's processor for every hook of the route and hand it the
// shared secret header), and sent the crawl loop to another URL with private
// addresses allowed, while every serving-path read, VerifyAudit and every
// fresh open were clean and only Integrity saw it. Now both views run
// checkFile like every other view and anchor the three columns to the chain
// the Store verified: the newest server.processor_set entry about the server
// must carry the address the row holds (and an empty address must have no
// entry), and the server.added entry must carry the SHA-256 of the URL and the
// allow_private flag, each entry verified through chainMemory.verify, whose
// memory records both events. SetProcessorAddr anchors the row before it
// compares the address it is asked to record, so a forged column equal to the
// new address cannot pass as unchanged and leave the log without an entry.
// The URL is never printed: a report says that its hash differs. The paused
// flag is anchored too, to the newest server.paused or server.resumed entry
// (no entry means not paused), by both views and by every path that acts on
// it: Snapshot, which serves nothing of a paused server, RecordCrawl, which
// refuses one, and PauseServer and ResumeServer, which compare the request
// with the flag; an un-pause by one UPDATE therefore serves nothing and turns
// the operator's resume into ErrCorrupt instead of "already paused=false".
// Each anchored entry goes through entryChecker.verify, so a server.paused or
// server.resumed entry after the trust bootstrap must also name the signed
// decision of its own transaction (D22 (d), requireSigned).

// firstServerEntry returns the oldest entry with this event about a server;
// found is false when the log has none. One index seek, no sort.
func firstServerEntry(ctx context.Context, q queryer, server, event string) (audit.Entry, bool, error) {
	e, err := scanAudit(q.QueryRowContext(ctx,
		`SELECT `+auditCols+` FROM audit_log WHERE subject = ? AND event = ? ORDER BY seq ASC LIMIT 1`, server, event))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return audit.Entry{}, false, nil
	case err != nil:
		return audit.Entry{}, false, fmt.Errorf("catalog: read server entry: %w", err)
	}
	return e, true, nil
}

// newestServerEntryQuery selects the newest entry with one event about one
// subject. It is one seek on the audit_log_by_subject index with no sort (an
// IN list over two events would make SQLite sort every matching entry in a
// temporary b-tree), so a lookup costs the same whatever the log holds;
// TestAnchorQueries_StayOnTheAuditLogBySubjectIndex holds it to that plan.
const newestServerEntryQuery = `SELECT ` + auditCols + ` FROM audit_log WHERE subject = ? AND event = ? ORDER BY seq DESC LIMIT 1`

// newestServerEntry returns the newest entry with this event about a server;
// found is false when the log has none.
func newestServerEntry(ctx context.Context, q queryer, server, event string) (audit.Entry, bool, error) {
	e, err := scanAudit(q.QueryRowContext(ctx, newestServerEntryQuery, server, event))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return audit.Entry{}, false, nil
	case err != nil:
		return audit.Entry{}, false, fmt.Errorf("catalog: read server entry: %w", err)
	}
	return e, true, nil
}

// anchorServer requires a servers row to be what the verified chain recorded:
// allow_private and the URL as the server.added entry wrote them, the
// processor address as the newest server.processor_set entry wrote it, and
// the paused flag as the newest server.paused or server.resumed entry left it.
// Any disagreement, a missing entry or an entry outside the verified chain is
// ErrCorrupt.
func anchorServer(ctx context.Context, q queryer, chain *chainMemory, srv Server) error {
	if err := anchorServerAdded(ctx, q, chain, srv); err != nil {
		return err
	}
	if err := anchorProcessorAddr(ctx, q, chain, srv); err != nil {
		return err
	}
	return anchorPaused(ctx, q, chain, srv)
}

// anchorPaused checks the paused flag against the newest server.paused or
// server.resumed entry; a row without such an entry must not be paused.
func anchorPaused(ctx context.Context, q queryer, chain *chainMemory, srv Server) error {
	shown := quote(srv.Name)
	e, found, err := newestPauseEntry(ctx, q, srv.Name)
	if err != nil {
		return err
	}
	if !found {
		if !srv.Paused {
			return nil
		}
		return fmt.Errorf("%w: paused of server %s is true but the audit log has no server.paused or server.resumed entry about it", ErrCorrupt, shown)
	}
	if err := newEntryChecker(chain).verify(e); err != nil {
		return err
	}
	paused, ok := detailBool(e.Detail, fieldPaused)
	if !ok {
		return errServerEntryField(e, fieldPaused)
	}
	if paused != srv.Paused {
		return fmt.Errorf("%w: paused of server %s is %t but the newest %s entry (seq %d) recorded %t", ErrCorrupt, shown, srv.Paused, e.Event, e.Seq, paused)
	}
	return nil
}

// anchorServerAdded checks the URL and the allow_private flag against the
// FIRST server.added entry about the server: AddServer writes exactly one per
// name and nothing deletes a server, so a later server.added is foreign, and
// anchoring to the newest would let whoever can append a sealed entry (the
// access D14 admits) register a new URL and policy for an existing server
// without rewriting anything (eighth review). Integrity reports the second
// entry; the forger must now rewrite the original in place, which the chain
// catches.
func anchorServerAdded(ctx context.Context, q queryer, chain *chainMemory, srv Server) error {
	shown := quote(srv.Name)
	added, found, err := firstServerEntry(ctx, q, srv.Name, evServerAdded)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("%w: server %s has no server.added audit entry", ErrCorrupt, shown)
	}
	if err := newEntryChecker(chain).verify(added); err != nil {
		return err
	}
	private, ok := detailBool(added.Detail, fieldAllowPrivate)
	if !ok {
		return errServerEntryField(added, fieldAllowPrivate)
	}
	sha, ok := detailField(added.Detail, fieldURLSHA256)
	if !ok {
		return errServerEntryField(added, fieldURLSHA256)
	}
	if private != srv.AllowPrivate {
		return fmt.Errorf("%w: allow_private of server %s is %t but its server.added entry (seq %d) recorded %t", ErrCorrupt, shown, srv.AllowPrivate, added.Seq, private)
	}
	if urlSHA256(srv.URL) != sha {
		return fmt.Errorf("%w: the URL of server %s is not the one its server.added entry (seq %d) recorded (its hash differs)", ErrCorrupt, shown, added.Seq)
	}
	return nil
}

// anchorProcessorAddr checks the processor address against the newest
// server.processor_set entry; a row with no address must have no entry.
func anchorProcessorAddr(ctx context.Context, q queryer, chain *chainMemory, srv Server) error {
	shown := quote(srv.Name)
	set, found, err := newestServerEntry(ctx, q, srv.Name, evServerProcessorSet)
	if err != nil {
		return err
	}
	if !found {
		if srv.ProcessorAddr == "" {
			return nil
		}
		return fmt.Errorf("%w: processor_addr of server %s is %s but the audit log has no server.processor_set entry about it", ErrCorrupt, shown, quote(srv.ProcessorAddr))
	}
	if err := newEntryChecker(chain).verify(set); err != nil {
		return err
	}
	addr, ok := detailField(set.Detail, fieldProcessorAddr)
	if !ok {
		return errServerEntryField(set, fieldProcessorAddr)
	}
	if addr != srv.ProcessorAddr {
		return fmt.Errorf("%w: processor_addr of server %s is %s but the newest server.processor_set entry (seq %d) recorded %s", ErrCorrupt, shown, quote(srv.ProcessorAddr), set.Seq, quote(addr))
	}
	return nil
}

// newestPauseEntry is the newer of the newest server.paused and the newest
// server.resumed entry about a server: two index seeks, no sort.
func newestPauseEntry(ctx context.Context, q queryer, server string) (audit.Entry, bool, error) {
	paused, foundPaused, err := newestServerEntry(ctx, q, server, evServerPaused)
	if err != nil {
		return audit.Entry{}, false, err
	}
	resumed, foundResumed, err := newestServerEntry(ctx, q, server, evServerResumed)
	if err != nil {
		return audit.Entry{}, false, err
	}
	switch {
	case foundPaused && (!foundResumed || paused.Seq > resumed.Seq):
		return paused, true, nil
	case foundResumed:
		return resumed, true, nil
	}
	return audit.Entry{}, false, nil
}

// errServerEntryField is the ErrCorrupt for a server entry whose detail lacks
// a field the Store always writes.
func errServerEntryField(e audit.Entry, field string) error {
	return fmt.Errorf("%w: the %s entry (seq %d) about server %s has no %s field", ErrCorrupt, e.Event, e.Seq, quote(e.Subject), field)
}
