package catalog

import (
	"context"
	"fmt"
)

// Rows below id 1 (D17 b, d, g). The catalog assigns every approvals and
// tool_versions id and every audit_log seq from 1 upwards, and every rule that
// ranks history rows reads them from the top: the newest decision is the
// approvals row with the highest id, and every chain walk read the log from
// seq 1. SQLite evaluates an unsupplied INTEGER PRIMARY KEY as -1 inside a
// BEFORE INSERT trigger, so a row placed at id -1 by hand made the no-replace
// guards (EXISTS ... WHERE id = NEW.id) refuse every insert the Store made
// afterwards, under a message that named the wrong cause; a row at id -2 was
// never the newest decision while it satisfied the per-version evidence (some
// approve or rollback row exists), which made a proposer's own pending bytes
// a rollback target with no audit entry touched; and a row at seq 0 or below
// was read by no walk while the decision path read it and refused the tool
// for good (the seventh review). Two rules close this. The positive-id guards
// refuse such an insert (AFTER INSERT, where NEW.id is the id the row got; a
// BEFORE INSERT guard cannot tell an explicit -1 from an unsupplied id). And
// every read and every write transaction refuses a file that holds such a row
// before it trusts or writes anything (checkGhostRows, run by checkFile and
// inTx), so a row planted under a dropped and re-created guard fails closed
// with its cause named instead of hiding from the ranking rules or blocking
// inserts under the no-replace guards' message. Integrity reports every such
// row (IntegrityReport.GhostRows, and ChainBreaks for the log). The
// signed_records table of schema version 7 is keyed by the seq of the audit
// entry it belongs to, so a row below seq 1 there is a row of no entry at
// all, and it is refused and reported like the others (D22 g).

// ghostRowsQuery asks whether any history table holds a row below id 1. Each
// EXISTS is one seek on the rowid b-tree (rowid < 1), so the check costs
// nothing a read would notice.
const ghostRowsQuery = `SELECT EXISTS (SELECT 1 FROM approvals WHERE id < 1),
	EXISTS (SELECT 1 FROM tool_versions WHERE id < 1),
	EXISTS (SELECT 1 FROM audit_log WHERE seq < 1),
	EXISTS (SELECT 1 FROM signed_records WHERE seq < 1)`

// checkGhostRows is ErrCorrupt when approvals, tool_versions, audit_log or
// signed_records holds a row whose id or seq is below 1.
func checkGhostRows(ctx context.Context, q queryer) error {
	var approvals, versions, entries, records int
	if err := q.QueryRowContext(ctx, ghostRowsQuery).Scan(&approvals, &versions, &entries, &records); err != nil {
		return fmt.Errorf("catalog: look for rows below id 1: %w", err)
	}
	switch {
	case approvals == 1:
		return errGhostRow("approvals", "id")
	case versions == 1:
		return errGhostRow("tool_versions", "id")
	case entries == 1:
		return errGhostRow("audit_log", "seq")
	case records == 1:
		return errGhostRow(signedRecordsTable, "seq")
	}
	return nil
}

// errGhostRow names the table and column that hold a row below 1.
func errGhostRow(table, column string) error {
	return fmt.Errorf("%w: %s holds a row whose %s is below 1, which the catalog never assigns; the file was edited outside toolwarrant, run audit verify", ErrCorrupt, table, column)
}
