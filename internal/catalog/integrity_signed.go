package catalog

import (
	"fmt"
	"slices"
)

// checkSignedRecords reports every signed_records row whose seq is below 1
// (IntegrityReport.GhostRows): the catalog assigns seqs from 1 and the
// positive-id guard refuses the insert, so such a row was planted under a
// dropped guard, and every read and write refuses the file that holds one
// (checkGhostRows). A file whose table is gone was already reported by
// checkGuardObjects and is left alone here, so that the report still comes
// out. The trust-list round extends this pass with the record checks the
// walk makes (the sigref token, the signature, the signer).
func (c *integrityCheck) checkSignedRecords() error {
	if slices.Contains(c.rep.GuardsMissing, kindTable+" "+signedRecordsTable) {
		return nil
	}
	rows, err := c.q.QueryContext(c.ctx, `SELECT seq FROM signed_records WHERE seq < 1 ORDER BY seq`)
	if err != nil {
		return fmt.Errorf("catalog: read signed records: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var seq int64
		if err := rows.Scan(&seq); err != nil {
			return fmt.Errorf("catalog: read signed records: %w", err)
		}
		c.rep.GhostRows++
		c.problem("signed_records row %d has a seq below 1, which the catalog never assigns; the row was inserted by hand and is not a signed record", seq)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("catalog: read signed records: %w", err)
	}
	return nil
}
