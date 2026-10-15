package catalog

import (
	"database/sql"
	"errors"
	"fmt"
	"slices"

	"github.com/sairam0424/toolwarrant/internal/audit"
)

// The signed-record side of Integrity (D22 (c)). The walk refuses a file at
// the first signed entry that breaks a rule; Integrity applies the same
// functions (trustwalk.go) to every signed entry in seq order, reports each
// refusal as one problem line with the walk's own sentence, keeps the list in
// force past a refused record, and then names the rows that belong to no
// signed entry. The identity the records must name is read from the file
// itself, as every other pass reads what it compares, and the trust root is
// the one the Store was opened with.

// noteSignedEntry keeps a signed entry for checkSignedRecords.
func (c *integrityCheck) noteSignedEntry(e audit.Entry) {
	c.signedEntries = append(c.signedEntries, e)
}

// checkSignedRecords reports every signed_records row whose seq is below 1
// (IntegrityReport.GhostRows: the catalog assigns seqs from 1 and the
// positive-id guard refuses the insert, so such a row was planted under a
// dropped guard), every signed entry whose record the walk would refuse
// (SignedRecordsInvalid, TrustListsInvalid) and every row of no signed entry
// (SignedRecordsOrphaned). A file whose table is gone was already reported by
// checkGuardObjects and is left alone here, so that the report still comes
// out.
func (c *integrityCheck) checkSignedRecords() error {
	if slices.Contains(c.rep.GuardsMissing, kindTable+" "+signedRecordsTable) {
		return nil
	}
	if err := c.checkSignedGhostRows(); err != nil {
		return err
	}
	if err := c.checkSignedEntries(); err != nil {
		return err
	}
	return c.checkOrphanRecords()
}

// checkSignedGhostRows names every row below seq 1.
func (c *integrityCheck) checkSignedGhostRows() error {
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

// checkSignedEntries runs the walk's rules over every signed entry in seq
// order, against the identity the file carries and the pinned trust root,
// reporting each refusal and folding the trust list past it.
func (c *integrityCheck) checkSignedEntries() error {
	if len(c.signedEntries) == 0 {
		return nil
	}
	identity, err := readIdentity(c.ctx, c.q)
	if err != nil {
		c.problem("the catalog identity cannot be read, so no signed record can name this catalog: %v", err)
	}
	seqs := make([]int64, 0, len(c.signedEntries))
	for _, e := range c.signedEntries {
		seqs = append(seqs, e.Seq)
	}
	rows, err := readSignedRecords(c.ctx, c.q, seqs)
	if err != nil {
		return err
	}
	var tm trustMemory
	for _, e := range c.signedEntries {
		rec, ok := rows[e.Seq]
		if !ok {
			c.noteSignedProblem(errNoSignedRecord(e))
			continue
		}
		res, err := checkSignedEntry(e, rec, tm, identity, c.trustRoot)
		if err != nil {
			c.noteSignedProblem(err)
			continue
		}
		tm = res.trust
	}
	return nil
}

// noteSignedProblem counts one refusal under the counter of the rule it broke
// and prints the walk's sentence.
func (c *integrityCheck) noteSignedProblem(err error) {
	var p *signedProblem
	if errors.As(err, &p) && p.rule == ruleTrust {
		c.rep.TrustListsInvalid++
	} else {
		c.rep.SignedRecordsInvalid++
	}
	c.problem("%s", err.Error())
}

// checkOrphanRecords names every row at the seq of an entry that carries no
// signed record, or of no entry at all.
func (c *integrityCheck) checkOrphanRecords() error {
	signed := make(map[int64]bool, len(c.signedEntries))
	for _, e := range c.signedEntries {
		signed[e.Seq] = true
	}
	rows, err := c.q.QueryContext(c.ctx, `SELECT seq FROM signed_records WHERE seq >= 1 ORDER BY seq`)
	if err != nil {
		return fmt.Errorf("catalog: read signed records: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var orphans []int64
	for rows.Next() {
		var seq int64
		if err := rows.Scan(&seq); err != nil {
			return fmt.Errorf("catalog: read signed records: %w", err)
		}
		if !signed[seq] {
			orphans = append(orphans, seq)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("catalog: read signed records: %w", err)
	}
	for _, seq := range orphans {
		if err := c.reportOrphanRecord(seq); err != nil {
			return err
		}
	}
	return nil
}

// reportOrphanRecord names one orphan row with the entry at its seq, if any.
func (c *integrityCheck) reportOrphanRecord(seq int64) error {
	c.rep.SignedRecordsOrphaned++
	var event string
	err := c.q.QueryRowContext(c.ctx, `SELECT event FROM audit_log WHERE seq = ?`, seq).Scan(&event)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		c.problem("signed_records row %d belongs to no audit entry; the row was inserted by hand", seq)
	case err != nil:
		return fmt.Errorf("catalog: read audit entry %d: %w", seq, err)
	default:
		c.problem("signed_records row %d belongs to audit entry %d, a %s, which carries no signed record; the row was inserted by hand", seq, seq, quote(event))
	}
	return nil
}
