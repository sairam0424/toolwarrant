package catalog

import (
	"context"
	"fmt"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/signing"
	"github.com/sairam0424/toolwarrant/internal/trust"
)

// The signed records of the chain (D22 (c); the v0.4 plan, section 1). Three
// audit events carry an OpenSSH sshsig record in the signed_records table at
// the entry's own seq: trust.bootstrap and trust.rotated, the operator trust
// list (this round), and decision.signed, a person's decision (the next
// round). The entry's detail carries the signer's fingerprint and the sigref
// token, the digest signing.RecordDigest computes over the exact payload, the
// signature blob and the signer, so the entry's hash, and through it the
// chain, commits to the exact record: a row swapped under an entry no longer
// matches the token the chain verified, which is what the fourth and fifth
// reviews taught about every table the chain does not cover. The rows are
// read by primary key and only for the entries of a walked page, and the
// seqs of the rows within a page's range by one primary-key range seek, so a
// row under an entry that carries no record is refused where the walk meets
// the entry and a crawl-only reload reads no record
// (TestAnchorQueries_StayOnTheAuditLogBySubjectIndex pins both plans,
// TestReload_ANewTrustListEntersTheStateOnTheSuffixWalk the count,
// TestWalk_RefusesASignedRecordRowUnderAnEntryThatCarriesNone the refusal).

// The signed events and the detail fields their entries carry. The trust
// events spell what internal/trust folds (trust.Kind(e.Event) is the kind);
// the subject of a trust entry can collide with no server (no server name
// starts with '@', validateServerName) and no tool (a tool subject holds a
// '/').
const (
	evDecisionSigned = "decision.signed"
	evTrustBootstrap = string(trust.KindBootstrap)
	evTrustRotated   = string(trust.KindRotated)
	trustSubject     = "@trust"
	// fieldKind is the decision a decision.signed entry records (its first
	// token, so isToolDetail never takes the entry for a tool entry).
	fieldKind = "kind"
	// fieldVersion and fieldSigners are the first two tokens of a trust
	// entry: the list's version and how many operators it names.
	fieldVersion = "version"
	fieldSigners = "signers"
	// fieldSigner and fieldSigref end every signed entry's detail: the
	// SHA256: fingerprint of the key that signed and the record digest.
	fieldSigner = "signer"
	fieldSigref = "sigref"
	// fieldSigned is the token every lifecycle, budget-reset, pause and
	// resume entry of a signed decision carries after its own fields: the
	// seq of the decision.signed entry of the same transaction (rule 5,
	// decisionwalk.go).
	fieldSigned = "signed"

	signedRecordCols = `seq, payload, signer_fingerprint, signature`
	// signedRecordsSelect reads rows by primary key; the caller appends the
	// placeholders and the closing parenthesis.
	signedRecordsSelect   = `SELECT ` + signedRecordCols + ` FROM signed_records WHERE seq IN (`
	insertSignedRecordSQL = `INSERT INTO signed_records (` + signedRecordCols + `) VALUES (?, ?, ?, ?)`
	// signedSeqsInRange reads, by a primary-key range seek, the seqs of the
	// rows within a walked page, so that a row under an entry that carries no
	// signed record is refused (checkOrphanRows).
	signedSeqsInRange = `SELECT seq FROM signed_records WHERE seq >= ? AND seq <= ? ORDER BY seq`
)

// SignedRecord is one signed record as audit list --json shows it: the exact
// bytes that were signed, the sshsig blob and the signer's fingerprint, at the
// seq of the entry that carries its token.
type SignedRecord struct {
	Seq       int64
	Payload   []byte
	Signature []byte
	Signer    string
}

// isSignedEvent reports whether an entry of this event carries a signed record.
func isSignedEvent(event string) bool {
	return event == evDecisionSigned || event == evTrustBootstrap || event == evTrustRotated
}

// namespaceOf is the sshsig namespace a signed event's record is verified
// under: a constant of internal/signing, never a string from the file.
func namespaceOf(event string) signing.Namespace {
	if event == evDecisionSigned {
		return signing.NamespaceDecision
	}
	return signing.NamespaceTrust
}

// signedDetail ends a signed entry's detail with the two tokens every such
// entry carries: the signer's fingerprint and the sigref digest of the record.
func signedDetail(detail string, rec signing.Record) string {
	return fmt.Sprintf("%s %s=%s %s=%s", detail, fieldSigner, rec.Signer, fieldSigref, signing.RecordDigest(rec))
}

// decisionDetail is the leading part of a decision.signed entry's detail: the
// kind and the digest the decision names (noDigest for the kinds that name
// none), the two tokens rule 2 compares with the signed payload.
func decisionDetail(kind signing.Kind, digest string) string {
	return fmt.Sprintf("%s=%s %s=%s", fieldKind, kind, fieldDigest, orNoDigest(digest))
}

// signedNote is the note the entries of a signed decision carry after their
// own fields: " signed=N" for the decision.signed entry at seq N, nothing for
// an unsigned decision (seq 0, before the bootstrap).
func signedNote(seq int64) string {
	if seq == 0 {
		return ""
	}
	return fmt.Sprintf(" %s=%d", fieldSigned, seq)
}

// signedSeqs lists the seqs of the signed entries of a page, in order.
func signedSeqs(page []audit.Entry) []int64 {
	var seqs []int64
	for _, e := range page {
		if isSignedEvent(e.Event) {
			seqs = append(seqs, e.Seq)
		}
	}
	return seqs
}

// readSignedRecords reads the rows at the given seqs by primary key, in chunks
// of inChunk. A seq without a row is absent from the result; the caller
// decides what that means.
func readSignedRecords(ctx context.Context, q queryer, seqs []int64) (map[int64]signing.Record, error) {
	out := make(map[int64]signing.Record, len(seqs))
	for chunk := range chunks(seqs) {
		if err := readSignedChunk(ctx, q, chunk, out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// readSignedChunk reads one chunk of rows into out.
func readSignedChunk(ctx context.Context, q queryer, seqs []int64, out map[int64]signing.Record) error {
	rows, err := q.QueryContext(ctx, signedRecordsSelect+placeholders(len(seqs))+`)`, int64Args(seqs)...)
	if err != nil {
		return fmt.Errorf("catalog: read signed records: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			seq int64
			rec signing.Record
		)
		if err := rows.Scan(&seq, &rec.Payload, &rec.Signer, &rec.Signature); err != nil {
			return fmt.Errorf("catalog: read signed records: %w", err)
		}
		out[seq] = rec
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("catalog: read signed records: %w", err)
	}
	return nil
}

// checkOrphanRows requires every signed_records row within the seq range of
// a verified page to sit at the seq of a signed entry of that page: the
// catalog writes a row only together with a signed entry, so a row under any
// other entry was inserted by hand, and the walk refuses it where it meets
// the entry (errOrphanRecord; Integrity prints the same sentence and counts
// SignedRecordsOrphaned). One primary-key range seek per walked page, so a
// reload that walks no page reads nothing. A row at a seq above the head can
// only be written with the foreign key off and belongs to no page until an
// entry arrives at its seq, where this check or the Store's own insert (the
// primary key) refuses it; Integrity names it at once (checkOrphanRecords).
func checkOrphanRows(ctx context.Context, q queryer, page []audit.Entry) error {
	if len(page) == 0 {
		return nil
	}
	rows, err := q.QueryContext(ctx, signedSeqsInRange, page[0].Seq, page[len(page)-1].Seq)
	if err != nil {
		return fmt.Errorf("catalog: read signed records: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var seq int64
		if err := rows.Scan(&seq); err != nil {
			return fmt.Errorf("catalog: read signed records: %w", err)
		}
		e, ok := entryAt(page, seq)
		if !ok {
			return problemf(ruleBinding, nil, "signed_records row %d lies in the range of a verified page but at the seq of none of its entries; the row was inserted by hand", seq)
		}
		if !isSignedEvent(e.Event) {
			return errOrphanRecord(seq, e.Event)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("catalog: read signed records: %w", err)
	}
	return nil
}

// entryAt returns the entry of a verified page at seq. audit.VerifyFrom
// accepted the page, so its seqs are contiguous and the entry is seq minus
// the first seq away; the index is checked all the same.
func entryAt(page []audit.Entry, seq int64) (audit.Entry, bool) {
	i := seq - page[0].Seq
	if i < 0 || i >= int64(len(page)) || page[i].Seq != seq {
		return audit.Entry{}, false
	}
	return page[i], true
}

// errOrphanRecord is the refusal of a signed_records row at the seq of an
// entry that carries no signed record, as the walk and Integrity both word it.
func errOrphanRecord(seq int64, event string) error {
	return problemf(ruleBinding, nil, "signed_records row %d belongs to audit entry %d, a %s, which carries no signed record; the row was inserted by hand", seq, seq, quote(event))
}

// insertSignedRecord stores one record at the seq of the entry that carries
// its token, inside the transaction that appended the entry.
func (t *txn) insertSignedRecord(ctx context.Context, seq int64, rec signing.Record) error {
	if _, err := t.exec(ctx, insertSignedRecordSQL, seq, rec.Payload, rec.Signer, rec.Signature); err != nil {
		return fmt.Errorf("catalog: store signed record: %w", err)
	}
	return nil
}

// SignedRecords returns the signed record behind each of the given audit
// entries that carries one, keyed by seq, as a checked read: the file check of
// every view runs first, each entry is verified against the chain this Store
// walked and its sigref token must equal the digest of the row it names, so a
// row swapped under an entry is ErrCorrupt rather than shown. An entry that
// carries no record, or a seq the log does not hold, is left out. It is the
// read behind audit list --json.
func (s *Store) SignedRecords(ctx context.Context, seqs []int64) (map[int64]SignedRecord, error) {
	out := map[int64]SignedRecord{}
	err := s.inRead(ctx, func(q queryer) error {
		if err := s.checkFile(ctx, q); err != nil {
			return err
		}
		entries, err := readAllEntries(ctx, q, seqs)
		if err != nil {
			return err
		}
		var signed []int64
		for _, seq := range seqs {
			if e, ok := entries[seq]; ok && isSignedEvent(e.Event) {
				signed = append(signed, seq)
			}
		}
		rows, err := readSignedRecords(ctx, q, signed)
		if err != nil {
			return err
		}
		return s.collectSignedRecords(entries, signed, rows, out)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// collectSignedRecords verifies each signed entry against the chain memory
// and its row against the entry's token, then adds the row to out.
func (s *Store) collectSignedRecords(entries map[int64]audit.Entry, signed []int64, rows map[int64]signing.Record, out map[int64]SignedRecord) error {
	for _, seq := range signed {
		e := entries[seq]
		if err := s.chain.verify(e); err != nil {
			return err
		}
		rec, ok := rows[seq]
		if !ok {
			return fmt.Errorf("%w: %w", ErrCorrupt, errNoSignedRecord(e))
		}
		if err := checkRecordBinding(e, rec); err != nil {
			return fmt.Errorf("%w: %w", ErrCorrupt, err)
		}
		out[seq] = SignedRecord{Seq: seq, Payload: rec.Payload, Signature: rec.Signature, Signer: rec.Signer}
	}
	return nil
}

// trustEntriesQuery selects every trust entry (the bootstrap and each
// rotation, about the trust subject) in sequence order. It rests on the
// audit_log_by_subject index, so it reads the trust entries alone, however
// long the log; TestAnchorQueries_StayOnTheAuditLogBySubjectIndex holds it to
// that plan.
const trustEntriesQuery = `SELECT ` + auditCols + ` FROM audit_log WHERE subject = ? AND event IN ('` +
	evTrustBootstrap + `', '` + evTrustRotated + `') ORDER BY seq`

// TrustEntries returns every trust entry of the log, the bootstrap and each
// rotation, in sequence order: as many as the list has had versions, read
// through the subject index rather than the whole log. The entries are
// returned as the file holds them, as AuditEntries returns them; the checked
// read of their records is SignedRecords, which verifies the chain first. An
// empty slice means no list was ever recorded.
func (s *Store) TrustEntries(ctx context.Context) ([]audit.Entry, error) {
	out := []audit.Entry{}
	err := s.inRead(ctx, func(q queryer) error {
		rows, err := q.QueryContext(ctx, trustEntriesQuery, trustSubject)
		if err != nil {
			return fmt.Errorf("catalog: read trust entries: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			e, err := scanAudit(rows)
			if err != nil {
				return fmt.Errorf("catalog: read trust entries: %w", err)
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
