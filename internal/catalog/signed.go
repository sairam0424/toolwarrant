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
// read by primary key and only for the entries of a walked page, so a
// crawl-only reload reads none (TestAnchorQueries_StayOnTheAuditLogBySubjectIndex
// pins the plan, TestReload_ANewTrustListEntersTheStateOnTheSuffixWalk the
// count).

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

	signedRecordCols = `seq, payload, signer_fingerprint, signature`
	// signedRecordsSelect reads rows by primary key; the caller appends the
	// placeholders and the closing parenthesis.
	signedRecordsSelect   = `SELECT ` + signedRecordCols + ` FROM signed_records WHERE seq IN (`
	insertSignedRecordSQL = `INSERT INTO signed_records (` + signedRecordCols + `) VALUES (?, ?, ?, ?)`
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
