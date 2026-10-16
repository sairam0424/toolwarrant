package main

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/catalog"
	"github.com/sairam0424/toolwarrant/internal/signing"
	"github.com/sairam0424/toolwarrant/internal/trust"
)

// What audit verify and audit list say about the signed records (D22 (h)).
// The names repeat the catalog's: the three events whose entry carries a
// record and the subject of a trust entry, which the catalog does not export
// and the listing must recognise to ask for the records of exactly those
// entries.
const (
	eventDecisionSigned = "decision.signed"
	trustSubject        = "@trust"
)

// isTrustEvent reports whether an entry of this event is a trust list.
func isTrustEvent(event string) bool {
	return event == string(trust.KindBootstrap) || event == string(trust.KindRotated)
}

// isSignedEvent reports whether an entry of this event carries a signed
// record: a decision or a trust list.
func isSignedEvent(event string) bool {
	return event == eventDecisionSigned || isTrustEvent(event)
}

// reportTrust prints, after a clean chain and a clean integrity report, what
// the signed records say: how many the walk verified, the list in force with
// its operators, the root and where the signed history starts, and the
// approvals in service that predate the bootstrap, which stand by chain
// anchoring alone until re-approved (O-12). Without a list it names L13 and
// the command that closes it.
func (a *app) reportTrust(store *catalog.Store, rep catalog.IntegrityReport) error {
	view, err := store.TrustList(a.ctx)
	if err != nil {
		return fmt.Errorf("read the trust list: %w", err)
	}
	if !view.InForce() {
		a.stdout.printf("signed records: none; the catalog has no trust list (L13 open); run \"%s trust init\"\n", programName)
		return nil
	}
	vouched, err := bootstrapActor(a, store, view.BootstrapSeq)
	if err != nil {
		return err
	}
	a.stdout.printf("signed records ok: %d decisions and %d trust lists verified; trust list v%d in force (%s); root %s at entry %d; %d entries before the bootstrap are unsigned history vouched for by %s\n",
		view.SignedDecisions, view.Lists, view.Version, signerList(view.Signers), view.Root, view.BootstrapSeq, view.BootstrapSeq-1, cell(vouched))
	if n := len(rep.LegacyApprovalsInService); n > 0 {
		a.stdout.printf("unsigned approvals in service: %d (approved before the cut-over at entry %d; re-approve them to sign them): %s\n", n, view.BootstrapSeq, cells(rep.LegacyApprovalsInService))
	}
	return nil
}

// bootstrapActor is the person who signed the bootstrap: the entry's actor,
// read by seq. The walk verified the entry and its record, so the actor is
// the canonical name the list gave the root key.
func bootstrapActor(a *app, store *catalog.Store, seq int64) (string, error) {
	entries, err := store.AuditEntries(a.ctx, seq-1, 1)
	if err != nil {
		return "", err
	}
	if len(entries) != 1 || entries[0].Seq != seq || entries[0].Event != string(trust.KindBootstrap) {
		return "", fmt.Errorf("%w: audit entry %d is not the trust bootstrap the walk recorded", catalog.ErrCorrupt, seq)
	}
	return entries[0].Actor, nil
}

// auditEntryJSON is one entry of audit list --json: the entry as the log
// holds it and, for an entry that carries a signed record, the record; null
// for every other entry.
type auditEntryJSON struct {
	audit.Entry
	Signed *signedRecordJSON `json:"signed"`
}

// signedRecordJSON is a signed record as a verifier outside toolwarrant
// consumes it: the exact signed bytes in base64, the signature in the armored
// form ssh-keygen -Y verify reads, and the signer's fingerprint, which the
// allowed_signers file of trust show maps to a person.
type signedRecordJSON struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
	Signer    string `json:"signer"`
}

// auditJSON renders the entries with their signed records, read through the
// checked read behind SignedRecords: each entry is verified against the chain
// and its row against the entry's token. On a file whose chain or records are
// broken that read is ErrCorrupt; the listing is the forensic view and keeps
// listing, with null in every signed field and one line on stderr naming the
// refusal and the judge, audit verify (orchestrator decision 5).
func (a *app) auditJSON(store *catalog.Store, entries []audit.Entry) ([]auditEntryJSON, error) {
	var seqs []int64
	for _, e := range entries {
		if isSignedEvent(e.Event) {
			seqs = append(seqs, e.Seq)
		}
	}
	records := map[int64]catalog.SignedRecord{}
	if len(seqs) > 0 {
		var err error
		if records, err = store.SignedRecords(a.ctx, seqs); err != nil {
			if !errors.Is(err, catalog.ErrCorrupt) {
				return nil, err
			}
			a.stderr.printf("signed records not shown: %s; run \"%s audit verify\"\n", cell(err.Error()), programName)
			records = map[int64]catalog.SignedRecord{}
		}
	}
	out := make([]auditEntryJSON, 0, len(entries))
	for _, e := range entries {
		row := auditEntryJSON{Entry: e}
		if rec, ok := records[e.Seq]; ok {
			armored, err := signing.Armor(rec.Signature)
			if err != nil {
				return nil, fmt.Errorf("%w: signed record of audit entry %d: %w", catalog.ErrCorrupt, e.Seq, err)
			}
			row.Signed = &signedRecordJSON{Payload: base64.StdEncoding.EncodeToString(rec.Payload), Signature: string(armored), Signer: rec.Signer}
		}
		out = append(out, row)
	}
	return out, nil
}
