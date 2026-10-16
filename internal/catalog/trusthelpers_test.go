package catalog

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
	"github.com/sairam0424/toolwarrant/internal/signing"
	"github.com/sairam0424/toolwarrant/internal/signing/sigtest"
	"github.com/sairam0424/toolwarrant/internal/trust"
)

// The fixtures of the trust-list tests: throwaway Ed25519 keys made at run
// time (sigtest; nothing in the tree), the lists they sign over a catalog's
// head, and the forgeries written with a SQLite shell's powers, each a
// correctly sealed entry appended past the head with its signed_records row,
// as whoever can write the file would write them.

// operator is one person of the tests: a D7 name and a generated key.
type operator struct {
	name string
	key  sigtest.Key
}

// newOperator makes a person with a fresh Ed25519 key.
func newOperator(t *testing.T, name string) operator {
	t.Helper()
	return operator{name: name, key: sigtest.GenerateEd25519(t)}
}

// fp is the operator's key fingerprint, the only key text any message holds.
func (o operator) fp() string { return signing.Fingerprint(o.key.Public) }

// actor is the operator as a human Actor.
func (o operator) actor() Actor { return Actor{Name: o.name, Type: ActorHuman} }

// listSignedAt is the instant every test list is signed at; signed_at is
// informational and never compared.
func listSignedAt() time.Time { return time.Date(2026, 10, 15, 18, 0, 0, 0, time.UTC) }

// listFor builds the payload of a trust list for the catalog with identity,
// over head, at version v, naming ops in order, with by as the signer the
// payload names.
func listFor(identity, head string, v int, by operator, ops ...operator) signing.TrustList {
	signers := make([]signing.Signer, 0, len(ops))
	for _, op := range ops {
		signers = append(signers, signing.Signer{Key: signing.MarshalKey(op.key.Public), Name: op.name})
	}
	return signing.TrustList{
		Catalog: identity, PrevHead: head, SignedAt: listSignedAt(), Signer: by.fp(),
		Signers: signers, Threshold: trust.Threshold, Version: v,
	}
}

// signBytes signs payload under ns with k; the record names k's fingerprint.
func signBytes(t *testing.T, payload []byte, k sigtest.Key, ns signing.Namespace) signing.Record {
	t.Helper()
	rec, err := signing.Sign(bg, payload, k.Signer, ns)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return rec
}

// signList marshals l and signs it under the trust namespace with k.
func signList(t *testing.T, l signing.TrustList, k sigtest.Key) signing.Record {
	t.Helper()
	payload, err := signing.MarshalTrustList(l)
	if err != nil {
		t.Fatalf("MarshalTrustList: %v", err)
	}
	return signBytes(t, payload, k, signing.NamespaceTrust)
}

// mustHead is the verified head of s.
func mustHead(t *testing.T, s *Store) string {
	t.Helper()
	head, err := s.AuditHead(bg)
	if err != nil {
		t.Fatalf("AuditHead: %v", err)
	}
	return head
}

// mustTrustList is the trust list in force on s.
func mustTrustList(t *testing.T, s *Store) TrustView {
	t.Helper()
	view, err := s.TrustList(bg)
	if err != nil {
		t.Fatalf("TrustList: %v", err)
	}
	return view
}

// mustSetTrust signs a version v list naming ops over s's current head with
// by's key and records it as by, failing the test on refusal.
func mustSetTrust(t *testing.T, s *Store, v int, by operator, ops ...operator) Receipt {
	t.Helper()
	rec := signList(t, listFor(s.identity, mustHead(t, s), v, by, ops...), by.key)
	r, err := s.SetTrust(bg, rec, by.actor())
	if err != nil {
		t.Fatalf("SetTrust(v%d by %s): %v", v, by.name, err)
	}
	return r
}

// trustedCatalog is a catalog with history before and after its bootstrap:
// an approved tool, alice's bootstrap (v1) and the rotation that added bob
// (v2), and a crawl after it, so the trust records sit below the head.
func trustedCatalog(t *testing.T) (s *Store, path string, alice, bob operator) {
	t.Helper()
	path = dbPath(t)
	s = openStore(t, path, lifecycle.DefaultPolicy())
	approvedEcho(t, s)
	alice, bob = newOperator(t, "alice"), newOperator(t, "bob")
	mustSetTrust(t, s, 1, alice, alice)
	mustSetTrust(t, s, 2, alice, alice, bob)
	mustCrawl(t, s, "alpha", tool("echo", "v1"), tool("sum", "v1"))
	mustBeClean(t, s, "after the bootstrap and the rotation")
	return s, path, alice, bob
}

// rawHead is the head of the log as the file holds it, read through a raw
// handle: what a forger with write access signs over.
func rawHead(t *testing.T, db *sql.DB) string {
	t.Helper()
	return audit.Head(rawEntries(t, db))
}

// forgedEntry describes one entry a forger appends: the actor, the event, the
// subject and the detail's leading tokens; signedDetail adds the signer and
// sigref tokens as the Store does unless rawDetail is set, and the row is
// written unless withoutRow is set.
type forgedEntry struct {
	by         Actor
	event      string
	subject    string
	detail     string
	rawDetail  string
	withoutRow bool
}

// appendSigned appends f, correctly sealed from the file's head, with rec's
// row at its seq, and bumps the generation as any write would. The sequential
// guard admits an append at the next seq, so no guard is dropped: this is
// exactly the access D14 grants to whoever can write the file.
func appendSigned(t *testing.T, db *sql.DB, f forgedEntry, rec signing.Record) int64 {
	t.Helper()
	entries := rawEntries(t, db)
	prev := audit.Entry{}
	if len(entries) > 0 {
		prev = entries[len(entries)-1]
	}
	detail := f.rawDetail
	if detail == "" {
		detail = signedDetail(f.detail, rec)
	}
	sealed, err := audit.Seal(prev, audit.Entry{
		Seq: prev.Seq + 1, TS: formatTime(time.Now()), Actor: f.by.Name, ActorType: string(f.by.Type),
		Event: f.event, Subject: f.subject, Detail: detail,
	})
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, insertAudit, sealed.Seq, sealed.TS, sealed.Actor, sealed.ActorType, sealed.Event, sealed.Subject,
		sealed.BeforeHash, sealed.AfterHash, sealed.Detail, sealed.PrevHash, sealed.Hash)
	if !f.withoutRow {
		mustExec(t, db, insertSignedRecordSQL, sealed.Seq, rec.Payload, rec.Signer, rec.Signature)
	}
	mustExec(t, db, `UPDATE meta SET value = value + 1 WHERE key = 'generation'`)
	return sealed.Seq
}

// forgeTrust appends a trust entry of event at version v naming ops, signed
// over the file's head by by's key, with actor as the entry's actor; the
// detail's tokens are the ones the Store writes.
func forgeTrust(t *testing.T, db *sql.DB, identity, event string, v int, by operator, actor Actor, ops ...operator) int64 {
	t.Helper()
	rec := signList(t, listFor(identity, rawHead(t, db), v, by, ops...), by.key)
	detail := fmt.Sprintf("%s=%d %s=%d", fieldVersion, v, fieldSigners, len(ops))
	return appendSigned(t, db, forgedEntry{by: actor, event: event, subject: trustSubject, detail: detail}, rec)
}

// wantCorruptNaming requires err to be ErrCorrupt whose text holds sentence.
func wantCorruptNaming(t *testing.T, label string, err error, sentence string) {
	t.Helper()
	if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), sentence) {
		t.Errorf("%s = %v, want ErrCorrupt saying %q", label, err, sentence)
	}
}

// openErrors opens path read-only and read-write, as a restarted processor
// and the CLI do, closes whatever opened, and returns each open's error under
// its name, so that a test can read the error itself and not only its verdict.
func openErrors(t *testing.T, path string) map[string]error {
	t.Helper()
	errs := make(map[string]error, 2)
	for name, opts := range map[string]OpenOptions{"read-only": {ReadOnly: true}, "read-write": {Policy: lifecycle.DefaultPolicy()}} {
		s, err := OpenWith(path, opts)
		if s != nil {
			_ = s.Close()
		}
		errs[name+" open"] = err
	}
	return errs
}

// opensRefuseNaming requires a read-only and a read-write open of path to
// fail at open with ErrCorrupt naming sentence: a restarted processor and the
// CLI alike refuse the file.
func opensRefuseNaming(t *testing.T, path, sentence string) {
	t.Helper()
	for name, err := range openErrors(t, path) {
		wantCorruptNaming(t, name, err, sentence)
	}
}

// forensicOpen opens path for inspection; the Store closes with the test.
func forensicOpen(t *testing.T, path string, root string) *Store {
	t.Helper()
	f, err := OpenWith(path, OpenOptions{Forensic: true, TrustRoot: root})
	if err != nil {
		t.Fatalf("forensic open: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// signerNames lists the names of a view's operators in list order.
func signerNames(view TrustView) []string {
	out := make([]string, 0, len(view.Signers))
	for _, op := range view.Signers {
		out = append(out, op.Name)
	}
	return out
}
