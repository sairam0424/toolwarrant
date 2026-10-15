package catalog

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/signing"
)

// The rule 1 probes against a trust record (D22 (c); plan section 1, rule 1):
// the entry and the record disagree, or the record does not verify or parse.
// Each is checked on every reader as the rule 3 probes of trustwalk_test.go
// are (runTrustForgery).

// bindingForgeries are the rule 1 probes against a trust record: the entry
// and the record disagree, or the record does not verify or parse. Each is a
// version 3 rotation by alice on the trusted catalog with one twist.
func bindingForgeries() []trustForgery {
	rotate := func(t *testing.T, s *Store, db *sql.DB, alice, bob, carol operator) signing.Record {
		t.Helper()
		return signList(t, listFor(s.identity, rawHead(t, db), 3, alice, alice, bob, carol), alice.key)
	}
	entry := func(by Actor, detail string) forgedEntry {
		return forgedEntry{by: by, event: evTrustRotated, subject: trustSubject, detail: detail}
	}
	const good = "version=3 signers=3"
	return []trustForgery{
		{"the version token disagrees", false,
			func(t *testing.T, s *Store, db *sql.DB, alice, bob, carol operator) int64 {
				return appendSigned(t, db, entry(alice.actor(), "version=9 signers=3"), rotate(t, s, db, alice, bob, carol))
			},
			func(seq int64, alice, bob operator) string {
				return fmt.Sprintf(`audit entry %d says version="9" but its signed trust list is version 3`, seq)
			}},
		{"the signers token disagrees", false,
			func(t *testing.T, s *Store, db *sql.DB, alice, bob, carol operator) int64 {
				return appendSigned(t, db, entry(alice.actor(), "version=3 signers=1"), rotate(t, s, db, alice, bob, carol))
			},
			func(seq int64, alice, bob operator) string {
				return fmt.Sprintf(`audit entry %d says signers="1" but its signed trust list names 3`, seq)
			}},
		{"the payload names another prev_head", false,
			func(t *testing.T, s *Store, db *sql.DB, alice, bob, carol operator) int64 {
				l := listFor(s.identity, strings.Repeat("ab", 32), 3, alice, alice, bob, carol)
				return appendSigned(t, db, entry(alice.actor(), good), signList(t, l, alice.key))
			},
			func(seq int64, alice, bob operator) string {
				return fmt.Sprintf("signed record of entry %d names %s as prev_head but the entry's prev_hash is", seq, strings.Repeat("ab", 32))
			}},
		{"the payload names another catalog", false,
			func(t *testing.T, s *Store, db *sql.DB, alice, bob, carol operator) int64 {
				l := listFor(strings.Repeat("cd", 16), rawHead(t, db), 3, alice, alice, bob, carol)
				return appendSigned(t, db, entry(alice.actor(), good), signList(t, l, alice.key))
			},
			func(seq int64, alice, bob operator) string {
				return fmt.Sprintf("signed record of entry %d names catalog %s, not this one", seq, strings.Repeat("cd", 16))
			}},
		{"the payload is a decision under the trust namespace", false,
			func(t *testing.T, s *Store, db *sql.DB, alice, bob, carol operator) int64 {
				d := signing.Decision{Actor: "alice", Catalog: s.identity, Digest: digestOf(t, "echo", "v1"), Kind: signing.KindApprove,
					PrevHead: rawHead(t, db), Server: "alpha", SignedAt: listSignedAt(), Signer: alice.fp(), Tool: "echo"}
				payload, err := signing.MarshalDecision(d)
				if err != nil {
					t.Fatal(err)
				}
				return appendSigned(t, db, entry(alice.actor(), good), signBytes(t, payload, alice.key, signing.NamespaceTrust))
			},
			func(seq int64, alice, bob operator) string {
				return fmt.Sprintf("signed record of entry %d is not a canonical trust list", seq)
			}},
		{"the payload is not canonical", false,
			func(t *testing.T, s *Store, db *sql.DB, alice, bob, carol operator) int64 {
				payload, err := signing.MarshalTrustList(listFor(s.identity, rawHead(t, db), 3, alice, alice, bob, carol))
				if err != nil {
					t.Fatal(err)
				}
				spaced := append([]byte("{ "), payload[1:]...)
				return appendSigned(t, db, entry(alice.actor(), good), signBytes(t, spaced, alice.key, signing.NamespaceTrust))
			},
			func(seq int64, alice, bob operator) string {
				return fmt.Sprintf("signed record of entry %d is not a canonical trust list", seq)
			}},
		{"the payload names another signer than the key that signed", false,
			func(t *testing.T, s *Store, db *sql.DB, alice, bob, carol operator) int64 {
				l := listFor(s.identity, rawHead(t, db), 3, bob, alice, bob, carol)
				return appendSigned(t, db, entry(alice.actor(), good), signList(t, l, alice.key))
			},
			func(seq int64, alice, bob operator) string {
				return fmt.Sprintf("signed record of entry %d names signer", seq) + " " + "SHA256:"
			}},
		{"the signer token disagrees", false,
			func(t *testing.T, s *Store, db *sql.DB, alice, bob, carol operator) int64 {
				rec := rotate(t, s, db, alice, bob, carol)
				raw := fmt.Sprintf("%s signer=%s sigref=%s", good, bob.fp(), signing.RecordDigest(rec))
				return appendSigned(t, db, forgedEntry{by: alice.actor(), event: evTrustRotated, subject: trustSubject, rawDetail: raw}, rec)
			},
			func(seq int64, alice, bob operator) string { return fmt.Sprintf("audit entry %d names signer", seq) }},
		{"the sigref token disagrees", false,
			func(t *testing.T, s *Store, db *sql.DB, alice, bob, carol operator) int64 {
				rec := rotate(t, s, db, alice, bob, carol)
				raw := fmt.Sprintf("%s signer=%s sigref=%s", good, alice.fp(), strings.Repeat("ef", 32))
				return appendSigned(t, db, forgedEntry{by: alice.actor(), event: evTrustRotated, subject: trustSubject, rawDetail: raw}, rec)
			},
			func(seq int64, alice, bob operator) string {
				return fmt.Sprintf("the signed record of audit entry %d was replaced", seq)
			}},
		{"a system actor", false,
			func(t *testing.T, s *Store, db *sql.DB, alice, bob, carol operator) int64 {
				return appendSigned(t, db, entry(crawler, good), rotate(t, s, db, alice, bob, carol))
			},
			func(seq int64, alice, bob operator) string {
				return fmt.Sprintf(`audit entry %d is a trust.rotated by "crawler", a "system" actor; only a person signs`, seq)
			}},
		{"no row at the seq", false,
			func(t *testing.T, s *Store, db *sql.DB, alice, bob, carol operator) int64 {
				f := entry(alice.actor(), good)
				f.withoutRow = true
				return appendSigned(t, db, f, rotate(t, s, db, alice, bob, carol))
			},
			func(seq int64, alice, bob operator) string {
				return fmt.Sprintf("audit entry %d is a trust.rotated with no signed record at its seq", seq)
			}},
		{"another subject", false,
			func(t *testing.T, s *Store, db *sql.DB, alice, bob, carol operator) int64 {
				f := entry(alice.actor(), good)
				f.subject = "alpha"
				return appendSigned(t, db, f, rotate(t, s, db, alice, bob, carol))
			},
			func(seq int64, alice, bob operator) string {
				return fmt.Sprintf(`audit entry %d is a trust.rotated about "alpha", not @trust`, seq)
			}},
		{"a signature that does not verify over the stored payload", false,
			func(t *testing.T, s *Store, db *sql.DB, alice, bob, carol operator) int64 {
				rec := rotate(t, s, db, alice, bob, carol)
				rec.Payload = append([]byte(nil), rec.Payload...)
				rec.Payload[len(rec.Payload)/2] ^= 0x01 // the tokens are computed over the altered record, so only the signature refuses it
				return appendSigned(t, db, entry(alice.actor(), good), rec)
			},
			func(seq int64, alice, bob operator) string {
				return fmt.Sprintf("signed record of entry %d: the signature by %s does not verify over the stored payload", seq, alice.fp())
			}},
	}
}

// Every rule 1 refusal of a trust record, with its sentence, checked on every
// reader as the rule 3 probes are; Integrity counts them as invalid records.
func TestWalk_RefusesATrustRecordWhoseTokensOrPayloadDisagreeWithTheEntry(t *testing.T) {
	t.Parallel()
	for _, tc := range bindingForgeries() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runTrustForgery(t, tc, 1, 0)
		})
	}
}
