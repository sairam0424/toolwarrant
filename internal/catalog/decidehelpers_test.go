package catalog

import (
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
	"github.com/sairam0424/toolwarrant/internal/signing"
)

// The fixtures of the signed-decision tests: a decision payload signed over
// the head a Store hands out, the Decide call that records it, and the
// forgeries a writer with a SQLite shell makes against the entries of a
// decision, each a correctly sealed entry appended past the head.

// decisionOf builds the payload of a decision by by, for the catalog with
// identity, over head.
func decisionOf(identity, head string, by operator, kind signing.Kind, server, tool, digest string) signing.Decision {
	return signing.Decision{
		Actor: by.name, Catalog: identity, Digest: digest, Kind: kind, PrevHead: head,
		Server: server, SignedAt: listSignedAt(), Signer: by.fp(), Tool: tool,
	}
}

// signDecisionPayload marshals d and signs it under the decision namespace
// with k.
func signDecisionPayload(t *testing.T, d signing.Decision, k operator) *signing.Record {
	t.Helper()
	payload, err := signing.MarshalDecision(d)
	if err != nil {
		t.Fatalf("MarshalDecision: %v", err)
	}
	rec := signBytes(t, payload, k.key, signing.NamespaceDecision)
	return &rec
}

// signDecision signs a decision by by over s's current head.
func signDecision(t *testing.T, s *Store, by operator, kind signing.Kind, server, tool, digest string) *signing.Record {
	t.Helper()
	return signDecisionPayload(t, decisionOf(s.identity, mustHead(t, s), by, kind, server, tool, digest), by)
}

// decisionFor is the Decision Decide takes for a signed decision by by.
func decisionFor(by operator, kind signing.Kind, server, tool, digest string, rec *signing.Record) Decision {
	return Decision{Kind: kind, Server: server, Tool: tool, Digest: digest, By: by.actor(), Signed: rec}
}

// mustDecide signs a decision over s's current head and records it, failing
// the test on refusal.
func mustDecide(t *testing.T, s *Store, by operator, kind signing.Kind, server, tool, digest string) Receipt {
	t.Helper()
	rec := signDecision(t, s, by, kind, server, tool, digest)
	r, err := s.Decide(bg, decisionFor(by, kind, server, tool, digest, rec))
	if err != nil {
		t.Fatalf("Decide(%s %s/%s by %s): %v", kind, server, tool, by.name, err)
	}
	return r
}

// entriesOfTransaction returns the entries that share the decision.signed
// entry's time, in seq order: the entries of its transaction.
func entriesOfTransaction(t *testing.T, s *Store, seq int64) []audit.Entry {
	t.Helper()
	entries, err := s.AuditEntries(bg, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	var signed audit.Entry
	for _, e := range entries {
		if e.Seq == seq {
			signed = e
		}
	}
	if signed.Seq == 0 || signed.Event != evDecisionSigned {
		t.Fatalf("entry %d is not a decision.signed entry", seq)
	}
	var out []audit.Entry
	for _, e := range entries {
		if e.TS == signed.TS {
			out = append(out, e)
		}
	}
	return out
}

// appendEntry appends e, correctly sealed from the file's head, with the time
// now unless e names one, and bumps the generation as any write would. The
// sequential guard admits an append at the next seq, so no guard is dropped:
// this is exactly the access D14 grants to whoever can write the file.
func appendEntry(t *testing.T, db *sql.DB, e audit.Entry) int64 {
	t.Helper()
	entries := rawEntries(t, db)
	prev := audit.Entry{}
	if len(entries) > 0 {
		prev = entries[len(entries)-1]
	}
	e.Seq = prev.Seq + 1
	if e.TS == "" {
		e.TS = formatTime(time.Now())
	}
	sealed, err := audit.Seal(prev, e)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, insertAudit, sealed.Seq, sealed.TS, sealed.Actor, sealed.ActorType, sealed.Event, sealed.Subject,
		sealed.BeforeHash, sealed.AfterHash, sealed.Detail, sealed.PrevHash, sealed.Hash)
	mustExec(t, db, `UPDATE meta SET value = value + 1 WHERE key = 'generation'`)
	return sealed.Seq
}

// toolEntry describes one forged entry about a tool: the actor, the event, the
// subject, the digest the event concerns, the approved digest before and
// after, the state transition and the note after the four fields.
type toolEntry struct {
	by       Actor
	event    string
	subject  string
	digest   string
	before   string
	after    string
	from, to lifecycle.State
	lastSeen string
	note     string
	ts       string
}

// entry renders the forged entry as the Store would have written it.
func (f toolEntry) entry() audit.Entry {
	detail := fmt.Sprintf("%s=%s %s=%s %s=%s %s=0->0%s", fieldDigest, orNoDigest(f.digest), fieldState, transition(string(f.from), string(f.to)),
		fieldLastSeen, orNoDigest(f.lastSeen), fieldProposals, f.note)
	return audit.Entry{TS: f.ts, Actor: f.by.Name, ActorType: string(f.by.Type), Event: f.event, Subject: f.subject,
		BeforeHash: f.before, AfterHash: f.after, Detail: detail}
}

// forgedApproval is a version.approved entry about alpha/<tool> approving
// digest by by, as the Store writes one from pending_review, with note.
func forgedApproval(by Actor, tool, digest, note string) toolEntry {
	return toolEntry{by: by, event: string(lifecycle.EvApproved), subject: "alpha/" + tool, digest: digest, after: digest,
		from: lifecycle.PendingReview, to: lifecycle.Enabled, lastSeen: digest, note: note}
}

// forgeDecision appends a decision.signed entry about subject by by's key with
// the tokens the Store writes, signed over the file's head, and returns its
// seq and the record.
func forgeDecision(t *testing.T, db *sql.DB, identity string, by operator, actor Actor, kind signing.Kind, server, tool, digest string) (int64, *signing.Record) {
	t.Helper()
	rec := signDecisionPayload(t, decisionOf(identity, rawHead(t, db), by, kind, server, tool, digest), by)
	f := forgedEntry{by: actor, event: evDecisionSigned, subject: decisionSubject(kind, server, tool), detail: decisionDetail(kind, digest)}
	return appendSigned(t, db, f, *rec), rec
}

// rawEntryAt reads one entry of the file through a raw handle.
func rawEntryAt(t *testing.T, db *sql.DB, seq int64) audit.Entry {
	t.Helper()
	for _, e := range rawEntries(t, db) {
		if e.Seq == seq {
			return e
		}
	}
	t.Fatalf("no entry at seq %d", seq)
	return audit.Entry{}
}

// pendingSum is trustedCatalog with sum's v1 proposal re-read: the digest the
// signed approval names.
func pendingSum(t *testing.T) string {
	t.Helper()
	return digestOf(t, "sum", "v1")
}
