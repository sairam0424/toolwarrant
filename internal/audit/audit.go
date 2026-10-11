// Package audit is the hash chain behind the append-only audit log. It is pure:
// the catalog stores the entries, this package computes and checks the links.
//
// Each entry's Hash covers every field of the entry, including the previous
// entry's Hash, serialised as RFC 8785 canonical JSON. Changing, deleting,
// reordering or inserting any row therefore breaks verification from that row
// on. The chain alone cannot prove the log is complete: whoever can rewrite
// the whole file can rebuild a valid chain. Record Head() somewhere outside the
// database to detect that.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/sairam0424/toolwarrant/internal/gate"
)

// Genesis is the PrevHash of the first entry.
var Genesis = strings.Repeat("0", 64)

// Entry is one audit record.
type Entry struct {
	Seq        int64  `json:"seq"`
	TS         string `json:"ts"` // RFC 3339, UTC, nanosecond precision
	Actor      string `json:"actor"`
	ActorType  string `json:"actor_type"` // "human" or "system"
	Event      string `json:"event"`
	Subject    string `json:"subject"` // for example "server/tool"
	BeforeHash string `json:"before_hash"`
	AfterHash  string `json:"after_hash"`
	Detail     string `json:"detail"`
	PrevHash   string `json:"prev_hash"`
	Hash       string `json:"hash"`
}

// minSeq and maxSeq bound Seq to [-2^53, 2^53-1]. RFC 8785 serialises numbers
// as IEEE 754 doubles, which represent every integer in that range exactly and
// distinctly, whereas 2^53+1 rounds onto 2^53 and -2^53-1 onto -2^53: two
// entries differing only there would hash alike, so one past each end is
// refused.
const (
	maxSeq = int64(1)<<53 - 1
	minSeq = -(int64(1) << 53)
)

// validate rejects entries whose hash would not identify them uniquely. Invalid
// UTF-8 is re-encoded as U+FFFD by JSON, so two different byte strings would
// share a hash and a change between them would go unnoticed.
func validate(e Entry) error {
	// Only exactness matters here. Whether the sequence runs 1..n is Verify's job.
	if e.Seq < minSeq || e.Seq > maxSeq {
		return fmt.Errorf("audit: seq %d is outside [%d, %d]", e.Seq, minSeq, maxSeq)
	}
	fields := []struct {
		name  string
		value string
	}{
		{"ts", e.TS}, {"actor", e.Actor}, {"actor_type", e.ActorType}, {"event", e.Event},
		{"subject", e.Subject}, {"before_hash", e.BeforeHash}, {"after_hash", e.AfterHash},
		{"detail", e.Detail}, {"prev_hash", e.PrevHash},
	}
	for _, f := range fields {
		if !utf8.ValidString(f.value) {
			return fmt.Errorf("audit: field %s is not valid UTF-8", f.name)
		}
	}
	return nil
}

// compute returns the hash of e over every field except Hash itself.
func compute(e Entry) (string, error) {
	if err := validate(e); err != nil {
		return "", err
	}
	hashless := e
	hashless.Hash = ""
	raw, err := json.Marshal(struct {
		Seq        int64  `json:"seq"`
		TS         string `json:"ts"`
		Actor      string `json:"actor"`
		ActorType  string `json:"actor_type"`
		Event      string `json:"event"`
		Subject    string `json:"subject"`
		BeforeHash string `json:"before_hash"`
		AfterHash  string `json:"after_hash"`
		Detail     string `json:"detail"`
		PrevHash   string `json:"prev_hash"`
	}{hashless.Seq, hashless.TS, hashless.Actor, hashless.ActorType, hashless.Event,
		hashless.Subject, hashless.BeforeHash, hashless.AfterHash, hashless.Detail, hashless.PrevHash})
	if err != nil {
		return "", fmt.Errorf("audit: encode entry: %w", err)
	}
	canon, err := gate.Canonical(raw)
	if err != nil {
		return "", fmt.Errorf("audit: canonicalize entry: %w", err)
	}
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:]), nil
}

// HashOf returns the hash of e computed from its fields alone, ignoring the
// Hash field it carries: the value Seal stores in Hash for an entry with these
// fields. It exists so that a reader can identify an entry by what its fields
// say rather than by the hash column it was stored with, which whoever can
// write the log can write too (the catalog's verified chain, D15). Verify and
// VerifyFrom keep their behaviour; this is the same computation exposed.
func HashOf(e Entry) (string, error) { return compute(e) }

// Seal fills in PrevHash and Hash for the entry that follows prev. Pass the
// zero Entry (Hash "") for the first entry.
func Seal(prev Entry, e Entry) (Entry, error) {
	e.PrevHash = prev.Hash
	if e.PrevHash == "" {
		e.PrevHash = Genesis
	}
	h, err := compute(e)
	if err != nil {
		return Entry{}, err
	}
	e.Hash = h
	return e, nil
}

// BrokenError says where verification failed.
type BrokenError struct {
	Seq    int64
	Reason string
}

func (b *BrokenError) Error() string {
	return fmt.Sprintf("audit: chain broken at seq %d: %s", b.Seq, b.Reason)
}

// Verify checks that entries, in order, form an unbroken chain starting at
// sequence 1. It returns *BrokenError on the first problem.
func Verify(entries []Entry) error { return VerifyFrom(Entry{}, entries) }

// VerifyFrom checks that entries, in order, continue the chain after prev: the
// first entry must carry prev.Seq+1 and prev.Hash as its PrevHash (Genesis when
// prev is the zero Entry), and every entry must re-seal from the one before.
// It exists so that a reader which has already verified the log up to prev can
// verify only what was appended since, instead of reading the whole log again;
// it returns *BrokenError on the first problem, as Verify does.
func VerifyFrom(prev Entry, entries []Entry) error {
	prevHash := prev.Hash
	if prevHash == "" {
		prevHash = Genesis
	}
	for i, e := range entries {
		want := prev.Seq + int64(i+1)
		if e.Seq != want {
			return &BrokenError{Seq: e.Seq, Reason: fmt.Sprintf("expected seq %d (gap or reorder)", want)}
		}
		if e.PrevHash != prevHash {
			return &BrokenError{Seq: e.Seq, Reason: "prev_hash does not match the previous entry"}
		}
		h, err := compute(e)
		if err != nil {
			return &BrokenError{Seq: e.Seq, Reason: err.Error()}
		}
		if h != e.Hash {
			return &BrokenError{Seq: e.Seq, Reason: "hash does not match the entry contents"}
		}
		prevHash = e.Hash
	}
	return nil
}

// Head returns the hash of the last entry, or Genesis for an empty log.
func Head(entries []Entry) string {
	if len(entries) == 0 {
		return Genesis
	}
	return entries[len(entries)-1].Hash
}
