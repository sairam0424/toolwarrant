package audit_test

// Fuzz test: Verify, Head and Seal must never panic on arbitrary entries, and
// must stay consistent with each other. Under plain `go test` the seed corpus
// below runs as ordinary test cases; `go test -fuzz FuzzVerify` explores
// further.

import (
	"errors"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/audit"
)

const (
	fuzzMaxEntries = 6
	fuzzModes      = 3
)

// fuzzEntries builds up to fuzzMaxEntries entries from the fuzz inputs. In
// mode 0 the entries are raw and unsealed, in mode 1 they are sealed into a
// chain starting at seq, in mode 2 the chain is sealed and then one entry is
// damaged. ok is false when Seal refused the input (which is allowed).
func fuzzEntries(count uint8, seq int64, a, b, c, d string, mode uint8) (entries []audit.Entry, ok bool) {
	n := int(count) % (fuzzMaxEntries + 1)
	prev := audit.Entry{}
	for i := 0; i < n; i++ {
		e := audit.Entry{
			Seq: seq + int64(i), TS: a, Actor: b, ActorType: c, Event: d,
			Subject: a + b, BeforeHash: c, AfterHash: d, Detail: a + c,
		}
		if mode%fuzzModes == 0 {
			e.PrevHash, e.Hash = c, d
			entries = append(entries, e)
			continue
		}
		sealed, err := audit.Seal(prev, e)
		if err != nil {
			return nil, false
		}
		entries = append(entries, sealed)
		prev = sealed
	}
	if mode%fuzzModes == 2 && len(entries) > 0 {
		entries[len(entries)/2].Detail += a
	}
	return entries, true
}

func FuzzVerifyNeverPanics(f *testing.F) {
	f.Add(uint8(3), int64(1), "alice", "bob", "human", "version.approved", uint8(1))
	f.Add(uint8(3), int64(1), "alice", "bob", "human", "version.approved", uint8(2))
	f.Add(uint8(4), int64(0), "", "", "", "", uint8(0))
	f.Add(uint8(2), int64(1), "a\xffb", "\xfe", "\x00", " ", uint8(1))
	f.Add(uint8(5), int64(-7), `"}`, `\`, "\n", "<&>", uint8(2))
	f.Add(uint8(6), int64(1<<62), "x", "y", "z", "w", uint8(1))
	f.Add(uint8(1), int64(1), audit.Genesis, audit.Genesis, audit.Genesis, audit.Genesis, uint8(0))

	f.Fuzz(func(t *testing.T, count uint8, seq int64, a, b, c, d string, mode uint8) {
		entries, ok := fuzzEntries(count, seq, a, b, c, d, mode)
		if !ok {
			return
		}
		err := audit.Verify(entries)
		var broken *audit.BrokenError
		if err != nil && !errors.As(err, &broken) {
			t.Fatalf("Verify returned %T (%v), want nil or *BrokenError", err, err)
		}
		head := audit.Head(entries)
		if len(entries) == 0 && head != audit.Genesis {
			t.Fatalf("Head(empty) = %q", head)
		}
		if len(entries) > 0 && head != entries[len(entries)-1].Hash {
			t.Fatalf("Head = %q, want the last Hash %q", head, entries[len(entries)-1].Hash)
		}
		// A chain that Seal produced from seq 1 must verify; the same chain with
		// one damaged entry must not.
		if seq == 1 && mode%fuzzModes == 1 && err != nil {
			t.Fatalf("a sealed chain from seq 1 failed to verify: %v", err)
		}
		if seq == 1 && mode%fuzzModes == 2 && len(entries) > 0 && a != "" && err == nil {
			t.Fatalf("a damaged chain verified: %+v", entries)
		}
	})
}
