package audit_test

import (
	"testing"

	"github.com/sairam0424/toolwarrant/internal/audit"
)

// HashOf is the seal's computation exposed: for a sealed entry it returns the
// Hash field, it ignores whatever Hash field the entry carries, and it changes
// with every content field, so a reader can tell an entry by its fields alone.
func TestHashOf_IsTheSealComputationAndIgnoresTheHashField(t *testing.T) {
	sealed := sealOn(t, audit.Entry{}, sampleEntry(1))
	h, err := audit.HashOf(sealed)
	if err != nil || h != sealed.Hash {
		t.Fatalf("HashOf(sealed) = %s, %v; want the Hash field %s", h, err, sealed.Hash)
	}
	withOtherColumn := sealed
	withOtherColumn.Hash = "not a hash"
	if h2, err := audit.HashOf(withOtherColumn); err != nil || h2 != h {
		t.Errorf("HashOf with another Hash field = %s, %v; the field must not take part", h2, err)
	}
	for name, change := range map[string]func(*audit.Entry){
		"after_hash": func(e *audit.Entry) { e.AfterHash = "x" + e.AfterHash[1:] },
		"actor":      func(e *audit.Entry) { e.Actor = "mallory" },
		"prev_hash":  func(e *audit.Entry) { e.PrevHash = "f" + e.PrevHash[1:] },
		"detail":     func(e *audit.Entry) { e.Detail += " edited" },
		"seq":        func(e *audit.Entry) { e.Seq++ },
	} {
		edited := sealed
		change(&edited)
		if h2, err := audit.HashOf(edited); err != nil || h2 == h {
			t.Errorf("HashOf after editing %s = %s, %v; want another hash", name, h2, err)
		}
	}
	if _, err := audit.HashOf(audit.Entry{Seq: 1, Actor: "\xff"}); err == nil {
		t.Error("HashOf of an entry with invalid UTF-8 = nil, want the validation error")
	}
}
