package catalog

import (
	"errors"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// AuditHead is the pin of the verified chain after the file check every view
// runs, so that an export can record the exact log it mirrors (D21 e): it is
// the genesis on an empty log, equals what the operator's own walk
// (VerifyAudit) reports after every decision, agrees between a long-lived and
// a fresh Store, moves when the log grows, and refuses a replaced file as
// every other read does instead of vouching for the head of a file that is
// gone.
func TestAuditHead_IsTheVerifiedHeadAndMovesWithTheLog(t *testing.T) {
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	wantHead := func(when string) string {
		t.Helper()
		head, err := s.AuditHead(bg)
		if err != nil {
			t.Fatalf("AuditHead %s: %v", when, err)
		}
		rec, err := s.VerifyAudit(bg)
		if err != nil {
			t.Fatalf("VerifyAudit %s: %v", when, err)
		}
		if head != rec.Head {
			t.Fatalf("AuditHead %s = %s, VerifyAudit reports %s", when, head, rec.Head)
		}
		if pin := s.loadPin(); (pin.seq == 0 && head != audit.Genesis) || (pin.seq != 0 && pin.hash != head) {
			t.Fatalf("AuditHead %s = %s, the pin is %+v", when, head, pin)
		}
		return head
	}
	if head := wantHead("on an empty log"); head != audit.Genesis {
		t.Fatalf("AuditHead on an empty log = %s, want the genesis", head)
	}

	approvedEcho(t, s)
	first := wantHead("after the approval")
	if first == audit.Genesis {
		t.Fatal("AuditHead after the approval is still the genesis")
	}
	ro, err := OpenWith(path, OpenOptions{ReadOnly: true, MustExist: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ro.Close() }()
	if head, err := ro.AuditHead(bg); err != nil || head != first {
		t.Fatalf("AuditHead through a fresh read-only Store = %s, %v; want %s", head, err, first)
	}

	mustCrawl(t, s, "alpha", tool("echo", "v2"))
	second := wantHead("after the crawl")
	if second == first {
		t.Fatal("AuditHead did not move although the crawl appended entries")
	}
	if head, err := ro.AuditHead(bg); err != nil || head != second {
		t.Fatalf("AuditHead through the read-only Store after the crawl = %s, %v; want %s", head, err, second)
	}

	removeDatabase(t, path)
	fresh := openStore(t, path, lifecycle.DefaultPolicy())
	if head, err := fresh.AuditHead(bg); err != nil || head != audit.Genesis {
		t.Fatalf("AuditHead of the fresh catalog = %s, %v; want the genesis", head, err)
	}
	if _, err := s.AuditHead(bg); !errors.Is(err, ErrReplaced) {
		t.Fatalf("AuditHead on the replaced file = %v, want ErrReplaced: the old head must not be recorded for a file that is gone", err)
	}
}
