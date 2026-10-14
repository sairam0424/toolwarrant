package catalog

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

// headSeen is one ApprovedWithHead result: the head it returned and how many
// approved tools came with it.
type headSeen struct {
	head  string
	tools int
}

// headReaders calls ApprovedWithHead on every Store in stores until stop is
// closed and collects what each call returned; the first error, if any, is
// kept. It returns a function that stops the readers and hands back the
// results.
func headReaders(stores []*Store, stop <-chan struct{}) func() ([]headSeen, string) {
	var (
		mu       sync.Mutex
		seen     []headSeen
		firstErr atomic.Pointer[string]
		wg       sync.WaitGroup
	)
	for _, r := range stores {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				tools, head, err := r.ApprovedWithHead(bg)
				if err != nil {
					msg := err.Error()
					firstErr.CompareAndSwap(nil, &msg)
					continue
				}
				mu.Lock()
				seen = append(seen, headSeen{head: head, tools: len(tools)})
				mu.Unlock()
			}
		})
	}
	return func() ([]headSeen, string) {
		wg.Wait()
		if msg := firstErr.Load(); msg != nil {
			return seen, *msg
		}
		return seen, ""
	}
}

// The export records the head beside the approvals it mirrors, so the two must
// come from one snapshot (D21 e). One writer toggles the only approved tool off
// and on for pinRaceDuration under a policy that restores the approval on
// enable, and after every commit records the head the log then has with the
// number of approved tools that commit left; two readers, one on the writer's
// own Store and one on a read-only Store of the same file, call
// ApprovedWithHead throughout. Every head a reader returned must be one the
// writer recorded, with the approval count that head's commit left: a head
// taken in a second transaction, or read after the walk lock was released,
// pairs the approvals of one snapshot with the head of a later commit, which
// this test reports as a mismatch (it did so on the two-call export: see the
// decision record).
func TestApprovedWithHead_HeadAndToolsComeFromOneSnapshot(t *testing.T) {
	policy := lifecycle.DefaultPolicy()
	policy.ReEnableRequiresReview = false
	w, path := newStoreAt(t, policy)
	approvedEcho(t, w)
	ro, err := OpenWith(path, OpenOptions{ReadOnly: true, MustExist: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ro.Close() }()
	states := map[string]int{}
	record := func(when string, approved int) {
		t.Helper()
		head, err := w.AuditHead(bg)
		if err != nil {
			t.Fatalf("AuditHead %s: %v", when, err)
		}
		states[head] = approved
	}
	record("before the writes", 1)
	stop := make(chan struct{})
	collect := headReaders([]*Store{w, ro}, stop)
	writes := 0
	for deadline := time.Now().Add(pinRaceDuration); time.Now().Before(deadline); writes++ {
		if writes%2 == 0 {
			if err := w.Disable(bg, "alpha", "echo", alice); err != nil {
				close(stop)
				t.Fatalf("Disable %d: %v", writes, err)
			}
			record("after the disable", 0)
			continue
		}
		if err := w.Enable(bg, "alpha", "echo", alice); err != nil {
			close(stop)
			t.Fatalf("Enable %d: %v", writes, err)
		}
		record("after the enable", 1)
	}
	close(stop)
	seen, readErr := collect()
	t.Logf("%d writes, %d ApprovedWithHead calls, %d distinct heads", writes, len(seen), len(states))
	if readErr != "" {
		t.Fatalf("a reader failed: %s", readErr)
	}
	if writes < 2 || len(seen) == 0 {
		t.Fatalf("the race was not exercised: %d writes, %d reads", writes, len(seen))
	}
	mismatches, unknown := 0, 0
	for _, r := range seen {
		want, ok := states[r.head]
		switch {
		case !ok:
			unknown++
		case want != r.tools:
			mismatches++
		}
	}
	if mismatches != 0 || unknown != 0 {
		t.Errorf("%d results paired approvals with the head of another commit and %d named a head the writer never committed; the head and the approvals must come from one snapshot", mismatches, unknown)
	}
}
