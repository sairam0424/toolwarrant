package catalog

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// Each goroutine owns one server, so the outcome of every operation is known in
// advance; what is under test is that writes from many goroutines and two
// handles (standing in for two processes) on one file all succeed, serialise
// cleanly, and leave one unbroken hash chain. The default busy timeout must
// carry a loaded machine.
func TestConcurrency_ManyWritersOnTwoHandles(t *testing.T) {
	path := dbPath(t)
	handles := []*Store{
		openStore(t, path, lifecycle.DefaultPolicy()),
		openStore(t, path, lifecycle.DefaultPolicy()),
	}
	const (
		writers = 8
		rounds  = 10
	)
	for i := 0; i < writers; i++ {
		mustAddServer(t, handles[i%2], fmt.Sprintf("s%d", i))
	}
	start := mustGeneration(t, handles[0])

	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s, server := handles[i%2], fmt.Sprintf("s%d", i)
			for r := 0; r < rounds; r++ {
				variant := fmt.Sprintf("v%d", r)
				if _, err := s.RecordCrawl(bg, crawlFor(server, tool("echo", variant)), crawler); err != nil {
					t.Errorf("writer %d round %d: crawl: %v", i, r, err)
					return
				}
				if err := s.Approve(bg, server, "echo", digestOf(t, "echo", variant), bob); err != nil {
					t.Errorf("writer %d round %d: approve: %v", i, r, err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
	if t.Failed() {
		return
	}

	want := start + int64(writers*rounds*2)
	for i, s := range handles {
		if got := mustGeneration(t, s); got != want {
			t.Errorf("handle %d: generation %d, want %d", i, got, want)
		}
	}
	sum, err := handles[1].VerifyAudit(bg)
	if err != nil {
		t.Fatalf("VerifyAudit after concurrent writers: %v", err)
	}
	// Per round: discovered+proposed (first) or superseded+proposed+drifted, then approved(+superseded).
	if sum.Entries < writers*rounds*3 {
		t.Errorf("only %d audit entries", sum.Entries)
	}
	for i := 0; i < writers; i++ {
		v := mustTool(t, handles[0], fmt.Sprintf("s%d", i), "echo")
		if v.State != lifecycle.Enabled || v.Approved != digestOf(t, "echo", fmt.Sprintf("v%d", rounds-1)) || v.Versions != rounds {
			t.Errorf("server s%d ended as %+v", i, v)
		}
	}
}

// Exactly one of several simultaneous approvals of the same proposal wins; the
// rest see the tool already enabled. No interleaving can approve twice.
func TestConcurrency_OnlyOneApprovalOfAProposalWins(t *testing.T) {
	path := dbPath(t)
	handles := []*Store{
		openStore(t, path, lifecycle.DefaultPolicy()),
		openStore(t, path, lifecycle.DefaultPolicy()),
	}
	mustAddServer(t, handles[0], "alpha")
	mustCrawl(t, handles[0], "alpha", tool("echo", "v1"))
	d := digestOf(t, "echo", "v1")

	const contenders = 10
	var wins, refused atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			approver := Actor{Name: fmt.Sprintf("approver%d", i), Type: ActorHuman}
			switch err := handles[i%2].Approve(bg, "alpha", "echo", d, approver); {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, lifecycle.ErrInvalidTransition):
				refused.Add(1)
			default:
				t.Errorf("contender %d: unexpected error %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	if wins.Load() != 1 || refused.Load() != contenders-1 {
		t.Fatalf("wins = %d, refused = %d", wins.Load(), refused.Load())
	}
	if n := countEvents(t, handles[0], "version.approved"); n != 1 {
		t.Errorf("%d approval events", n)
	}
	if _, err := handles[0].VerifyAudit(bg); err != nil {
		t.Fatal(err)
	}
}

// A reader on one handle must always see a snapshot whose policy belongs to
// its generation, never a generation ahead of or behind its data, while another
// handle keeps writing. The upstream flips between two definitions, so every
// crawl moves LastSeen without ever adding a third version.
func TestConcurrency_SnapshotMatchesItsGeneration(t *testing.T) {
	path := dbPath(t)
	writer := openStore(t, path, lifecycle.DefaultPolicy())
	reader := openStore(t, path, lifecycle.DefaultPolicy())
	mustAddServer(t, writer, "alpha")
	base := mustGeneration(t, writer) // crawl k leaves the generation at base+k
	const crawls = 40
	variant := func(k int64) string { return fmt.Sprintf("v%d", k%2) }

	var writerFailed atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		for k := int64(1); k <= crawls; k++ {
			if _, err := writer.RecordCrawl(bg, crawlFor("alpha", tool("echo", variant(k))), crawler); err != nil {
				t.Errorf("crawl %d: %v", k, err)
				writerFailed.Store(true)
				return
			}
		}
	}()
	defer func() { <-done }() // never leave the writer running after the test

	var last int64
	for {
		snap, err := reader.Snapshot(bg, "alpha")
		if err != nil {
			t.Fatalf("Snapshot: %v", err)
		}
		if snap.Generation < last {
			t.Fatalf("generation went backwards: %d after %d", snap.Generation, last)
		}
		last = snap.Generation
		if k := snap.Generation - base; k > 0 {
			if got, want := snap.Tools["echo"].LastSeen, digestOf(t, "echo", variant(k)); got != want {
				t.Fatalf("snapshot at generation %d (crawl %d) shows another definition", snap.Generation, k)
			}
		}
		if snap.Generation == base+crawls {
			return
		}
		select {
		case <-done:
			if writerFailed.Load() {
				return // already reported
			}
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

// A writer in another process holds the file lock: our write waits for it
// (busy timeout) instead of failing.
func TestConcurrency_WaitingForTheWriteLock(t *testing.T) {
	path := dbPath(t)
	holder := openStore(t, path, lifecycle.DefaultPolicy())
	other := openStore(t, path, lifecycle.DefaultPolicy())
	mustAddServer(t, holder, "alpha")

	const hold = 300 * time.Millisecond
	locked, release := make(chan struct{}), make(chan struct{})
	var holding sync.WaitGroup
	holding.Add(1)
	go func() {
		defer holding.Done()
		// Nothing is written before the signal: the lock must already be held
		// because the transaction began with BEGIN IMMEDIATE.
		err := holder.inTx(bg, func(*txn) error {
			close(locked)
			<-release
			return nil
		})
		if err != nil {
			t.Errorf("lock holder: %v", err)
		}
	}()
	<-locked

	// Inside one process the writers queue on the pool, and a caller's deadline ends the wait.
	ctx, cancel := context.WithTimeout(bg, 100*time.Millisecond)
	if _, err := holder.AddServer(ctx, ServerSpec{Name: "early", URL: "https://e.example.com"}, alice); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("a write that cannot start before its deadline: %v, want context.DeadlineExceeded", err)
	}
	cancel()

	go func() { time.Sleep(hold); close(release) }()
	began := time.Now()
	if _, err := other.AddServer(bg, ServerSpec{Name: "late", URL: "https://l.example.com"}, alice); err != nil {
		t.Fatalf("a write that waits for the lock failed: %v", err)
	}
	if waited := time.Since(began); waited < hold/3 {
		t.Errorf("the write did not wait for the lock holder (%v)", waited)
	}
	holding.Wait()
	if _, err := other.Server(bg, "early"); !errors.Is(err, ErrNotFound) {
		t.Errorf("the abandoned write left a server behind: %v", err)
	}
	if _, err := holder.VerifyAudit(bg); err != nil {
		t.Error(err)
	}
}

// The busy timeout is configurable: a store opened with a short one gives up
// on a lock another process holds for longer, with SQLITE_BUSY.
func TestConcurrency_BusyTimeoutIsConfigurable(t *testing.T) {
	path := dbPath(t)
	holder := openStore(t, path, lifecycle.DefaultPolicy())
	impatient, err := OpenWith(path, OpenOptions{Policy: lifecycle.DefaultPolicy(), BusyTimeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = impatient.Close() })
	mustAddServer(t, holder, "alpha")

	locked, release := make(chan struct{}), make(chan struct{})
	var holding sync.WaitGroup
	holding.Add(1)
	go func() {
		defer holding.Done()
		_ = holder.inTx(bg, func(*txn) error {
			close(locked)
			<-release
			return nil
		})
	}()
	<-locked
	began := time.Now()
	_, err = impatient.AddServer(bg, ServerSpec{Name: "late", URL: "https://l.example.com"}, alice)
	waited := time.Since(began)
	close(release)
	holding.Wait()
	if err == nil || !isBusy(err) {
		t.Fatalf("a 50 ms busy timeout against a held lock: %v, want SQLITE_BUSY", err)
	}
	if waited > 5*time.Second {
		t.Errorf("gave up after %v; the short timeout was not applied", waited)
	}
}

// A panic inside a transaction must not strand the only writer connection.
func TestInTx_PanicReleasesTheWriter(t *testing.T) {
	s := newStore(t)
	func() {
		defer func() { _ = recover() }()
		_ = s.inTx(bg, func(*txn) error { panic("boom") })
	}()
	done := make(chan error, 1)
	go func() {
		_, err := s.AddServer(bg, ServerSpec{Name: "alpha", URL: "https://a.example.com"}, alice)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("AddServer after a panic: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the writer connection was never released after a panic")
	}
}
