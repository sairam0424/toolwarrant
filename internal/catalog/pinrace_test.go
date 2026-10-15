package catalog

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// The seventh hostile review's race (D17 f). A read transaction's snapshot was
// fixed by its first statement (the identity read) while the pin it was
// compared with was read later, under walkMu; a commit between the two, walked
// by another handle of the same Store first, moved the pin past the reader's
// snapshot and checkPinnedEntry read the absent entry as a truncation
// ("audit entry N, which this store verified, is gone"). Under six readers
// and one writer on one Store, one in five Snapshot calls failed that way on
// an untouched file. checkFile now takes walkMu before the transaction's first
// statement, so no snapshot predates the pin it is compared with.

// pinRaceDuration is how long the readers and the writer run: long enough for
// the old code to fail within the first hundred calls (it failed one call in
// five), short enough for the suite.
const pinRaceDuration = 2 * time.Second

// Readers calling Snapshot while the same Store writes never see a false
// truncation, and no other error either.
func TestSnapshot_ConcurrentReadersAndAWriterNeverSeeAFalseTruncation(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mustAddServer(t, s, "alpha")
	mustCrawl(t, s, "alpha", tool("echo", "v1"))
	var (
		reads, falseCorrupt, other atomic.Int64
		firstErr                   atomic.Pointer[string]
		wg                         sync.WaitGroup
	)
	stop := make(chan struct{})
	for range 4 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, err := s.Snapshot(bg, "alpha")
				reads.Add(1)
				switch {
				case err == nil:
				case errors.Is(err, ErrCorrupt) && strings.Contains(err.Error(), "is gone"):
					falseCorrupt.Add(1)
					msg := err.Error()
					firstErr.CompareAndSwap(nil, &msg)
				default:
					other.Add(1)
					msg := err.Error()
					firstErr.CompareAndSwap(nil, &msg)
				}
			}
		})
	}
	writes := 0
	for deadline := time.Now().Add(pinRaceDuration); time.Now().Before(deadline); writes++ {
		if err := s.SetProcessorAddr(bg, "alpha", "127.0.0.1:"+itoa(int64(10000+writes%20000)), alice); err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("write %d: %v", writes, err)
		}
	}
	close(stop)
	wg.Wait()
	t.Logf("%d writes, %d Snapshot calls", writes, reads.Load())
	if writes == 0 || reads.Load() == 0 {
		t.Fatalf("the race was not exercised: %d writes, %d reads", writes, reads.Load())
	}
	if falseCorrupt.Load() != 0 || other.Load() != 0 {
		t.Errorf("%d Snapshot calls reported a truncation of an untouched file and %d failed otherwise; first: %s",
			falseCorrupt.Load(), other.Load(), *firstErr.Load())
	}
	mustBeClean(t, s, "after the run")
	fresh, err := OpenWith(s.path, OpenOptions{Policy: lifecycle.DefaultPolicy()})
	if err != nil {
		t.Fatalf("a fresh open after the run = %v", err)
	}
	_ = fresh.Close()
}
