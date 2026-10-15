package catalog

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sairam0424/toolwarrant/internal/lifecycle"
	"github.com/sairam0424/toolwarrant/internal/signing"
)

// The compare-and-set of SetTrust under a concurrent writer (finding 12,
// O-17): the test, its scheduled crawler and the check that every stored
// prev_head is the prev_hash of its entry.

// crawlerCadence is the pause between the crawls of the scheduled crawler in
// TestSetTrust_ExpectHeadRefusesWhenTheLogMoved: a few tens of milliseconds,
// so that a crawl lands inside the operator's read-sign-write window often
// enough to exercise the retry while, on an idle host, leaving windows the
// operator fits in. The invariant the test pins does not depend on who wins:
// where the window does not fit (a loaded host, the race detector, a slow
// runner) the operator parks the crawler for the rest of that rotation after
// parkAfterRetries refusals, and every stored prev_head is compared with its
// entry's prev_hash all the same. A crawler whose whole cycle is shorter than
// the window (a few milliseconds here, where a synced commit takes about
// twenty) starves every compare-and-set, as it would starve any writer; the
// scheduled crawl of a deployment runs once a minute.
const crawlerCadence = 40 * time.Millisecond

// parkAfterRetries is how many refusals in a row one rotation takes before
// the test parks the crawler for the rest of it: the liveness of the test is
// then the test's own, while every attempt still ran the compare-and-set.
const parkAfterRetries = 5

// parkedRetryLimit bounds the attempts of one rotation made with the crawler
// parked: at most one crawl already in flight can still land, so more
// refusals than this mean the compare-and-set never succeeds (a regression),
// not contention.
const parkedRetryLimit = 10

// The compare-and-set (finding 12). A record signed over a head the log has
// left behind is refused with nothing written; under a crawler that commits
// every few tens of milliseconds, fifty rotations each retried on
// ErrHeadMoved leave a chain in which every stored prev_head equals its
// entry's prev_hash, which is what makes the signed record a signed head.
func TestSetTrust_ExpectHeadRefusesWhenTheLogMoved(t *testing.T) {
	t.Parallel()
	s, path := newStoreAt(t, lifecycle.DefaultPolicy())
	mustAddServer(t, s, "alpha")
	alice, bob := newOperator(t, "alice"), newOperator(t, "bob")
	mustSetTrust(t, s, 1, alice, alice)
	stale := signList(t, listFor(s.identity, mustHead(t, s), 2, alice, alice, bob), alice.key)
	mustCrawl(t, s, "alpha", tool("echo", "v1"))
	n := auditCount(t, s)
	_, err := s.SetTrust(bg, stale, alice.actor())
	if !errors.Is(err, ErrHeadMoved) || !strings.Contains(err.Error(), "audit head mismatch") {
		t.Fatalf("SetTrust over a stale head = %v, want ErrHeadMoved", err)
	}
	if auditCount(t, s) != n || mustTrustList(t, s).Version != 1 || mustCount(t, rawDB(t, path), `SELECT COUNT(*) FROM signed_records`) != 1 {
		t.Fatal("the refused record left something behind")
	}

	const rotations = 50
	var parked atomic.Bool
	stop := startCrawler(t, s, &parked)
	retries, parkedRotations := rotateUnderCrawler(t, s, rotations, alice, bob, &parked)
	stop()
	t.Logf("%d rotations, %d attempts refused after the head moved, %d rotations finished with the crawler parked", rotations, retries, parkedRotations)
	if retries == 0 {
		t.Log("no attempt met a moved head on this host; the invariant is checked all the same")
	}
	checkPrevHeadsAreTheEntriesPrevHashes(t, path, rotations+1)
	if view := mustTrustList(t, s); view.Version != rotations+1 || view.Lists != rotations+1 {
		t.Errorf("TrustList = %+v, want version %d", view, rotations+1)
	}
	mustBeClean(t, s, "after the rotations under the crawler")
}

// startCrawler runs a crawl of s every crawlerCadence, alternating the tool's
// definition so that every crawl commits, until the returned stop function is
// called (idempotent; the test's Cleanup calls it too, before the Store
// closes). While parked is set the crawler sleeps instead of crawling.
func startCrawler(t *testing.T, s *Store, parked *atomic.Bool) (stop func()) {
	t.Helper()
	done := make(chan struct{})
	var crawls sync.WaitGroup
	crawls.Go(func() {
		for k := 0; ; k++ {
			select {
			case <-done:
				return
			default:
			}
			if !parked.Load() {
				if _, err := s.RecordCrawl(bg, crawlOf(tool("echo", "v"+itoa(int64(k%2)))), crawler); err != nil {
					t.Errorf("crawl %d: %v", k, err)
					return
				}
			}
			time.Sleep(crawlerCadence)
		}
	})
	stop = sync.OnceFunc(func() {
		close(done)
		crawls.Wait()
	})
	t.Cleanup(stop)
	return stop
}

// rotateUnderCrawler rotates the list rotations times, each from the head and
// version SigningState hands out, retrying a rotation on ErrHeadMoved and
// parking the crawler for the rest of it after parkAfterRetries refusals. It
// returns how many attempts were refused and how many rotations finished
// with the crawler parked.
func rotateUnderCrawler(t *testing.T, s *Store, rotations int, alice, bob operator, parked *atomic.Bool) (retries, parkedRotations int) {
	t.Helper()
	for i := 0; i < rotations; i++ {
		ops := []operator{alice}
		if i%2 == 0 {
			ops = append(ops, bob)
		}
		for attempt := 0; ; attempt++ {
			if attempt == parkAfterRetries {
				parked.Store(true)
				parkedRotations++
			}
			if attempt > parkAfterRetries+parkedRetryLimit {
				t.Fatalf("rotation %d: the head moved on %d attempts in a row, %d of them with the crawler parked; the compare-and-set never succeeds", i, attempt, parkedRetryLimit)
			}
			st, err := s.SigningState(bg)
			if err != nil {
				t.Fatal(err)
			}
			rec := signList(t, listFor(st.Identity, st.Head, st.Trust.Version+1, alice, ops...), alice.key)
			_, err = s.SetTrust(bg, rec, alice.actor())
			if errors.Is(err, ErrHeadMoved) {
				retries++
				continue
			}
			if err != nil {
				t.Fatalf("rotation %d: %v", i, err)
			}
			break
		}
		parked.Store(false)
	}
	return retries, parkedRotations
}

// checkPrevHeadsAreTheEntriesPrevHashes reads every signed row of the file
// through a raw handle, requires want of them, and requires each payload's
// prev_head to be the prev_hash of the entry at its seq: the compare-and-set
// and the seal are one transaction, so the two can never disagree.
func checkPrevHeadsAreTheEntriesPrevHashes(t *testing.T, path string, want int) {
	t.Helper()
	db := rawDB(t, path)
	entries := rawEntries(t, db)
	rows, err := readSignedRecords(bg, db, signedSeqs(entries))
	if err != nil || len(rows) != want {
		t.Fatalf("%d signed rows, %v; want %d", len(rows), err, want)
	}
	for seq, rec := range rows {
		list, err := signing.ParseTrustList(rec.Payload)
		if err != nil || list.PrevHead != entries[seq-1].PrevHash {
			t.Errorf("row %d: stored prev_head %s, entry prev_hash %s (%v)", seq, list.PrevHead, entries[seq-1].PrevHash, err)
		}
	}
}
