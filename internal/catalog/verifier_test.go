package catalog

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sairam0424/toolwarrant/internal/gate"
)

// testClock is a clock the test moves by hand.
type testClock struct{ at time.Time }

func newTestClock() *testClock {
	return &testClock{at: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *testClock) now() time.Time          { return c.at }
func (c *testClock) advance(d time.Duration) { c.at = c.at.Add(d) }

// clockAt pins a Store's clock to a settable instant and returns the function
// that moves it. The verifier reads the clock through the Store, so it moves
// with it.
func clockAt(s *Store, start time.Time) func(time.Duration) {
	c := &testClock{at: start}
	s.now = c.now
	return c.advance
}

// canonicalOf builds a distinct canonical form per row and its digest.
func canonicalOf(i int64) ([]byte, string) {
	canonical := []byte(fmt.Sprintf(`{"name":"tool-%d"}`, i))
	return canonical, gate.DigestOfCanonical(canonical)
}

func TestVerifier_RemembersARowForExactlyTheTTL(t *testing.T) {
	clock := newTestClock()
	v := newVerifier(clock.now, 8)
	canonical, digest := canonicalOf(1)

	if v.remembered(1, digest) {
		t.Fatal("an empty verifier remembers nothing")
	}
	if !v.verify(1, digest, canonical) || v.hashCount() != 1 {
		t.Fatalf("first verify: hashes = %d, want 1", v.hashCount())
	}
	if !v.verify(1, digest, canonical) || v.hashCount() != 1 {
		t.Fatalf("second verify within the TTL hashed again: hashes = %d", v.hashCount())
	}
	clock.advance(RecheckTTL - time.Nanosecond)
	if !v.remembered(1, digest) {
		t.Fatal("one nanosecond before the TTL the row must still be remembered")
	}
	clock.advance(time.Nanosecond)
	if v.remembered(1, digest) {
		t.Fatal("at the TTL the memory must have lapsed")
	}
	if !v.verify(1, digest, canonical) || v.hashCount() != 2 {
		t.Fatalf("verify after the TTL: hashes = %d, want 2", v.hashCount())
	}
	if !v.remembered(1, digest) || v.size() != 1 {
		t.Fatalf("a re-verified row is remembered again in place: size = %d", v.size())
	}
}

func TestVerifier_NeverRemembersAFailureOrAnotherDigest(t *testing.T) {
	v := newVerifier(newTestClock().now, 8)
	canonical, good := canonicalOf(1)
	bad := strings.Repeat("0", 64)

	for i := 1; i <= 2; i++ {
		if v.verify(1, bad, canonical) {
			t.Fatal("a wrong digest was accepted")
		}
		if v.size() != 0 || v.remembered(1, bad) {
			t.Fatal("a failed row was remembered")
		}
		if got := v.hashCount(); got != int64(i) {
			t.Fatalf("a failed row must be hashed on every read: hashes = %d, want %d", got, i)
		}
	}
	if !v.verify(1, good, canonical) || v.size() != 1 {
		t.Fatal("the right digest was refused")
	}
	if v.remembered(1, bad) || v.verify(1, bad, canonical) {
		t.Fatal("a memory for one digest vouched for another")
	}
	if got := v.hashCount(); got != 4 {
		t.Fatalf("hashes = %d, want 4: two failures, one success, one failure against a memory", got)
	}
	if !v.remembered(1, good) {
		t.Fatal("a failure against another digest must not evict the good memory")
	}
}

func TestVerifier_IsBoundedAndDropsOnDemand(t *testing.T) {
	const bound = 4
	v := newVerifier(newTestClock().now, bound)
	for i := int64(1); i <= 100; i++ {
		canonical, digest := canonicalOf(i)
		if !v.verify(i, digest, canonical) {
			t.Fatalf("row %d refused", i)
		}
		if v.size() > bound {
			t.Fatalf("size %d after %d rows, bound %d", v.size(), i, bound)
		}
	}
	if v.size() != bound {
		t.Fatalf("size = %d, want the bound %d", v.size(), bound)
	}
	hits := 0
	for i := int64(1); i <= 100; i++ {
		_, digest := canonicalOf(i)
		if v.remembered(i, digest) {
			hits++
		}
		if v.remembered(i, strings.Repeat("f", 64)) {
			t.Fatalf("row %d remembered with a digest it never had", i)
		}
	}
	if hits != bound {
		t.Fatalf("remembered rows = %d, want %d: every slot holds a real memory", hits, bound)
	}
	// Refreshing a remembered row does not take a slot.
	for i := int64(1); i <= 100; i++ {
		if canonical, digest := canonicalOf(i); v.remembered(i, digest) {
			v.check(i, digest, canonical)
		}
	}
	if v.size() != bound {
		t.Fatalf("size after refreshing = %d, want %d", v.size(), bound)
	}
	v.drop()
	if v.size() != 0 {
		t.Fatalf("size after drop = %d", v.size())
	}
	canonical, digest := canonicalOf(1)
	if v.remembered(1, digest) || !v.verify(1, digest, canonical) || v.size() != 1 {
		t.Fatal("a dropped verifier must start over, and still work")
	}
}

func TestVerifier_ZeroBoundRemembersNothing(t *testing.T) {
	for _, bound := range []int{0, -1} {
		v := newVerifier(newTestClock().now, bound)
		canonical, digest := canonicalOf(1)
		for i := 1; i <= 3; i++ {
			if !v.verify(1, digest, canonical) {
				t.Fatal("refused a good row")
			}
			if got := v.hashCount(); got != int64(i) {
				t.Fatalf("bound %d: hashes = %d, want %d", bound, got, i)
			}
		}
		if v.size() != 0 || v.remembered(1, digest) {
			t.Fatalf("bound %d remembered a row", bound)
		}
	}
}
