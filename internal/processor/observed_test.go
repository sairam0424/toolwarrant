package processor

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	api "github.com/sairam0424/toolwarrant/internal/extmcpv1"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// Third review, core-2: evidence about a tool that can never be served is
// never consulted (judgeCall denies such a tool before it looks), so recording
// it only let never-served names crowd a bounded table and push out the
// evidence the call rule depends on. With MaxTracked=2 the page [p1 pending,
// p2 pending, add changed] used to hide add as mismatched and then forget the
// contradiction, so the following tools/call add passed on the crawl's word.
func TestCheckResponse_EvidenceIsKeptOnlyForServableTools(t *testing.T) {
	p1, p2 := tool("p1", "x"), tool("p2", "y")
	add1 := tool("add", "a1")
	add2 := tool("add", "a2: changed upstream")
	off := tool("off", "disabled")
	tools := map[string]catalog.ToolPolicy{
		"p1":  policy(lifecycle.PendingReview, "", mustDigest(t, p1)),
		"p2":  policy(lifecycle.PendingReview, "", mustDigest(t, p2)),
		"off": policy(lifecycle.Disabled, mustDigest(t, off), mustDigest(t, off)),
		"add": servedPolicy(mustDigest(t, add1)),
	}
	s, _ := newTestServer(newFakeSource(tools), func(c *Config) { c.MaxTracked = 2 })
	if got := servedNames(t, list(t, s, listBody("", p1, p2, off, add2))); len(got) != 0 {
		t.Fatalf("served %v, want nothing: p1, p2 and off are not servable, add is changed", got)
	}
	if st := s.Stats(); st.ToolsMismatched != 1 || st.ToolsUnapproved != 3 || st.EvidenceDropped != 0 {
		t.Fatalf("stats = %+v", st)
	}
	for _, name := range []string{"p1", "p2", "off"} {
		if _, ok := s.observedDigest(name); ok {
			t.Errorf("evidence was recorded for %s, which can never be served", name)
		}
	}
	if seen, ok := s.observedDigest("add"); !ok || seen != mustDigest(t, add2) {
		t.Fatalf("evidence for add = %q, %v; want the changed digest", seen, ok)
	}
	if n := s.trackedCount(); n != 1 {
		t.Errorf("tracked %d names, want 1", n)
	}
	requireCallDenied(t, call(t, s, callReq("add")), "add", causeChanged)
}

// Third review, processor-emit-3 and core-2: at the MaxTracked ceiling a new
// name evicts an entry that agrees with its approval, never one that
// contradicts it. With MaxTracked=1 and echo filling the slot, a listing that
// showed a changed add used to be hidden and then forgotten (a Warn line was
// the only trace), so tools/call add passed on the crawl's word; the conflict
// marker of a denied page listing add was dropped the same way.
func TestCheckResponse_FullObservedTableEvictsAgreeingEvidenceNeverAContradiction(t *testing.T) {
	echo1, add1 := tool("echo", "e1"), tool("add", "a1")
	add2 := tool("add", "a2: changed")
	tools := map[string]catalog.ToolPolicy{"echo": servedPolicy(mustDigest(t, echo1)), "add": servedPolicy(mustDigest(t, add1))}
	s, logs := newTestServer(newFakeSource(tools), func(c *Config) { c.MaxTracked = 1 })
	servedNames(t, list(t, s, listBody("", echo1))) // echo fills the one slot, agreeing with its approval

	// The gateway lists the changed add: echo is evicted, add is kept, the call is denied.
	if got := servedNames(t, list(t, s, listBody("", add2))); len(got) != 0 {
		t.Fatalf("served %v", got)
	}
	if seen, ok := s.observedDigest("add"); !ok || seen != mustDigest(t, add2) {
		t.Fatalf("evidence for add = %q, %v; want the changed digest", seen, ok)
	}
	if _, ok := s.observedDigest("echo"); ok {
		t.Fatal("echo, which agreed with its approval, should have been evicted")
	}
	if n := s.trackedCount(); n != 1 {
		t.Fatalf("tracked %d names, want the bound of 1", n)
	}
	if !strings.Contains(logs.String(), "agreeing evidence was evicted") {
		t.Errorf("the eviction should be logged:\n%s", logs.String())
	}
	requireCallDenied(t, call(t, s, callReq("add")), "add", causeChanged)
	requireAllowed(t, call(t, s, callReq("echo"))) // on the crawl's word alone: nothing was dropped
	if st := s.Stats(); st.EvidenceDropped != 0 {
		t.Fatalf("stats = %+v, want no drop", st)
	}

	// A denied page listing add keeps the marker: the name is tracked.
	requireListDenied(t, list(t, s, listBody("", add2, add2)), api.AuthorizationError_INVALID)
	if seen, ok := s.observedDigest("add"); !ok || seen != observedConflict {
		t.Fatalf("evidence for add after the denied page = %q, %v; want the conflict marker", seen, ok)
	}
	requireCallDenied(t, call(t, s, callReq("add")), "add", causeChanged)

	// The contradiction is never evicted: echo, listed with the approved
	// bytes, finds no room, and the marker for add stands.
	if got := servedNames(t, list(t, s, listBody("", echo1))); !reflect.DeepEqual(got, []string{"echo"}) {
		t.Fatalf("served %v, want [echo]: the live bytes are the approved ones", got)
	}
	if seen, ok := s.observedDigest("add"); !ok || seen != observedConflict {
		t.Fatalf("the conflict marker for add was evicted: evidence = %q, %v", seen, ok)
	}
	if _, ok := s.observedDigest("echo"); ok {
		t.Fatal("echo was recorded although the only slot holds a contradiction")
	}
	requireCallDenied(t, call(t, s, callReq("add")), "add", causeChanged)
}

// When a full table holds nothing but contradictions, new evidence is lost.
// The loss is counted (Stats.EvidenceDropped) and from then on a servable tool
// with no listing evidence is denied as not yet verified: the processor cannot
// tell a tool that was never listed from one whose contradiction it had to
// drop, so it stops taking absence of evidence as evidence of absence. Before
// D13 the dropped contradiction let tools/call pass on the crawl's word
// (core-2's fail-open). A listing that is recorded lifts the denial for that
// tool, and only for it.
func TestCheckRequest_DroppedEvidenceDeniesUnlistedToolsUntilListed(t *testing.T) {
	echo1, add1 := tool("echo", "e1"), tool("add", "a1")
	echo2, add2 := tool("echo", "e2: changed"), tool("add", "a2: changed")
	tools := map[string]catalog.ToolPolicy{"echo": servedPolicy(mustDigest(t, echo1)), "add": servedPolicy(mustDigest(t, add1))}
	s, logs := newTestServer(newFakeSource(tools), func(c *Config) { c.MaxTracked = 1 })
	servedNames(t, list(t, s, listBody("", echo2))) // a contradiction fills the one slot
	requireCallDenied(t, call(t, s, callReq("echo")), "echo", causeChanged)
	requireAllowed(t, call(t, s, callReq("add"))) // never listed, the crawl agrees, nothing dropped yet

	// add changed: no room, nothing agreeing to evict. The evidence is lost,
	// and the call must not fall back to the crawl's word.
	if got := servedNames(t, list(t, s, listBody("", add2))); len(got) != 0 {
		t.Fatalf("served %v", got)
	}
	if _, ok := s.observedDigest("add"); ok {
		t.Fatal("add was recorded although the only slot holds a contradiction")
	}
	if st := s.Stats(); st.EvidenceDropped != 1 || st.ToolsMismatched != 2 {
		t.Fatalf("stats = %+v, want one drop and two mismatches", st)
	}
	if !strings.Contains(logs.String(), "evidence was dropped") {
		t.Errorf("the drop should be logged:\n%s", logs.String())
	}
	requireCallDenied(t, call(t, s, callReq("add")), "add", causeUnverified)
	requireCallDenied(t, call(t, s, callReq("echo")), "echo", causeChanged)

	// Recovery is per tool: a clean page for echo makes its entry agree, so
	// the next listing of add is recorded (evicting echo) and judged on it.
	servedNames(t, list(t, s, listBody("", echo1)))
	requireAllowed(t, call(t, s, callReq("echo")))
	servedNames(t, list(t, s, listBody("", add2)))
	requireCallDenied(t, call(t, s, callReq("add")), "add", causeChanged)
	requireCallDenied(t, call(t, s, callReq("echo")), "echo", causeUnverified) // untracked again, and the loss stands
	servedNames(t, list(t, s, listBody("", add1)))
	requireAllowed(t, call(t, s, callReq("add")))
	servedNames(t, list(t, s, listBody("", echo1)))
	requireAllowed(t, call(t, s, callReq("echo")))
	if st := s.Stats(); st.EvidenceDropped != 1 {
		t.Errorf("stats = %+v, want the one drop only", st)
	}
}

// D13: the observed table is sized from the snapshot at every reload, its
// tool count plus trackedMargin, so under the default bound it is never full
// and nothing is ever evicted or dropped; MaxTracked is only the ceiling.
func TestReload_SizesTheObservedTableFromTheSnapshot(t *testing.T) {
	const n = 300
	defs := make([][]byte, 0, n)
	policies := make(map[string]catalog.ToolPolicy, n)
	for i := 0; i < n; i++ {
		d := tool(fmt.Sprintf("t%03d", i), "x")
		defs = append(defs, d)
		policies[fmt.Sprintf("t%03d", i)] = servedPolicy(mustDigest(t, d))
	}
	src := newFakeSource(policies)
	s, logs := newTestServer(src)
	if got := servedNames(t, list(t, s, listBody("", defs...))); len(got) != n {
		t.Fatalf("served %d tools, want %d", len(got), n)
	}
	if limit, tracked := s.trackedLimit(), s.trackedCount(); limit != n+trackedMargin || tracked != n {
		t.Errorf("limit %d, tracked %d; want %d and %d", limit, tracked, n+trackedMargin, n)
	}
	if strings.Contains(logs.String(), "observed-digest table is full") {
		t.Errorf("a table sized from the snapshot must not fill:\n%s", logs.String())
	}

	// The catalog shrinks: the table is pruned and re-sized with it.
	small := map[string]catalog.ToolPolicy{"t000": policies["t000"], "t001": policies["t001"], "t002": policies["t002"]}
	src.publish(small)
	requireAllowed(t, call(t, s, callReq("t000")))
	if limit, tracked := s.trackedLimit(), s.trackedCount(); limit != 3+trackedMargin || tracked != 3 {
		t.Errorf("after the shrink: limit %d, tracked %d; want %d and 3", limit, tracked, 3+trackedMargin)
	}

	// MaxTracked is the ceiling the snapshot cannot lift.
	bounded, _ := newTestServer(newFakeSource(policies), func(c *Config) { c.MaxTracked = 10 })
	servedNames(t, list(t, bounded, listBody("", defs...)))
	if limit, tracked := bounded.trackedLimit(), bounded.trackedCount(); limit != 10 || tracked != 10 {
		t.Errorf("limit %d, tracked %d; want the ceiling 10 for both", limit, tracked)
	}
	if st := bounded.Stats(); st.EvidenceDropped != 0 {
		t.Errorf("every entry agreed with its approval, nothing should have been dropped: %+v", st)
	}
}
