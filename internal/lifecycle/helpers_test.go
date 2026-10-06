package lifecycle_test

// Shared fixtures and assertions for the spec-first lifecycle tests.
//
// These tests are written from the written specification, not from the
// implementation. They only use the exported API (external test package), so a
// behaviour the implementation adds beyond the spec cannot leak into an
// expectation.

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"

	lc "github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// Digests and principals used by the fixtures. They are deliberately short,
// distinct and non-empty.
const (
	dA = "digest-a"
	dB = "digest-b"
	dC = "digest-c"
	dD = "digest-d"

	alice   = "alice"
	bob     = "bob"
	carol   = "carol"
	crawler = "crawler"

	// deprecateAfterThree matches the shipped default and is used by most
	// tables so the third missed crawl is the interesting one.
	deprecateAfterThree = 3

	// spareSlots is how many sentinel slots sit beyond len(Versions) when
	// checking that Apply never appends into the caller's backing array.
	spareSlots = 4
)

// errorfer is the only thing the shared helpers need from *testing.T and
// *rapid.T, so the same assertions serve table tests and property tests.
type errorfer interface {
	Errorf(format string, args ...any)
}

// allStates lists every lifecycle state; a function so no mutable package
// state exists.
func allStates() []lc.State {
	return []lc.State{
		lc.Discovered, lc.PendingReview, lc.Enabled,
		lc.ChangedPendingReapproval, lc.Disabled, lc.Deprecated,
	}
}

// plainPolicy is the policy most tables use: no self-approval, no re-review
// on enable, deprecate after three missed crawls.
func plainPolicy() lc.Policy {
	return lc.Policy{DeprecateAfter: deprecateAfterThree}
}

// reviewPolicy is plainPolicy with ReEnableRequiresReview switched on.
func reviewPolicy() lc.Policy {
	p := plainPolicy()
	p.ReEnableRequiresReview = true
	return p
}

// selfApprovePolicy is plainPolicy with AllowSelfApproval switched on.
func selfApprovePolicy() lc.Policy {
	p := plainPolicy()
	p.AllowSelfApproval = true
	return p
}

// ver builds a Version literal whose only proposer is by.
func ver(digest string, status lc.VersionStatus, by string, ever bool) lc.Version {
	return verP(digest, status, by, ever, by)
}

// verP builds a Version literal with an explicit proposer history; by is the
// first proposer and must head the list.
func verP(digest string, status lc.VersionStatus, by string, ever bool, proposers ...string) lc.Version {
	return lc.Version{Digest: digest, Status: status, ProposedBy: by, EverApproved: ever, Proposers: lc.ProposersOf(proposers...)}
}

// toolOf builds a Tool literal. The versions are copied so fixtures never
// share backing arrays.
func toolOf(state lc.State, approved, lastSeen string, missing int, vs ...lc.Version) lc.Tool {
	return lc.Tool{
		State:         state,
		Versions:      slices.Clone(vs),
		Approved:      approved,
		LastSeen:      lastSeen,
		MissingCrawls: missing,
	}
}

// newTool is a tool that nothing has observed yet.
func newTool() lc.Tool { return lc.Tool{State: lc.Discovered} }

// pendingReviewTool is a tool with one pending proposal and nothing approved.
func pendingReviewTool(digest, by string) lc.Tool {
	return toolOf(lc.PendingReview, "", digest, 0, ver(digest, lc.VersionPending, by, false))
}

// enabledTool is a tool with digest approved and currently served upstream.
func enabledTool(digest string) lc.Tool {
	return toolOf(lc.Enabled, digest, digest, 0, ver(digest, lc.VersionApproved, alice, true))
}

// changedTool has approved digest a with a pending proposal b (proposed by by);
// the upstream currently serves b.
func changedTool(a, b, by string) lc.Tool {
	return toolOf(lc.ChangedPendingReapproval, a, b, 0,
		ver(a, lc.VersionApproved, alice, true),
		ver(b, lc.VersionPending, by, false))
}

// crawl is a successful crawl that saw digest d.
func crawl(d, actor string) lc.ObserveCrawl {
	return lc.ObserveCrawl{Present: true, Digest: d, Actor: actor}
}

// miss is a successful crawl that did not list the tool.
func miss() lc.ObserveCrawl {
	return lc.ObserveCrawl{Present: false, Actor: crawler}
}

// unusable is a successful crawl that listed the tool with a definition that
// could not be used.
func unusable() lc.ObserveCrawl {
	return lc.ObserveCrawl{Present: true, Unusable: true, Actor: crawler}
}

// isLiveDigest reports whether a LastSeen value names a definition: neither
// absent nor the unusable marker.
func isLiveDigest(s string) bool { return s != "" && s != lc.UnusableDigest }

// cloneTool deep-copies a Tool.
func cloneTool(t lc.Tool) lc.Tool {
	c := t
	c.Versions = slices.Clone(t.Versions)
	return c
}

// sameTool compares two tools, treating a nil and an empty Versions slice as
// equal. Versions compare with ==, proposer history included.
func sameTool(a, b lc.Tool) bool {
	return a.State == b.State &&
		a.Approved == b.Approved &&
		a.LastSeen == b.LastSeen &&
		a.MissingCrawls == b.MissingCrawls &&
		slices.Equal(a.Versions, b.Versions)
}

// sentinel marks the spare capacity used to detect appends into the caller's
// backing array.
func sentinel() lc.Version {
	return verP("sentinel", lc.VersionRejected, "nobody", true, "nobody")
}

// withSpareCapacity returns a copy of t whose Versions slice has spare
// capacity filled with sentinels, plus the whole backing array for inspection.
func withSpareCapacity(t lc.Tool) (lc.Tool, []lc.Version) {
	n := len(t.Versions)
	backing := make([]lc.Version, n+spareSlots)
	copy(backing, t.Versions)
	for i := n; i < len(backing); i++ {
		backing[i] = sentinel()
	}
	c := t
	c.Versions = backing[:n]
	return c, backing
}

// apply calls lifecycle.Apply and turns a panic into a test error, because the
// specification says bad input is an error and never a panic.
func apply(t errorfer, tool lc.Tool, cmd lc.Command, p lc.Policy) (res lc.Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Apply(%T) panicked: %v", cmd, r)
			res = lc.Result{}
			err = fmt.Errorf("apply panicked: %v", r)
		}
	}()
	return lc.Apply(tool, cmd, p)
}

// checkPure applies cmd to a copy of tool that has spare capacity and reports
// any sign that Apply mutated its argument: the visible fields, the elements,
// the spare backing array, or an alias between the result and the input.
func checkPure(t errorfer, tool lc.Tool, cmd lc.Command, p lc.Policy) (lc.Result, error) {
	in, backing := withSpareCapacity(tool)
	snapshot := cloneTool(in)
	res, err := apply(t, in, cmd, p)
	if !sameTool(in, snapshot) {
		t.Errorf("Apply(%T) mutated its input: got %+v, want %+v", cmd, in, snapshot)
	}
	for i := len(in.Versions); i < len(backing); i++ {
		if backing[i] != sentinel() {
			t.Errorf("Apply(%T) wrote into the input's spare capacity at index %d", cmd, i)
		}
	}
	if err != nil {
		if !reflect.DeepEqual(res, lc.Result{}) {
			t.Errorf("Apply(%T) returned a non-zero Result alongside error %v: %+v", cmd, err, res)
		}
		return res, err
	}
	// Mutating the returned Versions must not change the input, and mutating
	// the input afterwards must not change the result.
	saved := slices.Clone(res.Tool.Versions)
	scramble(res.Tool.Versions)
	if !sameTool(in, snapshot) {
		t.Errorf("mutating the Versions returned by Apply(%T) changed the input: got %+v, want %+v",
			cmd, in, snapshot)
	}
	copy(res.Tool.Versions, saved)
	scramble(in.Versions)
	if !sameTool(res.Tool, lc.Tool{
		State: res.Tool.State, Approved: res.Tool.Approved, LastSeen: res.Tool.LastSeen,
		MissingCrawls: res.Tool.MissingCrawls, Versions: saved,
	}) {
		t.Errorf("mutating the input after Apply(%T) changed the returned Tool: %+v", cmd, res.Tool)
	}
	return res, nil
}

// scramble overwrites every element of vs in place (so a shared backing array
// would show up as a change in another Tool) and returns vs.
func scramble(vs []lc.Version) []lc.Version {
	for i := range vs {
		vs[i] = verP("scrambled", "scrambled", "scrambled", false, "scrambled")
	}
	return vs
}

// applyOK applies cmd, fails the test on error, and returns the full Result.
// It also runs the purity checks.
func applyOK(t *testing.T, tool lc.Tool, cmd lc.Command, p lc.Policy) lc.Result {
	t.Helper()
	res, err := checkPure(t, tool, cmd, p)
	if err != nil {
		t.Fatalf("Apply(%T %+v) failed: %v", cmd, cmd, err)
	}
	return res
}

// step is applyOK that returns only the new tool, for chaining in path tests.
// The result is re-cloned so the next step never aliases the previous result.
func step(t *testing.T, tool lc.Tool, cmd lc.Command, p lc.Policy) lc.Tool {
	t.Helper()
	return cloneTool(applyOK(t, tool, cmd, p).Tool)
}

// mustFail applies cmd and requires an error matching want, a zero Result and
// an unchanged input.
func mustFail(t *testing.T, tool lc.Tool, cmd lc.Command, p lc.Policy, want error) {
	t.Helper()
	res, err := checkPure(t, tool, cmd, p)
	if err == nil {
		t.Fatalf("Apply(%T %+v) succeeded, want %v; result %+v", cmd, cmd, want, res.Tool)
	}
	if !errors.Is(err, want) {
		t.Fatalf("Apply(%T %+v) error = %v, want errors.Is %v", cmd, cmd, err, want)
	}
}

// applyCase is one row of a success table.
type applyCase struct {
	name  string
	start lc.Tool
	cmd   lc.Command
	pol   lc.Policy
	want  lc.Tool
}

// runApplyCases runs each row as a subtest and compares the whole tool.
func runApplyCases(t *testing.T, cases []applyCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := applyOK(t, tc.start, tc.cmd, tc.pol).Tool
			if !sameTool(got, tc.want) {
				t.Errorf("tool mismatch\n got: %+v\nwant: %+v", got, tc.want)
			}
		})
	}
}

// errCase is one row of a failure table.
type errCase struct {
	name  string
	start lc.Tool
	cmd   lc.Command
	pol   lc.Policy
	want  error
}

// runErrCases runs each row as a subtest.
func runErrCases(t *testing.T, cases []errCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mustFail(t, tc.start, tc.cmd, tc.pol, tc.want)
		})
	}
}

// hasEvent reports whether res contains an event of the given kind; if digest
// is non-empty the event must concern that digest.
func hasEvent(res lc.Result, kind lc.EventKind, digest string) bool {
	for _, e := range res.Events {
		if e.Kind == kind && (digest == "" || e.Digest == digest) {
			return true
		}
	}
	return false
}

// kindsOf returns the event kinds of res, sorted, so two results can be
// compared as multisets.
func kindsOf(res lc.Result) []lc.EventKind {
	kinds := make([]lc.EventKind, 0, len(res.Events))
	for _, e := range res.Events {
		kinds = append(kinds, e.Kind)
	}
	slices.Sort(kinds)
	return kinds
}

// requireKinds asserts that res emitted exactly the given kinds (as a
// multiset, in any order).
func requireKinds(t *testing.T, res lc.Result, want ...lc.EventKind) {
	t.Helper()
	w := slices.Clone(want)
	slices.Sort(w)
	if got := kindsOf(res); !slices.Equal(got, w) {
		t.Errorf("events = %v, want %v (full events %+v)", got, w, res.Events)
	}
}

// findVersion returns the version with the given digest.
func findVersion(t lc.Tool, digest string) (lc.Version, bool) {
	for _, v := range t.Versions {
		if v.Digest == digest {
			return v, true
		}
	}
	return lc.Version{}, false
}

// requireServes asserts Tool.Serves(live) == want.
func requireServes(t *testing.T, tool lc.Tool, live string, want bool) {
	t.Helper()
	if got := tool.Serves(live); got != want {
		t.Errorf("Serves(%q) = %v, want %v (state %s, approved %q)", live, got, want, tool.State, tool.Approved)
	}
}

// requireState asserts the tool state.
func requireState(t *testing.T, tool lc.Tool, want lc.State) {
	t.Helper()
	if tool.State != want {
		t.Errorf("state = %s, want %s (tool %+v)", tool.State, want, tool)
	}
}

// requireProposers asserts the proposer history of one version: ProposedBy is
// the first name and the list is exactly want.
func requireProposers(t *testing.T, tool lc.Tool, digest string, want ...string) {
	t.Helper()
	v, ok := findVersion(tool, digest)
	if !ok {
		t.Fatalf("version %s not found in %+v", digest, tool)
	}
	if got := v.Proposers.All(); !slices.Equal(got, want) || v.ProposedBy != want[0] {
		t.Errorf("version %s: ProposedBy=%q Proposers=%v, want %v", digest, v.ProposedBy, got, want)
	}
}
