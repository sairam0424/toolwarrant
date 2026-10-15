package lifecycle_test

// The invariants from the specification, as pure functions over a recorded
// step so they can be run on random sequences and also unit-tested against
// hand-made violations (see meta_test.go). The event rules (D5) and the
// proposer history rules (D4) live in event_invariants_test.go.

import (
	"errors"
	"fmt"

	lc "github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// liveProbes are the live digests used when probing Serves.
func liveProbes() []string { return []string{"", dA, dB, dC, dD, "digest-unknown", lc.UnusableDigest} }

func sentinelErrors() []error {
	return []error{
		lc.ErrInvalidTransition, lc.ErrUnknownVersion, lc.ErrStaleVersion, lc.ErrSelfApproval,
		lc.ErrNotRollbackTarget, lc.ErrNoActor, lc.ErrNoDigest, lc.ErrInvalidObservation,
	}
}

func isSentinel(err error) bool {
	for _, s := range sentinelErrors() {
		if errors.Is(err, s) {
			return true
		}
	}
	return false
}

func actorOf(cmd lc.Command) string {
	switch c := cmd.(type) {
	case lc.ObserveCrawl:
		return c.Actor
	case lc.Approve:
		return c.Actor
	case lc.Reject:
		return c.Actor
	case lc.Disable:
		return c.Actor
	case lc.Enable:
		return c.Actor
	case lc.Rollback:
		return c.Actor
	}
	return ""
}

func statusCounts(t lc.Tool) (pending, approved int) {
	for _, v := range t.Versions {
		switch v.Status {
		case lc.VersionPending:
			pending++
		case lc.VersionApproved:
			approved++
		}
	}
	return pending, approved
}

func isServableState(s lc.State) bool {
	return s == lc.Enabled || s == lc.ChangedPendingReapproval
}

// stepViolations returns every invariant the recorded step breaks.
func stepViolations(rec stepRecord) []string {
	if rec.err != nil {
		return failureViolations(rec)
	}
	var out []string
	if actorOf(rec.cmd) == "" {
		out = append(out, "a command with an empty actor succeeded")
	}
	out = append(out, shapeViolations(rec.res.Tool)...)
	out = append(out, edgeViolations(rec)...)
	out = append(out, crawlViolations(rec)...)
	out = append(out, serveViolations(rec.res.Tool)...)
	out = append(out, effectViolations(rec)...)
	out = append(out, eventViolations(rec)...)
	return out
}

// failureViolations covers invariant (9) and the error contract: a failed
// Apply names a sentinel, and the empty-input errors are reported as such.
func failureViolations(rec stepRecord) []string {
	var out []string
	if !isSentinel(rec.err) {
		out = append(out, fmt.Sprintf("error wraps no documented sentinel: %v", rec.err))
	}
	if actorOf(rec.cmd) == "" && !errors.Is(rec.err, lc.ErrNoActor) {
		out = append(out, fmt.Sprintf("empty actor reported as %v, want ErrNoActor", rec.err))
	}
	if c, ok := rec.cmd.(lc.ObserveCrawl); ok && c.Present && !c.Unusable && c.Actor != "" && c.Digest == "" && !errors.Is(rec.err, lc.ErrNoDigest) {
		out = append(out, fmt.Sprintf("crawl without digest reported as %v, want ErrNoDigest", rec.err))
	}
	return out
}

// shapeViolations covers invariants (1), (2) and (3) plus field consistency.
func shapeViolations(t lc.Tool) []string {
	var out []string
	seen := map[string]bool{}
	for _, v := range t.Versions {
		if v.Digest == "" || v.Digest == lc.UnusableDigest {
			out = append(out, "a version has an empty or marker digest")
		}
		if seen[v.Digest] {
			out = append(out, "duplicate digest "+v.Digest)
		}
		seen[v.Digest] = true
		if v.Status == lc.VersionApproved && !v.EverApproved {
			out = append(out, "approved version "+v.Digest+" is not EverApproved")
		}
	}
	pending, approved := statusCounts(t)
	if pending > 1 {
		out = append(out, fmt.Sprintf("%d pending versions", pending))
	}
	if approved > 1 {
		out = append(out, fmt.Sprintf("%d approved versions", approved))
	}
	out = append(out, approvedFieldViolations(t, approved)...)
	out = append(out, stateShapeViolations(t, pending)...)
	if t.MissingCrawls < 0 {
		out = append(out, "negative MissingCrawls")
	}
	if isLiveDigest(t.LastSeen) {
		if _, ok := findVersion(t, t.LastSeen); !ok {
			out = append(out, "LastSeen names an unknown version")
		}
	}
	if t.LastSeen != "" && t.MissingCrawls != 0 {
		out = append(out, "LastSeen is set while MissingCrawls is not zero")
	}
	return out
}

func approvedFieldViolations(t lc.Tool, approved int) []string {
	if t.Approved == "" {
		if approved != 0 {
			return []string{"an approved version exists but Approved is empty"}
		}
		return nil
	}
	v, ok := findVersion(t, t.Approved)
	if !ok || v.Status != lc.VersionApproved {
		return []string{"Approved " + t.Approved + " is not the digest of an approved version"}
	}
	return nil
}

func stateShapeViolations(t lc.Tool, pending int) []string {
	switch t.State {
	case lc.Enabled:
		if t.Approved == "" || pending != 0 {
			return []string{fmt.Sprintf("enabled needs an approval and no pending version (approved=%q pending=%d)", t.Approved, pending)}
		}
	case lc.ChangedPendingReapproval:
		if t.Approved == "" || pending != 1 {
			return []string{fmt.Sprintf("changed_pending_reapproval needs an approval and one pending version (approved=%q pending=%d)", t.Approved, pending)}
		}
	case lc.PendingReview:
		if t.Approved != "" {
			return []string{"pending_review with an approved digest " + t.Approved}
		}
	case lc.Discovered:
		// An unusable marker is the one sighting a discovered tool may carry:
		// it proves nothing about a definition, so it does not move the state.
		if len(t.Versions) != 0 || t.Approved != "" || isLiveDigest(t.LastSeen) {
			return []string{"discovered tool has versions, an approval or a sighting"}
		}
	case lc.Disabled, lc.Deprecated:
	default:
		return []string{"unknown state " + string(t.State)}
	}
	return nil
}

func allowedEdge(from, to lc.VersionStatus) bool {
	if from == to {
		return true
	}
	switch from {
	case lc.VersionPending:
		return to == lc.VersionApproved || to == lc.VersionRejected || to == lc.VersionSuperseded
	case lc.VersionApproved:
		return to == lc.VersionSuperseded
	case lc.VersionSuperseded:
		return to == lc.VersionApproved || to == lc.VersionPending
	}
	return false // rejected is terminal
}

func isApproveOrRollback(cmd lc.Command) bool {
	switch cmd.(type) {
	case lc.Approve, lc.Rollback:
		return true
	}
	return false
}

// retiresThenProposes is true for the two commands whose spec retires the
// approval and then proposes a digest in one step, which is why an approved
// version may come out pending.
func retiresThenProposes(rec stepRecord) bool {
	switch c := rec.cmd.(type) {
	case lc.Enable:
		return true
	case lc.ObserveCrawl:
		return c.Present && !c.Unusable && rec.before.State == lc.Deprecated
	}
	return false
}

// edgeViolations covers invariant (4) and the append-only shape of Versions.
func edgeViolations(rec stepRecord) []string {
	before, after := rec.before, rec.res.Tool
	if len(after.Versions) < len(before.Versions) {
		return []string{"a version was removed"}
	}
	var out []string
	added := len(after.Versions) - len(before.Versions)
	c, isCrawl := rec.cmd.(lc.ObserveCrawl)
	if added > 1 || (added == 1 && (!isCrawl || c.Unusable)) {
		out = append(out, fmt.Sprintf("%d versions added by %T", added, rec.cmd))
	}
	for i, old := range before.Versions {
		out = append(out, versionEdgeViolations(rec, old, after.Versions[i])...)
		out = append(out, proposerViolations(rec, old, after.Versions[i])...)
	}
	for _, nv := range after.Versions[len(before.Versions):] {
		if nv.Status != lc.VersionPending || nv.EverApproved || nv.ProposedBy != actorOf(rec.cmd) ||
			nv.Proposers != lc.ProposersOf(actorOf(rec.cmd)) {
			out = append(out, fmt.Sprintf("new version is not a fresh proposal by the actor: %+v", nv))
		}
	}
	return out
}

func versionEdgeViolations(rec stepRecord, old, nw lc.Version) []string {
	if nw.Digest != old.Digest {
		return []string{"version digest changed: " + old.Digest + " -> " + nw.Digest}
	}
	var out []string
	composite := old.Status == lc.VersionApproved && nw.Status == lc.VersionPending && retiresThenProposes(rec)
	if !allowedEdge(old.Status, nw.Status) && !composite {
		out = append(out, fmt.Sprintf("illegal status edge %s -> %s for %s via %T", old.Status, nw.Status, old.Digest, rec.cmd))
	}
	if old.EverApproved && !nw.EverApproved {
		out = append(out, "EverApproved went from true to false for "+old.Digest)
	}
	if !old.EverApproved && nw.EverApproved && (nw.Status != lc.VersionApproved || !isApproveOrRollback(rec.cmd)) {
		out = append(out, "EverApproved set without an approval for "+old.Digest)
	}
	if nw.Status == lc.VersionApproved && old.Status != lc.VersionApproved && !isApproveOrRollback(rec.cmd) {
		out = append(out, fmt.Sprintf("%T made %s approved", rec.cmd, old.Digest))
	}
	if _, isReject := rec.cmd.(lc.Reject); nw.Status == lc.VersionRejected && old.Status != lc.VersionRejected && !isReject {
		out = append(out, fmt.Sprintf("%T rejected %s", rec.cmd, old.Digest))
	}
	return out
}

// crawlViolations covers invariant (5) and the ObserveCrawl rules.
func crawlViolations(rec stepRecord) []string {
	c, ok := rec.cmd.(lc.ObserveCrawl)
	if !ok {
		return nil
	}
	before, after := rec.before, rec.res.Tool
	retired := c.Present && !c.Unusable && before.State == lc.Deprecated
	var out []string
	// Rule 6 of the v0.4 plan reads this table through the exported function;
	// every step the machine takes is checked against it here, so the table
	// cannot be narrower than the machine (TestCrawlMayMove_EqualsTheInvariantsTable
	// pins that it is not wider).
	if !lc.CrawlMayMove(before.State, after.State) {
		out = append(out, fmt.Sprintf("a crawl moved %s -> %s, which CrawlMayMove forbids", before.State, after.State))
	}
	if after.Approved != before.Approved && (!retired || after.Approved != "") {
		out = append(out, fmt.Sprintf("crawl changed Approved %q -> %q", before.Approved, after.Approved))
	}
	if retired && (after.State != lc.PendingReview || after.Approved != "") {
		out = append(out, "a reappearing deprecated tool must be pending_review with no approval")
	}
	switch {
	case c.Unusable:
		return append(out, unusableCrawlViolations(before, after)...)
	case c.Present:
		return append(out, presentCrawlViolations(c, before, after)...)
	}
	return append(out, missingCrawlViolations(rec.pol, before, after)...)
}

// unusableCrawlViolations: "LastSeen = UnusableDigest, MissingCrawls = 0,
// nothing else changes."
func unusableCrawlViolations(before, after lc.Tool) []string {
	want := cloneTool(before)
	want.LastSeen, want.MissingCrawls = lc.UnusableDigest, 0
	if !sameTool(after, want) {
		return []string{fmt.Sprintf("an unusable sighting changed more than the marker: %+v -> %+v", before, after)}
	}
	return nil
}

func presentCrawlViolations(c lc.ObserveCrawl, before, after lc.Tool) []string {
	var out []string
	if after.LastSeen != c.Digest || after.MissingCrawls != 0 {
		out = append(out, fmt.Sprintf("after a sighting LastSeen=%q MissingCrawls=%d", after.LastSeen, after.MissingCrawls))
	}
	if _, ok := findVersion(after, c.Digest); !ok {
		out = append(out, "the crawled digest is not a known version afterwards")
	}
	// A sighting moves along the exported crawl table, except that it never
	// deprecates (a miss does that); a sighting of a discovered or deprecated
	// tool must move it, which the shape and reappearance rules above pin.
	if !lc.CrawlMayMove(before.State, after.State) || after.State == lc.Deprecated {
		out = append(out, fmt.Sprintf("sighting moved %s -> %s", before.State, after.State))
	}
	if before.State != lc.Deprecated && c.Digest == before.Approved && len(after.Versions) != len(before.Versions) {
		out = append(out, "a sighting of the approved digest added a version")
	}
	if before.State == lc.Enabled && c.Digest != before.Approved {
		if after.State != lc.ChangedPendingReapproval && !isRejected(before, c.Digest) {
			out = append(out, "a new digest on an enabled tool must flag it changed")
		}
	}
	return out
}

func isRejected(t lc.Tool, digest string) bool {
	v, ok := findVersion(t, digest)
	return ok && v.Status == lc.VersionRejected
}

func missingCrawlViolations(p lc.Policy, before, after lc.Tool) []string {
	if before.State == lc.Discovered || before.State == lc.Deprecated {
		want := cloneTool(before)
		want.LastSeen = "" // only an unusable marker can go
		if !sameTool(want, after) {
			return []string{fmt.Sprintf("a miss changed a %s tool: %+v -> %+v", before.State, before, after)}
		}
		return nil
	}
	var out []string
	if after.LastSeen != "" || after.MissingCrawls != before.MissingCrawls+1 {
		out = append(out, fmt.Sprintf("after a miss LastSeen=%q MissingCrawls=%d (was %d)", after.LastSeen, after.MissingCrawls, before.MissingCrawls))
	}
	if after.Approved != before.Approved || !sameVersions(before, after) {
		out = append(out, "a miss changed approvals or versions")
	}
	switch {
	case before.State == lc.Disabled && after.State != lc.Disabled:
		out = append(out, "a disabled tool was deprecated")
	case after.State == lc.Deprecated && (p.DeprecateAfter <= 0 || after.MissingCrawls < p.DeprecateAfter):
		out = append(out, "deprecated before the threshold")
	case before.State != lc.Disabled && p.DeprecateAfter > 0 && after.MissingCrawls == p.DeprecateAfter && after.State != lc.Deprecated:
		out = append(out, "not deprecated at the threshold")
	case after.State != before.State && after.State != lc.Deprecated:
		out = append(out, fmt.Sprintf("a miss moved %s -> %s", before.State, after.State))
	}
	return out
}

func sameVersions(a, b lc.Tool) bool {
	return sameTool(lc.Tool{Versions: a.Versions}, lc.Tool{Versions: b.Versions})
}

// serveViolations covers invariants (6) and (7).
func serveViolations(t lc.Tool) []string {
	var out []string
	for _, live := range liveProbes() {
		got := t.Serves(live)
		if got != wantServes(t.State, t.Approved, live) {
			out = append(out, fmt.Sprintf("Serves(%q) = %v disagrees with the specification", live, got))
		}
		if !got {
			continue
		}
		v, ok := findVersion(t, t.Approved)
		switch {
		case t.Approved == "" || live != t.Approved:
			out = append(out, "served a digest that is not the approved one")
		case !ok || !v.EverApproved || v.Status != lc.VersionApproved:
			out = append(out, "served without an approved, EverApproved version")
		case !isServableState(t.State):
			out = append(out, "served in state "+string(t.State))
		}
	}
	return out
}
