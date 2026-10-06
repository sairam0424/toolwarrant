package lifecycle

import "fmt"

// observe applies one crawl observation. The rules, including which events
// each change produces, are documented on ObserveCrawl.
func observe(t Tool, c ObserveCrawl, p Policy) (Result, error) {
	if err := validateObservation(c); err != nil {
		return Result{}, err
	}
	switch {
	case !c.Present:
		return observeMissing(t, p), nil
	case c.Unusable:
		return observeUnusable(t), nil
	default:
		return observePresent(t, c), nil
	}
}

// validateObservation rejects observations that contradict themselves. A
// digest on a non-present observation is ignored, as before, because absence
// is the whole message.
func validateObservation(c ObserveCrawl) error {
	if c.Actor == "" {
		return ErrNoActor
	}
	if c.Unusable {
		if !c.Present {
			return fmt.Errorf("%w: an unusable definition is a present one", ErrInvalidObservation)
		}
		if c.Digest != "" {
			return fmt.Errorf("%w: an unusable definition has no digest", ErrInvalidObservation)
		}
		return nil
	}
	if !c.Present {
		return nil
	}
	if c.Digest == "" {
		return ErrNoDigest
	}
	if c.Digest == UnusableDigest {
		return fmt.Errorf("%w: %q is a marker, not a digest", ErrInvalidObservation, UnusableDigest)
	}
	return nil
}

// observeMissing handles a successful crawl that did not list the tool.
func observeMissing(t Tool, p Policy) Result {
	out := clone(t)
	if t.State == Deprecated || t.State == Discovered {
		// Neither state counts misses; the only thing to clear is an unusable
		// marker left by an earlier sighting.
		if t.LastSeen == "" {
			return Result{Tool: out}
		}
		out.LastSeen = ""
		return Result{Tool: out, Events: []Event{{EvMissing, ""}}}
	}
	out.LastSeen = ""
	out.MissingCrawls = t.MissingCrawls + 1
	if p.DeprecateAfter > 0 && out.MissingCrawls >= p.DeprecateAfter && t.State != Disabled {
		out.State = Deprecated
		return Result{Tool: out, Events: []Event{{EvDeprecated, ""}}}
	}
	return Result{Tool: out, Events: []Event{{EvMissing, ""}}}
}

// observeUnusable records a listed definition that cannot be used. The state
// and the versions are untouched: there is nothing to propose, and the marker
// in LastSeen alone keeps the tool hidden until a clean definition appears.
func observeUnusable(t Tool) Result {
	out := clone(t)
	out.LastSeen, out.MissingCrawls = UnusableDigest, 0
	var ev []Event
	if t.MissingCrawls > 0 {
		ev = append(ev, Event{EvReturned, ""})
	}
	if t.LastSeen != UnusableDigest {
		ev = append(ev, Event{EvUnusable, ""})
	}
	return Result{Tool: out, Events: ev}
}

// observePresent handles a sighting with a real digest.
func observePresent(t Tool, c ObserveCrawl) Result {
	out := clone(t)
	out.LastSeen, out.MissingCrawls = c.Digest, 0
	var ev []Event
	if t.MissingCrawls > 0 {
		ev = append(ev, Event{EvReturned, c.Digest})
	}
	switch {
	case t.State == Deprecated:
		return reappear(out, c, ev)
	case c.Digest == t.Approved:
		return revert(t, out, c, ev)
	case isDecided(t, c.Digest):
		// Already rejected or already proposed: only the sighting is new, and
		// it is drift because the digest is not the approved one.
		if t.LastSeen != c.Digest {
			ev = append(ev, Event{EvDrifted, c.Digest})
		}
		return Result{Tool: out, Events: ev}
	default:
		return proposeLive(t, out, c, ev)
	}
}

// isDecided reports whether digest names a version that needs no new proposal:
// one a person rejected, or one that is pending already.
func isDecided(t Tool, digest string) bool {
	i := find(t, digest)
	return i >= 0 && (t.Versions[i].Status == VersionRejected || t.Versions[i].Status == VersionPending)
}

// reappear handles a sighting of a deprecated tool as a fresh proposal: the
// old approval is retired and a person has to approve again. The reappearance
// is the event; no drift or revert is reported against an approval that this
// same step retires.
func reappear(out Tool, c ObserveCrawl, ev []Event) Result {
	ev = append(ev, Event{EvReappeared, c.Digest})
	supersedeApproved(&out, &ev)
	out.State = PendingReview
	if i := find(out, c.Digest); i < 0 || out.Versions[i].Status != VersionRejected {
		propose(&out, c.Digest, c.Actor, &ev)
	}
	return Result{Tool: out, Events: ev}
}

// revert handles a sighting of the approved digest. It is reported whenever
// the sighting changes what is served: LastSeen moved back to the approval, or
// the tool leaves changed_pending_reapproval.
func revert(before, out Tool, c ObserveCrawl, ev []Event) Result {
	changed := before.LastSeen != c.Digest
	if out.State == ChangedPendingReapproval {
		supersedePending(&out, "", &ev)
		out.State = Enabled
		changed = true
	}
	if changed {
		ev = append(ev, Event{EvReverted, c.Digest})
	}
	return Result{Tool: out, Events: ev}
}

// proposeLive proposes a digest the tool has not decided on: a new one, or a
// superseded one that is back. The sighting is drift unless the tool had never
// been sighted (EvDiscovered reports that) or LastSeen already named this
// digest; an enabled tool that stops being served by it is drift regardless.
func proposeLive(before, out Tool, c ObserveCrawl, ev []Event) Result {
	wasNew := len(out.Versions) == 0
	propose(&out, c.Digest, c.Actor, &ev)
	switch {
	case before.State == Discovered:
		out.State = PendingReview
		if wasNew {
			ev = append([]Event{{EvDiscovered, c.Digest}}, ev...)
		}
	case before.State == Enabled:
		out.State = ChangedPendingReapproval
		ev = append(ev, Event{EvDrifted, c.Digest})
	case before.LastSeen != c.Digest:
		ev = append(ev, Event{EvDrifted, c.Digest})
	}
	return Result{Tool: out, Events: ev}
}
