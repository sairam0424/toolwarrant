package lifecycle

import "fmt"

// Disable and Enable: the operator's switch. Neither touches LastSeen or
// MissingCrawls, so what the upstream last did survives the round trip.

func disable(t Tool, c Disable) (Result, error) {
	if c.Actor == "" {
		return Result{}, ErrNoActor
	}
	if t.State == Disabled {
		return Result{}, fmt.Errorf("%w: already disabled", ErrInvalidTransition)
	}
	out := clone(t)
	out.State = Disabled
	return Result{Tool: out, Events: []Event{{EvDisabled, ""}}}, nil
}

// enable implements the Enable command; see its documentation for the rules.
func enable(t Tool, c Enable, p Policy) (Result, error) {
	if c.Actor == "" {
		return Result{}, ErrNoActor
	}
	if t.State != Disabled {
		return Result{}, fmt.Errorf("%w: cannot enable in state %s", ErrInvalidTransition, t.State)
	}
	out := clone(t)
	var ev []Event
	switch {
	case p.ReEnableRequiresReview || !isDigest(t.LastSeen):
		// A fresh approval is needed: by policy, or because the upstream shows
		// no usable definition to compare the retained approval with.
		supersedeApproved(&out, &ev)
		out.State = PendingReview
		if isDigest(t.LastSeen) && !isRejected(out, t.LastSeen) {
			repropose(&out, t.LastSeen, &ev)
		}
	case out.Approved == "":
		out.State = PendingReview
	case out.Pending() != "":
		out.State = ChangedPendingReapproval
	default:
		out.State = Enabled
	}
	ev = append(ev, Event{EvEnabled, ""})
	return Result{Tool: out, Events: ev}, nil
}

// isRejected reports whether digest names a version a person rejected; such a
// definition is never proposed again.
func isRejected(t Tool, digest string) bool {
	i := find(t, digest)
	return i >= 0 && t.Versions[i].Status == VersionRejected
}
