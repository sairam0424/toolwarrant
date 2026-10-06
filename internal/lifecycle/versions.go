package lifecycle

// Version bookkeeping shared by the command handlers. Every function here
// edits the Tool it is given, which is always a clone made by the handler, and
// records the events that the edit produces.

// supersedePending marks every pending version superseded, except the one
// named by except, and records an event for each.
func supersedePending(t *Tool, except string, ev *[]Event) {
	for i := range t.Versions {
		if t.Versions[i].Status == VersionPending && t.Versions[i].Digest != except {
			t.Versions[i].Status = VersionSuperseded
			*ev = append(*ev, Event{EvSuperseded, t.Versions[i].Digest})
		}
	}
}

// supersedeApproved retires the approval: the approved version becomes
// superseded and Approved becomes "".
func supersedeApproved(t *Tool, ev *[]Event) {
	if t.Approved == "" {
		return
	}
	if i := find(*t, t.Approved); i >= 0 && t.Versions[i].Status == VersionApproved {
		t.Versions[i].Status = VersionSuperseded
		*ev = append(*ev, Event{EvSuperseded, t.Approved})
	}
	t.Approved = ""
}

// propose makes digest the single pending version, proposed by actor. A digest
// seen before and since superseded is proposed again: its status returns to
// pending and actor joins its proposers, while ProposedBy keeps naming the
// first one. The list only grows, so nobody who ever introduced these bytes
// can approve them later.
func propose(t *Tool, digest, actor string, ev *[]Event) {
	supersedePending(t, digest, ev)
	if i := find(*t, digest); i >= 0 {
		v := &t.Versions[i]
		v.Status = VersionPending
		if v.ProposedBy == "" {
			v.ProposedBy = actor
		}
		v.Proposers = proposersOf(*v).Add(actor)
	} else {
		t.Versions = append(t.Versions, Version{
			Digest: digest, Status: VersionPending, ProposedBy: actor, Proposers: ProposersOf(actor),
		})
	}
	*ev = append(*ev, Event{EvProposed, digest})
}

// repropose is propose for Enable: the known version named by digest becomes
// the single pending version again, but nobody is added to its proposers,
// because Enable introduces no definition. A version that is pending already
// is left alone without an event, and so is a digest that names no version:
// Enable has no bytes to create one from.
func repropose(t *Tool, digest string, ev *[]Event) {
	i := find(*t, digest)
	if i < 0 || t.Versions[i].Status == VersionPending {
		return
	}
	supersedePending(t, digest, ev)
	t.Versions[i].Status = VersionPending
	*ev = append(*ev, Event{EvProposed, digest})
}
