package catalog

import (
	"fmt"
	"testing"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// The four sentences of the shape rule (checkTransactionShape), pinned byte
// for byte against a transaction the walk has recorded: the once, state,
// after_hash and ended sentences in the order the rule applies them. The
// after_hash and once sentences are also reached end to end by the history
// probes of TestWalk_RefusesASignedTokenThatDoesNotBindTheEntry; the state
// sentence is not reachable by an appended forgery since the ended clause
// (every forgery lands after the decision's own event) and was pinned by no
// test, so docs/operations.md quoted it without the strconv.Quote the code
// puts around the two state fields (the third review of PR 7.5).
func TestWalk_TheShapeRuleSentencesAreFixed(t *testing.T) {
	t.Parallel()
	const n, first, ts = 5, 6, "2026-10-16T10:00:00.000000000Z"
	ech, ech2 := digestOf(t, "echo", "v1"), digestOf(t, "echo", "v2")
	entry := func(seq int64, event, digest, after string, to lifecycle.State) audit.Entry {
		e := toolEntry{by: alice, event: event, subject: "alpha/echo", digest: digest, before: ech, after: after,
			from: lifecycle.Enabled, to: to, lastSeen: ech, note: signedNote(n), ts: ts}.entry()
		e.Seq = seq
		return e
	}
	open := openTxn{seq: n, first: first, state: "enabled->disabled", after: ech,
		events: []txnEvent{{seq: first, event: string(lifecycle.EvSuperseded), digest: ech}}}
	ended := open
	ended.events = append(ended.events, txnEvent{seq: first + 1, event: string(lifecycle.EvDisabled), digest: noDigest})
	cases := []struct {
		name     string
		txn      openTxn
		entry    audit.Entry
		sentence string
	}{
		{"an entry of the transaction's shape is accepted", open,
			entry(first+1, string(lifecycle.EvDisabled), "", ech, lifecycle.Disabled), ""},
		{"a second event of the same digest", open,
			entry(first+1, string(lifecycle.EvSuperseded), ech, ech, lifecycle.Disabled),
			fmt.Sprintf("audit entry %d is a second version.superseded of digest %s under signed=%d (entry %d wrote the first); a decision writes each of its events once", first+1, ech, n, first)},
		{"another transition than the first entry's", open,
			entry(first+1, string(lifecycle.EvDisabled), "", ech, lifecycle.PendingReview),
			fmt.Sprintf(`audit entry %d names signed=%d and says state="enabled->pending_review" but the first entry of that transaction (seq %d) says state="enabled->disabled"; the entries of one decision record one transition`, first+1, n, first)},
		{"another after_hash than the first entry's", open,
			entry(first+1, string(lifecycle.EvDisabled), "", "", lifecycle.Disabled),
			fmt.Sprintf("audit entry %d names signed=%d and records after_hash none but the first entry of that transaction (seq %d) records %s; the entries of one decision record one approved digest", first+1, n, first, ech)},
		{"an entry after the decision's own event", ended,
			entry(first+2, string(lifecycle.EvProposed), ech2, ech, lifecycle.Disabled),
			fmt.Sprintf("audit entry %d names signed=%d but that transaction ended with its tool.disabled (seq %d), the last entry a decision writes; the entry was appended outside toolwarrant", first+2, n, first+1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := checkTransactionShape(tc.entry, tc.txn)
			switch {
			case tc.sentence == "" && err != nil:
				t.Errorf("checkTransactionShape = %v, want accepted", err)
			case tc.sentence != "" && (err == nil || err.Error() != tc.sentence):
				t.Errorf("checkTransactionShape = %v, want exactly %q", err, tc.sentence)
			}
		})
	}
}
