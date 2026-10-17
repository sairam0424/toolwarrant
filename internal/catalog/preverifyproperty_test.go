package catalog

import (
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
	"github.com/sairam0424/toolwarrant/internal/signing"
)

// The pure half of the signed-record walk is pure and order-independent (D23
// (a)): for any page of entries, signed ones carrying a flaw or none among
// unsigned ones, the slots preverifyPage fills under any worker count are the
// slots obtained by running the check on the signed entries one at a time in
// any drawn order, slot for slot. The check reads nothing but the entry, its
// row and the identity, so no catalog is built: the entries are made in memory
// over a drawn head and signed with one throwaway key.

// flaw is one way a drawn signed entry or its row departs from what the Store
// writes, each refused by a different sentence of the pure half; flawNone is a
// record it accepts.
type flaw int

const (
	flawNone flaw = iota
	flawOtherCatalog
	flawOtherHead
	flawTamperedPayload
	flawSignerToken
	flawSystemActor
	flawNoRow
	flawCount
)

// drawnPage is one drawn page: the entries, the rows by seq and the positions
// of the signed entries in the page.
type drawnPage struct {
	page   []audit.Entry
	rows   map[int64]signing.Record
	signed []int
}

func TestProperty_preverifyIsPureAndOrderIndependent(t *testing.T) {
	t.Parallel()
	alice := newOperator(t, "alice")
	identity := strings.Repeat("ab", identityBytes)
	rapid.Check(t, func(rt *rapid.T) {
		d := drawPage(t, rt, alice, identity)
		workers := rapid.IntRange(1, 2*runtime.NumCPU()).Draw(rt, "workers")
		slots, err := preverifyPage(bg, d.page, d.rows, identity, workers)
		if err != nil || len(slots) != len(d.signed) {
			rt.Fatalf("preverifyPage = %d slots, %v; want one per signed entry, %d", len(slots), err, len(d.signed))
		}
		ordinals := make([]int, len(d.signed))
		for k := range ordinals {
			ordinals[k] = k
		}
		want := make([]preverified, len(slots))
		for _, k := range rapid.Permutation(ordinals).Draw(rt, "order") {
			want[k] = preverifyEntry(d.page[d.signed[k]], d.rows, identity)
		}
		for k := range want {
			if !samePreverified(want[k], slots[k]) {
				rt.Fatalf("slot %d under %d workers is %s; the same entry checked alone is %s", k, workers, describePreverified(slots[k]), describePreverified(want[k]))
			}
		}
	})
}

// drawPage draws up to twelve entries, each signed or not, the signed ones
// with a drawn flaw, every entry over its own drawn head.
func drawPage(t *testing.T, rt *rapid.T, alice operator, identity string) drawnPage {
	t.Helper()
	d := drawnPage{rows: map[int64]signing.Record{}}
	for i := range rapid.IntRange(0, 12).Draw(rt, "entries") {
		seq := int64(i + 1)
		head := fmt.Sprintf("%064x", rapid.Uint64().Draw(rt, "head"))
		if !rapid.Bool().Draw(rt, "signed") {
			d.page = append(d.page, audit.Entry{Seq: seq, Actor: crawler.Name, ActorType: string(crawler.Type),
				Event: string(lifecycle.EvDiscovered), Subject: "alpha/echo", PrevHash: head})
			continue
		}
		e, rec := drawSignedEntry(t, rt, alice, identity, seq, head)
		d.signed = append(d.signed, len(d.page))
		d.page = append(d.page, e)
		if rec != nil {
			d.rows[seq] = *rec
		}
	}
	return d
}

// drawSignedEntry draws one signed entry at seq over head, a trust bootstrap
// or a decision by alice, with a drawn flaw; the row is nil under flawNoRow.
func drawSignedEntry(t *testing.T, rt *rapid.T, alice operator, identity string, seq int64, head string) (audit.Entry, *signing.Record) {
	t.Helper()
	f := flaw(rapid.IntRange(0, int(flawCount)-1).Draw(rt, "flaw"))
	catalog, prev := identity, head
	switch f {
	case flawOtherCatalog:
		catalog = strings.Repeat("cd", identityBytes)
	case flawOtherHead:
		prev = strings.Repeat("0", 2*len(entryHash{}))
	}
	var rec signing.Record
	var event, subject, detail string
	if rapid.Bool().Draw(rt, "trust") {
		rec = signList(t, listFor(catalog, prev, 1, alice, alice), alice.key)
		event, subject, detail = evTrustBootstrap, trustSubject, fmt.Sprintf("%s=1 %s=1", fieldVersion, fieldSigners)
	} else {
		digest := digestOf(t, "echo", "v1")
		rec = *signDecisionPayload(t, decisionOf(catalog, prev, alice, signing.KindApprove, "alpha", "echo", digest), alice)
		event, subject, detail = evDecisionSigned, "alpha/echo", decisionDetail(signing.KindApprove, digest)
	}
	if f == flawTamperedPayload {
		rec.Payload = append([]byte(nil), rec.Payload...)
		rec.Payload[len(rec.Payload)-1] ^= 1 // the sigref below is taken over the tampered bytes, so the signature is what refuses
	}
	e := audit.Entry{Seq: seq, TS: formatTime(listSignedAt()), Actor: alice.name, ActorType: string(ActorHuman),
		Event: event, Subject: subject, Detail: signedDetail(detail, rec), PrevHash: head}
	switch f {
	case flawSignerToken:
		e.Detail = strings.Replace(e.Detail, fieldSigner+"="+rec.Signer, fieldSigner+"=SHA256:nobody", 1)
	case flawSystemActor:
		e.ActorType = string(ActorSystem)
	case flawNoRow:
		return e, nil
	}
	return e, &rec
}

// samePreverified reports whether two slots say the same: the same parsed
// payload, or the same refusal under the same rule.
func samePreverified(a, b preverified) bool {
	if (a.err == nil) != (b.err == nil) {
		return false
	}
	if a.err != nil {
		var pa, pb *signedProblem
		errors.As(a.err, &pa)
		errors.As(b.err, &pb)
		return a.err.Error() == b.err.Error() && (pa == nil) == (pb == nil) && (pa == nil || pa.rule == pb.rule)
	}
	return reflect.DeepEqual(a.list, b.list) && reflect.DeepEqual(a.decision, b.decision)
}

// describePreverified renders a slot for a failure message: the refusal, or
// the parsed payload with the head it was signed over, which tells two
// accepted records of one page apart.
func describePreverified(pv preverified) string {
	switch {
	case pv.err != nil:
		return "refused: " + pv.err.Error()
	case pv.list != nil:
		return fmt.Sprintf("trust list v%d over %s", pv.list.Version, pv.list.PrevHead)
	case pv.decision != nil:
		return fmt.Sprintf("decision %s over %s", pv.decision.Kind, pv.decision.PrevHead)
	}
	return "empty"
}
