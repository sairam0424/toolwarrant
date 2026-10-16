package catalog

import (
	"testing"

	"github.com/sairam0424/toolwarrant/internal/signing"
)

// The Tool view carries who approved and whether a signed record backs it,
// from the verified approval entry the anchor pass reads (D22 (h): what show
// prints): the approver and the entry's seq for every approval, the seq of
// the decision.signed entry for one made after the bootstrap, 0 for a legacy
// approval, and nothing while nothing is approved.
func TestTool_CarriesTheApproverAndTheSignedTokenOfItsApprovalEntry(t *testing.T) {
	t.Parallel()
	s, _, _, bob := trustedCatalog(t)
	pending := mustTool(t, s, "alpha", "sum")
	if pending.Approved != "" || pending.ApprovedBy != "" || pending.ApprovedSeq != 0 || pending.SignedSeq != 0 {
		t.Fatalf("nothing approved, yet the view says %+v", pending)
	}
	legacy := mustTool(t, s, "alpha", "echo")
	if legacy.Approved == "" || legacy.ApprovedBy != bob.name || legacy.ApprovedSeq == 0 || legacy.SignedSeq != 0 {
		t.Fatalf("legacy approval view = %+v, want bob's unsigned approval (mustApprove approves as bob)", legacy)
	}
	r := mustDecide(t, s, bob, signing.KindApprove, "alpha", "sum", pendingSum(t))
	signed := mustTool(t, s, "alpha", "sum")
	if signed.Approved != pendingSum(t) || signed.ApprovedBy != bob.name || signed.SignedSeq != r.Seq || signed.ApprovedSeq <= r.Seq {
		t.Fatalf("signed approval view = %+v, want bob's approval naming signed=%d after it", signed, r.Seq)
	}
	if signed.ApprovedSeq != entriesOfTransaction(t, s, r.Seq)[len(entriesOfTransaction(t, s, r.Seq))-1].Seq {
		t.Errorf("ApprovedSeq %d is not the last entry of the decision's transaction", signed.ApprovedSeq)
	}
}
