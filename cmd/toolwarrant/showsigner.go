package main

import (
	"fmt"

	"github.com/sairam0424/toolwarrant/internal/catalog"
)

// What show says about the approval in force (D22 (h), owner decision O-12):
// who approved and whether a signed record backs it. The approver and the
// entry come from the verified approval entry (ToolView.ApprovedBy,
// ApprovedSeq, SignedSeq); the signer's fingerprint from the decision.signed
// record that entry names, through the checked read behind audit list --json.

// signerJSON is the "signer" of show --json: the operator who approved, the
// fingerprint of the key that signed and the decision.signed entry; null for
// an unsigned approval and while nothing is approved.
type signerJSON struct {
	Operator string `json:"operator"`
	Key      string `json:"key"`
	Entry    int64  `json:"entry"`
}

// approvalLine is the line show prints under the versions table and the
// signer of show --json: `approved by alice, signed with SHA256:FP (audit
// entry N)` for a signed approval; `approved by alice, unsigned (before the
// cut-over at entry B)` for one made before the bootstrap, which stands by
// chain anchoring alone until re-approved; `approved by alice, unsigned (no
// trust list)` on a catalog never bootstrapped. Nothing while nothing is
// approved.
func (a *app) approvalLine(store *catalog.Store, view catalog.ToolView) (string, *signerJSON, error) {
	if view.Approved == "" {
		return "", nil, nil
	}
	if view.SignedSeq != 0 {
		records, err := store.SignedRecords(a.ctx, []int64{view.SignedSeq})
		if err != nil {
			return "", nil, err
		}
		rec, ok := records[view.SignedSeq]
		if !ok {
			return "", nil, fmt.Errorf("%w: the approval entry %d names signed=%d, which carries no signed record", catalog.ErrCorrupt, view.ApprovedSeq, view.SignedSeq)
		}
		line := fmt.Sprintf("approved by %s, signed with %s (audit entry %d)", cell(view.ApprovedBy), rec.Signer, view.SignedSeq)
		return line, &signerJSON{Operator: view.ApprovedBy, Key: rec.Signer, Entry: view.SignedSeq}, nil
	}
	tv, err := store.TrustList(a.ctx)
	if err != nil {
		return "", nil, err
	}
	if tv.InForce() {
		return fmt.Sprintf("approved by %s, unsigned (before the cut-over at entry %d)", cell(view.ApprovedBy), tv.BootstrapSeq), nil, nil
	}
	return fmt.Sprintf("approved by %s, unsigned (no trust list)", cell(view.ApprovedBy)), nil, nil
}
