package catalog

import (
	"context"

	"github.com/sairam0424/toolwarrant/internal/audit"
)

// AuditHead returns the head of the audit chain as this Store has verified it:
// the hash of the newest entry, as the walk computed it from the entry's
// fields, or audit.Genesis for an empty log. It runs the same file check as
// every view (checkFile): the file at the path still the one this Store
// opened, no row below id 1, the guard objects intact, and the chain verified
// from the pin to the newest entry under the walk lock, so the value never
// comes from a stored hash column and never predates a commit this read can
// see. The export records it in MANIFEST.json so that a signed export names
// the exact log it mirrors (D21 e); the export reads it after Approved, so
// that the head covers every approval the export carries.
func (s *Store) AuditHead(ctx context.Context) (string, error) {
	head := audit.Genesis
	err := s.inRead(ctx, func(q queryer) error {
		if err := s.checkFile(ctx, q); err != nil {
			return err
		}
		if pin := s.chain.pin(); pin.seq != 0 {
			head = pin.hash
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return head, nil
}
