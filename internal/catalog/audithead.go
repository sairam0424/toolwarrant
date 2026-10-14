package catalog

import (
	"context"

	"github.com/sairam0424/toolwarrant/internal/audit"
)

// AuditHead returns the head of the audit chain as this Store has verified it:
// the hash of the newest entry, as the walk computed it from the entry's
// fields, or audit.Genesis for an empty log. It runs the same file check as
// every view (checkFilePinned): the file at the path still the one this Store
// opened, no row below id 1, the guard objects intact, and the chain verified
// from the pin to the newest entry; the pin is read under the same hold of the
// walk lock as that walk, so the value is the head of this read's own snapshot
// and never comes from a stored hash column. An export that needs the head of
// the same snapshot its approvals came from calls ApprovedWithHead; AuditHead
// is for a caller that wants the head alone.
func (s *Store) AuditHead(ctx context.Context) (string, error) {
	head := audit.Genesis
	err := s.inRead(ctx, func(q queryer) error {
		pin, err := s.checkFilePinned(ctx, q)
		if err != nil {
			return err
		}
		head = headOf(pin)
		return nil
	})
	if err != nil {
		return "", err
	}
	return head, nil
}

// headOf renders a verified pin as the head an operator records: the hash of
// the pinned entry, or audit.Genesis when nothing has been verified because
// the log is empty.
func headOf(pin chainPin) string {
	if pin.seq == 0 {
		return audit.Genesis
	}
	return pin.hash
}
