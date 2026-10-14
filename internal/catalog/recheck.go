package catalog

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/sairam0424/toolwarrant/internal/gate"
)

// wireStore assembles a Store from its pools, with its clock and its memory of
// the audit chain. Nothing else is remembered between reads: a path that hands
// out bytes hashes them on every call, and the serving path hands out digests
// anchored to the verified chain without reading bytes at all (D21 d).
func wireStore(wdb, rdb *sql.DB, path string, opts OpenOptions) *Store {
	return &Store{wdb: wdb, rdb: rdb, path: path, policy: opts.Policy, now: time.Now,
		readOnly: opts.ReadOnly || opts.Forensic, forensic: opts.Forensic, caps: defaultServerCaps(),
		chain: newChainMemory()}
}

// approvedRef names one approved version row so that its approval can be
// anchored to the verified chain after the policy rows have been read. tool
// is the audit subject (server/tool) and entry the seq of the newest
// version.approved or version.rolled_back entry about it, NULL when the log
// has none; anchorApproved checks both. approver and at are the approver and
// the time the tool's newest approvals row holds, set by Approved alone, which
// checkAnchor compares with the entry's actor and timestamp (D17 e): the
// export used to take them from the row, which a re-created guard lets anyone
// rewrite while the chain stays clean. Empty where the caller shows neither.
// The row id is kept so that the reference can name the row; no path reads
// the row's bytes through it.
type approvedRef struct {
	id       int64
	tool     string
	digest   string
	entry    sql.NullInt64
	approver string
	at       string
	// showsApprover is set by Approved, whose rows carry the approver and the
	// time the verified entry must confirm; an empty at is then a rewritten row
	// and not a reason to skip the comparison (eighth review).
	showsApprover bool
}

// checkApprovedProfile requires an approved version to have been digested
// under the profile this build uses: an approval made under another rule means
// another thing. A string compare costs nothing.
func checkApprovedProfile(name, profile string) error {
	if profile != gate.DigestProfile {
		return fmt.Errorf("%w: approved version of %s was digested under profile %s, this build uses %s",
			ErrCorrupt, quote(name), quote(profile), gate.DigestProfile)
	}
	return nil
}
