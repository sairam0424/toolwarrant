package catalog

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/sairam0424/toolwarrant/internal/gate"
)

// wireStore assembles a Store from its pools, with its clock, its verifier and
// its memory of the audit chain. A forensic open remembers no re-check of
// version bytes: it exists to look at a database someone edited and must
// report what the rows hold now.
func wireStore(wdb, rdb *sql.DB, path string, opts OpenOptions) *Store {
	s := &Store{wdb: wdb, rdb: rdb, path: path, policy: opts.Policy, now: time.Now,
		readOnly: opts.ReadOnly || opts.Forensic, forensic: opts.Forensic, caps: defaultServerCaps(),
		chain: newChainMemory()}
	bound := recheckCacheEntries
	if opts.Forensic {
		bound = 0
	}
	s.verified = newVerifier(s.clock, bound)
	return s
}

// clock reads the Store's clock at call time, so the verifier follows a test
// that replaces now after Open.
func (s *Store) clock() time.Time { return s.now() }

// approvedRef names one approved version row so that its bytes can be
// re-checked after the policy rows have been read, and only if the verifier
// does not remember it: a remembered row is neither read nor hashed. tool is
// the audit subject (server/tool) and entry the seq of the newest
// version.approved or version.rolled_back entry about it, NULL when the log
// has none; anchorApproved checks both. approver and at are the approver and
// the time the tool's newest approvals row holds, set by Approved alone, which
// checkAnchor compares with the entry's actor and timestamp (D17 e): the
// export used to take them from the row, which a re-created guard lets anyone
// rewrite while the chain stays clean. Empty where the caller shows neither.
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

// canonicalChunk is how many rows one re-check query fetches. The rows stream
// through one at a time, so the chunk bounds the statement, not the memory;
// SQLite accepts far more bound parameters than this.
const canonicalChunk = 256

// recheckApproved re-hashes every approved version in refs that the verifier
// does not remember. The bytes are read by row id, in chunks, inside the same
// read transaction, so the check sees the snapshot the policy came from and a
// remembered row costs no read at all.
func (s *Store) recheckApproved(ctx context.Context, q queryer, refs []approvedRef) error {
	missed := make(map[int64]approvedRef)
	var ids []int64
	for _, r := range refs {
		if !s.verified.remembered(r.id, r.digest) {
			missed[r.id] = r
			ids = append(ids, r.id)
		}
	}
	for len(ids) > 0 {
		n := min(len(ids), canonicalChunk)
		if err := s.recheckChunk(ctx, q, missed, ids[:n]); err != nil {
			return err
		}
		ids = ids[n:]
	}
	return nil
}

// recheckChunk reads the canonical bytes of the given rows and hashes each
// against the digest the policy carries. Every id must come back: the policy
// query joined the same rows in the same transaction.
func (s *Store) recheckChunk(ctx context.Context, q queryer, missed map[int64]approvedRef, ids []int64) error {
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	rows, err := q.QueryContext(ctx,
		`SELECT id, canonical FROM tool_versions WHERE id IN (?`+strings.Repeat(",?", len(ids)-1)+`)`, args...)
	if err != nil {
		return fmt.Errorf("catalog: read approved versions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	seen := 0
	for rows.Next() {
		var (
			id        int64
			canonical []byte
		)
		if err := rows.Scan(&id, &canonical); err != nil {
			return fmt.Errorf("catalog: read approved versions: %w", err)
		}
		r, ok := missed[id]
		if !ok {
			return fmt.Errorf("%w: version %d was read but not asked for", ErrCorrupt, id)
		}
		if !s.verified.check(r.id, r.digest, canonical) {
			return fmt.Errorf("%w: approved version of %s does not hash to its digest", ErrCorrupt, quote(r.tool))
		}
		seen++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("catalog: read approved versions: %w", err)
	}
	if seen != len(ids) {
		return fmt.Errorf("%w: %d approved versions vanished within one read", ErrCorrupt, len(ids)-seen)
	}
	return nil
}

// checkApprovedProfile requires an approved version to have been digested
// under the profile this build uses: an approval made under another rule means
// another thing. The verifier never covers it; a string compare costs nothing.
func checkApprovedProfile(name, profile string) error {
	if profile != gate.DigestProfile {
		return fmt.Errorf("%w: approved version of %s was digested under profile %s, this build uses %s",
			ErrCorrupt, quote(name), quote(profile), gate.DigestProfile)
	}
	return nil
}
