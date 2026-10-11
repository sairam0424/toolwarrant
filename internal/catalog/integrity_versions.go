package catalog

import (
	"fmt"
	"slices"
	"strings"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/gate"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// The version side of Integrity: the approvals table behind every approved
// version, the bytes behind every approved digest, and (D14) every version's
// status, ever_approved flag and proposer list reconstructed from the log,
// because the status columns are mutable (a rejected version put back to
// pending is approvable again) and the proposer history is as rewritable as
// any guarded table under a re-created trigger.

// versionKey names one version as the log does: the tool subject and the digest.
type versionKey struct {
	subject, digest string
}

// versionTrace is what the log says about one version: the entry that first
// proposed it, the last entry about it, the status and ever_approved flag its
// events leave behind, and the actors of its version.proposed entries in order
// (an Enable re-proposal adds nobody, see isEnableReproposal). seen is set by
// checkVersionHistory when a row matched it.
type versionTrace struct {
	first, last int64
	status      lifecycle.VersionStatus
	ever        bool
	proposers   []string
	seen        bool
}

// version returns the trace for a version, creating it at entry seq.
func (c *integrityCheck) version(subject, digest string, seq int64) *versionTrace {
	k := versionKey{subject: subject, digest: digest}
	t := c.versions[k]
	if t == nil {
		t = &versionTrace{first: seq}
		c.versions[k] = t
	}
	return t
}

// noteVersionEvent folds one version.* entry into its version's trace. An
// event that the lifecycle never produces from the status the log left the
// version in (versionEdges) is reported: the Store writes every status move as
// an event, so an impossible edge in the log means the row was edited between
// the two entries (a rejected version put back to pending by hand and then
// approved reads rejected then approved, with no proposal between).
func (c *integrityCheck) noteVersionEvent(e audit.Entry) {
	digest, ok := detailField(e.Detail, fieldDigest)
	if !ok || digest == noDigest {
		return
	}
	t := c.version(e.Subject, digest, e.Seq)
	if from := t.status; !slices.Contains(versionEdges(e.Event), from) {
		c.problem("audit entry %d: %s of digest %s of tool %s from status %s, which the lifecycle never does; the row was edited between the entries",
			e.Seq, e.Event, digest, quote(e.Subject), shownStatus(from))
		c.rep.VersionStatusMismatches++
	}
	t.last = e.Seq
	switch e.Event {
	case string(lifecycle.EvProposed):
		t.status = lifecycle.VersionPending
		t.proposers = addProposer(t.proposers, e)
	case string(lifecycle.EvSuperseded):
		t.status = lifecycle.VersionSuperseded
	case string(lifecycle.EvRejected):
		t.status = lifecycle.VersionRejected
	case string(lifecycle.EvApproved), string(lifecycle.EvRolledBack):
		t.status, t.ever = lifecycle.VersionApproved, true
	}
}

// versionEdges lists the statuses the lifecycle moves a version from for one
// event ("" is a version the log has not proposed yet): a proposal names a new
// or superseded digest, or a pending one when a deprecated tool reappears on
// it; supersession retires a pending or the approved one; a reject and an
// approve take the pending one; a rollback takes a superseded digest, or a
// pending one that was approved before and proposed again.
func versionEdges(event string) []lifecycle.VersionStatus {
	switch event {
	case string(lifecycle.EvProposed):
		return []lifecycle.VersionStatus{"", lifecycle.VersionSuperseded, lifecycle.VersionPending}
	case string(lifecycle.EvSuperseded):
		return []lifecycle.VersionStatus{lifecycle.VersionPending, lifecycle.VersionApproved}
	case string(lifecycle.EvRejected), string(lifecycle.EvApproved):
		return []lifecycle.VersionStatus{lifecycle.VersionPending}
	case string(lifecycle.EvRolledBack):
		return []lifecycle.VersionStatus{lifecycle.VersionSuperseded, lifecycle.VersionPending}
	}
	return nil
}

// shownStatus renders a log status for a report line; "" is a digest the log
// has not proposed.
func shownStatus(s lifecycle.VersionStatus) string {
	if s == "" {
		return "unproposed"
	}
	return string(s)
}

// isEnableReproposal reports whether a version.proposed entry was written by
// Enable, which re-proposes the last seen definition without adding its actor
// to the proposers (D4: the enabler introduced no bytes). Enable is the one
// operation that leaves the disabled state, and every event of one operation
// carries the operation's state transition, so a version.proposed whose state
// field leaves disabled is Enable's; a crawl that proposes to a disabled tool
// leaves it disabled.
func isEnableReproposal(detail string) bool {
	state, ok := detailField(detail, fieldState)
	if !ok {
		return false
	}
	before, after, ok := strings.Cut(state, transitionArrow)
	return ok && before == string(lifecycle.Disabled) && after != string(lifecycle.Disabled)
}

// isVersionEvent reports whether an event moves a version's status.
func isVersionEvent(event string) bool {
	switch event {
	case string(lifecycle.EvProposed), string(lifecycle.EvSuperseded), string(lifecycle.EvRejected),
		string(lifecycle.EvApproved), string(lifecycle.EvRolledBack):
		return true
	}
	return false
}

// integrityVersionsQuery reads every version that claims to have been approved
// at some point, with whether the approvals table agrees.
const integrityVersionsQuery = `SELECT s.name, t.name, v.version_no, v.status, v.ever_approved, ` + approvalRecorded + `
	FROM tool_versions v JOIN tools t ON t.id = v.tool_id JOIN servers s ON s.id = t.server_id
	WHERE v.status = 'approved' OR v.ever_approved = 1
	ORDER BY s.name, t.name, v.version_no`

// checkVersions requires an approve or rollback row behind every version that
// is, or was ever, approved.
func (c *integrityCheck) checkVersions() error {
	rows, err := c.q.QueryContext(c.ctx, integrityVersionsQuery)
	if err != nil {
		return fmt.Errorf("catalog: read versions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			server, tool, status string
			no, ever, recorded   int
		)
		if err := rows.Scan(&server, &tool, &no, &status, &ever, &recorded); err != nil {
			return fmt.Errorf("catalog: read versions: %w", err)
		}
		if recorded == 0 {
			c.rep.ApprovalsWithoutRecord++
			c.problem("version %d of tool %s is marked approved (status %s, ever_approved %d) but has no approval record",
				no, quote(server+"/"+tool), status, ever)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("catalog: read versions: %w", err)
	}
	return nil
}

// versionHistoryQuery reads every version with its subject, status and flag.
const versionHistoryQuery = `SELECT s.name || '/' || t.name, v.id, v.version_no, v.digest, v.status, v.ever_approved
	FROM tool_versions v JOIN tools t ON t.id = v.tool_id JOIN servers s ON s.id = t.server_id
	ORDER BY s.name, t.name, v.version_no`

// checkVersionHistory compares every version row with what the log says about
// it, then reports the versions the log proposed that have no row.
func (c *integrityCheck) checkVersionHistory() error {
	proposers, err := c.readProposers()
	if err != nil {
		return err
	}
	rows, err := c.q.QueryContext(c.ctx, versionHistoryQuery)
	if err != nil {
		return fmt.Errorf("catalog: read versions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			subject, digest, status string
			id                      int64
			no, ever                int
		)
		if err := rows.Scan(&subject, &id, &no, &digest, &status, &ever); err != nil {
			return fmt.Errorf("catalog: read versions: %w", err)
		}
		c.compareVersion(subject, digest, no, lifecycle.VersionStatus(status), ever == 1, proposers[id])
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("catalog: read versions: %w", err)
	}
	c.reportVersionsWithoutRow()
	return nil
}

// compareVersion checks one version row against its trace.
func (c *integrityCheck) compareVersion(subject, digest string, no int, status lifecycle.VersionStatus, ever bool, names []string) {
	shown := quote(subject)
	t := c.versions[versionKey{subject: subject, digest: digest}]
	if t == nil {
		c.problem("version %d of tool %s: the audit log never proposed digest %s", no, shown, digest)
		c.rep.VersionStatusMismatches++
		return
	}
	t.seen = true
	if t.status != status || t.ever != ever {
		c.problem("version %d of tool %s: status is %s (ever_approved %t) but the audit log (latest entry seq %d) leaves it %s (ever_approved %t)",
			no, shown, quote(string(status)), ever, t.last, t.status, t.ever)
		c.rep.VersionStatusMismatches++
	}
	if !slices.Equal(t.proposers, names) {
		c.problem("version %d of tool %s: proposers are %q but the version.proposed entries name %q",
			no, shown, names, t.proposers)
		c.rep.ProposerMismatches++
	}
}

// reportVersionsWithoutRow lists, by subject and first entry, every version
// the log proposed whose row is gone.
func (c *integrityCheck) reportVersionsWithoutRow() {
	keys := slices.SortedFunc(func(yield func(versionKey) bool) {
		for k, t := range c.versions {
			if !t.seen && !yield(k) {
				return
			}
		}
	}, func(a, b versionKey) int {
		if a.subject != b.subject {
			return strings.Compare(a.subject, b.subject)
		}
		return int(c.versions[a].first - c.versions[b].first)
	})
	for _, k := range keys {
		c.problem("tool %s: the audit log proposed digest %s (entry seq %d) but no tool_versions row exists", quote(k.subject), k.digest, c.versions[k].first)
		c.rep.RowsMissing++
	}
}

// readProposers loads every version's proposers in position order. A gap in
// the positions is reported and leaves the version's list as read so far,
// where the Store's own loader would refuse the file: a report must list every
// disagreement, not stop at the first.
func (c *integrityCheck) readProposers() (map[int64][]string, error) {
	rows, err := c.q.QueryContext(c.ctx, `SELECT version_id, position, actor FROM tool_version_proposers ORDER BY version_id, position`)
	if err != nil {
		return nil, fmt.Errorf("catalog: read proposers: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[int64][]string{}
	for rows.Next() {
		var (
			versionID int64
			position  int
			actor     string
		)
		if err := rows.Scan(&versionID, &position, &actor); err != nil {
			return nil, fmt.Errorf("catalog: read proposers: %w", err)
		}
		if position != len(out[versionID]) {
			c.problem("proposers of version row %d are not in sequence at position %d", versionID, position)
			c.rep.ProposerMismatches++
			continue
		}
		out[versionID] = append(out[versionID], actor)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("catalog: read proposers: %w", err)
	}
	return out, nil
}

// orphanVersionsQuery reads every version whose tool row is gone.
const orphanVersionsQuery = `SELECT v.id, v.tool_id, v.version_no, v.digest FROM tool_versions v
	LEFT JOIN tools t ON t.id = v.tool_id WHERE t.id IS NULL ORDER BY v.id`

// checkOrphanVersions reports tool_versions rows whose tool is gone: the
// catalog never deletes a tools row, and every other pass joins the tools
// table and would drop them.
func (c *integrityCheck) checkOrphanVersions() error {
	rows, err := c.q.QueryContext(c.ctx, orphanVersionsQuery)
	if err != nil {
		return fmt.Errorf("catalog: read versions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			id, toolID int64
			no         int
			digest     string
		)
		if err := rows.Scan(&id, &toolID, &no, &digest); err != nil {
			return fmt.Errorf("catalog: read versions: %w", err)
		}
		c.problem("version row %d (version %d, digest %s) belongs to tool row %d, which does not exist", id, no, shownDigest(digest), toolID)
		c.rep.RowsMissing++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("catalog: read versions: %w", err)
	}
	return nil
}

// integrityBytesQuery streams the bytes of every approved version.
const integrityBytesQuery = `SELECT s.name, t.name, v.digest, v.digest_profile, v.canonical
	FROM tool_versions v JOIN tools t ON t.id = v.tool_id JOIN servers s ON s.id = t.server_id
	WHERE v.status = 'approved' ORDER BY s.name, t.name`

// checkApprovedBytes re-hashes every approved definition against its digest
// and checks its profile, as the read paths do, but without the Store's
// memory of earlier checks: a report must say what the rows hold now.
func (c *integrityCheck) checkApprovedBytes() error {
	rows, err := c.q.QueryContext(c.ctx, integrityBytesQuery)
	if err != nil {
		return fmt.Errorf("catalog: read approved versions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			server, tool, digest, profile string
			canonical                     []byte
		)
		if err := rows.Scan(&server, &tool, &digest, &profile, &canonical); err != nil {
			return fmt.Errorf("catalog: read approved versions: %w", err)
		}
		shown := quote(server + "/" + tool)
		if profile != gate.DigestProfile {
			c.problem("approved version of tool %s was digested under profile %s, this build uses %s", shown, quote(profile), gate.DigestProfile)
		}
		if gate.DigestOfCanonical(canonical) != digest {
			c.problem("approved version of tool %s does not hash to its digest %s", shown, shownDigest(digest))
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("catalog: read approved versions: %w", err)
	}
	return nil
}
