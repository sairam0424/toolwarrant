package catalog

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"

	"github.com/sairam0424/toolwarrant/internal/audit"
	"github.com/sairam0424/toolwarrant/internal/gate"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
)

// toolViewSelect reads a tool as the list and show commands render it, with
// the approval evidence the serving path applies (D14 f): the approved version
// aliased v so that newestDecisionNames applies, its tool id, its profile and
// the seq of the newest approval entry about the tool. The list command runs
// against a suspect file in the ErrCorrupt procedure, so it must refuse the
// same forgeries Snapshot refuses instead of printing them as fact.
const toolViewSelect = `SELECT s.name, t.id, t.name, t.state,
		t.approved_version_id, v.id, v.tool_id, COALESCE(v.digest, ''), COALESCE(v.digest_profile, ''),
		COALESCE(pv.digest, ''), t.last_seen_digest, t.missing_crawls,
		(SELECT COUNT(*) FROM tool_versions c WHERE c.tool_id = t.id),
		` + newestDecisionNames + `,
		CASE WHEN t.approved_version_id IS NULL THEN NULL ELSE ` + decisionEntryOfServerTool + ` END,
		` + stateEntryOfServerTool + `
	FROM tools t
	JOIN servers s ON s.id = t.server_id
	LEFT JOIN tool_versions v ON v.id = t.approved_version_id
	LEFT JOIN tool_versions pv ON pv.tool_id = t.id AND pv.status = 'pending'`

// toolViewsQuery and toolViewQuery are toolViewSelect as Tools (one server, or
// every server when the name is empty) and Tool run it; both are named so that
// TestAnchorQueries_StayOnTheAuditLogBySubjectIndex explains the statements
// the views run rather than copies of them.
const (
	toolViewsQuery = toolViewSelect + ` WHERE (? = '' OR s.name = ?) ORDER BY s.name, t.name`
	toolViewQuery  = toolViewSelect + ` WHERE s.name = ? AND t.name = ?`
)

// scanToolView reads one row of toolViewSelect and checks the approval
// evidence that needs no log; the returned reference (id 0 when the tool has
// no approval) is what the caller anchors afterwards.
func scanToolView(sc rowScanner) (ToolView, approvedRef, stateRef, error) {
	var (
		v                           ToolView
		state, profile              string
		pointer, joined, joinedTool sql.NullInt64
		newest                      int
		entry, stateEntry           sql.NullInt64
	)
	err := sc.Scan(&v.Server, &v.ID, &v.Name, &state, &pointer, &joined, &joinedTool, &v.Approved, &profile,
		&v.Pending, &v.LastSeen, &v.MissingCrawls, &v.Versions, &newest, &entry, &stateEntry)
	if err != nil {
		return ToolView{}, approvedRef{}, stateRef{}, err
	}
	v.State = lifecycle.State(state)
	v.Drifted = lifecycle.Tool{Approved: v.Approved, LastSeen: v.LastSeen}.Drifted()
	v.Unusable = v.LastSeen == lifecycle.UnusableDigest
	subject := v.Server + "/" + v.Name
	st := stateRef{tool: subject, state: v.State, entry: stateEntry}
	if !pointer.Valid {
		return v, approvedRef{}, st, nil
	}
	if err := checkPointer(subject, v.ID, joined, joinedTool); err != nil {
		return ToolView{}, approvedRef{}, stateRef{}, err
	}
	if err := checkApprovedProfile(subject, profile); err != nil {
		return ToolView{}, approvedRef{}, stateRef{}, err
	}
	if newest == 0 {
		return ToolView{}, approvedRef{}, stateRef{}, errNotNewestDecision(subject)
	}
	return v, approvedRef{id: joined.Int64, tool: subject, digest: v.Approved, entry: entry}, st, nil
}

// Tools lists tools ordered by server then name. An empty server means all. A
// server that does not exist has no tools. Every approved version shown is
// checked as the serving path checks it (pointer, profile, newest decision,
// chain anchor), so a forged approval is ErrCorrupt here too. The list hands
// out digests and reads no bytes, as Snapshot does; the bytes behind a digest
// are hashed by the paths that hand them out (Versions, Approved).
func (s *Store) Tools(ctx context.Context, server string) ([]ToolView, error) {
	out := []ToolView{}
	err := s.inRead(ctx, func(q queryer) error {
		if err := s.checkFile(ctx, q); err != nil {
			return err
		}
		refs, states, err := s.readToolViews(ctx, q, server, &out)
		if err != nil {
			return err
		}
		_, err = anchorTools(ctx, q, s.chain, refs, states)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// readToolViews runs toolViewSelect for one server or all, appends the views
// to out and returns the approvals and states to anchor once the rows are
// closed.
func (s *Store) readToolViews(ctx context.Context, q queryer, server string, out *[]ToolView) ([]approvedRef, []stateRef, error) {
	rows, err := q.QueryContext(ctx, toolViewsQuery, server, server)
	if err != nil {
		return nil, nil, fmt.Errorf("catalog: list tools: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var (
		refs   []approvedRef
		states []stateRef
	)
	for rows.Next() {
		v, ref, st, err := scanToolView(rows)
		if err != nil {
			return nil, nil, fmt.Errorf("catalog: list tools: %w", err)
		}
		*out = append(*out, v)
		states = append(states, st)
		if ref.id != 0 {
			refs = append(refs, ref)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("catalog: list tools: %w", err)
	}
	return refs, states, nil
}

// Tool returns one tool, or ErrNotFound; its approval is checked as in Tools.
func (s *Store) Tool(ctx context.Context, server, tool string) (ToolView, error) {
	var v ToolView
	err := s.inRead(ctx, func(q queryer) error {
		if err := s.checkFile(ctx, q); err != nil {
			return err
		}
		var (
			ref approvedRef
			st  stateRef
			err error
		)
		v, ref, st, err = scanToolView(q.QueryRowContext(ctx, toolViewQuery, server, tool))
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return fmt.Errorf("%w: tool %s/%s", ErrNotFound, quote(server), quote(tool))
		case err != nil:
			return fmt.Errorf("catalog: load tool: %w", err)
		}
		var refs []approvedRef
		if ref.id != 0 {
			refs = []approvedRef{ref}
		}
		entries, err := anchorTools(ctx, q, s.chain, refs, []stateRef{st})
		if err != nil {
			return err
		}
		if ref.id != 0 {
			return adoptApproval(&v, entries[ref.entry.Int64])
		}
		return nil
	})
	if err != nil {
		return ToolView{}, err
	}
	return v, nil
}

// adoptApproval fills in the view's approver, the seq of the verified approval
// entry and the decision.signed entry its signed= token names, as Approved
// adopts the approver from the verified entry (D17 e). The anchor pass has
// already held the token to rule 5 when a bootstrap is in force below the
// entry (requireSigned); an entry before any bootstrap carries none, so a
// token that is not a positive seq below the entry is a row the catalog never
// wrote and is refused rather than shown.
func adoptApproval(v *ToolView, e audit.Entry) error {
	v.ApprovedBy, v.ApprovedSeq = e.Actor, e.Seq
	token, ok := detailField(e.Detail, fieldSigned)
	if !ok {
		return nil
	}
	n, err := strconv.ParseInt(token, 10, 64)
	if err != nil || n < 1 || n >= e.Seq {
		return fmt.Errorf("%w: audit entry %d names %s=%s, which is not the seq of a decision.signed entry below it", ErrCorrupt, e.Seq, fieldSigned, quote(token))
	}
	v.SignedSeq = n
	return nil
}

func toolID(ctx context.Context, q queryer, server, tool string) (int64, error) {
	var id int64
	err := q.QueryRowContext(ctx,
		`SELECT t.id FROM tools t JOIN servers s ON s.id = t.server_id WHERE s.name = ? AND t.name = ?`,
		server, tool).Scan(&id)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return 0, fmt.Errorf("%w: tool %s/%s", ErrNotFound, quote(server), quote(tool))
	case err != nil:
		return 0, fmt.Errorf("catalog: find tool: %w", err)
	}
	return id, nil
}

// versionViewQuery reads a tool's versions with the two pieces of approval
// evidence (approvalRecorded, newestDecisionNames).
const versionViewQuery = `SELECT v.id, v.version_no, v.digest, v.digest_profile, v.status, v.proposed_by, v.ever_approved,
		v.first_seen_at, v.canonical, ` + approvalRecorded + `, ` + newestDecisionNames + `
	FROM tool_versions v WHERE v.tool_id = ? ORDER BY v.version_no`

// Versions lists a tool's versions oldest first, each with its full proposer
// history. The file is checked first as on every serving-path read
// (checkFile). It hands out bytes, so each canonical form is hashed on the way
// out on every call, with no memory of an earlier call (D21 d), its digest
// profile is checked, a version in status approved or marked ever approved
// must have an approve or rollback record behind it, the status, the
// ever-approved flag and the
// proposers shown must be what the verified version.* entries about the tool
// leave behind (verifyVersionHistory, D17 a: an approver decides on this
// history, and a version shown as approved before is a rollback target), and
// the version in status approved must be the one the tool's newest decision
// names and the one its newest approval entry recorded (anchorApproved), so a
// tampered row is reported, not displayed.
func (s *Store) Versions(ctx context.Context, server, tool string) ([]VersionView, error) {
	out := []VersionView{}
	err := s.inRead(ctx, func(q queryer) error {
		if err := s.checkFile(ctx, q); err != nil {
			return err
		}
		id, err := toolID(ctx, q, server, tool)
		if err != nil {
			return err
		}
		proposers, err := loadProposers(ctx, q, nil, proposersOfTool, id)
		if err != nil {
			return err
		}
		approvedID, approved, err := s.readVersionViews(ctx, q, id, proposers, &out)
		if err != nil {
			return err
		}
		subject := server + "/" + tool
		if err := anchorOne(ctx, q, s.chain, subject, approvedID, approved); err != nil {
			return err
		}
		return verifyVersionHistory(ctx, q, s.chain, subject, viewedVersions(out))
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// readVersionViews runs versionViewQuery, appends the views to out and
// returns the row id and digest of the version in status approved ("" when
// none). The rows are closed before the anchor's own queries run.
func (s *Store) readVersionViews(ctx context.Context, q queryer, toolID int64, proposers map[int64][]string, out *[]VersionView) (int64, string, error) {
	rows, err := q.QueryContext(ctx, versionViewQuery, toolID)
	if err != nil {
		return 0, "", fmt.Errorf("catalog: list versions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var (
		approvedID int64
		approved   string
	)
	for rows.Next() {
		v, id, err := scanVersionView(rows, proposers)
		if err != nil {
			return 0, "", err
		}
		if v.Status == lifecycle.VersionApproved {
			approvedID, approved = id, v.Digest
		}
		*out = append(*out, v)
	}
	if err := rows.Err(); err != nil {
		return 0, "", fmt.Errorf("catalog: list versions: %w", err)
	}
	return approvedID, approved, nil
}

// scanVersionView reads one version, hashes its bytes against its digest and
// returns it with its row id.
func scanVersionView(sc rowScanner, proposers map[int64][]string) (VersionView, int64, error) {
	var (
		v                VersionView
		id               int64
		status           string
		ever             int
		seen             string
		recorded, newest int
	)
	if err := sc.Scan(&id, &v.No, &v.Digest, &v.DigestProfile, &status, &v.ProposedBy, &ever, &seen, &v.Canonical, &recorded, &newest); err != nil {
		return VersionView{}, 0, fmt.Errorf("catalog: list versions: %w", err)
	}
	if (status == string(lifecycle.VersionApproved) || ever == 1) && recorded == 0 {
		return VersionView{}, 0, fmt.Errorf("%w: version %d is marked approved but has no approval record", ErrCorrupt, v.No)
	}
	if status == string(lifecycle.VersionApproved) && newest == 0 {
		return VersionView{}, 0, fmt.Errorf("%w: version %d is marked approved but is not the tool's newest approval decision", ErrCorrupt, v.No)
	}
	if v.DigestProfile != gate.DigestProfile {
		return VersionView{}, 0, fmt.Errorf("%w: version %d was digested under profile %s, this build uses %s",
			ErrCorrupt, v.No, quote(v.DigestProfile), gate.DigestProfile)
	}
	if gate.DigestOfCanonical(v.Canonical) != v.Digest {
		return VersionView{}, 0, fmt.Errorf("%w: version %d does not hash to its stored digest", ErrCorrupt, v.No)
	}
	names := proposers[id]
	if len(names) == 0 || names[0] != v.ProposedBy {
		return VersionView{}, 0, fmt.Errorf("%w: version %d has no proposer list, or its first proposer is not proposed_by", ErrCorrupt, v.No)
	}
	at, err := parseTime(seen)
	if err != nil {
		return VersionView{}, 0, err
	}
	v.Status, v.EverApproved, v.FirstSeen = lifecycle.VersionStatus(status), ever == 1, at
	v.Proposers = append([]string(nil), names...)
	return v, id, nil
}
