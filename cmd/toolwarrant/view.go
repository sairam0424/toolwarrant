package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	"github.com/sairam0424/toolwarrant/internal/drift"
	"github.com/sairam0424/toolwarrant/internal/textdiff"
)

const (
	flagDrift    = "DRIFT"
	flagMissing  = "MISSING"
	flagUnusable = "UNUSABLE"
	// emptyDocument stands in for "nothing approved yet", so the first
	// proposal of a tool is reviewed as a diff against nothing: every line is
	// an addition and nothing is hidden by an absent baseline.
	emptyDocument   = "{}"
	noApprovedLabel = "(nothing approved)"
)

// toolJSON is one tool in machine-readable output.
type toolJSON struct {
	Server        string `json:"server"`
	Tool          string `json:"tool"`
	State         string `json:"state"`
	Approved      string `json:"approved"`
	Live          string `json:"live"`
	Pending       string `json:"pending"`
	Drifted       bool   `json:"drifted"`
	Unusable      bool   `json:"unusable"`
	MissingCrawls int    `json:"missing_crawls"`
	Versions      int    `json:"versions"`
}

// versionJSON is one immutable version in machine-readable output. Proposers
// lists every principal whose crawl proposed it, oldest first; none of them
// may approve it. DigestProfile names the rule the digest was computed under.
// Change classifies the version against the approved one; it is null for the
// approved version and for every version while nothing is approved.
type versionJSON struct {
	No            int             `json:"no"`
	Digest        string          `json:"digest"`
	DigestProfile string          `json:"digest_profile"`
	Status        string          `json:"status"`
	ProposedBy    string          `json:"proposed_by"`
	Proposers     []string        `json:"proposers"`
	EverApproved  bool            `json:"ever_approved"`
	FirstSeen     time.Time       `json:"first_seen"`
	Canonical     json.RawMessage `json:"canonical"`
	Change        *driftJSON      `json:"change"`
}

// showJSON is the output of show --json. Signer names who approved and the
// key that signed (showsigner.go); null for an unsigned approval and while
// nothing is approved.
type showJSON struct {
	toolJSON
	History []versionJSON `json:"history"`
	Signer  *signerJSON   `json:"signer"`
}

// diffSide is one side of a diff: a stored version, or the empty document
// when nothing is approved yet.
type diffSide struct {
	label     string
	summary   string
	canonical []byte
}

// runList prints every tool, or those of one server, with the digests an
// operator compares: approved, live (last crawled) and pending.
func runList(a *app, c *command, args []string) (err error) {
	fs := newFlagSet(c.name)
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := a.parseArgs(c, fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		return &usageError{msg: fmt.Sprintf("expected at most one argument (SERVER), got %d", len(pos)), cmd: c}
	}
	store, err := a.openStore(openWrite)
	if err != nil {
		return err
	}
	defer closeStore(store, &err)
	server := ""
	if len(pos) == 1 {
		server = pos[0]
		if _, err := store.Server(a.ctx, server); err != nil {
			return err
		}
	}
	tools, err := store.Tools(a.ctx, server)
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(a.stdout, toolsJSON(tools))
	}
	t := newTable(a.stdout)
	t.row("SERVER/TOOL", "STATE", "APPROVED", "LIVE", "PENDING", "FLAGS")
	for _, v := range tools {
		t.row(cell(v.Server)+"/"+cell(v.Name), string(v.State), shortDigest(v.Approved), shortDigest(v.LastSeen), shortDigest(v.Pending), toolFlags(v))
	}
	return t.flush()
}

// toolFlags marks the conditions that need a person: the upstream serves
// something other than the approved digest, stopped serving the tool, or
// serves a definition that cannot be used at all.
func toolFlags(v catalog.ToolView) string {
	var flags []string
	if v.Drifted {
		flags = append(flags, flagDrift)
	}
	if v.MissingCrawls > 0 {
		flags = append(flags, flagMissing)
	}
	if v.Unusable {
		flags = append(flags, flagUnusable)
	}
	return strings.Join(flags, ",")
}

func toolJSONOf(v catalog.ToolView) toolJSON {
	return toolJSON{Server: v.Server, Tool: v.Name, State: string(v.State), Approved: v.Approved, Live: v.LastSeen,
		Pending: v.Pending, Drifted: v.Drifted, Unusable: v.Unusable, MissingCrawls: v.MissingCrawls, Versions: v.Versions}
}

func toolsJSON(tools []catalog.ToolView) []toolJSON {
	out := make([]toolJSON, 0, len(tools))
	for _, v := range tools {
		out = append(out, toolJSONOf(v))
	}
	return out
}

// versionsJSON renders the versions with their classification against the
// approved one (reports has one entry per version, see classifyVersions).
func versionsJSON(versions []catalog.VersionView, reports []*drift.Report) []versionJSON {
	out := make([]versionJSON, 0, len(versions))
	for i, v := range versions {
		proposers := append([]string{}, v.Proposers...)
		out = append(out, versionJSON{No: v.No, Digest: v.Digest, DigestProfile: v.DigestProfile, Status: string(v.Status),
			ProposedBy: v.ProposedBy, Proposers: proposers, EverApproved: v.EverApproved, FirstSeen: v.FirstSeen.UTC(),
			Canonical: json.RawMessage(v.Canonical), Change: driftJSONOf(reports[i])})
	}
	return out
}

// loadTool reads a tool and its versions together.
func loadTool(ctx context.Context, store *catalog.Store, server, tool string) (catalog.ToolView, []catalog.VersionView, error) {
	view, err := store.Tool(ctx, server, tool)
	if err != nil {
		return catalog.ToolView{}, nil, err
	}
	versions, err := store.Versions(ctx, server, tool)
	if err != nil {
		return catalog.ToolView{}, nil, err
	}
	return view, versions, nil
}

// runShow prints one tool and every version it ever had, with full digests,
// every proposer, the digest profile each version was hashed under and, once
// a version is approved, what each other version changes against it: the
// CHANGE column carries the grade and the line under the table groups the
// versions by the kinds of change, so the reader can tell nineteen versions
// that differ only in description from the one that also removes a parameter.
func runShow(a *app, c *command, args []string) (err error) {
	fs := newFlagSet(c.name)
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := a.parseArgs(c, fs, args)
	if err != nil {
		return err
	}
	if err := wantArgs(c, pos, "SERVER", "TOOL"); err != nil {
		return err
	}
	store, err := a.openStore(openWrite)
	if err != nil {
		return err
	}
	defer closeStore(store, &err)
	view, versions, err := loadTool(a.ctx, store, pos[0], pos[1])
	if err != nil {
		return err
	}
	vc, err := classifyVersions(versions, view.Approved)
	if err != nil {
		return err
	}
	approval, signer, err := a.approvalLine(store, view)
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(a.stdout, showJSON{toolJSON: toolJSONOf(view), History: versionsJSON(versions, vc.reports), Signer: signer})
	}
	a.stdout.printf("%s/%s\n  state:          %s\n  approved:       %s\n  pending:        %s\n  live:           %s\n  drifted:        %t\n  unusable:       %t\n  missing crawls: %d\n\n",
		cell(view.Server), cell(view.Name), view.State, cell(view.Approved), cell(view.Pending), cell(view.LastSeen), view.Drifted, view.Unusable, view.MissingCrawls)
	t := newTable(a.stdout)
	t.row("NO", "STATUS", "CHANGE", "PROPOSERS", "FIRST SEEN", "PROFILE", "DIGEST")
	for i, v := range versions {
		t.row(strconv.Itoa(v.No), string(v.Status), changeCell(vc.reports[i]), cells(proposersOf(v)), v.FirstSeen.UTC().Format(time.RFC3339), cell(v.DigestProfile), v.Digest)
	}
	if err := t.flush(); err != nil {
		return err
	}
	if approval != "" {
		a.stdout.printf("\n%s\n", approval)
	}
	if summary := changeSummary(versions, vc); summary != "" {
		a.stdout.printf("\n%s\n", summary)
	}
	return a.stdout.broken()
}

// proposersOf lists a version's proposers, falling back to the first one for
// a version stored before the history existed.
func proposersOf(v catalog.VersionView) []string {
	if len(v.Proposers) > 0 {
		return v.Proposers
	}
	if v.ProposedBy != "" {
		return []string{v.ProposedBy}
	}
	return nil
}

// runDiff renders what changed between two versions through textdiff.Tool,
// so every line an approver reads is escaped, with the drift classification
// (internal/drift) on the line after the to: header; the classification is
// advice, the gate stays the digest.
func runDiff(a *app, c *command, args []string) (err error) {
	fs := newFlagSet(c.name)
	from := fs.String("from", "", "digest or prefix to compare from (default: the approved version)")
	to := fs.String("to", "", "digest or prefix to compare to (default: the pending version, or the live one when drifted)")
	pos, err := a.parseArgs(c, fs, args)
	if err != nil {
		return err
	}
	if err := wantArgs(c, pos, "SERVER", "TOOL"); err != nil {
		return err
	}
	store, err := a.openStore(openWrite)
	if err != nil {
		return err
	}
	defer closeStore(store, &err)
	view, versions, err := loadTool(a.ctx, store, pos[0], pos[1])
	if err != nil {
		return err
	}
	fromDigest, toDigest, err := diffTargets(a.ctx, store, view, *from, *to)
	if err != nil {
		return err
	}
	fromSide, err := sideOf(view, versions, fromDigest)
	if err != nil {
		return err
	}
	toSide, err := sideOf(view, versions, toDigest)
	if err != nil {
		return err
	}
	classified, err := driftLine(fromDigest, fromSide.canonical, toSide.canonical)
	if err != nil {
		return err
	}
	a.stdout.printf("%s/%s\nfrom: %s\nto:   %s\n%s\n\n", cell(view.Server), cell(view.Name), fromSide.summary, toSide.summary, classified)
	rendered, err := textdiff.Tool(fromSide.label, toSide.label, fromSide.canonical, toSide.canonical)
	if err != nil {
		return fmt.Errorf("render diff: %w", err)
	}
	a.stdout.print(rendered)
	return a.stdout.broken()
}

// diffTargets chooses the two digests: explicit prefixes win; otherwise the
// approved version is compared with the pending one, or with the live one
// when the upstream drifted to a known digest and nothing is pending (for
// example after a reject). An unusable live definition has no digest to show.
func diffTargets(ctx context.Context, store *catalog.Store, view catalog.ToolView, from, to string) (string, string, error) {
	fromDigest := view.Approved
	if from != "" {
		d, err := store.ResolveDigest(ctx, view.Server, view.Name, from)
		if err != nil {
			return "", "", err
		}
		fromDigest = d
	}
	switch {
	case to != "":
		d, err := store.ResolveDigest(ctx, view.Server, view.Name, to)
		if err != nil {
			return "", "", err
		}
		return fromDigest, d, nil
	case view.Pending != "":
		return fromDigest, view.Pending, nil
	case view.Unusable:
		return "", "", fmt.Errorf("nothing to compare: the upstream lists %s/%s with a definition that cannot be used, so there is no live version; run crawl again once it is fixed", view.Server, view.Name)
	case view.Drifted:
		return fromDigest, view.LastSeen, nil
	}
	return "", "", fmt.Errorf("nothing to compare: %s/%s has no pending proposal and has not drifted; pass --to HASH", view.Server, view.Name)
}

// sideOf resolves a digest to the version bytes behind it.
func sideOf(view catalog.ToolView, versions []catalog.VersionView, digest string) (diffSide, error) {
	if digest == "" {
		return diffSide{label: noApprovedLabel, summary: noApprovedLabel, canonical: []byte(emptyDocument)}, nil
	}
	v, err := versionByDigest(versions, digest)
	if err != nil {
		return diffSide{}, err
	}
	return diffSide{
		label:     fmt.Sprintf("%s/%s@%s", view.Server, view.Name, shortDigest(v.Digest)),
		summary:   fmt.Sprintf("%s (version %d, %s, proposed by %s)", v.Digest, v.No, v.Status, cells(proposersOf(v))),
		canonical: v.Canonical,
	}, nil
}

// versionByDigest finds a version by its full digest.
func versionByDigest(versions []catalog.VersionView, digest string) (catalog.VersionView, error) {
	for _, v := range versions {
		if v.Digest == digest {
			return v, nil
		}
	}
	return catalog.VersionView{}, fmt.Errorf("%w: version %s", catalog.ErrNotFound, digest)
}
