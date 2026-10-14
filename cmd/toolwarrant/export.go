package main

import (
	"fmt"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	"github.com/sairam0424/toolwarrant/internal/export"
	"github.com/sairam0424/toolwarrant/internal/gate"
	"github.com/sairam0424/toolwarrant/internal/textdiff"
)

const (
	// emailDomain is reserved by RFC 2606, so a default committer address can
	// never be somebody's real mailbox.
	emailDomain         = "toolwarrant.invalid"
	commitMessageFormat = "toolwarrant: export %d approved tools"
)

// runExport mirrors the approved definitions into a directory that people can
// read and diff in git. The export is write-only: nothing reads it back. Tools
// the exporter had to leave out are reported, because a missing file in the
// mirror must not be mistaken for a missing approval.
func runExport(a *app, c *command, args []string) (err error) {
	fs := newFlagSet(c.name)
	dir := fs.String("dir", "", "directory for <server>/<tool>.json and MANIFEST.json (required)")
	commit := fs.Bool("commit", false, "commit the directory in a git repository of its own")
	gitName := fs.String("git-name", "", "committer name (default: the actor)")
	gitEmail := fs.String("git-email", "", "committer email (default: ACTOR@"+emailDomain+")")
	pos, err := a.parseArgs(c, fs, args)
	if err != nil {
		return err
	}
	if err := wantArgs(c, pos); err != nil {
		return err
	}
	if err := requireFlag(c, *dir, "dir", "name the directory to write"); err != nil {
		return err
	}
	store, err := a.openStore(openWrite)
	if err != nil {
		return err
	}
	defer closeStore(store, &err)
	approved, err := store.Approved(a.ctx)
	if err != nil {
		return err
	}
	// The head is read after the approvals, so that the head the manifest
	// records covers every approval the export carries.
	head, err := store.AuditHead(a.ctx)
	if err != nil {
		return err
	}
	tools := exportTools(approved)
	report, err := export.Write(*dir, tools, export.Options{AuditHead: head, DigestProfile: gate.DigestProfile})
	if err != nil {
		return err
	}
	a.stdout.printf("exported %d approved tools to %s: %d written, %d removed, %d unchanged, %d skipped\n",
		len(tools), textdiff.Escape(*dir), report.Written, report.Removed, report.Unchanged, len(report.Skipped))
	for _, s := range report.Skipped {
		a.stderr.printf("warning: %s/%s is approved but was not exported: %s\n", cell(s.Server), cell(s.Name), cell(s.Reason))
	}
	if !*commit {
		return a.stdout.broken()
	}
	return a.commitExport(*dir, len(tools), *gitName, *gitEmail)
}

func exportTools(approved []catalog.ApprovedTool) []export.Tool {
	out := make([]export.Tool, 0, len(approved))
	for _, t := range approved {
		out = append(out, export.Tool{Server: t.Server, Name: t.Name, Digest: t.Digest, Canonical: t.Canonical,
			ApprovedBy: t.ApprovedBy, ApprovedAt: t.ApprovedAt, VersionNo: t.VersionNo})
	}
	return out
}

// commitExport records the export as one commit under an explicit identity,
// defaulting to the acting person so the history names who exported.
func (a *app) commitExport(dir string, count int, name, email string) error {
	actor, err := a.actor(false)
	if err != nil {
		return err
	}
	if name == "" {
		name = actor.Name
	}
	if email == "" {
		email = actor.Name + "@" + emailDomain
	}
	who := export.Identity{Name: name, Email: email}
	committed, err := export.Commit(a.ctx, dir, fmt.Sprintf(commitMessageFormat, count), who)
	if err != nil {
		return err
	}
	if !committed {
		a.stdout.printf("nothing to commit\n")
		return a.stdout.broken()
	}
	a.stdout.printf("committed as %s <%s>\n", cell(name), cell(email))
	return a.stdout.broken()
}
