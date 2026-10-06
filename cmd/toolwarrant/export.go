package main

import (
	"fmt"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	"github.com/sairam0424/toolwarrant/internal/export"
	"github.com/sairam0424/toolwarrant/internal/textdiff"
)

const (
	// emailDomain is reserved by RFC 2606, so a default committer address can
	// never be somebody's real mailbox.
	emailDomain         = "toolwarrant.invalid"
	commitMessageFormat = "toolwarrant: export %d approved tools"
)

// runExport mirrors the approved definitions into a directory that people can
// read and diff in git. The export is write-only: nothing reads it back.
func runExport(a *app, c *command, args []string) error {
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
	store, err := a.openStore(false)
	if err != nil {
		return err
	}
	defer store.Close()
	approved, err := store.Approved(a.ctx)
	if err != nil {
		return err
	}
	tools := exportTools(approved)
	report, err := export.Write(*dir, tools)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "exported %d approved tools to %s: %d written, %d removed, %d unchanged\n",
		len(tools), textdiff.Escape(*dir), report.Written, report.Removed, report.Unchanged)
	if !*commit {
		return nil
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
		fmt.Fprintln(a.stdout, "nothing to commit")
		return nil
	}
	fmt.Fprintf(a.stdout, "committed as %s <%s>\n", cell(name), cell(email))
	return nil
}
