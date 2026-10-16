package main

import (
	"crypto/ed25519"
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
	flagSignKey         = "--sign-key"
	// The three files at the top of an export directory, as the export
	// package names them; the lines below name them so an operator knows
	// what to keep and what to verify.
	manifestFile  = "MANIFEST.json"
	signatureFile = manifestFile + ".sig"
	publicKeyFile = manifestFile + ".pub"
)

// runExport mirrors the approved definitions into a directory that people can
// read and diff in git. The export is write-only: nothing reads it back to
// decide anything. MANIFEST.json records the head of the audit chain the
// catalog had verified in the same read transaction as the approvals
// (Store.ApprovedWithHead) and the digest profile, so the export names the
// exact log it mirrors, and with --sign-key PATH the
// complete manifest is signed with the Ed25519 key in that file (D21 e); the
// key is read before the catalog is opened, so a refused key changes nothing,
// and it is zeroed when the command ends. Tools the exporter had to leave out
// are reported, because a missing file in the mirror must not be mistaken for
// a missing approval. "export verify" is dispatched to its own command.
func runExport(a *app, c *command, args []string) (err error) {
	if len(args) > 0 {
		if sub, ok := findCommand(c.sub, args[0]); ok {
			return sub.run(a, sub, args[1:])
		}
	}
	fs := newFlagSet(c.name)
	dir := fs.String("dir", "", "directory for <server>/<tool>.json and "+manifestFile+" (required)")
	signKey := fs.String("sign-key", "", "path of an Ed25519 private key (PKCS#8 PEM; a regular file with mode 0600 or stricter, never a symbolic link) that signs the complete "+manifestFile+" into "+signatureFile+", with its public key written to "+publicKeyFile+"; the key is read from this file only, never from the environment or a flag value, and never printed")
	commit := fs.Bool("commit", false, "commit the directory in a git repository of its own; a signature from an earlier export that does not sign the current "+manifestFile+" is refused")
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
	key, err := loadSignKey(*signKey)
	if err != nil {
		return err
	}
	defer clear(key)
	store, err := a.openStore(openWrite)
	if err != nil {
		return err
	}
	defer closeStore(store, &err)
	tools, opts, err := exportInputs(a, store, key)
	if err != nil {
		return err
	}
	report, err := export.Write(*dir, tools, opts)
	if err != nil {
		return err
	}
	a.printExportReport(*dir, *signKey, len(tools), report, opts)
	if !*commit {
		return a.stdout.broken()
	}
	return a.commitExport(*dir, len(tools), *gitName, *gitEmail)
}

// loadSignKey reads the signing key named with --sign-key, or returns nil when
// the flag was not given. The export package applies the file rules (a regular
// file, owner-only, one PKCS#8 Ed25519 key); the refusal is wrapped with the
// flag and the path as given (describe escapes the sentence once when it
// prints it), never with anything from the file.
func loadSignKey(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, nil
	}
	key, err := export.ReadSigningKey(path)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", flagSignKey, path, err)
	}
	return key, nil
}

// exportInputs reads the approvals and the audit head from one snapshot of the
// catalog (Store.ApprovedWithHead), so that the head the manifest records is
// the head of exactly the log state whose approvals the export carries: a
// crawl or a decision committed while the export runs lands in both or in
// neither. Read as two calls, a commit between them made the manifest name a
// head whose approval set differed from the files written. It then builds the
// options of the Write.
func exportInputs(a *app, store *catalog.Store, key ed25519.PrivateKey) ([]export.Tool, export.Options, error) {
	approved, head, err := store.ApprovedWithHead(a.ctx)
	if err != nil {
		return nil, export.Options{}, err
	}
	return exportTools(approved), export.Options{AuditHead: head, DigestProfile: gate.DigestProfile, SignKey: key}, nil
}

// printExportReport prints what the export did, the catalog fields the
// manifest records, the signature when one was made, and every tool that was
// left out (on stderr, escaped: the names are upstream text).
func (a *app) printExportReport(dir, signKey string, count int, report export.Report, opts export.Options) {
	a.stdout.printf("exported %d approved tools to %s: %d written, %d removed, %d unchanged, %d skipped\n",
		count, textdiff.Escape(dir), report.Written, report.Removed, report.Unchanged, len(report.Skipped))
	a.stdout.printf("%s records audit head %s and digest profile %s; record the head with the export\n", manifestFile, opts.AuditHead, opts.DigestProfile)
	if signKey != "" {
		a.stdout.printf("signed %s with the key at %s: %s and %s sit beside it; verify with export verify --pub-key FILE\n", manifestFile, textdiff.Escape(signKey), signatureFile, publicKeyFile)
	}
	for _, s := range report.Skipped {
		a.stderr.printf("warning: %s/%s is approved but was not exported: %s\n", cell(s.Server), cell(s.Name), cell(s.Reason))
	}
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
