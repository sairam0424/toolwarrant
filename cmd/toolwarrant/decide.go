package main

import (
	"flag"
	"fmt"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	"github.com/sairam0424/toolwarrant/internal/signing"
	"github.com/sairam0424/toolwarrant/internal/textdiff"
)

const (
	hashFlagName = "hash"
	toFlagName   = "to"
	hashFlagHelp = "digest you reviewed, or a unique prefix of at least 8 hex characters (required)"
	// rootPath is the JSON path of the whole definition in a findings list.
	rootPath  = "$"
	keySuffix = " (key)"
)

// located is a suspicious character together with the JSON path of the string
// it was found in, so the approver can find it in the definition.
type located struct {
	path string
	textdiff.Finding
}

// decidingActor is actor(false) plus the rule that only a person decides: the
// system crawler proposes, it never approves, rejects, pauses or resumes. The
// catalog enforces the same rule (ErrHumanRequired); refusing here turns it
// into a usage error with the fix in it.
func (a *app) decidingActor(c *command) (catalog.Actor, error) {
	actor, err := a.actor(false)
	if err != nil {
		return catalog.Actor{}, err
	}
	if actor.Type != catalog.ActorHuman {
		return catalog.Actor{}, &usageError{msg: "the system actor cannot approve, reject, disable, enable, roll back, pause or resume; pass --as with your own name", cmd: c}
	}
	return actor, nil
}

// beginDecision parses SERVER TOOL plus the command's flags and resolves the
// human actor the unsigned path would use (--as, TOOLWARRANT_ACTOR, the OS
// user; never the system actor). The caller opens the store once its own
// checks have passed, so a usage error never touches the database; with a
// trust list in force beginSigned then derives the person from the key and
// holds this label to it (O-13).
func (a *app) beginDecision(c *command, fs *flag.FlagSet, args []string) (server, tool string, actor catalog.Actor, err error) {
	pos, err := a.parseArgs(c, fs, args)
	if err != nil {
		return "", "", catalog.Actor{}, err
	}
	if err := wantArgs(c, pos, "SERVER", "TOOL"); err != nil {
		return "", "", catalog.Actor{}, err
	}
	actor, err = a.decidingActor(c)
	if err != nil {
		return "", "", catalog.Actor{}, err
	}
	return pos[0], pos[1], actor, nil
}

// runApprove approves the exact digest the operator reviewed. How the version
// differs from the one approved now is printed first (internal/drift; advice
// only, the approval never depends on it), then the definition is reviewed
// for text an approver cannot see for what it is: characters a person cannot
// see or a terminal would obey, words that mix scripts, and values or keys
// that read the same as the approved version's but are spelt with other code
// points; a hidden instruction and a swapped parameter name are exactly what
// the review exists to catch. Once a trust list is in force the approval is
// signed (signflow.go): the key is resolved before the review, so a refused
// key touches nothing, and the signature is made after it, so a refused
// approval asks for no touch.
func runApprove(a *app, c *command, args []string) (err error) {
	fs := newFlagSet(c.name)
	hash := fs.String(hashFlagName, "", hashFlagHelp)
	accept := fs.Bool("accept-suspicious", false, "approve even though the definition holds invisible or terminal-controlling characters, mixed-script words or look-alike changes against the approved version")
	expect := fs.String(flagExpect, "", expectHelp)
	server, tool, label, err := a.beginDecision(c, fs, args)
	if err != nil {
		return err
	}
	if err := requireFlag(c, *hash, hashFlagName, "name the digest you reviewed"); err != nil {
		return err
	}
	f, err := a.beginSigned(c, *expect, label, a.givenLabel())
	if err != nil {
		return err
	}
	defer f.close(&err)
	digest, err := f.store.ResolveDigest(a.ctx, server, tool, *hash)
	if err != nil {
		return err
	}
	view, versions, err := loadTool(a.ctx, f.store, server, tool)
	if err != nil {
		return err
	}
	v, err := versionByDigest(versions, digest)
	if err != nil {
		return err
	}
	if err := reportChange(a.stderr, view.Approved, versions, v); err != nil {
		return err
	}
	approved, err := approvedVersion(view.Approved, versions, v)
	if err != nil {
		return err
	}
	if err := reviewSuspicious(a.stderr, approved, v, *accept); err != nil {
		return err
	}
	r, err := f.decide(a, signing.KindApprove, server, tool, digest)
	if err != nil {
		return err
	}
	a.stdout.printf("approved %s/%s at %s\n", cell(server), cell(tool), digest)
	f.report(a, r)
	return nil
}

// reviewSuspicious lists every suspicious character in the decoded strings of
// the definition, every word that mixes scripts outside the UTS #39 Highly
// Restrictive profile and, when another version is approved, every value or
// key that reads the same as the approved version's but is spelt with other
// code points (textdiff.LookAlikeChanges), and refuses unless the operator
// accepted them explicitly with --accept-suspicious.
func reviewSuspicious(stderr *stream, approved *catalog.VersionView, v catalog.VersionView, accept bool) error {
	found, err := gatherSuspicion(approved, v)
	if err != nil {
		return err
	}
	if found.total() == 0 {
		return nil
	}
	found.print(stderr)
	if !accept {
		return fmt.Errorf("refusing to approve: the definition holds %s, listed above; review them and pass --accept-suspicious to approve anyway", found.describe())
	}
	stderr.printf("warning: approving despite %s\n", found.describe())
	return nil
}

// scanStrings decodes the canonical definition and runs textdiff.Findings over
// every string value and object key. The decoded text is scanned because a
// JSON escape (backslash, u, 2, 0, 0, b for the zero-width space) hides the
// character in the raw bytes.
func scanStrings(canonical []byte) ([]located, error) {
	doc, err := decodeDefinition(canonical)
	if err != nil {
		return nil, err
	}
	return walkStrings(rootPath, doc), nil
}

// walkStrings lists the suspicious characters of every string value and key
// under v with their paths, in the order eachString visits them.
func walkStrings(path string, v any) []located {
	var out []located
	eachString(path, v, func(p, s string) {
		out = append(out, locate(p, s)...)
	})
	return out
}

func locate(path, s string) []located {
	findings := textdiff.Findings(s)
	out := make([]located, 0, len(findings))
	for _, f := range findings {
		out = append(out, located{path: path, Finding: f})
	}
	return out
}

// runReject rejects a pending version by the digest the operator looked at.
func runReject(a *app, c *command, args []string) (err error) {
	fs := newFlagSet(c.name)
	hash := fs.String(hashFlagName, "", hashFlagHelp)
	expect := fs.String(flagExpect, "", expectHelp)
	server, tool, label, err := a.beginDecision(c, fs, args)
	if err != nil {
		return err
	}
	if err := requireFlag(c, *hash, hashFlagName, "name the digest you are rejecting"); err != nil {
		return err
	}
	f, err := a.beginSigned(c, *expect, label, a.givenLabel())
	if err != nil {
		return err
	}
	defer f.close(&err)
	digest, err := f.store.ResolveDigest(a.ctx, server, tool, *hash)
	if err != nil {
		return err
	}
	r, err := f.decide(a, signing.KindReject, server, tool, digest)
	if err != nil {
		return err
	}
	a.stdout.printf("rejected %s/%s at %s\n", cell(server), cell(tool), digest)
	f.report(a, r)
	return nil
}

// runDisable switches a tool off; it is never served until enabled again.
func runDisable(a *app, c *command, args []string) (err error) {
	fs := newFlagSet(c.name)
	expect := fs.String(flagExpect, "", expectHelp)
	server, tool, label, err := a.beginDecision(c, fs, args)
	if err != nil {
		return err
	}
	f, err := a.beginSigned(c, *expect, label, a.givenLabel())
	if err != nil {
		return err
	}
	defer f.close(&err)
	r, err := f.decide(a, signing.KindDisable, server, tool, "")
	if err != nil {
		return err
	}
	a.stdout.printf("disabled %s/%s\n", cell(server), cell(tool))
	f.report(a, r)
	return nil
}

// runEnable brings a disabled tool back under the policy; with the default
// policy that means a fresh review, so the new state is printed. The enabler
// proposes nothing and so may approve what the crawl proposed (D4).
func runEnable(a *app, c *command, args []string) (err error) {
	fs := newFlagSet(c.name)
	expect := fs.String(flagExpect, "", expectHelp)
	server, tool, label, err := a.beginDecision(c, fs, args)
	if err != nil {
		return err
	}
	f, err := a.beginSigned(c, *expect, label, a.givenLabel())
	if err != nil {
		return err
	}
	defer f.close(&err)
	r, err := f.decide(a, signing.KindEnable, server, tool, "")
	if err != nil {
		return err
	}
	view, err := f.store.Tool(a.ctx, server, tool)
	if err != nil {
		return err
	}
	a.stdout.printf("enabled %s/%s; state is now %s\n", cell(server), cell(tool), view.State)
	f.report(a, r)
	return nil
}

// runRollback re-approves a version that was approved before.
func runRollback(a *app, c *command, args []string) (err error) {
	fs := newFlagSet(c.name)
	to := fs.String(toFlagName, "", "digest or prefix of a version that was approved before (required)")
	expect := fs.String(flagExpect, "", expectHelp)
	server, tool, label, err := a.beginDecision(c, fs, args)
	if err != nil {
		return err
	}
	if err := requireFlag(c, *to, toFlagName, "name the version to return to"); err != nil {
		return err
	}
	f, err := a.beginSigned(c, *expect, label, a.givenLabel())
	if err != nil {
		return err
	}
	defer f.close(&err)
	digest, err := f.store.ResolveDigest(a.ctx, server, tool, *to)
	if err != nil {
		return err
	}
	r, err := f.decide(a, signing.KindRollback, server, tool, digest)
	if err != nil {
		return err
	}
	a.stdout.printf("rolled back %s/%s to %s\n", cell(server), cell(tool), digest)
	f.report(a, r)
	return nil
}
