package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"sort"

	"github.com/sairam0424/toolwarrant/internal/catalog"
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
// human actor. The caller opens the store once its own checks have passed, so
// a usage error never touches the database.
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
// only, the approval never depends on it), then the definition is scanned for
// characters a person cannot see or a terminal would obey; a hidden
// instruction is exactly what the review exists to catch.
func runApprove(a *app, c *command, args []string) (err error) {
	fs := newFlagSet(c.name)
	hash := fs.String(hashFlagName, "", hashFlagHelp)
	accept := fs.Bool("accept-suspicious", false, "approve even though the definition holds invisible or terminal-controlling characters")
	server, tool, actor, err := a.beginDecision(c, fs, args)
	if err != nil {
		return err
	}
	if err := requireFlag(c, *hash, hashFlagName, "name the digest you reviewed"); err != nil {
		return err
	}
	store, err := a.openStore(openWrite)
	if err != nil {
		return err
	}
	defer closeStore(store, &err)
	digest, err := store.ResolveDigest(a.ctx, server, tool, *hash)
	if err != nil {
		return err
	}
	view, versions, err := loadTool(a.ctx, store, server, tool)
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
	if err := reviewSuspicious(a.stderr, v.Canonical, *accept); err != nil {
		return err
	}
	if err := store.Approve(a.ctx, server, tool, digest, actor); err != nil {
		return err
	}
	a.stdout.printf("approved %s/%s at %s\n", cell(server), cell(tool), digest)
	return nil
}

// reviewSuspicious lists every suspicious character in the decoded strings of
// the definition and refuses unless the operator accepted them explicitly.
func reviewSuspicious(stderr *stream, canonical []byte, accept bool) error {
	found, err := scanStrings(canonical)
	if err != nil {
		return err
	}
	if len(found) == 0 {
		return nil
	}
	stderr.printf("suspicious characters in this definition:\n")
	for _, f := range found {
		stderr.printf("  %s byte %d: U+%04X %s (%s)\n", cell(f.path), f.Offset, f.Rune, f.Name, f.Category)
	}
	if !accept {
		return fmt.Errorf("refusing to approve: the definition holds %d suspicious character(s), listed above; review them and pass --accept-suspicious to approve anyway", len(found))
	}
	stderr.printf("warning: approving despite %d suspicious character(s)\n", len(found))
	return nil
}

// scanStrings decodes the canonical definition and runs textdiff.Findings over
// every string value and object key. The decoded text is scanned because a
// JSON escape (backslash, u, 2, 0, 0, b for the zero-width space) hides the
// character in the raw bytes.
func scanStrings(canonical []byte) ([]located, error) {
	dec := json.NewDecoder(bytes.NewReader(canonical))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode definition: %w", err)
	}
	return walkStrings(rootPath, doc), nil
}

func walkStrings(path string, v any) []located {
	switch x := v.(type) {
	case string:
		return locate(path, x)
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var out []located
		for _, k := range keys {
			child := path + "." + k
			out = append(out, locate(child+keySuffix, k)...)
			out = append(out, walkStrings(child, x[k])...)
		}
		return out
	case []any:
		var out []located
		for i, e := range x {
			out = append(out, walkStrings(fmt.Sprintf("%s[%d]", path, i), e)...)
		}
		return out
	}
	return nil
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
	server, tool, actor, err := a.beginDecision(c, fs, args)
	if err != nil {
		return err
	}
	if err := requireFlag(c, *hash, hashFlagName, "name the digest you are rejecting"); err != nil {
		return err
	}
	store, err := a.openStore(openWrite)
	if err != nil {
		return err
	}
	defer closeStore(store, &err)
	digest, err := store.ResolveDigest(a.ctx, server, tool, *hash)
	if err != nil {
		return err
	}
	if err := store.Reject(a.ctx, server, tool, digest, actor); err != nil {
		return err
	}
	a.stdout.printf("rejected %s/%s at %s\n", cell(server), cell(tool), digest)
	return nil
}

// runDisable switches a tool off; it is never served until enabled again.
func runDisable(a *app, c *command, args []string) (err error) {
	fs := newFlagSet(c.name)
	server, tool, actor, err := a.beginDecision(c, fs, args)
	if err != nil {
		return err
	}
	store, err := a.openStore(openWrite)
	if err != nil {
		return err
	}
	defer closeStore(store, &err)
	if err := store.Disable(a.ctx, server, tool, actor); err != nil {
		return err
	}
	a.stdout.printf("disabled %s/%s\n", cell(server), cell(tool))
	return nil
}

// runEnable brings a disabled tool back under the policy; with the default
// policy that means a fresh review, so the new state is printed. The enabler
// proposes nothing and so may approve what the crawl proposed (D4).
func runEnable(a *app, c *command, args []string) (err error) {
	fs := newFlagSet(c.name)
	server, tool, actor, err := a.beginDecision(c, fs, args)
	if err != nil {
		return err
	}
	store, err := a.openStore(openWrite)
	if err != nil {
		return err
	}
	defer closeStore(store, &err)
	if err := store.Enable(a.ctx, server, tool, actor); err != nil {
		return err
	}
	view, err := store.Tool(a.ctx, server, tool)
	if err != nil {
		return err
	}
	a.stdout.printf("enabled %s/%s; state is now %s\n", cell(server), cell(tool), view.State)
	return nil
}

// runRollback re-approves a version that was approved before.
func runRollback(a *app, c *command, args []string) (err error) {
	fs := newFlagSet(c.name)
	to := fs.String(toFlagName, "", "digest or prefix of a version that was approved before (required)")
	server, tool, actor, err := a.beginDecision(c, fs, args)
	if err != nil {
		return err
	}
	if err := requireFlag(c, *to, toFlagName, "name the version to return to"); err != nil {
		return err
	}
	store, err := a.openStore(openWrite)
	if err != nil {
		return err
	}
	defer closeStore(store, &err)
	digest, err := store.ResolveDigest(a.ctx, server, tool, *to)
	if err != nil {
		return err
	}
	if err := store.Rollback(a.ctx, server, tool, digest, actor); err != nil {
		return err
	}
	a.stdout.printf("rolled back %s/%s to %s\n", cell(server), cell(tool), digest)
	return nil
}
