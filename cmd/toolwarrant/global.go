package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	"github.com/sairam0424/toolwarrant/internal/lifecycle"
	"github.com/sairam0424/toolwarrant/internal/textdiff"
)

const (
	envDB         = "TOOLWARRANT_DB"
	envActor      = "TOOLWARRANT_ACTOR"
	defaultDBName = "toolwarrant.db"
	// systemActorName is the principal a crawl runs as when nobody named
	// themselves. The name is reserved: passing it with --as means acting as
	// the system, so a person cannot borrow it to look like the crawler.
	systemActorName = "crawler"
	// dbFileMode keeps the approval state and audit log readable by the owner
	// only.
	dbFileMode os.FileMode = 0o600
	// argTerminator is the flag package's end-of-flags marker.
	argTerminator = "--"
)

// actorNamePattern bounds who can be named with --as. Lookalike and invisible
// characters are refused so one person cannot appear as two identities, which
// would defeat the rule that the proposer cannot approve.
var actorNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)

// globals are the flags that come before the command.
type globals struct {
	db                string
	actor             string
	allowSelfApproval bool
}

// bind registers the global flags on fs.
func (g *globals) bind(fs *flag.FlagSet) {
	fs.StringVar(&g.db, "db", "", "catalog database path (env "+envDB+"; default ./"+defaultDBName+")")
	fs.StringVar(&g.actor, "as", "", "who is acting (env "+envActor+"; default the current OS user)")
	fs.BoolVar(&g.allowSelfApproval, "allow-self-approval", false, "let the person who crawled a version approve it")
}

// newFlagSet returns a FlagSet that reports errors instead of exiting and
// prints nothing by itself; the dispatcher owns all output.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// parseArgs parses flags that may come before, between or after positional
// arguments, which the flag package alone does not allow, and returns the
// positional arguments. -h yields a helpError with the command's usage.
func (a *app) parseArgs(c *command, fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	rest := args
	for len(rest) > 0 {
		if err := fs.Parse(rest); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, &helpError{text: c.usage(fs)}
			}
			return nil, &usageError{msg: textdiff.Escape(err.Error()), cmd: c}
		}
		remaining := fs.Args()
		consumed := len(rest) - len(remaining)
		if consumed > 0 && rest[consumed-1] == argTerminator {
			return append(positional, remaining...), nil
		}
		if len(remaining) == 0 {
			break
		}
		positional = append(positional, remaining[0])
		rest = remaining[1:]
	}
	return positional, nil
}

// wantArgs checks that exactly the named positional arguments were given.
func wantArgs(c *command, got []string, names ...string) error {
	if len(got) == len(names) {
		return nil
	}
	return &usageError{msg: fmt.Sprintf("expected %d argument(s) (%s), got %d", len(names), strings.Join(names, " "), len(got)), cmd: c}
}

// requireFlag turns a missing required flag into a usage error.
func requireFlag(c *command, value, name, meaning string) error {
	if value != "" {
		return nil
	}
	return &usageError{msg: fmt.Sprintf("--%s is required: %s", name, meaning), cmd: c}
}

// dbPath resolves --db, then the environment, then the default.
func (a *app) dbPath() string {
	if a.globals.db != "" {
		return a.globals.db
	}
	if v := a.getenv(envDB); v != "" {
		return v
	}
	return defaultDBName
}

// policy is the lifecycle policy the catalog is opened with: the safe default,
// relaxed only by --allow-self-approval.
func (a *app) policy() lifecycle.Policy {
	p := lifecycle.DefaultPolicy()
	p.AllowSelfApproval = a.globals.allowSelfApproval
	return p
}

// openStore opens the catalog. Every command except init requires the file to
// exist already, so a typo in --db cannot quietly create an empty catalog.
func (a *app) openStore(create bool) (*catalog.Store, error) {
	path := a.dbPath()
	if !create {
		if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("database %s does not exist; run \"%s init\" first", path, programName)
		}
	}
	store, err := catalog.Open(path, a.policy())
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	return store, nil
}

// actor returns the principal for this invocation. A crawl without --as runs as
// the system crawler; everything else defaults to the OS user. The reserved
// name of the system actor always means the system actor.
func (a *app) actor(forCrawl bool) (catalog.Actor, error) {
	name := a.globals.actor
	if name == "" {
		name = a.getenv(envActor)
	}
	if name == "" {
		if forCrawl {
			return systemActor(), nil
		}
		var err error
		if name, err = currentUser(a.getenv); err != nil {
			return catalog.Actor{}, err
		}
	}
	normalized, err := normalizeActorName(name)
	if err != nil {
		return catalog.Actor{}, err
	}
	if normalized == systemActorName {
		return systemActor(), nil
	}
	return catalog.Actor{Name: normalized, Type: catalog.ActorHuman}, nil
}

func systemActor() catalog.Actor {
	return catalog.Actor{Name: systemActorName, Type: catalog.ActorSystem}
}

// normalizeActorName validates and lower-cases a name so that case and
// lookalike variants of one person's name collapse to one identity.
func normalizeActorName(name string) (string, error) {
	if !actorNamePattern.MatchString(name) {
		return "", &usageError{msg: fmt.Sprintf("actor name %s must match %s", textdiff.Escape(name), actorNamePattern)}
	}
	return strings.ToLower(name), nil
}

// currentUser names the OS user, falling back to the environment when the
// account database is unavailable (containers often have no passwd entry).
func currentUser(getenv func(string) string) (string, error) {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username, nil
	}
	for _, key := range []string{"USER", "LOGNAME", "USERNAME"} {
		if v := getenv(key); v != "" {
			return v, nil
		}
	}
	return "", &usageError{msg: "cannot determine the current user; pass --as NAME"}
}

// runInit creates the database if it is absent and prints its absolute path.
// The file is created owner-only before the catalog opens it, so the mode never
// depends on another package's defaults.
func runInit(a *app, c *command, args []string) error {
	fs := newFlagSet(c.name)
	pos, err := a.parseArgs(c, fs, args)
	if err != nil {
		return err
	}
	if err := wantArgs(c, pos); err != nil {
		return err
	}
	path := a.dbPath()
	if err := ensurePrivateFile(path); err != nil {
		return err
	}
	store, err := a.openStore(true)
	if err != nil {
		return err
	}
	if err := store.Close(); err != nil {
		return fmt.Errorf("close database: %w", err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve database path: %w", err)
	}
	fmt.Fprintln(a.stdout, textdiff.Escape(abs))
	return nil
}

// ensurePrivateFile creates path with dbFileMode if it does not exist.
func ensurePrivateFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, dbFileMode)
	if err != nil {
		return fmt.Errorf("create database file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close database file: %w", err)
	}
	return nil
}
