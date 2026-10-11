package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	"github.com/sairam0424/toolwarrant/internal/emit"
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
	// Printable ASCII bounds, the only characters a processor secret may hold:
	// the emitter writes it into a CEL string literal and the processor
	// compares it byte for byte.
	minPrintableASCII = 0x20
	maxPrintableASCII = 0x7e
)

// actorNamePattern bounds who can be named with --as. Lookalike and invisible
// characters are refused so one person cannot appear as two identities, which
// would defeat the rule that the proposer cannot approve. The catalog applies
// the same charset after NFKC and lower-casing, so a name accepted here is
// never refused there.
var actorNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)

// openMode says how a command opens the catalog. Only init may create the
// file, so a mistyped --db cannot quietly become an empty catalog; serve must
// never be able to write; the audit commands must be able to read a file that
// a normal open refuses as corrupt, because naming the broken entry is their
// job.
type openMode int

const (
	// openCreate creates a missing file (init only).
	openCreate openMode = iota
	// openWrite requires an existing file and allows changes.
	openWrite
	// openReadOnly requires an existing file and refuses every change.
	openReadOnly
	// openForensic reads a database even when its guard objects were
	// dropped, read-only.
	openForensic
)

// globals are the flags that come before the command.
type globals struct {
	db                string
	actor             string
	allowSelfApproval bool
}

// bind registers the global flags on fs.
func (g *globals) bind(fs *flag.FlagSet) {
	fs.StringVar(&g.db, "db", "", "catalog database path (env "+envDB+"; default ./"+defaultDBName+")")
	fs.StringVar(&g.actor, "as", "", "who is acting (env "+envActor+"; default the current OS user; \""+systemActorName+"\" is the system actor)")
	fs.BoolVar(&g.allowSelfApproval, "allow-self-approval", false, "let a person whose crawl proposed a version approve it")
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

// openStore opens the catalog in the given mode. Every mode but openCreate
// requires the file to exist already; the catalog reports that as ErrNotFound,
// which becomes the one sentence a new operator needs.
func (a *app) openStore(mode openMode) (*catalog.Store, error) {
	path := a.dbPath()
	opts := catalog.OpenOptions{
		Policy:    a.policy(),
		MustExist: mode != openCreate,
		ReadOnly:  mode == openReadOnly,
		Forensic:  mode == openForensic,
	}
	store, err := catalog.OpenWith(path, opts)
	if err != nil {
		if mode != openCreate && errors.Is(err, catalog.ErrNotFound) {
			return nil, fmt.Errorf("database %s does not exist; run \"%s init\" first", textdiff.Escape(path), programName)
		}
		return nil, fmt.Errorf("open database: %w", err)
	}
	return store, nil
}

// closeStore closes the store at the end of a command. Its error is kept only
// when the command itself succeeded, so a failed close is reported but never
// hides the error that made the command fail.
func closeStore(store *catalog.Store, err *error) {
	if cerr := store.Close(); cerr != nil && *err == nil {
		*err = fmt.Errorf("close database: %w", cerr)
	}
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

// readSecret takes the processor's shared secret from the named environment
// variable, never from a flag value, so it stays out of process listings and
// shell histories. It is checked against the emitter's rule up front, so a
// secret the gateway configuration could not carry is refused before anything
// is written or listened on. The value never appears in any message.
func readSecret(c *command, getenv func(string) string, name string) (string, error) {
	if name == "" {
		return "", nil
	}
	secret := getenv(name)
	if secret == "" {
		return "", &usageError{msg: fmt.Sprintf("environment variable %s is unset or empty", textdiff.Escape(name)), cmd: c}
	}
	if len(secret) < emit.MinSecretLen || len(secret) > emit.MaxSecretLen || !isPrintableASCII(secret) {
		return "", &usageError{msg: fmt.Sprintf("the secret in %s must be %d to %d printable ASCII characters", textdiff.Escape(name), emit.MinSecretLen, emit.MaxSecretLen), cmd: c}
	}
	return secret, nil
}

// isPrintableASCII reports whether every byte of s is printable ASCII.
func isPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < minPrintableASCII || s[i] > maxPrintableASCII {
			return false
		}
	}
	return true
}

// runInit creates the database if it is absent and prints its absolute path.
// The file is created owner-only before the catalog opens it, so the mode never
// depends on another package's defaults. The directory is checked for a
// planted link first (D14 i), then the final component.
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
	if err := refuseLinkedDirectory(path); err != nil {
		return err
	}
	if err := refuseSymlink(path); err != nil {
		return err
	}
	if err := ensurePrivateFile(path); err != nil {
		return err
	}
	store, err := a.openStore(openCreate)
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
	a.stdout.printf("%s\n", textdiff.Escape(abs))
	return nil
}

// refuseSymlink refuses a database path that is a symbolic link before
// anything is created: a link planted in a shared working directory would
// otherwise make init create an owner-only file wherever the link points
// (second review). The catalog refuses the link too, but only after the
// target exists; this check runs first, and ensurePrivateFile opens with
// O_NOFOLLOW so a link planted between the two is refused as well.
func refuseSymlink(path string) error {
	fi, err := os.Lstat(path)
	if err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("database path %s is a symbolic link; name the file itself", textdiff.Escape(path))
	}
	return nil
}

// ensurePrivateFile creates path with dbFileMode if it does not exist. The
// open never follows a symbolic link, so the file is created where the path
// says, or not at all.
func ensurePrivateFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, dbFileMode)
	if err != nil {
		return fmt.Errorf("create database file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close database file: %w", err)
	}
	return nil
}
