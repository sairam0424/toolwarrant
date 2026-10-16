// Command toolwarrant is the operator CLI of the toolwarrant control plane.
//
// It registers upstream MCP servers, crawls their tool definitions into the
// catalog as immutable digest-identified versions, lets a named person approve
// one exact digest, runs the ExtMCP processor that enforces those approvals at
// the agentgateway, and emits the gateway configuration. Nothing is served
// until approved; a crawl never approves anything.
//
// The whole program runs through run, which takes its arguments, streams and
// environment explicitly so that tests drive it in-process. main only maps the
// result to a process exit code.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/sairam0424/toolwarrant/internal/textdiff"
)

// Exit codes. Scripts branch on them, so they are part of the interface:
// 2 means the command line was wrong, 1 means the operation failed.
const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

// version is the build's version string. It is a variable rather than a
// constant only so that -ldflags "-X main.version=..." can set it at link
// time; nothing assigns to it while the program runs. When no linker flag set
// it, runVersion falls back to the module version the Go toolchain embedded
// (displayVersion), so a go install of a tag reports that tag.
var version = devVersion

// devVersion is the version the source carries when no linker flag set one.
const devVersion = "dev"

// unknownModuleVersion is the main module version the Go toolchain records in
// a binary it could not attribute to a module version: go test, go run, and
// go build in a checkout without version control information.
const unknownModuleVersion = "(devel)"

// gatewayVersion names the agentgateway release this build is tested against.
// The ExtMCP wire format and the config schema are pinned to it.
const gatewayVersion = "agentgateway v1.6.0 (pinned)"

const (
	programName = "toolwarrant"
	helpFlag    = "-h"
	// tabPadding is the space between table columns.
	tabPadding = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, os.Getenv))
}

// run executes one command line and returns the exit code. It cancels the
// command on SIGINT or SIGTERM so that long-running commands (serve, crawl
// --every, verify-gateway --every) shut down gracefully.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return runCtx(ctx, args, stdin, stdout, stderr, getenv)
}

// runCtx is run with an explicit context, so tests can bound a command that
// would otherwise wait for a signal. A command whose stdout or stderr broke
// exits 1 even when its work succeeded: the output is part of the work, and a
// closed pipe must not look like success.
func runCtx(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) int {
	a := &app{ctx: ctx, stdin: stdin, stdout: &stream{w: stdout}, stderr: &stream{w: stderr}, getenv: getenv}
	return a.checkStreams(a.exitCode(a.dispatch(args)))
}

// app is the state of one invocation. Everything a command needs comes from
// here, so nothing lives in package-level variables.
type app struct {
	ctx     context.Context
	stdin   io.Reader
	stdout  *stream
	stderr  *stream
	getenv  func(string) string
	globals globals
	// afterSign, when set, runs between a signature and the write that
	// follows it. Tests set it to move the log in that window and prove the
	// compare-and-set and its one retry; run never sets it.
	afterSign func()
}

// command is one entry of the command table. A command with sub-entries
// (server, audit, budget) dispatches to them instead of running itself, unless
// self is set (export): then it runs itself and hands a first argument that
// names a sub-entry to that entry, and the help lists its own row and flags
// beside its subcommands.
type command struct {
	name     string
	synopsis string // what follows "toolwarrant [global flags]"
	summary  string // one line for the command list
	run      func(a *app, c *command, args []string) error
	sub      []*command
	self     bool
}

// usageError means the command line was wrong. Its message must already be
// safe to print: whoever builds one escapes any text that came from outside.
type usageError struct {
	msg string
	cmd *command // whose synopsis to show; nil at the global level
}

func (e *usageError) Error() string { return e.msg }

// helpError carries usage text the operator asked for. It is not a failure.
type helpError struct{ text string }

func (e *helpError) Error() string { return "help requested" }

// commands is the top-level command table. It is built on demand so the
// package has no mutable global state.
func commands() []*command {
	return []*command{
		{name: "init", synopsis: "init", summary: "create the database (idempotent) and print its path", run: runInit},
		{name: "server", synopsis: "server add|list|pause|resume ...", summary: "register, list, pause and resume upstream MCP servers", run: runSub, sub: serverCommands()},
		{name: "crawl", synopsis: "crawl SERVER [--every DURATION] [--bearer-env VAR] [--strict] [--json]", summary: "fetch the upstream's tools and record what changed; never approves", run: runCrawl},
		{name: "list", synopsis: "list [SERVER] [--json]", summary: "show every tool with its state and digests; flags DRIFT, MISSING and UNUSABLE need a person", run: runList},
		{name: "show", synopsis: "show SERVER TOOL [--json]", summary: "show one tool and all of its versions with their proposers and digest profile", run: runShow},
		{name: "diff", synopsis: "diff SERVER TOOL [--from HASH] [--to HASH]", summary: "show what changed between two versions, escaped for the terminal", run: runDiff},
		{name: "approve", synopsis: "approve SERVER TOOL --hash HASH [--accept-suspicious] [--expect-head HEX]", summary: "approve the exact digest you reviewed; signed with --ssh-key once a trust list is in force", run: runApprove},
		{name: "reject", synopsis: "reject SERVER TOOL --hash HASH [--expect-head HEX]", summary: "reject a pending version", run: runReject},
		{name: "disable", synopsis: "disable SERVER TOOL [--expect-head HEX]", summary: "switch a tool off", run: runDisable},
		{name: "enable", synopsis: "enable SERVER TOOL [--expect-head HEX]", summary: "bring a disabled tool back for review", run: runEnable},
		{name: "rollback", synopsis: "rollback SERVER TOOL --to HASH [--expect-head HEX]", summary: "re-approve a version that was approved before", run: runRollback},
		{name: "budget", synopsis: "budget reset ...", summary: "reset the proposal budget of a tool that no other decision can unblock", run: runSub, sub: budgetCommands()},
		{name: "trust", synopsis: "trust init|add|remove|show ...", summary: "start, change and show the signed operator trust list that decisions must be signed under", run: runSub, sub: trustCommands()},
		{name: "serve", synopsis: "serve --server NAME --listen ADDR [--target NAME] [--secret-env VAR] [--tls-cert PATH --tls-key PATH [--tls-client-ca PATH]] [--allow-non-loopback [--insecure-no-secret]] [--max-evidence-age DURATION] [--max-crawl-age DURATION]", summary: "run the ExtMCP processor that enforces approvals at the gateway; with the global --trust-root it refuses a catalog whose trust bootstrap another key signed or that has none", run: runServe},
		{name: "emit", synopsis: "emit --out FILE [--listen-port N] [--bind-address ADDR [--allow-all-interfaces]] [--admin-addr ADDR | --disable-admin] [--stats-addr ADDR] [--readiness-addr ADDR] [--processor-base-port N] [--processor NAME=HOST:PORT ...] [--processor-tls NAME=cert=PATH,key=PATH,root=PATH,hostname=NAME ...] [--secret-env VAR] [--gateway-binary PATH]", summary: "write the agentgateway configuration for every server, validated with the gateway binary when one is named", run: runEmit},
		{name: "export", synopsis: "export --dir DIR [--sign-key PATH] [--commit] [--git-name N --git-email E]", summary: "write the approved definitions to a directory for review in git, with the audit head in MANIFEST.json and, with a key, its signature", run: runExport, sub: exportCommands(), self: true},
		{name: "audit", synopsis: "audit verify|list ...", summary: "verify and read the hash-chained audit log", run: runSub, sub: auditCommands()},
		{name: "verify-gateway", synopsis: "verify-gateway --server NAME --url URL [--bearer-env VAR] [--config FILE [--admin ADDR] [--expect-body-hash HEX]] [--no-probe | --expect-unhooked] [--every DURATION] [--keep-going]", summary: "canary: list through the gateway in a fresh session, compare with the catalog, the emitted file and the live configuration, probe for unhooked calls (LEAK, MISSING, CONFIG-EDITED, LIVE-CONFIG-MISMATCH, UNHOOKED-CALLS, PROBE-INCONCLUSIVE, PROBE-CHANGED, KNOWN-LIMIT)", run: runVerifyGateway},
		{name: "version", synopsis: "version", summary: "print the version and the pinned gateway version", run: runVersion},
		{name: "help", synopsis: "help [COMMAND ...]", summary: "print usage", run: runHelp},
	}
}

// findCommand looks a name up in a command list.
func findCommand(list []*command, name string) (*command, bool) {
	for _, c := range list {
		if c.name == name {
			return c, true
		}
	}
	return nil, false
}

// dispatch parses the global flags and hands the rest to the named command.
func (a *app) dispatch(args []string) error {
	fs := newFlagSet(programName)
	a.globals.bind(fs)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return &helpError{text: fullUsage()}
		}
		return &usageError{msg: textdiff.Escape(err.Error())}
	}
	rest := fs.Args()
	if len(rest) == 0 {
		return &usageError{msg: "a command is required"}
	}
	c, ok := findCommand(commands(), rest[0])
	if !ok {
		return &usageError{msg: fmt.Sprintf("unknown command %s", textdiff.Escape(rest[0]))}
	}
	return c.run(a, c, rest[1:])
}

// runSub dispatches a two-level command such as "server add".
func runSub(a *app, c *command, args []string) error {
	if len(args) == 0 {
		return &usageError{msg: fmt.Sprintf("%s needs a subcommand", c.name), cmd: c}
	}
	if args[0] == helpFlag || args[0] == "--help" || args[0] == "help" {
		return &helpError{text: subUsage(c)}
	}
	sub, ok := findCommand(c.sub, args[0])
	if !ok {
		return &usageError{msg: fmt.Sprintf("unknown %s subcommand %s", c.name, textdiff.Escape(args[0])), cmd: c}
	}
	return sub.run(a, sub, args[1:])
}

// runHelp prints the overall usage, or that of the named command by running it
// with -h so the text always matches the flags the command really defines.
func runHelp(a *app, c *command, args []string) error {
	if len(args) == 0 {
		return &helpError{text: fullUsage()}
	}
	list, target := commands(), (*command)(nil)
	for _, name := range args {
		next, ok := findCommand(list, name)
		if !ok {
			return &usageError{msg: fmt.Sprintf("unknown command %s", textdiff.Escape(name)), cmd: c}
		}
		target, list = next, next.sub
	}
	if len(target.sub) > 0 && !target.self {
		return &helpError{text: subUsage(target)}
	}
	return target.run(a, target, []string{helpFlag})
}

// runVersion prints the build version and the gateway release it is pinned to.
// The version text is escaped like everything else the source did not write.
func runVersion(a *app, _ *command, _ []string) error {
	v := textdiff.Escape(displayVersion(version, embeddedModuleVersion()))
	a.stdout.printf("%s %s\n%s\n", programName, v, gatewayVersion)
	return nil
}

// displayVersion decides which version the version command prints. A version
// set at link time wins. When linked is still the source default, the module
// version the Go toolchain embedded stands in for it, so a binary built with
// go install module@vX.Y.Z reports the tag instead of "dev"; the toolchain has
// already appended the revision and a +dirty marker when it stamped one, so
// nothing is added here. An empty module version or the "(devel)" the
// toolchain records for a go test or go run binary leaves the default alone.
func displayVersion(linked, moduleVersion string) string {
	if linked != devVersion {
		return linked
	}
	if moduleVersion == "" || moduleVersion == unknownModuleVersion {
		return linked
	}
	return moduleVersion
}

// embeddedModuleVersion returns the main module version the Go toolchain
// recorded in this binary, or "" when the binary carries no build information.
func embeddedModuleVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info == nil {
		return ""
	}
	return info.Main.Version
}

// exitCode prints err the way its kind demands and returns the exit code.
func (a *app) exitCode(err error) int {
	if err == nil {
		return exitOK
	}
	var help *helpError
	if errors.As(err, &help) {
		a.stdout.print(help.text)
		return exitOK
	}
	var usage *usageError
	if errors.As(err, &usage) {
		a.stderr.printf("%s: %s\n", programName, usage.msg)
		if usage.cmd != nil {
			a.stderr.printf("usage: %s [global flags] %s\n", programName, usage.cmd.synopsis)
		} else {
			a.stderr.printf("run \"%s help\" for usage\n", programName)
		}
		return exitUsage
	}
	a.stderr.printf("%s: %s\n", programName, describe(err))
	return exitFailure
}

// checkStreams turns a write failure on either stream into a failing exit
// code. A broken stdout is reported on stderr; a broken stderr can only be
// reported through the exit code. A command that already failed keeps its
// more specific code.
func (a *app) checkStreams(code int) int {
	if err := a.stdout.broken(); err != nil {
		a.stderr.printf("%s: writing to stdout failed: %s\n", programName, textdiff.Escape(err.Error()))
	}
	if code == exitOK && (a.stdout.broken() != nil || a.stderr.broken() != nil) {
		return exitFailure
	}
	return code
}

// fullUsage renders the help for everything.
func fullUsage() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s approves exactly which MCP tool definitions a gateway serves.\n\n", programName)
	fmt.Fprintf(&sb, "usage: %s [global flags] COMMAND [arguments]\n\nglobal flags:\n", programName)
	fs := newFlagSet(programName)
	(&globals{}).bind(fs)
	fs.SetOutput(&sb)
	fs.PrintDefaults()
	sb.WriteString("\ncommands:\n")
	var rows []*command
	for _, c := range commands() {
		if len(c.sub) == 0 || c.self {
			rows = append(rows, c)
		}
		rows = append(rows, c.sub...)
	}
	commandRows(&sb, rows)
	fmt.Fprintf(&sb, "\nexit codes: 0 success, 1 the operation failed, 2 the command line was wrong.\n")
	fmt.Fprintf(&sb, "run \"%s help COMMAND\" or \"%s COMMAND -h\" for the flags of one command.\n", programName, programName)
	return sb.String()
}

// subUsage lists the subcommands of a two-level command.
func subUsage(c *command) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "usage: %s [global flags] %s\n\n%s\n\nsubcommands:\n", programName, c.synopsis, c.summary)
	commandRows(&sb, c.sub)
	return sb.String()
}

// commandRows appends one aligned line per command. A strings.Builder cannot
// fail, so the error branch is unreachable in practice; should it ever run,
// the text says so instead of a command quietly going missing from the help.
func commandRows(sb *strings.Builder, cmds []*command) {
	t := newTable(sb)
	for _, c := range cmds {
		t.row("  "+c.synopsis, c.summary)
	}
	if err := t.flush(); err != nil {
		fmt.Fprintf(sb, "  (command list unavailable: %v)\n", err)
	}
}

// usage renders the help of one command, including the flags it defined and,
// for a command that also has subcommands (export), their rows.
func (c *command) usage(fs *flag.FlagSet) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "usage: %s [global flags] %s\n\n%s\n", programName, c.synopsis, c.summary)
	defined := 0
	fs.VisitAll(func(*flag.Flag) { defined++ })
	if defined > 0 {
		sb.WriteString("\nflags:\n")
		fs.SetOutput(&sb)
		fs.PrintDefaults()
	}
	if len(c.sub) > 0 {
		sb.WriteString("\nsubcommands:\n")
		commandRows(&sb, c.sub)
	}
	return sb.String()
}
