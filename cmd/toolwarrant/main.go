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
	"strings"
	"syscall"
	"text/tabwriter"

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
// time; nothing assigns to it while the program runs.
var version = "dev"

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
// --every) shut down gracefully.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return runCtx(ctx, args, stdin, stdout, stderr, getenv)
}

// runCtx is run with an explicit context, so tests can bound a command that
// would otherwise wait for a signal.
func runCtx(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) int {
	a := &app{ctx: ctx, stdin: stdin, stdout: stdout, stderr: stderr, getenv: getenv}
	return a.exitCode(a.dispatch(args))
}

// app is the state of one invocation. Everything a command needs comes from
// here, so nothing lives in package-level variables.
type app struct {
	ctx     context.Context
	stdin   io.Reader
	stdout  io.Writer
	stderr  io.Writer
	getenv  func(string) string
	globals globals
}

// command is one entry of the command table. A command with sub-entries
// (server, audit) dispatches to them instead of running itself.
type command struct {
	name     string
	synopsis string // what follows "toolwarrant [global flags]"
	summary  string // one line for the command list
	run      func(a *app, c *command, args []string) error
	sub      []*command
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
		{name: "server", synopsis: "server add|list ...", summary: "register and list upstream MCP servers", run: runSub, sub: serverCommands()},
		{name: "crawl", synopsis: "crawl SERVER [--every DURATION] [--bearer-env VAR] [--json]", summary: "fetch the upstream's tools and record what changed; never approves", run: runCrawl},
		{name: "list", synopsis: "list [SERVER] [--json]", summary: "show every tool with its state and digests; DRIFT marks a live digest that differs from the approved one", run: runList},
		{name: "show", synopsis: "show SERVER TOOL [--json]", summary: "show one tool and all of its versions", run: runShow},
		{name: "diff", synopsis: "diff SERVER TOOL [--from HASH] [--to HASH]", summary: "show what changed between two versions, escaped for the terminal", run: runDiff},
		{name: "approve", synopsis: "approve SERVER TOOL --hash HASH [--accept-suspicious]", summary: "approve the exact digest you reviewed", run: runApprove},
		{name: "reject", synopsis: "reject SERVER TOOL --hash HASH", summary: "reject a pending version", run: runReject},
		{name: "disable", synopsis: "disable SERVER TOOL", summary: "switch a tool off", run: runDisable},
		{name: "enable", synopsis: "enable SERVER TOOL", summary: "bring a disabled tool back for review", run: runEnable},
		{name: "rollback", synopsis: "rollback SERVER TOOL --to HASH", summary: "re-approve a version that was approved before", run: runRollback},
		{name: "serve", synopsis: "serve --server NAME --listen ADDR [--allow-non-loopback]", summary: "run the ExtMCP processor that enforces approvals at the gateway", run: runServe},
		{name: "emit", synopsis: "emit --out FILE [--listen-port N] [--processor-base-port N] [--processor NAME=HOST:PORT ...]", summary: "write the agentgateway configuration for every server", run: runEmit},
		{name: "export", synopsis: "export --dir DIR [--commit] [--git-name N --git-email E]", summary: "write the approved definitions to a directory for review in git", run: runExport},
		{name: "audit", synopsis: "audit verify|list ...", summary: "verify and read the hash-chained audit log", run: runSub, sub: auditCommands()},
		{name: "verify-gateway", synopsis: "verify-gateway --server NAME --url URL [--bearer-env VAR]", summary: "deploy-time self-test: list through the gateway and compare with the catalog", run: runVerifyGateway},
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
	if len(target.sub) > 0 {
		return &helpError{text: subUsage(target)}
	}
	return target.run(a, target, []string{helpFlag})
}

// runVersion prints the build version and the gateway release it is pinned to.
func runVersion(a *app, _ *command, _ []string) error {
	fmt.Fprintf(a.stdout, "%s %s\n%s\n", programName, version, gatewayVersion)
	return nil
}

// exitCode prints err the way its kind demands and returns the exit code.
func (a *app) exitCode(err error) int {
	if err == nil {
		return exitOK
	}
	var help *helpError
	if errors.As(err, &help) {
		fmt.Fprint(a.stdout, help.text)
		return exitOK
	}
	var usage *usageError
	if errors.As(err, &usage) {
		fmt.Fprintf(a.stderr, "%s: %s\n", programName, usage.msg)
		if usage.cmd != nil {
			fmt.Fprintf(a.stderr, "usage: %s [global flags] %s\n", programName, usage.cmd.synopsis)
		} else {
			fmt.Fprintf(a.stderr, "run \"%s help\" for usage\n", programName)
		}
		return exitUsage
	}
	fmt.Fprintf(a.stderr, "%s: %s\n", programName, describe(err))
	return exitFailure
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
	tw := tabwriter.NewWriter(&sb, 0, 0, tabPadding, ' ', 0)
	for _, c := range commands() {
		if len(c.sub) == 0 {
			fmt.Fprintf(tw, "  %s\t%s\n", c.synopsis, c.summary)
			continue
		}
		for _, s := range c.sub {
			fmt.Fprintf(tw, "  %s\t%s\n", s.synopsis, s.summary)
		}
	}
	_ = tw.Flush()
	fmt.Fprintf(&sb, "\nexit codes: 0 success, 1 the operation failed, 2 the command line was wrong.\n")
	fmt.Fprintf(&sb, "run \"%s help COMMAND\" or \"%s COMMAND -h\" for the flags of one command.\n", programName, programName)
	return sb.String()
}

// subUsage lists the subcommands of a two-level command.
func subUsage(c *command) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "usage: %s [global flags] %s\n\n%s\n\nsubcommands:\n", programName, c.synopsis, c.summary)
	tw := tabwriter.NewWriter(&sb, 0, 0, tabPadding, ' ', 0)
	for _, s := range c.sub {
		fmt.Fprintf(tw, "  %s\t%s\n", s.synopsis, s.summary)
	}
	_ = tw.Flush()
	return sb.String()
}

// usage renders the help of one command, including the flags it defined.
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
	return sb.String()
}
