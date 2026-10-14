package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/sairam0424/toolwarrant/internal/catalog"
	"github.com/sairam0424/toolwarrant/internal/emit"
	"github.com/sairam0424/toolwarrant/internal/textdiff"
)

const (
	defaultListenPort        = 3000
	defaultProcessorBasePort = 9001
	processorHost            = "127.0.0.1"
	// configFileMode is owner-only for every emitted file (D13 g). The file
	// may carry the processor secret, and an upstream URL may carry a
	// credential in its query string or, as hosted MCP servers do, in a path
	// segment that no heuristic can tell from a plain path (third review); the
	// gateway reads the file as one user, so the operator chowns it to that
	// user instead of the file guessing who may read it.
	configFileMode       os.FileMode = 0o600
	routeSuffix                      = "/mcp"
	allowNonLoopbackFlag             = "--allow-non-loopback"
)

// processorOverrides is the repeatable --processor NAME=HOST:PORT flag.
type processorOverrides map[string]string

func (p processorOverrides) String() string {
	parts := make([]string, 0, len(p))
	for name, addr := range p {
		parts = append(parts, name+"="+addr)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// Set records one override. The flag package reports the error with the raw
// value, which the dispatcher escapes before printing.
func (p processorOverrides) Set(v string) error {
	name, addr, ok := strings.Cut(v, "=")
	if !ok || name == "" || addr == "" {
		return errors.New("want NAME=HOST:PORT")
	}
	if _, dup := p[name]; dup {
		return errors.New("server given twice")
	}
	p[name] = addr
	return nil
}

// emitPlan is what one server contributes to the gateway config. previous is
// the processor address the catalog recorded for the server before this emit,
// "" when it had none (D14 i); tls is the backendTLS block --processor-tls
// gave for the server, nil for a plaintext link (D19, not recorded anywhere).
type emitPlan struct {
	name      string
	url       string
	processor string
	previous  string
	tools     []string
	tls       *emit.ProcessorTLS
}

// emitOptions are the flags of emit. The listener addresses default to ""
// and the emitter applies its defaults, so --disable-admin never contradicts
// an admin address nobody typed.
type emitOptions struct {
	out, bindAddress, adminAddr, statsAddr, readinessAddr, secretEnv, gatewayBinary string
	listenPort, basePort                                                            int
	allowAllInterfaces, disableAdmin                                                bool
	overrides                                                                       processorOverrides
	processorTLS                                                                    processorTLSFlags
}

// emitOutcome is what reportEmit prints: the plans, the emitter's output and
// the servers whose URL carries a query string.
type emitOutcome struct {
	plans        []emitPlan
	result       emit.Output
	credentialed []string
}

// bindEmitFlags registers the flags of emit.
func bindEmitFlags(fs *flag.FlagSet, getenv func(string) string) *emitOptions {
	o := &emitOptions{overrides: processorOverrides{}, processorTLS: processorTLSFlags{}}
	fs.StringVar(&o.out, "out", "", "file to write the gateway configuration to (required); it must be absent or a regular file emit wrote before (a symbolic link, directory, device, socket or named pipe is refused before anything is opened, so are the catalog database, its -wal and -shm siblings and the gateway binary, and so is an existing file whose first lines are not emit's header; a file the gateway rewrote keeps the header and is replaced) and is never read for addresses, since processor addresses come from the catalog; always written with mode 0600, so chown it to the gateway's user")
	fs.IntVar(&o.listenPort, "listen-port", defaultListenPort, "port the gateway binds")
	fs.StringVar(&o.bindAddress, "bind-address", emit.DefaultBindAddress, "IPv4 or IPv6 literal the gateway binds --listen-port on; an address other hosts can reach exposes every route to the network with the processor as its only guard, and a wildcard (0.0.0.0 or ::) also needs --allow-all-interfaces")
	fs.BoolVar(&o.allowAllInterfaces, "allow-all-interfaces", false, "permit a wildcard --bind-address and a listener address other hosts can reach; a permission, not a request: with loopback addresses it changes nothing")
	fs.StringVar(&o.adminAddr, "admin-addr", "", "host:port of the gateway's admin API, config.adminAddr (default "+emit.DefaultAdminAddr+"); it is unauthenticated and part of the trusted computing base, so keep it on loopback, and give verify-gateway --admin the same address")
	fs.BoolVar(&o.disableAdmin, "disable-admin", false, "turn the gateway's admin API off (config.adminAddr off) instead of binding it; verify-gateway --admin then has nothing to ask")
	fs.StringVar(&o.statsAddr, "stats-addr", "", "host:port of the gateway's metrics listener, config.statsAddr (default "+emit.DefaultStatsAddr+")")
	fs.StringVar(&o.readinessAddr, "readiness-addr", "", "host:port of the gateway's readiness probe, config.readinessAddr (default "+emit.DefaultReadinessAddr+")")
	fs.IntVar(&o.basePort, "processor-base-port", defaultProcessorBasePort, "on a first emit the i-th server in name order gets processor "+processorHost+":(base+i); every address is recorded in the catalog once the file is written (server list shows it, audit entry server.processor_set) and every later emit keeps it, giving a new server the next free port above the recorded ones, so adding a server moves nobody; the file at --out is never read for addresses")
	fs.Var(o.overrides, "processor", "NAME=HOST:PORT processor address for one server (repeatable); it replaces the address the catalog records for that server and is kept by later emits; a host other than loopback is warned about, and the printed serve command then carries "+allowNonLoopbackFlag+", which serve accepts only together with --secret-env or the explicit --insecure-no-secret")
	fs.Var(o.processorTLS, "processor-tls", processorTLSGrammar+" puts the gateway's backendTLS block on one server's processor entry (repeatable): the gateway then dials that processor with TLS, presents the client certificate at cert and key, verifies the processor's certificate against the root bundle and under hostname (the DNS name of the certificate serve --tls-cert presents; an IP literal is refused); the three paths are files on the gateway host, absolute, and are never opened by emit, except that --gateway-binary makes the gateway read them, so they must then exist on this host; nothing of the block is recorded in the catalog, so give the flag on every emit, as --secret-env, or the next file dials the processor in plaintext, which a processor started with --tls-cert refuses; the printed serve command then carries placeholders for --tls-cert, --tls-key and --tls-client-ca, and with --tls-client-ca the processor accepts a non-loopback listener without --secret-env (owner decision O-2)")
	fs.StringVar(&o.secretEnv, "secret-env", "", "environment variable holding a shared secret (16 to 256 printable ASCII characters) written into every processor entry")
	fs.StringVar(&o.gatewayBinary, "gateway-binary", getenv(envGatewayBinary), "agentgateway binary (env "+envGatewayBinary+"); when set, the file is staged under a temporary name, checked with <binary> -f FILE "+validateOnlyFlag+" and renamed into place only if the gateway accepts it; a refusal exits 1, prints the gateway's message, leaves no file and records no processor address")
	return o
}

// check validates the flags that are usage errors naming the fix, before
// anything is read or written: the required output path and the wildcard
// bind permission, then that --out is absent or a regular file (Lstat, before
// any open: a named pipe planted there blocked emit for ever, fourth review
// cli-docs-2, and a symbolic link would make it replace a file elsewhere),
// and then that the regular file is one emit may replace (checkOut, D17 j).
// Everything else about the input, an admin address given together with
// --disable-admin included, is the emitter's rule and is reported by it.
func (o *emitOptions) check(c *command, dbPath string) error {
	if err := requireFlag(c, o.out, "out", "name the file to write"); err != nil {
		return err
	}
	if err := checkBindAddress(c, o.bindAddress, o.allowAllInterfaces); err != nil {
		return err
	}
	if err := refuseIrregularFile(o.out, "--out"); err != nil {
		return err
	}
	return o.checkOut(c, dbPath)
}

// input is the emitter's view of the flags and the plans.
func (o *emitOptions) input(plans []emitPlan, secret string) emit.Input {
	return emit.Input{ListenPort: o.listenPort, BindAddress: o.bindAddress, AllowAllInterfaces: o.allowAllInterfaces,
		AdminAddr: o.adminAddr, DisableAdmin: o.disableAdmin, StatsAddr: o.statsAddr, ReadinessAddr: o.readinessAddr,
		Servers: emitServers(plans, secret)}
}

// runEmit writes the agentgateway configuration: one route per server, each
// with an explicit allow rule for its approved tools and the processor that
// enforces strict mode. The serving port is bound to loopback unless
// --bind-address says otherwise, and a wildcard address needs
// --allow-all-interfaces on top (seam finding F2). The file is always written
// owner-only (D13 g). Every server's processor address comes from the catalog
// and goes back into it when it is new or changed, after the file was
// validated and renamed into place (D14 i, D15 j): a refused or failed emit
// records nothing, so the next emit that writes a file still prints every
// address as new; the file at --out is never read for addresses and must be
// absent or a regular file emit wrote (D17 j). The addresses come from the
// catalog's Servers view, which since the seventh round is anchored to the
// verified server.processor_set entries and answers ErrCorrupt when the
// column disagrees with them (D17 c), so an emit against a rewritten column
// writes nothing instead of handing the forged address to the gateway, and
// every address that differs from the one the catalog recorded is printed
// as new or changed.
func runEmit(a *app, c *command, args []string) (err error) {
	fs := newFlagSet(c.name)
	o := bindEmitFlags(fs, a.getenv)
	pos, err := a.parseArgs(c, fs, args)
	if err != nil {
		return err
	}
	if err := wantArgs(c, pos); err != nil {
		return err
	}
	if err := o.check(c, a.dbPath()); err != nil {
		return err
	}
	secret, err := readSecret(c, a.getenv, o.secretEnv)
	if err != nil {
		return err
	}
	store, err := a.openStore(openWrite)
	if err != nil {
		return err
	}
	defer closeStore(store, &err)
	servers, err := store.Servers(a.ctx)
	if err != nil {
		return err
	}
	approved, err := store.Approved(a.ctx)
	if err != nil {
		return err
	}
	plans, err := planEmit(c, servers, approved, o.basePort, o.overrides)
	if err != nil {
		return err
	}
	plans, err = attachProcessorTLS(c, plans, o.processorTLS)
	if err != nil {
		return err
	}
	result, err := emit.AgentGateway(o.input(plans, secret))
	if err != nil {
		return err
	}
	if err := writeValidated(a.ctx, o.out, result.YAML, configFileMode, o.gatewayBinary); err != nil {
		return err
	}
	if err := recordProcessorAddrs(a, store, plans, o.out); err != nil {
		return err
	}
	return a.reportEmit(o, emitOutcome{plans: plans, result: result, credentialed: serversWithQuery(servers)})
}

// checkBindAddress refuses a wildcard --bind-address unless the operator said
// so explicitly, as a usage error that names the flag to pass: a wildcard makes
// every route reachable from the network with the processor as its only guard
// (seam finding F2), and the fix is a flag. The parser and the predicate are
// the emitter's own, so an address that passes here as not a wildcard is not a
// wildcard to the emitter either; everything else about the address (zones,
// mapped, link-local, multicast) is the emitter's rule and is reported by it.
func checkBindAddress(c *command, addr string, allowAllInterfaces bool) error {
	ip, err := netip.ParseAddr(addr)
	if err != nil || !ip.IsUnspecified() || allowAllInterfaces {
		return nil
	}
	return &usageError{msg: fmt.Sprintf("refusing to bind %s: the gateway would listen on every interface of this host and the toolwarrant processor would be the only guard of every route (seam finding F2); pass --allow-all-interfaces only behind a firewall that admits the gateway's clients alone", textdiff.Escape(addr)), cmd: c}
}

// emitServers is the emitter's view of the plans: one Server per route, every
// one carrying the same secret and its own TLS block, if any.
func emitServers(plans []emitPlan, secret string) []emit.Server {
	servers := make([]emit.Server, 0, len(plans))
	for _, p := range plans {
		servers = append(servers, emit.Server{Name: p.name, URL: p.url, ProcessorAddr: p.processor, Secret: secret, TLS: p.tls, ApprovedTools: p.tools})
	}
	return servers
}

// serversWithQuery names, in name order, the servers whose URL carries a
// query string. The catalog accepts a query and the code base treats it as
// the place credentials live (safeURL strips it), so a file that carries one
// is warned about by server name, never by URL. The file is owner-only either
// way; the warning tells the operator what the file holds.
func serversWithQuery(servers []catalog.Server) []string {
	var names []string
	for _, s := range servers {
		u, err := url.Parse(s.URL)
		if (err == nil && u.RawQuery != "") || (err != nil && strings.Contains(s.URL, "?")) {
			names = append(names, s.Name)
		}
	}
	sort.Strings(names)
	return names
}

// reportEmit prints what was written and the body hash the header records (so
// a canary can compare it later with --expect-body-hash), the table of routes,
// one line per server whose processor address is new or changed since the
// catalog last recorded it, every warning the emitter raised, the file
// warnings and the exact serve command for each server.
func (a *app) reportEmit(o *emitOptions, out emitOutcome) error {
	a.stdout.printf("wrote %s\nbody sha256 %s\n", textdiff.Escape(o.out), out.result.BodyHash)
	if o.gatewayBinary != "" {
		a.stdout.printf("validated with %s %s\n", textdiff.Escape(o.gatewayBinary), validateOnlyFlag)
	}
	t := newTable(a.stdout)
	t.row("SERVER", "ROUTE", "PROCESSOR", "APPROVED")
	for _, p := range out.plans {
		t.row(cell(p.name), "/"+cell(p.name)+routeSuffix, textdiff.Escape(p.processor), strconv.Itoa(len(p.tools)))
	}
	if err := t.flush(); err != nil {
		return err
	}
	a.printProcessorChanges(out.plans)
	a.printEmitWarnings(o, out)
	a.stdout.printf("run one processor per server:\n")
	for _, p := range out.plans {
		a.stdout.printf("  %s\n", textdiff.Escape(a.serveCommand(p, o.secretEnv)))
	}
	return a.stdout.broken()
}

// printProcessorChanges names every server whose processor address is not the
// one the catalog recorded before this emit: a new address on a first emit, or
// a changed one, which means the processor that is running must be restarted
// on the new address before the gateway reloads, or its route fails closed
// (D13 g, D14 i). With no such line the running processors are untouched.
func (a *app) printProcessorChanges(plans []emitPlan) {
	for _, p := range plans {
		switch {
		case p.previous == "":
			a.stdout.printf("processor address of server %s is new: %s\n", cell(p.name), textdiff.Escape(p.processor))
		case p.previous != p.processor:
			a.stdout.printf("processor address of server %s changed from %s to %s; restart its processor on the new address\n", cell(p.name), textdiff.Escape(p.previous), textdiff.Escape(p.processor))
		}
	}
}

// printEmitWarnings writes every warning on stderr: the emitter's own lines
// (a serving socket, a listener or a processor other hosts can reach), the
// approved tools it had to leave hidden, and the two reasons the owner-only
// file holds a credential. The emitter's text comes from validated addresses
// and names, not from the catalog.
func (a *app) printEmitWarnings(o *emitOptions, out emitOutcome) {
	for _, line := range strings.Split(out.result.Warning, "\n") {
		if line != "" {
			a.stderr.printf("warning: %s\n", line)
		}
	}
	for _, s := range out.result.Skipped {
		a.stderr.printf("warning: %s/%s is approved but left out of the allow rule and stays hidden: %s\n", cell(s.Server), cell(s.Tool), cell(s.Reason))
	}
	if o.secretEnv != "" {
		a.stderr.printf("warning: %s contains the processor secret from %s in clear and was written with mode %04o; keep it readable by the gateway's user only\n", textdiff.Escape(o.out), textdiff.Escape(o.secretEnv), configFileMode)
	}
	for _, name := range out.credentialed {
		a.stderr.printf("warning: the URL of server %s carries a query string, which is where credentials live; %s was written with mode %04o and must stay readable by the gateway's user only\n", cell(name), textdiff.Escape(o.out), configFileMode)
	}
}

// serveCommand is the command line that starts the processor for one server,
// with the database path made absolute so it works from any directory. The
// target is the server name because that is the backend name the emitted
// config gives the route; the secret is referenced by variable, never by
// value. A processor address other hosts can reach gets the flag serve needs
// to accept it; serve still refuses it without a secret or a client
// certificate authority, by design. A server whose entry carries the
// backendTLS block gets the three TLS flags with placeholders, since the
// processor's files live on its own host (D19).
func (a *app) serveCommand(p emitPlan, secretEnv string) string {
	db := a.dbPath()
	if abs, err := filepath.Abs(db); err == nil {
		db = abs
	}
	cmd := fmt.Sprintf("%s --db %s serve --server %s --target %s --listen %s", programName, shellWord(db), shellWord(p.name), shellWord(p.name), shellWord(p.processor))
	if host, _, err := net.SplitHostPort(p.processor); err == nil && !isLoopbackHost(host) {
		cmd += " " + allowNonLoopbackFlag
	}
	if secretEnv != "" {
		cmd += " --secret-env " + shellWord(secretEnv)
	}
	if p.tls != nil {
		cmd += tlsServePlaceholders
	}
	return cmd
}
