package main

import (
	"errors"
	"fmt"
	"net/netip"
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
	// configFileMode is world-readable: without a secret the config holds
	// upstream URLs and tool names, and the gateway often runs as another
	// user.
	configFileMode os.FileMode = 0o644
	// secretConfigFileMode is owner-only: with --secret-env the file carries
	// the processor secret in clear, so only the gateway's user may read it.
	secretConfigFileMode os.FileMode = 0o600
	tempPattern                      = ".toolwarrant-*.tmp"
	routeSuffix                      = "/mcp"
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

// emitPlan is what one server contributes to the gateway config.
type emitPlan struct {
	name      string
	url       string
	processor string
	tools     []string
}

// runEmit writes the agentgateway configuration: one route per server, each
// with an explicit allow rule for its approved tools and the processor that
// enforces strict mode. The serving port is bound to loopback unless
// --bind-address says otherwise, and a wildcard address needs
// --allow-all-interfaces on top (seam finding F2). With --secret-env every
// processor entry carries the shared secret and the file is written
// owner-only.
func runEmit(a *app, c *command, args []string) (err error) {
	fs := newFlagSet(c.name)
	out := fs.String("out", "", "file to write the gateway configuration to (required)")
	listenPort := fs.Int("listen-port", defaultListenPort, "port the gateway binds")
	bindAddress := fs.String("bind-address", emit.DefaultBindAddress, "IPv4 or IPv6 literal the gateway binds --listen-port on; an address other hosts can reach exposes every route to the network with the processor as its only guard, and a wildcard (0.0.0.0 or ::) also needs --allow-all-interfaces")
	allowAllInterfaces := fs.Bool("allow-all-interfaces", false, "permit a wildcard --bind-address; a permission, not a request: with any other address it changes nothing")
	basePort := fs.Int("processor-base-port", defaultProcessorBasePort, "the i-th server in name order gets processor "+processorHost+":(base+i)")
	overrides := processorOverrides{}
	fs.Var(overrides, "processor", "NAME=HOST:PORT processor address for one server (repeatable)")
	secretEnv := fs.String("secret-env", "", "environment variable holding a shared secret (16 to 256 printable ASCII characters) written into every processor entry; the file is then written 0600")
	pos, err := a.parseArgs(c, fs, args)
	if err != nil {
		return err
	}
	if err := wantArgs(c, pos); err != nil {
		return err
	}
	if err := requireFlag(c, *out, "out", "name the file to write"); err != nil {
		return err
	}
	if err := checkBindAddress(c, *bindAddress, *allowAllInterfaces); err != nil {
		return err
	}
	secret, err := readSecret(c, a.getenv, *secretEnv)
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
	plans, err := planEmit(c, servers, approved, *basePort, overrides)
	if err != nil {
		return err
	}
	in := emit.Input{ListenPort: *listenPort, BindAddress: *bindAddress, AllowAllInterfaces: *allowAllInterfaces, Servers: emitServers(plans, secret)}
	result, err := emit.AgentGateway(in)
	if err != nil {
		return err
	}
	mode := configFileMode
	if secret != "" {
		mode = secretConfigFileMode
	}
	if err := writeFileAtomic(*out, result.YAML, mode); err != nil {
		return err
	}
	return a.reportEmit(*out, plans, result, *secretEnv)
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

// planEmit assigns every server its route, processor address and approved
// tool names. Servers are taken in name order so the i-th port is stable.
func planEmit(c *command, servers []catalog.Server, approved []catalog.ApprovedTool, basePort int, overrides processorOverrides) ([]emitPlan, error) {
	sorted := append([]catalog.Server(nil), servers...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	byServer := map[string][]string{}
	for _, t := range approved {
		byServer[t.Server] = append(byServer[t.Server], t.Name)
	}
	known := map[string]bool{}
	plans := make([]emitPlan, 0, len(sorted))
	for i, s := range sorted {
		known[s.Name] = true
		addr, ok := overrides[s.Name]
		if !ok {
			addr = fmt.Sprintf("%s:%d", processorHost, basePort+i)
		}
		plans = append(plans, emitPlan{name: s.Name, url: s.URL, processor: addr, tools: byServer[s.Name]})
	}
	for name := range overrides {
		if !known[name] {
			return nil, &usageError{msg: fmt.Sprintf("--processor names unknown server %s", textdiff.Escape(name)), cmd: c}
		}
	}
	return plans, nil
}

// emitServers is the emitter's view of the plans: one Server per route, every
// one carrying the same secret.
func emitServers(plans []emitPlan, secret string) []emit.Server {
	servers := make([]emit.Server, 0, len(plans))
	for _, p := range plans {
		servers = append(servers, emit.Server{Name: p.name, URL: p.url, ProcessorAddr: p.processor, Secret: secret, ApprovedTools: p.tools})
	}
	return servers
}

// reportEmit prints what was written and the body hash the header records (so
// a canary can compare it later), warns when the gateway's serving socket is
// reachable from other hosts, about approved tools the emitter had to leave
// hidden and about a file that carries the secret, and prints the exact serve
// command for each server. The bind warning is the emitter's own text: it
// comes from a validated address, not from the catalog.
func (a *app) reportEmit(out string, plans []emitPlan, result emit.Output, secretEnv string) error {
	a.stdout.printf("wrote %s\nbody sha256 %s\n", textdiff.Escape(out), result.BodyHash)
	t := newTable(a.stdout)
	t.row("SERVER", "ROUTE", "PROCESSOR", "APPROVED")
	for _, p := range plans {
		t.row(cell(p.name), "/"+cell(p.name)+routeSuffix, textdiff.Escape(p.processor), strconv.Itoa(len(p.tools)))
	}
	if err := t.flush(); err != nil {
		return err
	}
	if result.Warning != "" {
		a.stderr.printf("warning: %s\n", result.Warning)
	}
	for _, s := range result.Skipped {
		a.stderr.printf("warning: %s/%s is approved but left out of the allow rule and stays hidden: %s\n", cell(s.Server), cell(s.Tool), cell(s.Reason))
	}
	if secretEnv != "" {
		a.stderr.printf("warning: %s contains the processor secret from %s in clear and was written with mode %04o; keep it readable by the gateway's user only\n", textdiff.Escape(out), textdiff.Escape(secretEnv), secretConfigFileMode)
	}
	a.stdout.printf("run one processor per server:\n")
	for _, p := range plans {
		a.stdout.printf("  %s\n", textdiff.Escape(a.serveCommand(p, secretEnv)))
	}
	return a.stdout.broken()
}

// serveCommand is the command line that starts the processor for one server,
// with the database path made absolute so it works from any directory. The
// target is the server name because that is the backend name the emitted
// config gives the route; the secret is referenced by variable, never by
// value.
func (a *app) serveCommand(p emitPlan, secretEnv string) string {
	db := a.dbPath()
	if abs, err := filepath.Abs(db); err == nil {
		db = abs
	}
	cmd := fmt.Sprintf("%s --db %s serve --server %s --target %s --listen %s", programName, shellWord(db), shellWord(p.name), shellWord(p.name), shellWord(p.processor))
	if secretEnv != "" {
		cmd += " --secret-env " + shellWord(secretEnv)
	}
	return cmd
}

// writeFileAtomic replaces path with data through a temporary file in the same
// directory and a rename, so the gateway never reads a half-written config.
// The mode is set on the temporary file before the rename, so a file that
// carries a secret is never readable by others for even an instant.
func writeFileAtomic(path string, data []byte, mode os.FileMode) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), tempPattern)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp.Name()) // the original error is the one to report
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err = tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("set file mode: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("rename into place: %w", err)
	}
	return nil
}
