package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sairam0424/toolwarrant/internal/emit"
	"github.com/sairam0424/toolwarrant/internal/processor"
	"github.com/sairam0424/toolwarrant/internal/textdiff"
)

const (
	unixPrefix = "unix:"
	// socketMode lets only the owner connect. The ExtMCP protocol has no
	// authentication of its own and every reply decides what the gateway
	// serves, so the socket must not be reachable by other users of the
	// machine.
	socketMode os.FileMode = 0o600
	// privateDirMask selects the group and other permission bits of the
	// socket's directory. A directory that grants any of them lets another
	// user reach the socket in the instant before it is chmod'ed.
	privateDirMask os.FileMode = 0o077
)

// serveOptions are the serve flags as the operator gave them.
type serveOptions struct {
	server           string
	listen           string
	target           string
	allowNonLoopback bool
	insecureNoSecret bool
	secretEnv        string
	maxEvidenceAge   time.Duration
	tls              *tlsFlags
}

// bindServeFlags registers the serve flags on fs.
func bindServeFlags(fs *flag.FlagSet) *serveOptions {
	o := &serveOptions{tls: bindTLSFlags(fs)}
	fs.StringVar(&o.server, "server", "", "catalog server this processor guards (required)")
	fs.StringVar(&o.listen, "listen", "", "host:port or unix:/path to listen on (required; a TCP address must be loopback unless --allow-non-loopback)")
	fs.StringVar(&o.target, "target", "", "backend name the gateway reports in service_names for this route (default: the server name, which is what emit writes)")
	fs.BoolVar(&o.allowNonLoopback, "allow-non-loopback", false, "listen on a TCP address other hosts can reach; refused without --secret-env or --tls-client-ca unless --insecure-no-secret is passed as well, and only for a network nobody but the gateway can reach")
	fs.BoolVar(&o.insecureNoSecret, "insecure-no-secret", false, "with --allow-non-loopback, listen on a TCP address other hosts can reach without a shared secret or a client certificate authority: anyone who reaches the port then decides what the gateway serves; a --secret-env or --tls-client-ca always wins over this flag")
	fs.StringVar(&o.secretEnv, "secret-env", "", "environment variable holding the shared secret the gateway sends with every hook (the one given to emit --secret-env); never a flag value")
	fs.DurationVar(&o.maxEvidenceAge, "max-evidence-age", 0, "how long a digest seen in a tools/list counts as evidence for a tools/call (0 means it never expires)")
	return o
}

// check applies the usage rules: the required flags, the evidence age, the TLS
// flag grammar and the listen policy, in that order, so a wrong TLS flag set is
// named before the address it would have authenticated.
func (o *serveOptions) check(c *command, pos []string) error {
	if err := wantArgs(c, pos); err != nil {
		return err
	}
	if err := requireFlag(c, o.server, "server", "name the catalog server to guard"); err != nil {
		return err
	}
	if err := requireFlag(c, o.listen, "listen", "give host:port or unix:/path"); err != nil {
		return err
	}
	if o.maxEvidenceAge < 0 {
		return &usageError{msg: "--max-evidence-age must not be negative", cmd: c}
	}
	if err := o.tls.check(c, o.listen); err != nil {
		return err
	}
	policy := listenPolicy{allowNonLoopback: o.allowNonLoopback, hasSecret: o.secretEnv != "", hasClientCA: o.tls.requiresClient(), insecureNoSecret: o.insecureNoSecret}
	return checkListenAddr(c, o.listen, policy)
}

// targetName is the backend name the processor guards: --target, else the
// server name, which is what emit writes.
func (o *serveOptions) targetName() string {
	if o.target != "" {
		return o.target
	}
	return o.server
}

// runServe runs the ExtMCP processor for one server until SIGINT or SIGTERM.
// The catalog is opened read-only: the processor reads policy and must never
// be able to change it. Only loopback and unix-socket listeners are accepted
// by default, for the same reason the socket is owner-only; a TCP listener
// other hosts can reach needs --allow-non-loopback and the shared secret, a
// client certificate authority (--tls-client-ca, O-2) or the operator's
// explicit --insecure-no-secret.
func runServe(a *app, c *command, args []string) (err error) {
	fs := newFlagSet(c.name)
	o := bindServeFlags(fs)
	pos, err := a.parseArgs(c, fs, args)
	if err != nil {
		return err
	}
	if err := o.check(c, pos); err != nil {
		return err
	}
	secret, err := readSecret(c, a.getenv, o.secretEnv)
	if err != nil {
		return err
	}
	tlsConf, err := o.tls.load()
	if err != nil {
		return err
	}
	target := o.targetName()
	store, err := a.openStore(openReadOnly)
	if err != nil {
		return err
	}
	defer closeStore(store, &err)
	if _, err := store.Server(a.ctx, o.server); err != nil {
		return err
	}
	lis, err := listenOn(o.listen, a.stderr)
	if err != nil {
		return err
	}
	// Serve closes the listener itself when it stops; this covers the error
	// paths, where a second Close only reports that it is already closed.
	defer func() { _ = lis.Close() }()
	cfg := processor.Config{
		Server:              o.server,
		Target:              target,
		Logger:              slog.New(slog.NewJSONHandler(a.stderr, nil)),
		Secret:              secret,
		AllowRemoteListener: o.allowNonLoopback,
		TLS:                 tlsConf,
		MaxEvidenceAge:      o.maxEvidenceAge,
	}
	proc := processor.New(store, cfg)
	a.stdout.printf("listening on %s, guarding server %s, target %s%s%s\n", textdiff.Escape(lis.Addr().String()), cell(o.server), cell(target), tlsNote(tlsConf), authNote(secret, tlsConf))
	serveErr := proc.Serve(a.ctx, lis)
	writeStats(a.stdout, proc.Stats())
	if serveErr != nil {
		return fmt.Errorf("processor stopped: %w", serveErr)
	}
	return a.stdout.broken()
}

// listenPolicy is what the operator said about a TCP listener that other
// hosts can reach: whether it is allowed at all, whether the hooks on it will
// be authenticated (by the shared secret, or by a client certificate the
// listener requires and verifies, O-2) and whether running it unauthenticated
// was asked for in so many words.
type listenPolicy struct {
	allowNonLoopback bool
	hasSecret        bool
	hasClientCA      bool
	insecureNoSecret bool
}

// checkListenAddr refuses a TCP address that is not loopback unless the
// operator said so explicitly, and refuses it even then unless the hooks will
// be authenticated (a shared secret or a verified client certificate; either
// one is enough, D19 planned) or --insecure-no-secret records that the
// operator accepts a processor that anyone who reaches it can steer. A unix
// socket or a loopback address passes whatever the policy says: the flags are
// permissions, not requests, and change nothing where nothing is exposed.
func checkListenAddr(c *command, addr string, p listenPolicy) error {
	if path, ok := strings.CutPrefix(addr, unixPrefix); ok {
		if path == "" {
			return &usageError{msg: "--listen unix: needs a socket path", cmd: c}
		}
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return &usageError{msg: fmt.Sprintf("--listen %s is neither host:port nor unix:/path", textdiff.Escape(addr)), cmd: c}
	}
	switch {
	case isLoopbackHost(host):
		return nil
	case !p.allowNonLoopback:
		return &usageError{msg: fmt.Sprintf("refusing to listen on %s: it is not a loopback address and the ExtMCP protocol has no authentication; pass --allow-non-loopback together with --secret-env or --tls-client-ca, only on a network that nobody but the gateway can reach", textdiff.Escape(addr)), cmd: c}
	case !p.hasSecret && !p.hasClientCA && !p.insecureNoSecret:
		return &usageError{msg: fmt.Sprintf("refusing to listen on %s without a shared secret or a client certificate authority: anyone who reaches the processor would decide what the gateway serves; pass --secret-env or --tls-client-ca, or --insecure-no-secret to run unauthenticated anyway on a network that nobody but the gateway can reach", textdiff.Escape(addr)), cmd: c}
	}
	return nil
}

// isLoopbackHost accepts the loopback names common resolvers map without a
// DNS query (localhost and the aliases emit.IsLoopbackName lists, one list for
// serve and the emitter; D15 h) and loopback IP literals. Any other host name
// is not resolved: a listen address is configuration, and a name is not a
// safe way to say "loopback".
func isLoopbackHost(host string) bool {
	if emit.IsLoopbackName(host) {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// listenOn opens the listener. A unix socket is made owner-only right after it
// is created; Go removes the socket file when the listener closes.
//
// The chmod window: between net.Listen and os.Chmod the socket file carries
// the process umask's permissions (0755 under the usual 022), so for that
// instant another local user could connect. Go cannot close the window
// without changing the umask of the whole process, which would also change
// how every other file this command creates comes out. The directory is
// checked instead: a 0700 directory keeps everyone else away from the socket
// during the window, and anything looser is warned about so the operator can
// move the socket.
func listenOn(addr string, warn *stream) (net.Listener, error) {
	path, ok := strings.CutPrefix(addr, unixPrefix)
	if !ok {
		lis, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("listen: %w", err)
		}
		return lis, nil
	}
	warnLooseSocketDir(path, warn)
	lis, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on unix socket: %w", err)
	}
	if err := os.Chmod(path, socketMode); err != nil {
		_ = lis.Close() // the chmod failure is the one to report
		return nil, fmt.Errorf("restrict socket permissions: %w", err)
	}
	return lis, nil
}

// warnLooseSocketDir warns when the socket's directory lets other users in. A
// directory that cannot be read is left to net.Listen to report.
func warnLooseSocketDir(path string, warn *stream) {
	dir := filepath.Dir(path)
	fi, err := os.Stat(dir)
	if err != nil {
		return
	}
	if perm := fi.Mode().Perm(); perm&privateDirMask != 0 {
		warn.printf("warning: socket directory %s has mode %04o, not 0700: until the socket is restricted to 0600 another local user could connect to it; use a private directory\n", textdiff.Escape(dir), perm)
	}
}

// writeStats prints the processor counters when it stops, so an operator can
// see at a glance whether the gateway ever asked, what was hidden and why.
// The four bracketed counters break ToolsHidden down (unverified: the live
// bytes matched the approval while the latest crawl left the unusable marker
// in the catalog); the remainder is tools the catalog has never heard of.
// docs/operations.md quotes this line, so the two must change together.
func writeStats(w *stream, st processor.Stats) {
	w.printf("stats: lists served=%d denied=%d, tools hidden=%d (mismatched=%d unapproved=%d oversized=%d unverified=%d), calls allowed=%d denied=%d, wrong backend=%d, unauthenticated=%d, throttled=%d, source errors=%d, evidence dropped=%d\n",
		st.ListsServed, st.ListsDenied, st.ToolsHidden, st.ToolsMismatched, st.ToolsUnapproved, st.ToolsOversized, st.ToolsUnverified,
		st.CallsAllowed, st.CallsDenied, st.WrongBackend, st.Unauthenticated, st.Throttled, st.SourceErrors, st.EvidenceDropped)
}
